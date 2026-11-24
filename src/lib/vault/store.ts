/**
 * Credential store — backed by the REAL canonical ECHO Master Vault ("Vault A"
 * on FORGE, PyNaCl SecretBox at rest) via `gate-client.ts`, NOT a local store.
 *
 * This file used to be an ephemeral in-memory `Map` with its own AES-256-GCM
 * "encryption at rest" — meaning every secret this broker ever touched lived
 * ONLY in this process's RAM, re-populated from raw env vars / sandbox token
 * files on every boot, and vanished on restart. That is exactly the kind of
 * second, disconnected credential store the fleet's vault doctrine forbids:
 * "Canonical store = Vault A... never write a dumpimport:/harvested. name...
 * all writes go through echo.vault.put." This rewrite makes that fix real:
 *
 *   - `put()`      writes THROUGH to Vault A (echo.vault.put) — one writer.
 *   - `resolveSecret()` LOCATES then GETS from Vault A live, every call — no
 *     local ciphertext, no local copy of the plaintext at rest anywhere.
 *   - `revoke()`   is a BROKER-LOCAL quarantine flag only. It does NOT delete
 *     or mutate the canonical vault (DELETE-from-credentials is a fleet-wide
 *     hard limit) — it just makes this broker refuse to use the ref again.
 *     Real credential rotation/deletion is a Vault A operation, not this
 *     broker's job.
 *
 * The public interface (put/getMetadata/listMetadata/updateMetadata/
 * resolveSecret/revoke/has/count) is UNCHANGED so broker.ts / tools.ts /
 * providers.ts need no changes at all — this is a pure backend swap.
 * (`syncFromVault` / `getMetadataOrDiscover` were added later so the
 * reporting tools can enumerate the canonical store instead of trusting
 * this process's cache — see their doc comments.)
 */
import { registerSecretForRedaction } from "./redaction.ts";
import { GateVaultBackend, type VaultBackend } from "./backend.ts";
import { GateUnavailableError } from "./gate-client.ts";
import { log } from "./log.ts";
import type { CredentialMetadata, CredentialType, ProviderId } from "./types.ts";
import { formatVaultRef, parseVaultRef, PROVIDER_IDS } from "./refs.ts";

export interface PutCredentialInput {
  provider: ProviderId;
  account: string;
  type: CredentialType;
  secret: string;
  source: string;
}

interface LocalRecord {
  meta: CredentialMetadata;
  /** Cached (service, username) coordinate once resolved, to avoid a locate() on every call. */
  coordinate?: { service: string; username: string };
}

const BYPASS_REASON =
  "echo-credential-broker: agent-facing opaque vault:// handle resolves through the canonical Master Vault; the raw secret is used server-side for one allowlisted provider call and never returned across the MCP/HTTP boundary.";

/** How long a completed census stays fresh before status/list re-search Vault A. */
const CENSUS_TTL_MS = 30_000;

export class CredentialStore {
  private readonly records = new Map<string, LocalRecord>();
  private readonly backend: VaultBackend;
  private lastCensusAt = 0;
  private censusInFlight: Promise<string[]> | null = null;

  /**
   * @param backend Defaults to the REAL canonical vault (GateVaultBackend).
   *   Tests MUST pass a FakeVaultBackend — never exercise the real gate from
   *   a test, or a throwaway test secret can overwrite a production credential.
   */
  constructor(backend: VaultBackend = new GateVaultBackend()) {
    this.backend = backend;
  }

  /** Write a NEW credential through to the canonical vault (the one writer). */
  async put(input: PutCredentialInput): Promise<CredentialMetadata> {
    const secret = input.secret.trim();
    if (!secret) {
      throw Object.assign(new Error("empty_secret"), { code: "empty_secret" });
    }
    registerSecretForRedaction(secret);
    const ref = formatVaultRef(input.provider, input.account);
    const result = await this.backend.put(
      input.provider,
      input.account,
      secret,
      `echo-credential-broker: ${input.source}`,
      BYPASS_REASON,
    );
    const meta: CredentialMetadata = {
      ref,
      provider: input.provider,
      account: input.account,
      type: input.type,
      status: "imported",
      last_verified: null,
      fingerprint: result.key_fingerprint ?? null,
      source: input.source,
    };
    this.records.set(ref, { meta, coordinate: { service: input.provider, username: input.account } });
    log.info("credential_put", { ref, provider: input.provider, account: input.account, source: input.source });
    return { ...meta };
  }

  /**
   * Discovery only — raw locate candidates (service/username/key_shape),
   * NEVER a secret. Lets a caller disambiguate across the vault's real
   * accounts for a provider instead of being stuck with one hardcoded
   * default, without ever fetching a value.
   */
  async find(query: string) {
    return this.backend.search(query, BYPASS_REASON);
  }

  getMetadata(ref: string): CredentialMetadata | null {
    const rec = this.records.get(ref);
    return rec ? { ...rec.meta } : null;
  }

  /**
   * Metadata with discover-on-miss: a cache miss LOCATES the ref in the
   * canonical vault (metadata only — no secret fetch) and registers it, so a
   * single metadata call can repopulate a ref this process has never seen.
   * Returns null only when the vault genuinely does not hold the ref (or the
   * gate is unavailable — fail closed, never fabricate).
   */
  async getMetadataOrDiscover(ref: string): Promise<CredentialMetadata | null> {
    const hit = this.getMetadata(ref);
    if (hit) return hit;
    const rec = await this.discover(ref);
    return rec ? { ...rec.meta } : null;
  }

  /**
   * Census — register metadata for every credential the canonical vault
   * actually holds for the broker's providers, enumerating via backend
   * SEARCH (the same source `find()` reads), never exact-coordinate guesses.
   *
   * This exists because `count()` / `listMetadata()` read only this
   * process's local cache, which used to be populated solely by this
   * process's own `put()` calls and a one-shot locate() of five hardcoded
   * default refs. After a restart, credentials that live in Vault A under
   * any other coordinates were invisible to vault_status / vault_list while
   * vault_find found them. The census makes status/list agree with find.
   *
   * Metadata only — no secret is ever fetched. Existing records (e.g. from
   * `put()`, which knows the real coordinate and type) are never overwritten.
   * Throttled by CENSUS_TTL_MS and de-duplicated while in flight; a failed
   * search for one provider is logged and skipped, never fabricated, and the
   * freshness timestamp only advances when at least one search succeeded.
   *
   * @returns the refs registered from the vault by this census.
   */
  async syncFromVault(options?: { force?: boolean; maxAgeMs?: number }): Promise<string[]> {
    const maxAgeMs = options?.maxAgeMs ?? CENSUS_TTL_MS;
    if (!options?.force && Date.now() - this.lastCensusAt < maxAgeMs) {
      return this.listMetadata().map((m) => m.ref);
    }
    if (this.censusInFlight) return this.censusInFlight;
    const run = (async (): Promise<string[]> => {
      let anySuccess = false;
      const refs: string[] = [];
      for (const provider of PROVIDER_IDS) {
        let result: Awaited<ReturnType<VaultBackend["search"]>>;
        try {
          result = await this.backend.search(provider, BYPASS_REASON);
        } catch (err) {
          log.warn("census_search_failed", { provider, message: (err as Error).message });
          continue;
        }
        anySuccess = true;
        for (const cand of result.candidates ?? []) {
          const ref = formatVaultRef(provider, cand.username);
          if (!parseVaultRef(ref)) continue; // username cannot be a vault:// account — not addressable as a ref
          if (!this.records.has(ref)) {
            const meta: CredentialMetadata = {
              ref,
              provider,
              account: cand.username,
              type: "api_key",
              status: "imported",
              last_verified: null,
              fingerprint: null,
              source: `vault:${cand.actual_service}/${cand.username}`,
            };
            this.records.set(ref, {
              meta,
              coordinate: { service: cand.actual_service, username: cand.username },
            });
          }
          refs.push(ref);
        }
      }
      if (anySuccess) this.lastCensusAt = Date.now();
      log.info("census_synced", { registered: refs.length });
      return [...new Set(refs)];
    })();
    this.censusInFlight = run;
    try {
      return await run;
    } finally {
      if (this.censusInFlight === run) this.censusInFlight = null;
    }
  }

  listMetadata(): CredentialMetadata[] {
    return [...this.records.values()].map((r) => ({ ...r.meta }));
  }

  updateMetadata(
    ref: string,
    patch: Partial<Pick<CredentialMetadata, "status" | "last_verified" | "account">>,
  ): CredentialMetadata | null {
    const rec = this.records.get(ref);
    if (!rec) return null;
    rec.meta = { ...rec.meta, ...patch, ref: rec.meta.ref };
    this.records.set(ref, rec);
    return { ...rec.meta };
  }

  /**
   * Register metadata for a ref this broker has not seen yet, by locating it
   * (metadata only — no secret fetch) in the canonical vault. Used so
   * `has()`/`vault_list` work for credentials that already live in Vault A
   * without requiring an explicit prior `put()` in THIS process.
   */
  private async discover(ref: string): Promise<LocalRecord | null> {
    const parsed = parseVaultRef(ref);
    if (!parsed) return null;
    try {
      const coordinate = await this.backend.locate(parsed.provider, parsed.account, BYPASS_REASON);
      if (!coordinate) {
        log.debug("discover_not_found", { ref, provider: parsed.provider, account: parsed.account });
        return null;
      }
      const meta: CredentialMetadata = {
        ref,
        provider: parsed.provider,
        account: parsed.account,
        type: "api_key",
        status: "imported",
        last_verified: null,
        fingerprint: null,
        source: `vault:${coordinate.service}/${coordinate.username}`,
      };
      const rec: LocalRecord = { meta, coordinate };
      this.records.set(ref, rec);
      log.debug("discover_ok", { ref, resolved_service: coordinate.service, resolved_username: coordinate.username });
      return rec;
    } catch (err) {
      if (err instanceof GateUnavailableError) {
        log.warn("discover_gate_unavailable", { ref, message: err.message });
        return null; // fail closed, never fabricate
      }
      return null;
    }
  }

  /**
   * Resolve the raw secret LIVE from the canonical vault. NEVER return this
   * across an MCP / HTTP / UI boundary — callers must keep it on the stack.
   */
  async resolveSecret(ref: string): Promise<string | null> {
    let rec = this.records.get(ref);
    if (!rec) rec = (await this.discover(ref)) ?? undefined;
    if (!rec) return null;
    if (rec.meta.status === "revoked") return null; // broker-local quarantine wins

    const tryGet = async (service: string, username: string): Promise<string | null> => {
      try {
        const got = await this.backend.get(service, username, BYPASS_REASON);
        registerSecretForRedaction(got.secret);
        rec!.coordinate = { service, username };
        rec!.meta = { ...rec!.meta, fingerprint: got.key_fingerprint ?? rec!.meta.fingerprint };
        this.records.set(ref, rec!);
        return got.secret;
      } catch {
        return null;
      }
    };

    if (rec.coordinate) {
      const secret = await tryGet(rec.coordinate.service, rec.coordinate.username);
      if (secret) return secret;
      rec.coordinate = undefined; // stale coordinate (rotated/renamed) — re-locate below
    }

    const parsed = parseVaultRef(ref);
    if (!parsed) return null;
    const coordinate = await this.backend.locate(parsed.provider, parsed.account, BYPASS_REASON);
    if (!coordinate) return null;
    return tryGet(coordinate.service, coordinate.username);
  }

  /** Broker-local quarantine — does NOT touch the canonical vault. */
  async revoke(ref: string): Promise<boolean> {
    let rec = this.records.get(ref);
    if (!rec) rec = (await this.discover(ref)) ?? undefined;
    if (!rec) return false;
    rec.meta.status = "revoked";
    this.records.set(ref, rec);
    log.warn("credential_revoked_local_quarantine", { ref });
    return true;
  }

  async has(ref: string): Promise<boolean> {
    let rec = this.records.get(ref);
    if (!rec) rec = (await this.discover(ref)) ?? undefined;
    return Boolean(rec && rec.meta.status !== "revoked");
  }

  count(): number {
    return [...this.records.values()].filter((r) => r.meta.status !== "revoked").length;
  }

  clear(): void {
    this.records.clear();
    this.lastCensusAt = 0;
    this.censusInFlight = null;
  }
}

const singleton = new CredentialStore();

export function getStore(): CredentialStore {
  return singleton;
}

export function resetStoreForTests(): CredentialStore {
  singleton.clear();
  return singleton;
}
