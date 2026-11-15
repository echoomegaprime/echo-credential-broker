// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 rotation and real delete.
 *
 * Invariant: agents may USE credentials, agents may NEVER READ credentials.
 * Nothing here returns, logs, ledgers or stores (outside the vault backend) a
 * secret value. A new secret obtained from a provider goes
 * provider response → `registerSecretForRedaction` → vault backend `put`, and
 * nowhere else. Provider response bodies are never logged or put in an error.
 *
 *   Rotator      One per provider. `rotate(currentSecret, entry, deps)` asks the
 *                provider for a replacement and returns it to rotateEntry only.
 *                Registered: Cloudflare user API tokens ("Roll token").
 *
 *   rotateEntry  read secret (same path as useEntry) → rotator → `put` the new
 *                secret FIRST → only then update metadata. Any failure before
 *                the provider rotated keeps the old secret and records a short
 *                code in `last_rotation_error`. One ledger row per attempt
 *                (capability "vault.entry.rotate", result ok/error).
 *
 *                WORST CASE — the provider already rotated (old token dead) and
 *                the new one could not be stored: the put is retried
 *                (PUT_ATTEMPTS, backoff); if every attempt fails the new value
 *                is dropped (never written anywhere else), the entry is flagged
 *                `needs_reentry` so nothing keeps using a dead token, the error
 *                code is the distinct `rotated_but_not_stored`, and it is logged
 *                at error level. Recovery: roll the token again at the provider
 *                and re-enter it on a card. See docs/ops/rotation-and-delete.md.
 *
 *   purgeEntry   The irreversible delete (deleteEntry in cards.ts is the
 *                reversible soft delete). Order: soft-delete → destroy the
 *                secret (backend delete, else overwrite with random bytes,
 *                verified) → ledger "vault.entry.purge" → remove grants, cards
 *                and the row. A crash at any point leaves either a row that
 *                still points at the secret or no secret at all — never a
 *                usable secret with no metadata — and success is reported only
 *                after the secret is destroyed.
 */
import { log } from "../log.ts";
import { registerSecretForRedaction } from "../redaction.ts";
import {
  EntryError,
  MAX_SECRET_LENGTH,
  MIN_SECRET_LENGTH,
  openEntryVault,
  secretFingerprint,
  setRotationPolicy,
  type CardsDeps,
  type EntryMetadata,
  type EntryVault,
  type RotationPolicyInput,
} from "./cards.ts";
import { getDefaultEntryGrantStore, type EntryGrantStore } from "./entry-grants.ts";

// ---------------------------------------------------------------- rotators

export interface RotatorDeps {
  /** Transport for the provider call. Injected in tests. */
  fetch: typeof fetch;
  timeoutMs: number;
}

export interface Rotator {
  /** Short lowercase name, e.g. "cloudflare". */
  provider: string;
  /** Pure: can this entry be auto-rotated by this rotator (site, kind, provider_token_id)? */
  supports(entry: EntryMetadata): boolean;
  /**
   * Ask the provider for a replacement secret. Must throw RotationError with a
   * short code on failure and must never put provider response text in it.
   */
  rotate(currentSecret: string, entry: EntryMetadata, deps: RotatorDeps): Promise<{ newSecret: string }>;
}

/**
 * Sanitized rotation/purge failure. `code` is a short stable code; the message
 * is fixed text. `providerRotated` = the provider has (or may have) already
 * invalidated the old secret.
 */
export class RotationError extends EntryError {
  readonly providerRotated: boolean;
  constructor(code: string, message: string, providerRotated = false) {
    super(code, message);
    this.name = "RotationError";
    this.providerRotated = providerRotated;
  }
}

const CODE_PATTERN = /^[a-z0-9_]{1,64}$/;
const ROTATOR_TIMEOUT_MS = 15_000;
const MAX_PROVIDER_BODY_BYTES = 64 * 1024;
export const PUT_ATTEMPTS = 5;
const PUT_BACKOFF_MS = 250;

/** The code of the worst case: the provider rotated, the new secret is not in the vault. */
export const ROTATED_BUT_NOT_STORED = "rotated_but_not_stored";

// --- Cloudflare: Roll token -------------------------------------------------
// Verified 2026-11-14 against the Cloudflare API reference, "User > API Tokens >
// Roll Token":
//   https://developers.cloudflare.com/api/resources/user/subresources/tokens/subresources/value/methods/update/
//   PUT https://api.cloudflare.com/client/v4/user/tokens/{token_id}/value
//   Authorization: Bearer <token with "API Tokens Write">   (token_id: max 32 chars)
//   200 → { "success": true, "errors": [], "messages": [], "result": "<new token value, 40-80 chars>" }
// The reference lists no body parameters; `{}` is sent as a valid empty JSON body.
// Rolling invalidates the previous value immediately; permissions are unchanged.
// A token can only roll itself if it carries the "API Tokens Write" permission.
const CLOUDFLARE_API = "https://api.cloudflare.com/client/v4";
const CLOUDFLARE_TOKEN_ID = /^[0-9a-f]{32}$/;

function isCloudflareSite(site: string): boolean {
  return site === "cloudflare.com" || site.endsWith(".cloudflare.com");
}

async function readCapped(res: Response, limit: number): Promise<string> {
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > limit) throw new Error("too large");
  return buf.toString("utf8");
}

export const cloudflareTokenRotator: Rotator = {
  provider: "cloudflare",
  supports(entry) {
    return (
      entry.kind === "api_key" &&
      isCloudflareSite(entry.site) &&
      typeof entry.provider_token_id === "string" &&
      CLOUDFLARE_TOKEN_ID.test(entry.provider_token_id)
    );
  },
  async rotate(currentSecret, entry, deps) {
    if (!this.supports(entry)) throw new RotationError("rotation_unsupported", "This entry cannot be auto-rotated");
    let res: Response;
    try {
      res = await deps.fetch(`${CLOUDFLARE_API}/user/tokens/${entry.provider_token_id}/value`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${currentSecret}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: "{}",
        redirect: "error",
        signal: AbortSignal.timeout(deps.timeoutMs),
      });
    } catch {
      // The request may or may not have reached Cloudflare; the old token is kept.
      throw new RotationError("provider_unreachable", "The provider could not be reached");
    }
    if (!res.ok) {
      // Deliberately not reading the body: an error body is provider text.
      await res.body?.cancel().catch(() => undefined);
      throw new RotationError(`provider_http_${res.status}`, "The provider refused the rotation");
    }
    // 2xx: Cloudflare has rolled the token. From here the old value is dead.
    let value: unknown;
    let success: unknown;
    try {
      const parsed = JSON.parse(await readCapped(res, MAX_PROVIDER_BODY_BYTES)) as { success?: unknown; result?: unknown };
      value = parsed?.result;
      success = parsed?.success;
      if (typeof value === "string") registerSecretForRedaction(value);
    } catch {
      throw new RotationError(ROTATED_BUT_NOT_STORED, "The provider rotated the secret but its answer was unreadable", true);
    }
    if (success !== true || typeof value !== "string" || value.trim().length < MIN_SECRET_LENGTH) {
      throw new RotationError(
        ROTATED_BUT_NOT_STORED,
        "The provider answered 2xx without a usable new secret",
        true,
      );
    }
    return { newSecret: value.trim() };
  },
};

const registry: Rotator[] = [cloudflareTokenRotator];

/** Add a provider rotator (first match wins; later registrations are consulted first). */
export function registerRotator(rotator: Rotator): void {
  if (!rotator || !/^[a-z][a-z0-9_-]{0,31}$/.test(rotator.provider)) {
    throw new RotationError("invalid_rotator", "A rotator needs a short lowercase provider name");
  }
  registry.unshift(rotator);
}

export function listRotatorProviders(): string[] {
  return [...new Set(registry.map((r) => r.provider))];
}

export function findRotator(entry: EntryMetadata, rotators: readonly Rotator[] = registry): Rotator | null {
  for (const r of rotators) {
    try {
      if (r.supports(entry)) return r;
    } catch {
      /* a broken rotator supports nothing */
    }
  }
  return null;
}

// ---------------------------------------------------------------- wiring

export interface RotationDeps extends CardsDeps {
  /** Transport for provider rotation calls. Default: globalThis.fetch. (CardsDeps.fetch is Telegram's.) */
  rotatorFetch?: typeof fetch;
  /** Rotators to consult instead of the registry (tests). */
  rotators?: readonly Rotator[];
  /** Ledger `client_id` for the row. Default "local:rotation". */
  actor?: string;
  /** Backoff between put attempts. Default: real timers. */
  sleep?: (ms: number) => Promise<void>;
  /** Consent grants to remove on purge. Default: the SQL store. */
  grants?: EntryGrantStore;
}

const DEFAULT_ACTOR = "local:rotation";
const inFlight = new Set<string>();

function actorOf(deps: RotationDeps): string {
  const a = deps.actor;
  return typeof a === "string" && a.length > 0 && a.length <= 200 ? a : DEFAULT_ACTOR;
}

function resourceOf(row: EntryMetadata | null): string {
  return row ? `entry:${row.site}/${row.account}` : "entry:unknown";
}

function refOf(row: EntryMetadata | null): string | undefined {
  return row ? `vault://entry/${row.id}` : undefined;
}

function safeCode(err: unknown, fallback: string): string {
  const code = err instanceof EntryError ? err.code : fallback;
  return CODE_PATTERN.test(code) ? code : fallback;
}

async function setError(v: EntryVault, id: string, code: string): Promise<void> {
  await v.entries.setRotationError(id, CODE_PATTERN.test(code) ? code : "rotation_failed", v.nowIso).catch(() => null);
}

// ---------------------------------------------------------------- rotateEntry

export interface RotateResult {
  /** Metadata after the rotation. Never a secret. */
  entry: EntryMetadata;
  provider: string;
  /** Non-fatal problems after the new secret was safely stored, e.g. "ledger_unavailable". */
  warnings: string[];
}

/**
 * Auto-rotate one entry now (any rotation_mode: the owner may force it).
 * Throws RotationError/EntryError with a short code; see the module header for
 * the ordering and the worst case.
 */
export async function rotateEntry(id: string, deps: RotationDeps = {}): Promise<RotateResult> {
  const v = openEntryVault(deps);
  const started = Date.now();
  const actor = actorOf(deps);
  const row = typeof id === "string" && /^ve_[0-9a-f]{32}$/.test(id) ? await v.entries.get(id) : null;
  const rotator = row ? findRotator(row, deps.rotators) : null;
  const ledgerRow = (result: "ok" | "error", error?: string) => ({
    client_id: actor,
    capability: "vault.entry.rotate",
    resource: resourceOf(row),
    credential_ref: refOf(row),
    decision: "allow" as const,
    tier: 3 as const,
    result,
    error,
    duration_ms: Date.now() - started,
    task: rotator ? `auto-rotate (${rotator.provider})` : "auto-rotate",
  });
  /** Record the failed attempt (ledger + last_rotation_error) and throw. */
  const fail = async (err: RotationError | EntryError): Promise<never> => {
    const code = safeCode(err, "rotation_failed");
    if (row && row.status !== "deleted") await setError(v, row.id, code);
    await v.ledger(ledgerRow("error", code), false);
    log.warn("vault_entry_rotation_failed", { entry_id: row?.id ?? "unknown", site: row?.site, error: code });
    throw err;
  };

  if (!row || row.status === "deleted") return fail(new RotationError("entry_not_found", "No such entry"));
  if (row.status !== "active") {
    return fail(new RotationError("entry_needs_reentry", "This entry needs its secret re-entered; it cannot be rotated"));
  }
  if (!rotator) {
    return fail(new RotationError("rotation_unsupported", "No rotator supports this entry (site, kind or provider_token_id)"));
  }
  if (inFlight.has(row.id)) return fail(new RotationError("rotation_in_progress", "This entry is already being rotated"));
  inFlight.add(row.id);
  try {
    let current: string;
    try {
      current = await v.readSecret(row);
    } catch (err) {
      return await fail(err instanceof EntryError ? err : new RotationError("vault_unavailable", "The vault could not be reached"));
    }

    // 1. Provider. On a failure here the old secret is still the stored one.
    let next: string;
    try {
      const out = await rotator.rotate(current, row, {
        fetch: deps.rotatorFetch ?? globalThis.fetch,
        timeoutMs: ROTATOR_TIMEOUT_MS,
      });
      next = typeof out?.newSecret === "string" ? out.newSecret : "";
      if (next) registerSecretForRedaction(next); // the moment we hold it
    } catch (err) {
      const e =
        err instanceof RotationError
          ? err
          : new RotationError("rotator_failed", "The rotator failed"); // never the underlying message
      if (e.providerRotated) return await lost(v, row, e, ledgerRow);
      return await fail(e);
    }
    if (next === current) {
      // Nothing changed at the provider: the stored secret is still the live one.
      return await fail(new RotationError("provider_returned_same_secret", "The provider returned the same secret"));
    }
    if (next.length < MIN_SECRET_LENGTH || next.length > MAX_SECRET_LENGTH) {
      // The provider said it rotated but gave nothing storable: the old token must be assumed dead.
      return await lost(
        v,
        row,
        new RotationError(ROTATED_BUT_NOT_STORED, "The provider rotated the secret but returned nothing storable", true),
        ledgerRow,
      );
    }

    // 2. Vault FIRST. The provider has already rotated: retry hard before giving up.
    const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
    let stored = false;
    for (let attempt = 1; attempt <= PUT_ATTEMPTS && !stored; attempt += 1) {
      try {
        await v.writeSecret(row, next);
        stored = true;
      } catch {
        log.error("vault_entry_rotation_put_retry", { entry_id: row.id, attempt, of: PUT_ATTEMPTS });
        if (attempt < PUT_ATTEMPTS) await sleep(PUT_BACKOFF_MS * 2 ** (attempt - 1));
      }
    }
    if (!stored) {
      return await lost(
        v,
        row,
        new RotationError(
          ROTATED_BUT_NOT_STORED,
          "The provider rotated the secret but the vault could not store the new one; re-enter a fresh credential",
          true,
        ),
        ledgerRow,
      );
    }

    // 3. Metadata, only now. The new secret is safe; nothing below can lose it.
    const warnings: string[] = [];
    const fingerprint = secretFingerprint(next);
    let updated: EntryMetadata | null = null;
    for (let attempt = 0; attempt < 2 && !updated; attempt += 1) {
      updated = await v.entries.replaceSecretMeta(row.id, fingerprint, next.length, v.nowIso).catch(() => null);
    }
    if (!updated) {
      warnings.push("metadata_update_failed");
      log.error("vault_entry_rotation_metadata_stale", { entry_id: row.id });
    }
    try {
      await v.ledger(ledgerRow("ok"), true);
    } catch {
      warnings.push("ledger_unavailable");
    }
    log.info("vault_entry_rotated", { entry_id: row.id, site: row.site, provider: rotator.provider, warnings: warnings.join(",") });
    return { entry: updated ?? row, provider: rotator.provider, warnings };
  } finally {
    inFlight.delete(row.id);
  }
}

/** The worst case: surface it loudly, stop the dead token being used, record it, throw. */
async function lost(
  v: EntryVault,
  row: EntryMetadata,
  err: RotationError,
  ledgerRow: (result: "ok" | "error", error?: string) => Parameters<EntryVault["ledger"]>[0],
): Promise<never> {
  log.error("vault_entry_rotation_SECRET_LOST", {
    entry_id: row.id,
    site: row.site,
    error: ROTATED_BUT_NOT_STORED,
    action: "roll the token again at the provider and re-enter it on a card",
  });
  await v.entries
    .flag(row.id, "auto-rotation: the provider rotated the secret but the new one was not stored; re-enter a fresh one", v.nowIso)
    .catch(() => null);
  await setError(v, row.id, ROTATED_BUT_NOT_STORED);
  await v.ledger(ledgerRow("error", ROTATED_BUT_NOT_STORED), false);
  throw new RotationError(ROTATED_BUT_NOT_STORED, err.message, true);
}

// ---------------------------------------------------------------- rotateDueEntries

export interface RotateDueResult {
  /** Entries whose rotate_by has passed. */
  due: number;
  rotated: number;
  failed: number;
  /** Rotations that succeeded with a warning (metadata/ledger). */
  warned: number;
  /** Due entries nobody can roll automatically: manual mode, or auto with no supporting rotator. Ids/labels only. */
  needs_manual_rotation: Array<{ id: string; label: string }>;
  /** Failed attempts: entry id + short code. */
  failures: Array<{ id: string; error: string }>;
}

/** Rotate every due `auto` entry that has a supporting rotator; report the rest. Never throws for one entry's failure. */
export async function rotateDueEntries(now: number | Date = Date.now(), deps: RotationDeps = {}): Promise<RotateDueResult> {
  const ms = now instanceof Date ? now.getTime() : now;
  if (!Number.isFinite(ms)) throw new RotationError("invalid_now", "now must be a valid time");
  const at = { ...deps, now: () => ms };
  const due = await openEntryVault(at).entries.listRotationDue(new Date(ms).toISOString());
  const out: RotateDueResult = { due: due.length, rotated: 0, failed: 0, warned: 0, needs_manual_rotation: [], failures: [] };
  for (const entry of due) {
    if (entry.rotation_mode !== "auto" || !findRotator(entry, deps.rotators)) {
      out.needs_manual_rotation.push({ id: entry.id, label: entry.label });
      continue;
    }
    try {
      const res = await rotateEntry(entry.id, at);
      out.rotated += 1;
      if (res.warnings.length > 0) out.warned += 1;
    } catch (err) {
      out.failed += 1;
      out.failures.push({ id: entry.id, error: safeCode(err, "rotation_failed") });
    }
  }
  return out;
}

// ---------------------------------------------------------------- policy (owner)

/**
 * Owner action: set the rotation policy. mode "auto" is refused unless a
 * registered rotator supports the entry with the resulting provider_token_id,
 * so an entry can never sit in "auto" with nothing able to rotate it.
 */
export async function setEntryRotation(
  id: string,
  policy: RotationPolicyInput,
  deps: RotationDeps = {},
): Promise<{ entry: EntryMetadata; auto_supported: boolean }> {
  const v = openEntryVault(deps);
  const current = typeof id === "string" && /^ve_[0-9a-f]{32}$/.test(id) ? await v.entries.get(id) : null;
  if (!current || current.status === "deleted") throw new EntryError("entry_not_found", "No such entry");
  if (policy?.mode === "auto") {
    const tokenId =
      policy.provider_token_id === undefined
        ? current.provider_token_id
        : policy.provider_token_id === null
          ? null
          : String(policy.provider_token_id).trim();
    if (!findRotator({ ...current, provider_token_id: tokenId }, deps.rotators)) {
      throw new RotationError(
        "rotation_unsupported",
        "No rotator supports this entry. Auto-rotation currently covers Cloudflare API tokens (site cloudflare.com, " +
          "kind api_key, provider_token_id = the 32-hex token ID). Use mode manual.",
      );
    }
  }
  const entry = await setRotationPolicy(id, policy, deps);
  return { entry, auto_supported: findRotator(entry, deps.rotators) !== null };
}

// ---------------------------------------------------------------- purgeEntry

export interface PurgeResult {
  purged: true;
  entry_id: string;
  site: string;
  account: string;
  /** How the stored secret was destroyed. */
  secret_disposal: "deleted" | "overwritten";
  grants_removed: number;
  cards_removed: number;
}

/**
 * Irreversibly destroy an entry (active, needs_reentry or soft-deleted): the
 * stored secret, the row, its cards and every consent grant. Idempotent until
 * the row is gone: a failed purge can simply be run again. Throws EntryError
 * with a short code and reports success only after the secret is destroyed and
 * the purge is in the ledger.
 */
export async function purgeEntry(id: string, deps: RotationDeps = {}): Promise<PurgeResult> {
  const v = openEntryVault(deps);
  const started = Date.now();
  const actor = actorOf(deps);
  const row = typeof id === "string" && /^ve_[0-9a-f]{32}$/.test(id) ? await v.entries.get(id) : null;
  const ledgerRow = (result: "ok" | "error", error?: string) => ({
    client_id: actor,
    capability: "vault.entry.purge",
    resource: resourceOf(row),
    credential_ref: refOf(row),
    decision: "allow" as const,
    tier: 3 as const,
    result,
    error,
    duration_ms: Date.now() - started,
  });
  const fail = async (err: EntryError): Promise<never> => {
    await v.ledger(ledgerRow("error", safeCode(err, "purge_failed")), false);
    log.error("vault_entry_purge_failed", { entry_id: row?.id ?? "unknown", site: row?.site, error: safeCode(err, "purge_failed") });
    throw err;
  };
  if (!row) return fail(new EntryError("entry_not_found", "No such entry"));

  // 1. Stop every use. The row stays, so the metadata still points at the secret.
  if (row.status !== "deleted") {
    const marked = await v.entries.markDeleted(row.id, v.nowIso).catch(() => null);
    if (!marked) return fail(new EntryError("entry_store_failed", "The entry could not be marked deleted"));
  }

  // 2. Destroy the secret (verified). Until this succeeds nothing else is removed.
  let how: "deleted" | "overwritten";
  try {
    how = await v.destroySecret(row);
  } catch (err) {
    return fail(err instanceof EntryError ? err : new EntryError("purge_secret_not_destroyed", "The secret could not be destroyed"));
  }

  // 3. Ledger, fail closed: the row is only removed once the purge is on the chain.
  try {
    await v.ledger(ledgerRow("ok"), true);
  } catch {
    log.error("vault_entry_purge_unrecorded", { entry_id: row.id });
    throw new EntryError(
      "ledger_unavailable",
      "The secret was destroyed but the purge could not be recorded; the entry row is kept (deleted). Run the purge again.",
    );
  }

  // 4. Grants, cards, then the row itself (vault_cards.entry_id references it).
  try {
    const grants = deps.grants ?? getDefaultEntryGrantStore();
    const held = await grants.list({ entry_id: row.id });
    let grantsRemoved = 0;
    for (const clientId of new Set(held.map((g) => g.client_id))) {
      if (await grants.remove(clientId, row.id)) grantsRemoved += held.filter((g) => g.client_id === clientId).length;
    }
    if ((await grants.list({ entry_id: row.id })).length > 0) throw new Error("grants remain");
    const cardsRemoved = await v.cards.deleteForEntry(row.id);
    if (!(await v.entries.hardDelete(row.id)) && (await v.entries.get(row.id))) throw new Error("row remains");
    log.warn("vault_entry_purged", { entry_id: row.id, site: row.site, secret_disposal: how, grants_removed: grantsRemoved });
    return {
      purged: true,
      entry_id: row.id,
      site: row.site,
      account: row.account,
      secret_disposal: how,
      grants_removed: grantsRemoved,
      cards_removed: cardsRemoved,
    };
  } catch {
    // The secret is already gone; only bookkeeping is left. Say so and let the owner retry.
    return fail(
      new EntryError(
        "purge_cleanup_failed",
        "The secret was destroyed but the entry's rows could not all be removed. Run the purge again.",
      ),
    );
  }
}
