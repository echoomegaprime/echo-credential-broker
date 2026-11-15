/**
 * Pluggable backend seam for CredentialStore. The production default
 * (`GateVaultBackend`) hits the REAL canonical Master Vault over the SDK
 * gate. `FakeVaultBackend` is an in-memory stand-in for tests — tests must
 * NEVER exercise `GateVaultBackend` against production Vault A (writing a
 * throwaway test secret under a real ref like `vault://github/echoomegaprime`
 * would clobber the actual credential every other service depends on).
 */
import {
  resolveCoordinate,
  vaultGet,
  vaultLocate,
  vaultPut,
  type GetResult,
  type LocateResult,
  type PutResult,
} from "./gate-client.ts";

export interface VaultBackend {
  put(service: string, username: string, secret: string, note: string, bypassReason: string): Promise<PutResult>;
  get(service: string, username: string, bypassReason: string): Promise<GetResult>;
  /** Locate-then-resolve a definite (service, username) coordinate, or null if not found/ambiguous. */
  locate(locateQuery: string, accountHint: string, bypassReason: string): Promise<{ service: string; username: string } | null>;
  /** Raw locate result (status + every candidate's service/username, never a secret) for discovery. */
  search(query: string, bypassReason: string): Promise<LocateResult>;
  /**
   * OPTIONAL real delete of one stored secret. `{ ok: true }` only when the
   * value is gone. Implement it ONLY where the backend has a genuine delete
   * call: the canonical gate vault has none (see store.ts), so GateVaultBackend
   * deliberately omits it and v2 purge falls back to overwriting the value.
   */
  delete?(service: string, username: string, bypassReason: string): Promise<{ ok: boolean }>;
}

export class GateVaultBackend implements VaultBackend {
  put(service: string, username: string, secret: string, note: string, bypassReason: string) {
    return vaultPut(service, username, secret, note, bypassReason);
  }
  get(service: string, username: string, bypassReason: string) {
    return vaultGet(service, username, bypassReason);
  }
  locate(locateQuery: string, accountHint: string, bypassReason: string) {
    return resolveCoordinate(locateQuery, accountHint, bypassReason);
  }
  search(query: string, bypassReason: string) {
    return vaultLocate(query, bypassReason);
  }
}

/** In-memory backend for tests. Never touches the network or the real vault. */
export class FakeVaultBackend implements VaultBackend {
  protected readonly secrets = new Map<string, string>(); // `${service}/${username}` -> secret
  private version = 0;

  async put(service: string, username: string, secret: string, _note: string, _bypassReason: string): Promise<PutResult> {
    this.secrets.set(`${service}/${username}`, secret);
    this.version += 1;
    return { stored: true, service, version: this.version, key_fingerprint: `fake${this.version}` };
  }

  async get(service: string, username: string, _bypassReason: string): Promise<GetResult> {
    const secret = this.secrets.get(`${service}/${username}`);
    if (secret === undefined) {
      throw Object.assign(new Error("not_found"), { code: "not_found" });
    }
    return { service, username, secret, key_fingerprint: `fake${this.version}` };
  }

  async locate(locateQuery: string, accountHint: string, _bypassReason: string) {
    // Fakes register directly under (provider, account) via put(), so an
    // exact-match lookup is sufficient for test scenarios.
    if (this.secrets.has(`${locateQuery}/${accountHint}`)) {
      return { service: locateQuery, username: accountHint };
    }
    return null;
  }

  async search(query: string, _bypassReason: string) {
    const candidates = [...this.secrets.keys()]
      .filter((k) => k.startsWith(`${query}/`))
      .map((k) => {
        const [service, username] = k.split("/");
        return { actual_service: service, username, key_shape: "fake" };
      });
    if (candidates.length === 0) return { status: "NOT_FOUND" as const, service: query, candidates: [], did_you_mean: [] };
    if (candidates.length === 1) {
      return { status: "EXACT" as const, service: query, candidates, get_with: { service: candidates[0].actual_service, username: candidates[0].username } };
    }
    return { status: "AMBIGUOUS" as const, service: query, count: candidates.length, candidates };
  }
}

/** FakeVaultBackend plus a real delete, for exercising the `delete?` path of v2 purge in tests. */
export class DeletableFakeVaultBackend extends FakeVaultBackend {
  async delete(service: string, username: string, _bypassReason: string): Promise<{ ok: boolean }> {
    return { ok: this.secrets.delete(`${service}/${username}`) };
  }
}
