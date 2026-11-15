// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * The `owner` identity and the console bootstrap code.
 *
 * `owner` is the human owner acting through the passkey-gated web console
 * (owner-console.ts). It is the only identity besides the local stdio process
 * that the gateway lets through the `vault.admin.*` carve-out.
 *
 * Minting: `mintOwnerIdentity` is called from exactly one place — the console
 * session path in owner-console.ts, after a session token was matched against
 * its stored hash. Every minted object is frozen and remembered in a WeakSet;
 * the gateway accepts `kind: "owner"` ONLY for an object in that set
 * (`isMintedOwnerIdentity`). An identity that was parsed from a request,
 * copied, spread or built by hand — whatever its fields say — is not in the
 * set and is refused as unauthenticated. The MCP, REST, OAuth and workload
 * paths never import this module.
 *
 * The bootstrap code is how the FIRST passkey is enrolled: the local stdio
 * identity mints it (`admin_console_bootstrap`), it is shown once in that tool
 * result, and only its sha256 is stored. It is an enrollment code, not a vault
 * secret, but it is still never logged or ledgered.
 */
import { createHash, randomBytes } from "node:crypto";
import type { ClientIdentity } from "./contracts.ts";
import { getDefaultOwnerConsoleStore, sha256Hex, type OwnerConsoleStore } from "./owner-console-store.ts";

export const OWNER_CLIENT_ID_PATTERN = /^owner:[0-9a-f]{12}$/;
/** Read scopes for the tier-0 tools the console renders (audit_list, audit_verify). Admin tools need no scope: see the gateway carve-out. */
export const OWNER_SCOPES: readonly string[] = Object.freeze(["audit.read", "vault.read"]);

const minted = new WeakSet<object>();

/** `owner:<first 12 hex of sha256(credential id bytes)>`. */
export function ownerClientId(credentialId: string): string {
  return `owner:${createHash("sha256").update(Buffer.from(credentialId, "base64url")).digest("hex").slice(0, 12)}`;
}

/** ONLY for owner-console.ts, after it authenticated a console session. */
export function mintOwnerIdentity(credentialId: string): ClientIdentity {
  const identity: ClientIdentity = Object.freeze({
    client_id: ownerClientId(credentialId),
    name: "Owner (console)",
    kind: "owner" as const,
    scopes: Object.freeze([...OWNER_SCOPES]) as unknown as string[],
  });
  minted.add(identity);
  return identity;
}

export function isMintedOwnerIdentity(identity: unknown): boolean {
  return typeof identity === "object" && identity !== null && minted.has(identity);
}

// ---------------------------------------------------------------------------
// Bootstrap code
// ---------------------------------------------------------------------------

export const BOOTSTRAP_TTL_MS = 15 * 60 * 1000;
/** `evb_` + 32 base64url chars = 192 random bits. */
export const BOOTSTRAP_CODE_PATTERN = /^evb_[A-Za-z0-9_-]{32}$/;

export interface BootstrapDeps {
  store?: OwnerConsoleStore;
  now?: () => number;
}

export function bootstrapCodeHash(code: string): string {
  return sha256Hex(`echo-vault-console-bootstrap-v1:${code}`);
}

/**
 * Mint the one active bootstrap code, replacing any earlier one. Local stdio
 * identity only: anything else throws `local_only` (the gateway also refuses
 * before it gets here).
 */
export async function mintBootstrapCode(
  identity: ClientIdentity,
  deps: BootstrapDeps = {},
): Promise<{ code: string; expires_at: string; ttl_seconds: number }> {
  if (identity?.kind !== "local") throw new Error("local_only");
  const store = deps.store ?? getDefaultOwnerConsoleStore();
  const now = (deps.now ?? Date.now)();
  const code = `evb_${randomBytes(24).toString("base64url")}`;
  await store.setBootstrapCode({
    code_hash: bootstrapCodeHash(code),
    minted_by: identity.client_id,
    created_at: now,
    expires_at: now + BOOTSTRAP_TTL_MS,
    consumed_at: null,
  });
  return { code, expires_at: new Date(now + BOOTSTRAP_TTL_MS).toISOString(), ttl_seconds: BOOTSTRAP_TTL_MS / 1000 };
}
