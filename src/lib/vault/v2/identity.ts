// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 caller identity. v2 NEVER trusts a self-asserted caller header:
 * `x-echo-agent` / `x-echo-caller` are ignored entirely here.
 *
 * Two transports, two trust roots:
 *   - Remote HTTP MCP (/api/mcp): the caller must present
 *     `Authorization: Bearer eva_…`, an opaque access token minted by the
 *     OAuth 2.1 server in oauth-server.ts after the owner approved the client
 *     on their phone. The token is checked against the sha256-hashed store
 *     (exists, kind=access, not revoked, not expired, audience = this MCP
 *     resource, client still approved).
 *   - Local stdio (scripts/mcp-stdio.ts): `localIdentity(name)`. There is no
 *     token. Trust = the OS process boundary: anyone who can spawn the stdio
 *     process as this OS user (and therefore read its environment) is trusted
 *     with ECHO_VAULT_LOCAL_SCOPES. Never bridge the stdio server onto a
 *     network socket — doing so would extend that trust to the network.
 */
import type { ClientIdentity } from "./contracts.ts";
import { log } from "../log.ts";
import { sanitizeError } from "../redaction.ts";
import type { OAuthClientRecord } from "./oauth-store.ts";
import {
  ACCESS_TOKEN_RE,
  DEFAULT_REQUESTED_SCOPES,
  SUPPORTED_SCOPES,
  buildWwwAuthenticate,
  canonicalScopes,
  oauthEnv,
  oauthNow,
  oauthStore,
  verifyAccessToken,
} from "./oauth-server.ts";

export type { ClientIdentity } from "./contracts.ts";
export {
  SUPPORTED_SCOPES,
  configureOAuth,
  type ClientApprovalRequest,
  type ClientApprovalStatus,
  type OwnerApprover,
} from "./oauth-server.ts";

/** Read-only default for the stdio transport. */
export const DEFAULT_LOCAL_SCOPES: readonly string[] = DEFAULT_REQUESTED_SCOPES;

const BEARER_RE = /^Bearer +(\S+) *$/i;
const LOCAL_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/**
 * Authenticate a remote MCP request. Accepts ONLY `Authorization: Bearer eva_…`
 * validated against the hashed token store. Any other header — including
 * `x-echo-agent: claude` — is ignored. Returns null on any failure (fail closed).
 */
export async function authenticateRequest(headers: Headers): Promise<ClientIdentity | null> {
  const auth = headers.get("authorization");
  if (!auth) return null;
  const m = BEARER_RE.exec(auth);
  if (!m) return null;
  const token = m[1];
  if (!ACCESS_TOKEN_RE.test(token)) return null;
  try {
    return await verifyAccessToken(token);
  } catch (err) {
    log.error("oauth_authenticate_failed", { error: sanitizeError(err).message });
    return null;
  }
}

/**
 * Value for the `WWW-Authenticate` header on a 401 from /api/mcp, per MCP
 * 2025-06-18 + RFC 9728 §5.1, e.g.
 *   Bearer resource_metadata="https://vault.example/.well-known/oauth-protected-resource"
 * Pass `{ error: "invalid_token" }` when a token was presented but rejected,
 * or `{ error: "insufficient_scope", scope: [...] }` alongside a 403.
 * If ECHO_VAULT_PUBLIC_URL is unusable this degrades to `Bearer realm="echo-vault"`.
 */
export function wwwAuthenticateHeader(opts?: {
  error?: "invalid_token" | "insufficient_scope";
  scope?: string[];
}): string {
  return buildWwwAuthenticate(opts ?? {});
}

/**
 * Identity for the stdio transport ONLY (see module doc: trust = OS process
 * boundary). Scopes come from ECHO_VAULT_LOCAL_SCOPES (comma list; unknown
 * entries are dropped with a warning) and default to read-only scopes.
 */
export function localIdentity(name: string): ClientIdentity {
  const normalized = String(name ?? "").trim().toLowerCase();
  if (!LOCAL_NAME_RE.test(normalized)) throw new Error("invalid_local_identity_name");
  const raw = oauthEnv().ECHO_VAULT_LOCAL_SCOPES;
  let scopes: string[];
  if (raw === undefined || raw.trim() === "") {
    scopes = [...DEFAULT_LOCAL_SCOPES];
  } else {
    const requested = raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const unknown = requested.filter((s) => !(SUPPORTED_SCOPES as readonly string[]).includes(s));
    if (unknown.length) log.warn("local_scopes_unknown_dropped", { unknown });
    scopes = canonicalScopes(requested);
  }
  return { client_id: `local:${normalized}`, name: normalized, kind: "local", scopes };
}

// ---------------------------------------------------------------------------
// Owner console
// ---------------------------------------------------------------------------

/** What the owner console sees about a client. Contains no secrets. */
export interface OAuthClientView {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  status: OAuthClientRecord["status"];
  requested_scopes: string[];
  granted_scopes: string[];
  created_at: string;
  approved_at: string | null;
  revoked_at: string | null;
}

function iso(ms: number | null): string | null {
  return ms === null ? null : new Date(ms).toISOString();
}

function view(rec: OAuthClientRecord): OAuthClientView {
  return {
    client_id: rec.client_id,
    client_name: rec.client_name,
    redirect_uris: [...rec.redirect_uris],
    status: rec.status,
    requested_scopes: [...rec.requested_scopes],
    granted_scopes: [...rec.granted_scopes],
    created_at: new Date(rec.created_at).toISOString(),
    approved_at: iso(rec.approved_at),
    revoked_at: iso(rec.revoked_at),
  };
}

export async function listClients(): Promise<OAuthClientView[]> {
  const rows = await oauthStore().listClients();
  return rows.map(view);
}

/**
 * Owner kill switch: mark the client revoked, drop its grant, revoke every
 * access/refresh token it holds, and deny its pending authorizations.
 * A revoked client cannot be re-approved; it must re-register (new client_id).
 */
export async function revokeClient(client_id: string): Promise<{ ok: boolean; tokens_revoked: number }> {
  const store = oauthStore();
  const now = oauthNow();
  const existing = await store.getClient(client_id);
  if (!existing) return { ok: false, tokens_revoked: 0 };
  await store.updateClient(client_id, { status: "revoked", granted_scopes: [], revoked_at: now });
  const tokensRevoked = await store.revokeClientTokens(client_id, now);
  await store.denyPendingForClient(client_id);
  log.warn("oauth_client_revoked", { client_id, tokens_revoked: tokensRevoked });
  return { ok: true, tokens_revoked: tokensRevoked };
}

/**
 * Owner sets an approved client's granted scopes. Narrowing takes effect on
 * existing tokens immediately (authenticateRequest intersects with the current
 * grant); widening applies to tokens issued afterwards.
 * Throws "unknown_scope", "client_not_found", or "client_not_approved".
 */
export async function setClientScopes(client_id: string, scopes: string[]): Promise<OAuthClientView> {
  if (!Array.isArray(scopes) || scopes.some((s) => !(SUPPORTED_SCOPES as readonly string[]).includes(s))) {
    throw new Error("unknown_scope");
  }
  const store = oauthStore();
  const existing = await store.getClient(client_id);
  if (!existing) throw new Error("client_not_found");
  if (existing.status !== "approved") throw new Error("client_not_approved");
  const granted = canonicalScopes(scopes);
  const updated = await store.updateClient(client_id, { granted_scopes: granted });
  if (!updated) throw new Error("client_not_found");
  log.info("oauth_client_scopes_set", { client_id, scopes: granted });
  return view(updated);
}
