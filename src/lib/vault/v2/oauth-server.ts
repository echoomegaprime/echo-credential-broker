// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * ECHO Vault v2 — OAuth 2.1 authorization server for the remote MCP endpoint.
 *
 * Framework-free: every handler takes a `Request` and returns a `Response`;
 * the TanStack routes under src/routes/[.]well-known and src/routes/api/oauth
 * only delegate here.
 *
 * Standards (read 2026-11-14):
 *   - MCP Authorization, rev 2025-06-18  (resource server + AS discovery)
 *   - RFC 9728 Protected Resource Metadata, RFC 8414 AS Metadata
 *   - RFC 7591 Dynamic Client Registration (public clients only)
 *   - OAuth 2.1 draft-ietf-oauth-v2-1-13 + RFC 7636 PKCE (S256 only)
 *   - RFC 7009 Token Revocation, RFC 8707 Resource Indicators, RFC 9207 `iss`
 *
 * Trust model:
 *   - Clients self-register (DCR) but receive NO scopes until the owner
 *     approves them on their phone through the injectable `OwnerApprover`.
 *   - Every /authorize run requires an owner approval, not just the first one
 *     for a client. A public client's client_id and redirect_uri are not
 *     secret, so "auto-approve after the first time" would let anyone who knows
 *     them start a flow in their own browser, read the code off the redirect,
 *     and redeem it with their own PKCE verifier. The first approval of a
 *     client sets its granted scopes; later approvals only re-authorize within
 *     those scopes (scope changes go through `setClientScopes`).
 *   - Access tokens (eva_) and refresh tokens (evr_) are opaque 256-bit random
 *     values, stored only as sha256 hex. Refresh tokens rotate; presenting a
 *     rotated one revokes the whole token family (OAuth 2.1 §4.3.1).
 *   - Nothing here logs or returns a raw code, token, verifier, or pending
 *     handle except the one place each is issued to its rightful holder.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { ClientIdentity } from "./contracts.ts";
import { log } from "../log.ts";
import { registerSecretForRedaction, sanitizeError } from "../redaction.ts";
import {
  MAX_EVENTS_PER_KEY,
  MemoryRateLimitStore,
  RateLimitUnavailableError,
  getDefaultRateLimitStore,
  rateLimitKey,
  withRateLimitStore,
  type RateLimitStore,
} from "./rate-limit-store.ts";
import {
  getOAuthStore,
  type OAuthClientRecord,
  type OAuthStore,
  type PendingAuthorizationRecord,
} from "./oauth-store.ts";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Every scope a client can be granted. Scope = `<namespace>.<read|write>` as
 * required by policy-engine.ts (`requiredScope`). No scope implies another.
 *   <provider>.read   tier-0 reads through that provider's credential
 *   <provider>.write  tier-1 writes; tier-2 writes still need a per-request approval
 *   vault.read        vault/entry metadata, card + approval status, read-only entry use
 *   vault.write       request a credential card; non-GET entry use (always approved per request)
 *   audit.read        read and verify the ledger
 * There is no stripe.write: Stripe writes are payments (tier 3, human only).
 */
export const SUPPORTED_SCOPES = [
  "github.read",
  "github.write",
  "cloudflare.read",
  "cloudflare.write",
  "openai.read",
  "openai.write",
  "stripe.read",
  "xai.read",
  "xai.write",
  "vault.read",
  "vault.write",
  "audit.read",
] as const;
export type VaultScope = (typeof SUPPORTED_SCOPES)[number];

/** Requested when a client asks for nothing specific. Read-only. */
export const DEFAULT_REQUESTED_SCOPES: readonly VaultScope[] = ["github.read", "cloudflare.read", "vault.read"];

export const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000;
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const CODE_TTL_MS = 60 * 1000;
export const PENDING_TTL_MS = 10 * 60 * 1000;
/** Never-approved registrations older than this are pruned to keep the client cap from filling with junk. */
export const STALE_CLIENT_MS = 24 * 60 * 60 * 1000;
const PURGE_INTERVAL_MS = 10 * 60 * 1000;
const POLL_INTERVAL_SECONDS = 3;

export const MCP_RESOURCE_PATH = "/api/mcp";
export const PROTECTED_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource";
export const AUTHORIZATION_SERVER_METADATA_PATH = "/.well-known/oauth-authorization-server";
export const AUTHORIZE_PATH = "/api/oauth/authorize";
export const TOKEN_PATH = "/api/oauth/token";
export const REGISTER_PATH = "/api/oauth/register";
export const REVOKE_PATH = "/api/oauth/revoke";

const MAX_BODY_BYTES = 16 * 1024;
const MAX_CLIENT_NAME = 100;
const MAX_REDIRECT_URIS = 10;
const MAX_REDIRECT_URI_LENGTH = 2048;
// State is opaque to us: we store it on the pending record (a text column)
// and echo it back byte-for-byte. RFC 6749 sets no length bound, and real
// clients exceed the old 1024 cap — Google's Gemini custom-connector flow
// issues multi-kilobyte state values and was rejected with "state is too
// long". 8192 leaves generous headroom while still bounding the value.
const MAX_STATE_LENGTH = 8192;

const B64URL_256 = "[A-Za-z0-9_-]{43}";
export const ACCESS_TOKEN_RE = new RegExp(`^eva_${B64URL_256}$`);
export const REFRESH_TOKEN_RE = new RegExp(`^evr_${B64URL_256}$`);
const CODE_RE = new RegExp(`^evc_${B64URL_256}$`);
const PENDING_RE = new RegExp(`^evp_${B64URL_256}$`);
const CLIENT_ID_RE = /^oc_[A-Za-z0-9_-]{22}$/;
const CODE_CHALLENGE_RE = new RegExp(`^${B64URL_256}$`);
/** RFC 7636 §4.1: 43–128 unreserved characters. */
const CODE_VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
// eslint-disable-next-line no-control-regex
const UNSAFE_NAME_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface Clock {
  /** Epoch milliseconds. */
  now(): number;
}

export type ClientApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface ClientApprovalRequest {
  client_id: string;
  /** Self-asserted by the client at registration. Display with care; `redirect_host` is the real identity signal. */
  client_name: string;
  requested_scopes: string[];
  /** Host (and port) of the redirect_uri the code will be sent to, e.g. "claude.ai" or "127.0.0.1:33418". */
  redirect_host: string;
  /** true the first time this client is seen; false when an already-approved client re-authorizes. */
  is_new_client?: boolean;
}

/**
 * Owner-side approval channel (capability "vault.client.authorize"). The lead
 * wires this to the Telegram approval system. Implementations must never put
 * secrets in the approval message — the request above contains none.
 */
export interface OwnerApprover {
  requestClientApproval(req: ClientApprovalRequest): Promise<{ approval_id: string }>;
  checkClientApproval(approval_id: string): Promise<ClientApprovalStatus>;
}

export type Env = Record<string, string | undefined>;

export class OAuthConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OAuthConfigError";
  }
}

export interface OAuthConfig {
  issuer: string;
  resource: string;
  protectedResourceMetadataUrl: string;
  authorizationServerMetadataUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint: string;
  revocationEndpoint: string;
  maxClients: number;
  maxPending: number;
}

// ---------------------------------------------------------------------------
// Configuration (read lazily; fail closed)
// ---------------------------------------------------------------------------

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function intEnv(env: Env, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw.trim());
  if (!Number.isInteger(n) || n < min || n > max) {
    log.warn("oauth_env_invalid_using_default", { name, fallback });
    return fallback;
  }
  return n;
}

/**
 * Resolve issuer + endpoint URLs from ECHO_VAULT_PUBLIC_URL.
 * Throws OAuthConfigError when unset, malformed, not an origin, or not https
 * (http is accepted only for loopback hosts and only outside NODE_ENV=production).
 */
export function resolveOAuthConfig(env: Env = process.env): OAuthConfig {
  const raw = (env.ECHO_VAULT_PUBLIC_URL ?? "").trim();
  if (!raw) throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL is not set");
  if (/[?#\s]/.test(raw)) throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL must not contain a query, fragment, or whitespace");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL is not a valid URL");
  }
  if (url.username || url.password) throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL must not contain credentials");
  if (url.pathname !== "/") throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL must be an origin (no path)");
  const httpsOk = url.protocol === "https:";
  const loopbackHttpOk =
    url.protocol === "http:" && isLoopbackHostname(url.hostname) && env.NODE_ENV !== "production";
  if (!httpsOk && !loopbackHttpOk) {
    throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL must use https (http only for localhost outside production)");
  }
  const issuer = url.origin;
  return {
    issuer,
    resource: `${issuer}${MCP_RESOURCE_PATH}`,
    protectedResourceMetadataUrl: `${issuer}${PROTECTED_RESOURCE_METADATA_PATH}`,
    authorizationServerMetadataUrl: `${issuer}${AUTHORIZATION_SERVER_METADATA_PATH}`,
    authorizationEndpoint: `${issuer}${AUTHORIZE_PATH}`,
    tokenEndpoint: `${issuer}${TOKEN_PATH}`,
    registrationEndpoint: `${issuer}${REGISTER_PATH}`,
    revocationEndpoint: `${issuer}${REVOKE_PATH}`,
    maxClients: intEnv(env, "ECHO_VAULT_OAUTH_MAX_CLIENTS", 256, 1, 100_000),
    maxPending: intEnv(env, "ECHO_VAULT_OAUTH_MAX_PENDING", 16, 1, 1_000),
  };
}

// ---------------------------------------------------------------------------
// Failed-attempt rate limiter (shared RateLimitStore, injectable clock)
// ---------------------------------------------------------------------------

/**
 * Counts failed attempts per key in a sliding window. State lives in a
 * RateLimitStore (default: the shared SQL store), so the limit survives a
 * restart and holds across server instances. Every method rejects with
 * RateLimitUnavailableError when the store fails; callers fail closed.
 */
export class FailureRateLimiter {
  private readonly now: () => number;
  readonly maxFailures: number;
  readonly windowMs: number;
  private readonly store: RateLimitStore | undefined;

  constructor(opts: {
    now: () => number;
    maxFailures?: number;
    windowMs?: number;
    /** Only used when no `store` is given: a private in-memory store capped at this many keys. */
    maxKeys?: number;
    /** Default: getDefaultRateLimitStore() (resolved per call). */
    store?: RateLimitStore;
  }) {
    this.now = opts.now;
    this.maxFailures = Math.min(opts.maxFailures ?? 10, MAX_EVENTS_PER_KEY);
    this.windowMs = opts.windowMs ?? 5 * 60 * 1000;
    this.store = opts.store ?? (opts.maxKeys !== undefined ? new MemoryRateLimitStore({ maxKeys: opts.maxKeys }) : undefined);
  }

  private backing(): RateLimitStore {
    return this.store ?? getDefaultRateLimitStore();
  }

  /** 0 when allowed; otherwise milliseconds until the oldest failure leaves the window. */
  async retryAfterMs(key: string): Promise<number> {
    const now = this.now();
    const { count, oldestAt } = await withRateLimitStore(this.backing(), "count", (s) => s.count(key, this.windowMs, now));
    if (count < this.maxFailures || oldestAt === null) return 0;
    return Math.max(1, oldestAt + this.windowMs - now);
  }

  async recordFailure(key: string): Promise<void> {
    const now = this.now();
    await withRateLimitStore(this.backing(), "hit", (s) => s.hit(key, this.windowMs, now));
  }

  async reset(key: string): Promise<void> {
    await withRateLimitStore(this.backing(), "reset", (s) => s.reset(key));
  }
}

// ---------------------------------------------------------------------------
// Process-wide context (globalThis so Vite HMR module copies share it)
// ---------------------------------------------------------------------------

export interface OAuthDeps {
  store?: OAuthStore;
  approver?: OwnerApprover | null;
  clock?: Clock;
  env?: Env;
  rateLimit?: { maxFailures?: number; windowMs?: number };
  /** Where failed-attempt counts live. Default: the shared SQL store. Tests pass a MemoryRateLimitStore. */
  rateLimitStore?: RateLimitStore;
}

interface OAuthContext {
  store: OAuthStore | null;
  approver: OwnerApprover | null;
  clock: Clock;
  env: Env;
  limiter: FailureRateLimiter;
  rateLimitStore: RateLimitStore | undefined;
  lastPurge: number;
}

const ctxRef = globalThis as typeof globalThis & { __echoVaultOAuthCtx__?: OAuthContext };

function newContext(): OAuthContext {
  const ctx: OAuthContext = {
    store: null,
    approver: null,
    clock: { now: () => Date.now() },
    env: process.env,
    limiter: undefined as unknown as FailureRateLimiter,
    rateLimitStore: undefined,
    lastPurge: 0,
  };
  ctx.limiter = new FailureRateLimiter({ now: () => ctx.clock.now() });
  return ctx;
}

function ctx(): OAuthContext {
  ctxRef.__echoVaultOAuthCtx__ ??= newContext();
  return ctxRef.__echoVaultOAuthCtx__;
}

/**
 * Wire dependencies. The lead calls this once at server start with the
 * Telegram-backed OwnerApprover; tests inject a MemoryOAuthStore, a fake
 * approver, a fake clock, and an env object.
 */
export function configureOAuth(deps: OAuthDeps): void {
  const c = ctx();
  if (deps.store !== undefined) c.store = deps.store;
  if (deps.approver !== undefined) c.approver = deps.approver;
  if (deps.clock !== undefined) c.clock = deps.clock;
  if (deps.env !== undefined) c.env = deps.env;
  if (deps.rateLimitStore !== undefined) c.rateLimitStore = deps.rateLimitStore;
  if (deps.rateLimit !== undefined || deps.clock !== undefined || deps.rateLimitStore !== undefined) {
    c.limiter = new FailureRateLimiter({ now: () => c.clock.now(), ...deps.rateLimit, store: c.rateLimitStore });
  }
}

/** Drop all wiring and in-process state (tests). */
export function resetOAuth(): void {
  ctxRef.__echoVaultOAuthCtx__ = newContext();
}

export function oauthStore(): OAuthStore {
  return ctx().store ?? getOAuthStore();
}

export function oauthNow(): number {
  return ctx().clock.now();
}

export function oauthEnv(): Env {
  return ctx().env;
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** RFC 7636 S256: BASE64URL(SHA256(ASCII(verifier))), no padding. */
export function s256Challenge(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

function pkceMatches(verifier: string, storedChallenge: string): boolean {
  const computed = Buffer.from(s256Challenge(verifier), "utf8");
  const stored = Buffer.from(storedChallenge, "utf8");
  if (computed.length !== stored.length) return false;
  return timingSafeEqual(computed, stored);
}

function randomValue(prefix: string, bytes = 32): string {
  return `${prefix}${randomBytes(bytes).toString("base64url")}`;
}

export function canonicalScopes(list: Iterable<string>): string[] {
  const set = new Set(list);
  return SUPPORTED_SCOPES.filter((s) => set.has(s));
}

function intersectScopes(a: readonly string[], b: readonly string[]): string[] {
  const bs = new Set(b);
  return canonicalScopes(a.filter((s) => bs.has(s)));
}

/** Parse a space-delimited scope string. `null` result = contains an unsupported scope. */
function parseScopeString(raw: string | null): string[] | null {
  if (raw === null) return [];
  const parts = raw.split(" ").filter((s) => s.length > 0);
  for (const p of parts) if (!(SUPPORTED_SCOPES as readonly string[]).includes(p)) return null;
  return canonicalScopes(parts);
}

/** Normalize an RFC 8707 resource indicator for comparison (case-insensitive scheme/host, no trailing slash). */
function normalizeResource(value: string): string | null {
  if (value.includes("#")) return null;
  try {
    const u = new URL(value);
    if (u.search || u.username || u.password) return null;
    const path = u.pathname.length > 1 ? u.pathname.replace(/\/+$/, "") : "";
    return `${u.protocol}//${u.host}${path}`;
  } catch {
    return null;
  }
}

function resourceMatches(value: string, cfg: OAuthConfig): boolean {
  return normalizeResource(value) === cfg.resource;
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-expose-headers": "www-authenticate, retry-after",
};

const SENSITIVE_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  pragma: "no-cache",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...SENSITIVE_HEADERS,
      ...CORS_HEADERS,
      ...extra,
    },
  });
}

/** Standard OAuth error JSON. Descriptions are fixed strings — never request values. */
function oauthError(error: string, description: string, status = 400, extra: Record<string, string> = {}): Response {
  return json({ error, error_description: description }, status, extra);
}

function configUnavailable(): Response {
  return oauthError("temporarily_unavailable", "authorization server is not configured", 503);
}

async function readBody(req: Request): Promise<string | null> {
  const declared = req.headers.get("content-length");
  if (declared && Number(declared) > MAX_BODY_BYTES) return null;
  const text = await req.text();
  return Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES ? null : text;
}

function parseForm(text: string): { params: URLSearchParams; duplicate: boolean } {
  const params = new URLSearchParams(text);
  let duplicate = false;
  for (const key of new Set(params.keys())) if (params.getAll(key).length > 1) duplicate = true;
  return { params, duplicate };
}

function isForm(req: Request): boolean {
  return (req.headers.get("content-type") ?? "").toLowerCase().includes("application/x-www-form-urlencoded");
}

async function maybePurge(store: OAuthStore, now: number): Promise<void> {
  const c = ctx();
  if (now - c.lastPurge < PURGE_INTERVAL_MS) return;
  c.lastPurge = now;
  try {
    await store.purgeExpired(now);
  } catch (err) {
    log.warn("oauth_purge_failed", { error: sanitizeError(err).message });
  }
}

function internalError(where: string, err: unknown): Response {
  log.error("oauth_internal_error", { where, error: sanitizeError(err).message });
  return oauthError("server_error", "internal error", 500);
}

// ---------------------------------------------------------------------------
// Metadata (RFC 9728 + RFC 8414)
// ---------------------------------------------------------------------------

export function protectedResourceMetadata(cfg: OAuthConfig): Record<string, unknown> {
  return {
    resource: cfg.resource,
    authorization_servers: [cfg.issuer],
    scopes_supported: [...SUPPORTED_SCOPES],
    bearer_methods_supported: ["header"],
    resource_name: "ECHO Vault",
  };
}

export function authorizationServerMetadata(cfg: OAuthConfig): Record<string, unknown> {
  return {
    issuer: cfg.issuer,
    authorization_endpoint: cfg.authorizationEndpoint,
    token_endpoint: cfg.tokenEndpoint,
    registration_endpoint: cfg.registrationEndpoint,
    revocation_endpoint: cfg.revocationEndpoint,
    scopes_supported: [...SUPPORTED_SCOPES],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
  };
}

function metadataResponse(body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=300",
      "x-content-type-options": "nosniff",
      ...CORS_HEADERS,
    },
  });
}

export async function handleProtectedResourceMetadata(_req: Request): Promise<Response> {
  let cfg: OAuthConfig;
  try {
    cfg = resolveOAuthConfig(ctx().env);
  } catch {
    return configUnavailable();
  }
  return metadataResponse(protectedResourceMetadata(cfg));
}

export async function handleAuthorizationServerMetadata(_req: Request): Promise<Response> {
  let cfg: OAuthConfig;
  try {
    cfg = resolveOAuthConfig(ctx().env);
  } catch {
    return configUnavailable();
  }
  return metadataResponse(authorizationServerMetadata(cfg));
}

/** CORS preflight for browser-based MCP clients (no cookies are ever used, so `*` is safe). */
export function handlePreflight(_req?: Request): Response {
  return new Response(null, {
    status: 204,
    headers: {
      ...CORS_HEADERS,
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "authorization, content-type, mcp-protocol-version",
      "access-control-max-age": "600",
    },
  });
}

// ---------------------------------------------------------------------------
// Dynamic client registration (RFC 7591) — public clients only
// ---------------------------------------------------------------------------

/** Returns an error description, or null when the redirect URI is acceptable. */
export function redirectUriProblem(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length === 0) return "redirect_uri must be a non-empty string";
  if (raw.length > MAX_REDIRECT_URI_LENGTH) return "redirect_uri is too long";
  if (raw.includes("#")) return "redirect_uri must not contain a fragment";
  // eslint-disable-next-line no-control-regex
  if (/[\s\u0000-\u001f\u007f]/.test(raw)) return "redirect_uri must not contain whitespace or control characters";
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return "redirect_uri must be an absolute URL";
  }
  if (url.username || url.password) return "redirect_uri must not contain credentials";
  if (url.protocol === "https:") return url.hostname ? null : "redirect_uri must have a host";
  if (url.protocol === "http:") {
    return isLoopbackHostname(url.hostname)
      ? null
      : "http redirect_uri is allowed only for loopback (localhost, 127.0.0.1, [::1])";
  }
  return "redirect_uri must use https (or http for loopback)";
}

export async function handleRegister(req: Request): Promise<Response> {
  let cfg: OAuthConfig;
  try {
    cfg = resolveOAuthConfig(ctx().env);
  } catch {
    return configUnavailable();
  }
  if (req.method !== "POST") return oauthError("invalid_request", "use POST", 405, { allow: "POST, OPTIONS" });
  try {
    if (!(req.headers.get("content-type") ?? "").toLowerCase().includes("application/json")) {
      return oauthError("invalid_client_metadata", "content-type must be application/json");
    }
    const text = await readBody(req);
    if (text === null) return oauthError("invalid_client_metadata", "registration request is too large", 413);
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return oauthError("invalid_client_metadata", "body must be a JSON object");
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return oauthError("invalid_client_metadata", "body must be a JSON object");
    }
    const meta = body as Record<string, unknown>;

    // redirect_uris: required, https or loopback http, no fragments.
    const uris = meta.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0) {
      return oauthError("invalid_redirect_uri", "redirect_uris must be a non-empty array");
    }
    if (uris.length > MAX_REDIRECT_URIS) return oauthError("invalid_redirect_uri", "too many redirect_uris");
    for (const u of uris) {
      const problem = redirectUriProblem(u);
      if (problem) return oauthError("invalid_redirect_uri", problem);
    }
    const redirectUris = [...new Set(uris as string[])];

    // response_types / grant_types: code + authorization_code(+refresh_token) only.
    if (meta.response_types !== undefined) {
      const rt = meta.response_types;
      if (!Array.isArray(rt) || rt.length === 0 || rt.some((v) => v !== "code")) {
        return oauthError("invalid_client_metadata", "only response_type \"code\" is supported");
      }
    }
    if (meta.grant_types !== undefined) {
      const gt = meta.grant_types;
      if (!Array.isArray(gt) || !gt.includes("authorization_code")) {
        return oauthError("invalid_client_metadata", "grant_types must include authorization_code");
      }
      // Unsupported extras (client_credentials, implicit, …) are dropped, per RFC 7591 §3.2.1 substitution.
    }
    // token_endpoint_auth_method: we only register public clients. Any requested
    // method is substituted with "none" and echoed back; no secret is ever issued.

    let clientName = "Unnamed client";
    if (meta.client_name !== undefined) {
      if (typeof meta.client_name !== "string") return oauthError("invalid_client_metadata", "client_name must be a string");
      const trimmed = meta.client_name.trim();
      if (trimmed.length > MAX_CLIENT_NAME) return oauthError("invalid_client_metadata", "client_name is too long");
      if (UNSAFE_NAME_CHARS.test(trimmed)) {
        return oauthError("invalid_client_metadata", "client_name contains control or bidi characters");
      }
      if (trimmed.length > 0) clientName = trimmed;
    }

    let requestedScopes: string[] = [];
    if (meta.scope !== undefined) {
      if (typeof meta.scope !== "string") return oauthError("invalid_client_metadata", "scope must be a string");
      // Unknown scopes are dropped (substitution) — the AS decides what is offered.
      requestedScopes = canonicalScopes(meta.scope.split(" "));
    }

    const store = oauthStore();
    const now = oauthNow();
    await store.deleteStaleClients(now - STALE_CLIENT_MS);
    if ((await store.countClients()) >= cfg.maxClients) {
      log.warn("oauth_client_cap_reached", { max: cfg.maxClients });
      return oauthError("temporarily_unavailable", "client registration limit reached", 429);
    }

    const record: OAuthClientRecord = {
      client_id: randomValue("oc_", 16),
      client_name: clientName,
      redirect_uris: redirectUris,
      requested_scopes: requestedScopes,
      granted_scopes: [],
      status: "registered",
      created_at: now,
      approved_at: null,
      revoked_at: null,
    };
    await store.createClient(record);
    log.info("oauth_client_registered", {
      client_id: record.client_id,
      redirect_hosts: redirectUris.map((u) => new URL(u).host),
    });

    return json(
      {
        client_id: record.client_id,
        client_id_issued_at: Math.floor(now / 1000),
        client_name: record.client_name,
        redirect_uris: record.redirect_uris,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        ...(requestedScopes.length ? { scope: requestedScopes.join(" ") } : {}),
      },
      201,
    );
  } catch (err) {
    return internalError("register", err);
  }
}

// ---------------------------------------------------------------------------
// Authorization endpoint + owner-approval waiting page
// ---------------------------------------------------------------------------

const PAGE_STYLE =
  "body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0b0d12;color:#e8eaf0;" +
  "display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}" +
  "main{max-width:30rem;margin:1rem;padding:2rem;border:1px solid #2a2f3a;border-radius:12px;background:#141821}" +
  "h1{font-size:1.25rem;margin:0 0 1rem}p,li{line-height:1.5;color:#b9bfcc}" +
  "code{background:#1f2430;padding:.1rem .35rem;border-radius:4px;color:#e8eaf0}a{color:#8ab4ff}";
const PAGE_STYLE_HASH = createHash("sha256").update(PAGE_STYLE, "utf8").digest("base64");
const PAGE_CSP =
  `default-src 'none'; style-src 'sha256-${PAGE_STYLE_HASH}'; img-src 'none'; ` +
  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/**
 * Render a minimal, script-free page. `paragraphs`/`after` are trusted HTML
 * fragments built by this module with every dynamic value already escaped;
 * `title`, `list` items and `refreshUrl` are escaped here.
 */
function htmlPage(opts: {
  status: number;
  title: string;
  paragraphs: string[];
  list?: string[];
  after?: string[];
  refreshUrl?: string;
}): Response {
  const refresh = opts.refreshUrl
    ? `<meta http-equiv="refresh" content="${POLL_INTERVAL_SECONDS};url=${escapeHtml(opts.refreshUrl)}">`
    : "";
  const list = opts.list?.length ? `<ul>${opts.list.map((li) => `<li><code>${escapeHtml(li)}</code></li>`).join("")}</ul>` : "";
  const after = (opts.after ?? []).map((p) => `<p>${p}</p>`).join("");
  const manual = opts.refreshUrl ? `<p><a href="${escapeHtml(opts.refreshUrl)}">Check now</a></p>` : "";
  const html =
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<meta name="robots" content="noindex,nofollow">${refresh}` +
    `<title>${escapeHtml(opts.title)}</title><style>${PAGE_STYLE}</style></head>` +
    `<body><main><h1>${escapeHtml(opts.title)}</h1>` +
    opts.paragraphs.map((p) => `<p>${p}</p>`).join("") +
    list +
    after +
    manual +
    `</main></body></html>`;
  return new Response(html, {
    status: opts.status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...SENSITIVE_HEADERS,
      "content-security-policy": PAGE_CSP,
      "x-frame-options": "DENY",
    },
  });
}

/** An error page. `message` is plain text and is escaped here. Never redirects. */
function htmlError(status: number, title: string, message: string): Response {
  return htmlPage({ status, title, paragraphs: [escapeHtml(message)] });
}

function redirectTo(location: string): Response {
  return new Response(null, {
    status: 302,
    headers: { location, ...SENSITIVE_HEADERS },
  });
}

function redirectError(cfg: OAuthConfig, redirectUri: string, error: string, description: string, state: string | null): Response {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  url.searchParams.set("error_description", description);
  if (state !== null) url.searchParams.set("state", state);
  url.searchParams.set("iss", cfg.issuer);
  return redirectTo(url.toString());
}

function waitingPage(cfg: OAuthConfig, handle: string, clientName: string, redirectHost: string, scopes: string[]): Response {
  return htmlPage({
    status: 200,
    title: "Approve this connection on your phone",
    paragraphs: [
      `<strong>${escapeHtml(clientName)}</strong> wants to connect to ECHO Vault.`,
      `After approval it will be sent to <code>${escapeHtml(redirectHost)}</code>.`,
      "Requested access:",
    ],
    list: scopes,
    after: ["Check your phone and approve or deny. Keep this page open — it refreshes automatically."],
    refreshUrl: `${cfg.authorizationEndpoint}?pending=${encodeURIComponent(handle)}`,
  });
}

function deniedPage(): Response {
  return htmlError(403, "Connection denied", "The owner denied this connection. You can close this window.");
}

function expiredPage(): Response {
  return htmlError(400, "Request expired", "This connection request expired. Start the connection again from your app.");
}

function redirectHostOf(uri: string): string {
  return new URL(uri).host;
}

const AUTHORIZE_SINGLE_PARAMS = [
  "response_type",
  "client_id",
  "redirect_uri",
  "code_challenge",
  "code_challenge_method",
  "state",
  "scope",
  "pending",
] as const;

/**
 * GET /api/oauth/authorize
 *   - with OAuth params: validate, ask the owner, render the waiting page.
 *   - with `pending=evp_…`: poll the owner decision; once approved, issue a
 *     single-use code and 302 to the registered redirect_uri with code+state+iss.
 */
export async function handleAuthorize(req: Request): Promise<Response> {
  let cfg: OAuthConfig;
  try {
    cfg = resolveOAuthConfig(ctx().env);
  } catch {
    return htmlError(503, "Unavailable", "This connector is not configured yet.");
  }
  if (req.method !== "GET") return htmlError(405, "Method not allowed", "Use GET.");
  try {
    const url = new URL(req.url);
    for (const k of AUTHORIZE_SINGLE_PARAMS) {
      if (url.searchParams.getAll(k).length > 1) return htmlError(400, "Invalid request", "A parameter was repeated.");
    }
    const pending = url.searchParams.get("pending");
    if (pending !== null) return await pollPending(cfg, pending);
    return await startAuthorization(cfg, url.searchParams);
  } catch (err) {
    log.error("oauth_internal_error", { where: "authorize", error: sanitizeError(err).message });
    return htmlError(500, "Something went wrong", "The authorization server hit an internal error.");
  }
}

async function startAuthorization(cfg: OAuthConfig, p: URLSearchParams): Promise<Response> {
  const c = ctx();
  const store = oauthStore();

  // 1. Client + redirect_uri. Failures here NEVER redirect (OAuth 2.1 §2.3.5 / §7.12.2).
  const clientId = p.get("client_id");
  const client = clientId && CLIENT_ID_RE.test(clientId) ? await store.getClient(clientId) : null;
  if (!client) return htmlError(400, "Unknown client", "This application is not registered with ECHO Vault.");
  const redirectUri = p.get("redirect_uri");
  if (!redirectUri || !client.redirect_uris.includes(redirectUri)) {
    return htmlError(400, "Invalid redirect", "redirect_uri does not exactly match a registered redirect URI.");
  }
  if (client.status === "revoked" || client.status === "denied") {
    return htmlError(403, "Connection refused", "The owner has denied or revoked this application.");
  }

  // 2. Everything else. Approved (owner-trusted) clients get a standard error
  //    redirect; never-approved clients get a page, so open DCR cannot turn this
  //    endpoint into an open redirector.
  const trusted = client.status === "approved";
  const stateRaw = p.get("state");
  const fail = (error: string, description: string): Response =>
    trusted && (stateRaw === null || stateRaw.length <= MAX_STATE_LENGTH)
      ? redirectError(cfg, redirectUri, error, description, stateRaw)
      : htmlError(400, "Invalid authorization request", description);

  if (stateRaw !== null && stateRaw.length > MAX_STATE_LENGTH) return fail("invalid_request", "state is too long");
  if (p.get("response_type") !== "code") return fail("unsupported_response_type", "response_type must be code");
  const challenge = p.get("code_challenge");
  if (!challenge) return fail("invalid_request", "code_challenge is required (PKCE)");
  if (p.get("code_challenge_method") !== "S256") return fail("invalid_request", "code_challenge_method must be S256");
  if (!CODE_CHALLENGE_RE.test(challenge)) return fail("invalid_request", "code_challenge is malformed");
  for (const r of p.getAll("resource")) {
    if (!resourceMatches(r, cfg)) return fail("invalid_target", "resource must be this server's MCP endpoint");
  }
  const parsed = parseScopeString(p.get("scope"));
  if (parsed === null) return fail("invalid_scope", "unsupported scope requested");
  const requested = parsed.length
    ? parsed
    : client.requested_scopes.length
      ? canonicalScopes(client.requested_scopes)
      : [...DEFAULT_REQUESTED_SCOPES];
  const effective = trusted ? intersectScopes(requested, client.granted_scopes) : requested;
  if (effective.length === 0) return fail("invalid_scope", "none of the requested scopes are granted to this client");

  // 3. Owner approval for this authorization.
  if (!c.approver) {
    log.error("oauth_owner_approver_missing", { client_id: client.client_id });
    return htmlError(503, "Approval unavailable", "Owner approval is not configured on this server.");
  }
  const now = oauthNow();
  await store.expirePending(now);
  if ((await store.countActivePending(now)) >= cfg.maxPending) {
    log.warn("oauth_pending_cap_reached", { max: cfg.maxPending });
    return htmlError(429, "Too many requests", "Too many connection requests are waiting for approval. Try again later.");
  }
  const redirectHost = redirectHostOf(redirectUri);
  const isNew = client.status === "registered";
  let approvalId: string;
  try {
    const res = await c.approver.requestClientApproval({
      client_id: client.client_id,
      client_name: client.client_name,
      requested_scopes: effective,
      redirect_host: redirectHost,
      is_new_client: isNew,
    });
    approvalId = res?.approval_id;
  } catch (err) {
    log.error("oauth_owner_approval_request_failed", { client_id: client.client_id, error: sanitizeError(err).message });
    return htmlError(503, "Approval unavailable", "Could not reach the owner approval service. Try again later.");
  }
  if (typeof approvalId !== "string" || approvalId.length === 0) {
    log.error("oauth_owner_approval_request_invalid", { client_id: client.client_id });
    return htmlError(503, "Approval unavailable", "The owner approval service returned an invalid response.");
  }

  const handle = randomValue("evp_");
  const pendingRecord: PendingAuthorizationRecord = {
    id_hash: sha256Hex(handle),
    client_id: client.client_id,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    scopes: effective,
    resource: cfg.resource,
    state: stateRaw,
    approval_id: approvalId,
    is_new_client: isNew,
    status: "pending",
    created_at: now,
    expires_at: now + PENDING_TTL_MS,
  };
  await store.createPending(pendingRecord);
  log.info("oauth_authorization_pending", {
    client_id: client.client_id,
    approval_id: approvalId,
    is_new_client: isNew,
    scopes: effective,
    redirect_host: redirectHost,
  });
  return waitingPage(cfg, handle, client.client_name, redirectHost, effective);
}

async function pollPending(cfg: OAuthConfig, handle: string): Promise<Response> {
  const c = ctx();
  const store = oauthStore();
  const unknown = () => htmlError(400, "Unknown request", "This connection request is unknown or has expired.");
  if (!PENDING_RE.test(handle)) return unknown();
  const idHash = sha256Hex(handle);
  const rec = await store.getPending(idHash);
  if (!rec) return unknown();
  if (rec.status === "completed") return htmlError(400, "Already completed", "This connection request was already completed.");
  if (rec.status === "denied") return deniedPage();
  const now = oauthNow();
  if (rec.status === "expired" || rec.expires_at <= now) {
    await store.setPendingStatus(idHash, "expired");
    return expiredPage();
  }
  const client = await store.getClient(rec.client_id);
  if (!client || client.status === "revoked" || client.status === "denied") {
    await store.setPendingStatus(idHash, "denied");
    return deniedPage();
  }
  if (!c.approver) return htmlError(503, "Approval unavailable", "Owner approval is not configured on this server.");

  let status: ClientApprovalStatus;
  try {
    status = await c.approver.checkClientApproval(rec.approval_id);
  } catch (err) {
    log.warn("oauth_owner_approval_check_failed", { client_id: rec.client_id, error: sanitizeError(err).message });
    return waitingPage(cfg, handle, client.client_name, redirectHostOf(rec.redirect_uri), rec.scopes);
  }

  switch (status) {
    case "pending":
      return waitingPage(cfg, handle, client.client_name, redirectHostOf(rec.redirect_uri), rec.scopes);
    case "approved":
      return completeApproved(cfg, store, idHash, client, now);
    case "expired":
      await store.setPendingStatus(idHash, "expired");
      return expiredPage();
    case "denied":
    default: {
      // Unknown statuses fail closed as a denial.
      await store.setPendingStatus(idHash, "denied");
      if (rec.is_new_client && client.status === "registered") {
        await store.updateClient(client.client_id, { status: "denied" });
      }
      log.warn("oauth_authorization_denied", { client_id: rec.client_id, approval_id: rec.approval_id });
      return deniedPage();
    }
  }
}

async function completeApproved(
  cfg: OAuthConfig,
  store: OAuthStore,
  idHash: string,
  client: OAuthClientRecord,
  now: number,
): Promise<Response> {
  const claimed = await store.claimPending(idHash);
  if (!claimed) return htmlError(400, "Already completed", "This connection request was already completed.");

  let current: OAuthClientRecord | null = client;
  if (client.status === "registered") {
    // First approval of a new client: its grant is exactly what the owner saw.
    current = await store.updateClient(client.client_id, {
      status: "approved",
      granted_scopes: canonicalScopes(claimed.scopes),
      approved_at: now,
    });
    log.info("oauth_client_approved", { client_id: client.client_id, scopes: claimed.scopes });
  }
  if (!current || current.status !== "approved") return deniedPage();
  const scopes = intersectScopes(claimed.scopes, current.granted_scopes);
  if (scopes.length === 0) {
    return redirectError(cfg, claimed.redirect_uri, "invalid_scope", "no granted scopes", claimed.state);
  }

  const code = randomValue("evc_");
  registerSecretForRedaction(code);
  await store.saveCode({
    code_hash: sha256Hex(code),
    client_id: claimed.client_id,
    redirect_uri: claimed.redirect_uri,
    code_challenge: claimed.code_challenge,
    scopes,
    resource: claimed.resource,
    family_id: randomValue("fam_", 16),
    created_at: now,
    expires_at: now + CODE_TTL_MS,
    used_at: null,
  });
  log.info("oauth_code_issued", { client_id: claimed.client_id, scopes });

  const location = new URL(claimed.redirect_uri);
  location.searchParams.set("code", code);
  if (claimed.state !== null) location.searchParams.set("state", claimed.state);
  location.searchParams.set("iss", cfg.issuer);
  return redirectTo(location.toString());
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

/** Public-client identification: client_id from the form or a secret-less Basic header. */
function tokenClientId(req: Request, params: URLSearchParams): { client_id: string } | { error: Response } {
  if (params.get("client_secret")) {
    return { error: oauthError("invalid_client", "this server registers public clients only; client_secret is not accepted", 401) };
  }
  let basicId: string | null = null;
  const auth = req.headers.get("authorization");
  if (auth) {
    const m = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(auth);
    if (!m) return { error: oauthError("invalid_client", "unsupported client authentication", 401) };
    const decoded = Buffer.from(m[1], "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    if (idx < 0) return { error: oauthError("invalid_client", "malformed client authentication", 401) };
    let secret: string;
    try {
      basicId = decodeURIComponent(decoded.slice(0, idx).replace(/\+/g, " "));
      secret = decodeURIComponent(decoded.slice(idx + 1).replace(/\+/g, " "));
    } catch {
      return { error: oauthError("invalid_client", "malformed client authentication", 401) };
    }
    if (secret) {
      return { error: oauthError("invalid_client", "this server registers public clients only; client_secret is not accepted", 401) };
    }
  }
  const formId = params.get("client_id");
  if (basicId !== null && formId !== null && basicId !== formId) {
    return { error: oauthError("invalid_request", "conflicting client_id values") };
  }
  const id = basicId ?? formId;
  if (!id) return { error: oauthError("invalid_request", "client_id is required") };
  return { client_id: id };
}

/**
 * Rate-limit key for one client's failed token attempts. Derived only from the
 * client_id (never the code, verifier or token presented) and hashed by
 * rateLimitKey, so nothing the caller sent is stored. A malformed client_id —
 * which could be anything, a pasted token included — collapses to one bucket.
 */
export function limiterKey(clientId: string): string {
  return rateLimitKey("oauth.token", CLIENT_ID_RE.test(clientId) ? clientId : "malformed");
}

/** 503 for a token request that cannot be rate-checked: failed-attempt limits fail closed. */
function rateLimitUnavailable(): Response {
  return oauthError("temporarily_unavailable", "rate_limit_unavailable: failed-attempt limits cannot be checked; retry later", 503, {
    "retry-after": "5",
  });
}

/**
 * Count one failed attempt. The request is already being refused, so a store
 * failure here is logged (withRateLimitStore) and does not change the answer;
 * the next request fails closed at the check in handleToken.
 */
async function noteFailure(key: string): Promise<void> {
  try {
    await ctx().limiter.recordFailure(key);
  } catch (err) {
    if (!(err instanceof RateLimitUnavailableError)) throw err;
    log.error("oauth_rate_limit_unavailable", { op: "record_failure" });
  }
}

/**
 * Forget a client's failures after a successful grant. The grant has already
 * been consumed, so a store failure must not lose the issued tokens: it is
 * logged and the stale failures simply keep counting (stricter, never looser).
 */
async function clearFailures(key: string): Promise<void> {
  try {
    await ctx().limiter.reset(key);
  } catch (err) {
    if (!(err instanceof RateLimitUnavailableError)) throw err;
    log.error("oauth_rate_limit_unavailable", { op: "reset" });
  }
}

export async function handleToken(req: Request): Promise<Response> {
  let cfg: OAuthConfig;
  try {
    cfg = resolveOAuthConfig(ctx().env);
  } catch {
    return configUnavailable();
  }
  if (req.method !== "POST") return oauthError("invalid_request", "use POST", 405, { allow: "POST, OPTIONS" });
  try {
    if (!isForm(req)) return oauthError("invalid_request", "content-type must be application/x-www-form-urlencoded");
    const text = await readBody(req);
    if (text === null) return oauthError("invalid_request", "request is too large", 413);
    const { params, duplicate } = parseForm(text);
    if (duplicate) return oauthError("invalid_request", "a parameter was repeated");
    const who = tokenClientId(req, params);
    if ("error" in who) return who.error;

    const c = ctx();
    const key = limiterKey(who.client_id);
    let retryMs: number;
    try {
      retryMs = await c.limiter.retryAfterMs(key);
    } catch (err) {
      if (!(err instanceof RateLimitUnavailableError)) throw err;
      log.error("oauth_rate_limit_unavailable", { op: "check", client_id: who.client_id.slice(0, 64) });
      return rateLimitUnavailable();
    }
    if (retryMs > 0) {
      log.warn("oauth_token_rate_limited", { client_id: who.client_id.slice(0, 64) });
      return oauthError("temporarily_unavailable", "too many failed attempts; retry later", 429, {
        "retry-after": String(Math.ceil(retryMs / 1000)),
      });
    }

    const resource = params.get("resource");
    if (resource !== null && !resourceMatches(resource, cfg)) {
      return oauthError("invalid_target", "resource must be this server's MCP endpoint");
    }

    const store = oauthStore();
    const now = oauthNow();
    await maybePurge(store, now);

    const grantType = params.get("grant_type");
    if (grantType === "authorization_code") return await authorizationCodeGrant(cfg, store, params, who.client_id, key, now);
    if (grantType === "refresh_token") return await refreshTokenGrant(store, params, who.client_id, key, now);
    if (!grantType) return oauthError("invalid_request", "grant_type is required");
    return oauthError("unsupported_grant_type", "supported grant types: authorization_code, refresh_token");
  } catch (err) {
    return internalError("token", err);
  }
}

async function invalidGrant(key: string, description: string): Promise<Response> {
  await noteFailure(key);
  return oauthError("invalid_grant", description);
}

async function authorizationCodeGrant(
  cfg: OAuthConfig,
  store: OAuthStore,
  params: URLSearchParams,
  clientId: string,
  key: string,
  now: number,
): Promise<Response> {
  const code = params.get("code");
  const verifier = params.get("code_verifier");
  if (!code) return oauthError("invalid_request", "code is required");
  if (!verifier) return oauthError("invalid_request", "code_verifier is required (PKCE)");

  const client = CLIENT_ID_RE.test(clientId) ? await store.getClient(clientId) : null;
  if (!client) {
    await noteFailure(key);
    return oauthError("invalid_client", "unknown client", 401);
  }
  if (!CODE_RE.test(code)) return invalidGrant(key, "invalid authorization code");

  const consumed = await store.consumeCode(sha256Hex(code), now);
  if (consumed.status === "not_found") return invalidGrant(key, "invalid authorization code");
  if (consumed.status === "reused") {
    // OAuth 2.1 §4.1.3: deny, and revoke everything minted from this code.
    const revoked = await store.revokeFamily(consumed.code.family_id, now);
    log.warn("oauth_code_reuse_detected", {
      client_id: consumed.code.client_id,
      family_id: consumed.code.family_id,
      tokens_revoked: revoked,
    });
    return invalidGrant(key, "authorization code was already used");
  }
  const rec = consumed.code;
  if (rec.client_id !== client.client_id) return invalidGrant(key, "authorization code was not issued to this client");
  if (rec.expires_at <= now) return invalidGrant(key, "authorization code expired");
  const redirectUri = params.get("redirect_uri");
  if (redirectUri !== null && redirectUri !== rec.redirect_uri) return invalidGrant(key, "redirect_uri does not match");
  if (rec.resource !== cfg.resource) return invalidGrant(key, "authorization code was issued for a different resource");
  if (!CODE_VERIFIER_RE.test(verifier) || !pkceMatches(verifier, rec.code_challenge)) {
    return invalidGrant(key, "PKCE verification failed");
  }
  if (client.status !== "approved") return invalidGrant(key, "client is not approved");
  const scopes = intersectScopes(rec.scopes, client.granted_scopes);
  if (scopes.length === 0) return oauthError("invalid_scope", "no granted scopes remain for this client");

  await clearFailures(key);
  return issueTokens(store, now, {
    client_id: client.client_id,
    family_id: rec.family_id,
    resource: rec.resource,
    accessScopes: scopes,
    refreshScopes: scopes,
  });
}

async function refreshTokenGrant(
  store: OAuthStore,
  params: URLSearchParams,
  clientId: string,
  key: string,
  now: number,
): Promise<Response> {
  const presented = params.get("refresh_token");
  if (!presented) return oauthError("invalid_request", "refresh_token is required");
  const client = CLIENT_ID_RE.test(clientId) ? await store.getClient(clientId) : null;
  if (!client) {
    await noteFailure(key);
    return oauthError("invalid_client", "unknown client", 401);
  }
  if (!REFRESH_TOKEN_RE.test(presented)) return invalidGrant(key, "invalid refresh token");
  const hash = sha256Hex(presented);
  const rec = await store.getToken(hash);
  if (!rec || rec.kind !== "refresh") return invalidGrant(key, "invalid refresh token");
  if (rec.client_id !== client.client_id) return invalidGrant(key, "refresh token was not issued to this client");
  if (rec.used_at !== null) {
    // Rotation reuse: someone is replaying an already-rotated token. Kill the family.
    const revoked = await store.revokeFamily(rec.family_id, now);
    log.warn("oauth_refresh_reuse_detected", { client_id: rec.client_id, family_id: rec.family_id, tokens_revoked: revoked });
    return invalidGrant(key, "refresh token was already used");
  }
  if (rec.revoked_at !== null) return invalidGrant(key, "refresh token was revoked");
  if (rec.expires_at <= now) return invalidGrant(key, "refresh token expired");
  if (client.status !== "approved") return invalidGrant(key, "client is not approved");

  const parsed = parseScopeString(params.get("scope"));
  if (parsed === null) return oauthError("invalid_scope", "unsupported scope requested");
  if (parsed.some((s) => !rec.scopes.includes(s))) return oauthError("invalid_scope", "scope exceeds the original grant");
  const accessScopes = intersectScopes(parsed.length ? parsed : rec.scopes, client.granted_scopes);
  if (accessScopes.length === 0) return oauthError("invalid_scope", "no granted scopes remain for this client");

  if (!(await store.markRefreshUsed(hash, now))) {
    // Lost a race with a concurrent presentation of the same token — treat as reuse.
    const revoked = await store.revokeFamily(rec.family_id, now);
    log.warn("oauth_refresh_reuse_detected", { client_id: rec.client_id, family_id: rec.family_id, tokens_revoked: revoked });
    return invalidGrant(key, "refresh token was already used");
  }
  await clearFailures(key);
  return issueTokens(store, now, {
    client_id: client.client_id,
    family_id: rec.family_id,
    resource: rec.resource,
    accessScopes,
    // The rotated refresh token keeps the original grant (OAuth 2.1 §4.3.3).
    refreshScopes: rec.scopes,
  });
}

async function issueTokens(
  store: OAuthStore,
  now: number,
  t: { client_id: string; family_id: string; resource: string; accessScopes: string[]; refreshScopes: string[] },
): Promise<Response> {
  const access = randomValue("eva_");
  const refresh = randomValue("evr_");
  registerSecretForRedaction(access);
  registerSecretForRedaction(refresh);
  await store.saveToken({
    token_hash: sha256Hex(access),
    kind: "access",
    client_id: t.client_id,
    family_id: t.family_id,
    scopes: t.accessScopes,
    resource: t.resource,
    created_at: now,
    expires_at: now + ACCESS_TOKEN_TTL_MS,
    used_at: null,
    revoked_at: null,
  });
  await store.saveToken({
    token_hash: sha256Hex(refresh),
    kind: "refresh",
    client_id: t.client_id,
    family_id: t.family_id,
    scopes: t.refreshScopes,
    resource: t.resource,
    created_at: now,
    expires_at: now + REFRESH_TOKEN_TTL_MS,
    used_at: null,
    revoked_at: null,
  });
  log.info("oauth_tokens_issued", { client_id: t.client_id, family_id: t.family_id, scopes: t.accessScopes });
  return json({
    access_token: access,
    token_type: "Bearer",
    expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
    refresh_token: refresh,
    scope: t.accessScopes.join(" "),
  });
}

// ---------------------------------------------------------------------------
// Revocation (RFC 7009)
// ---------------------------------------------------------------------------

export async function handleRevoke(req: Request): Promise<Response> {
  try {
    resolveOAuthConfig(ctx().env);
  } catch {
    return configUnavailable();
  }
  if (req.method !== "POST") return oauthError("invalid_request", "use POST", 405, { allow: "POST, OPTIONS" });
  try {
    if (!isForm(req)) return oauthError("invalid_request", "content-type must be application/x-www-form-urlencoded");
    const text = await readBody(req);
    if (text === null) return oauthError("invalid_request", "request is too large", 413);
    const { params, duplicate } = parseForm(text);
    if (duplicate) return oauthError("invalid_request", "a parameter was repeated");
    const token = params.get("token");
    if (!token) return oauthError("invalid_request", "token is required");
    // Possession of the token is sufficient to give it up; a client_id, when
    // supplied, must match the token's owner (RFC 7009 §2.1).
    let claimedClient: string | null = params.get("client_id");
    if (claimedClient === null) {
      const who = tokenClientId(req, params);
      if ("client_id" in who) claimedClient = who.client_id;
    }
    const ok = new Response(null, { status: 200, headers: { ...SENSITIVE_HEADERS, ...CORS_HEADERS } });
    if (!ACCESS_TOKEN_RE.test(token) && !REFRESH_TOKEN_RE.test(token)) return ok;

    const store = oauthStore();
    const now = oauthNow();
    const hash = sha256Hex(token);
    const rec = await store.getToken(hash);
    if (!rec || (claimedClient !== null && claimedClient !== rec.client_id)) return ok;
    if (rec.kind === "refresh") {
      const n = await store.revokeFamily(rec.family_id, now);
      log.info("oauth_token_revoked", { client_id: rec.client_id, kind: "refresh", family_id: rec.family_id, tokens_revoked: n });
    } else {
      await store.revokeToken(hash, now);
      log.info("oauth_token_revoked", { client_id: rec.client_id, kind: "access", family_id: rec.family_id });
    }
    return ok;
  } catch (err) {
    return internalError("revoke", err);
  }
}

// ---------------------------------------------------------------------------
// Resource-server side: verify a presented access token (used by identity.ts)
// ---------------------------------------------------------------------------

/**
 * Validate an "eva_…" access token against the hashed store: known, kind
 * access, not revoked, not expired, audience == this MCP resource, client
 * still approved. Effective scopes = token scopes ∩ client's current grant, so
 * an owner narrowing a client's scopes takes effect immediately.
 */
export async function verifyAccessToken(token: string): Promise<ClientIdentity | null> {
  let cfg: OAuthConfig;
  try {
    cfg = resolveOAuthConfig(ctx().env);
  } catch {
    return null;
  }
  if (!ACCESS_TOKEN_RE.test(token)) return null;
  const store = oauthStore();
  const rec = await store.getToken(sha256Hex(token));
  if (!rec || rec.kind !== "access") return null;
  if (rec.revoked_at !== null || rec.expires_at <= oauthNow()) return null;
  if (rec.resource !== cfg.resource) return null;
  const client = await store.getClient(rec.client_id);
  if (!client || client.status !== "approved") return null;
  return {
    client_id: client.client_id,
    name: client.client_name,
    kind: "oauth",
    scopes: intersectScopes(rec.scopes, client.granted_scopes),
  };
}

/** RFC 9728 §5.1 challenge for 401 responses from the MCP endpoint. */
export function buildWwwAuthenticate(opts: { error?: "invalid_token" | "insufficient_scope"; scope?: string[] } = {}): string {
  let cfg: OAuthConfig;
  try {
    cfg = resolveOAuthConfig(ctx().env);
  } catch {
    return 'Bearer realm="echo-vault"';
  }
  const parts = [`Bearer resource_metadata="${cfg.protectedResourceMetadataUrl}"`];
  if (opts.error) parts.push(`error="${opts.error}"`);
  const scope = opts.scope ? canonicalScopes(opts.scope) : [];
  if (scope.length) parts.push(`scope="${scope.join(" ")}"`);
  return parts.join(", ");
}
