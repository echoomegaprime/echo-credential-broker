// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Short-lived GitHub credentials for Vault v2, preferring GitHub App
 * installation tokens over long-lived PATs.
 *
 * Grounded in GitHub's docs (fetched 2026-11-14):
 *  - App JWT: RS256; `iat` 60 s in the past for clock drift; `exp` no more than
 *    10 min ahead; `iss` = app ID or client ID; sent as `Authorization: Bearer`.
 *    (docs.github.com/…/generating-a-json-web-token-jwt-for-a-github-app)
 *  - Installation token: `POST /app/installations/{id}/access_tokens` with the
 *    JWT; optional `repositories` (names, ≤ 500) / `repository_ids` and
 *    `permissions` down-scope it; it can never exceed the installation's own
 *    grant (→ 422). Tokens expire after 1 hour. Since 2026-04-27 GitHub is
 *    rolling out a stateless `ghs_<APPID>_<JWT>` format, so nothing here
 *    assumes a 40-character token. (rest/apps/apps#create-an-installation-access-token-for-an-app)
 *
 * Flow for `getGithubCredential({ account_login, account_id, … })`:
 *  1. The (login, numeric id) pair must match GITHUB_ACCOUNT_REGISTRY exactly.
 *  2. If ECHO_VAULT_GITHUB_INSTALLATIONS maps the login to an installation and
 *     the app ID / private key refs resolve from the canonical vault: sign a
 *     JWT, confirm `GET /app/installations/{id}` belongs to exactly that login
 *     AND id (mismatch fails closed — no fallback), then mint a down-scoped
 *     token. Tokens are cached in memory only, until 5 min before expiry.
 *  3. Otherwise (no installation, app not configured, or GitHub refuses the
 *     installation token: 401/403/404/422) fall back to the account PAT at
 *     `vault://github/<login>` — but only after `GET /user` with it returns the
 *     exact login AND numeric id ("identity_mismatch" otherwise). The path and
 *     reason are recorded as non-secret metadata on the handle.
 *
 * Token-escape guarantee: a caller never receives the token as a value. The
 * handle's `use(fn)` hands `fn` a short-lived `GithubRequester` whose
 * `request()` injects `Authorization` inside this module, enforces the
 * api.github.com allowlist (policy.ts), and returns responses with the token
 * scrubbed and redaction.ts applied. The requester stops working when `use`
 * settles. `use` deep-scans its return value and refuses
 * (`token_escape_blocked`) if the token appears anywhere; errors leaving `use`
 * are rebuilt with the token scrubbed; log lines never carry tokens, JWTs,
 * Authorization headers or response bodies. The handle's own properties,
 * `toJSON()` and `util.inspect` expose metadata only.
 * Limits: this protects every data path an agent or capability can influence;
 * it is not a sandbox against hostile code running in this process. The
 * injected `fetch` necessarily sees the Authorization header, and code able to
 * monkeypatch globals or read process memory can observe the token.
 */
import { createPrivateKey, type KeyObject } from "node:crypto";
import { inspect } from "node:util";
import { SignJWT } from "jose";
import { githubAuthHeaders } from "../http.ts";
import { log } from "../log.ts";
import { assertSafeDestination, buildProviderUrl, isAllowedMethod, PROVIDER_POLICIES } from "../policy.ts";
import { redactString, redactValue } from "../redaction.ts";
import { formatVaultRef, parseVaultRef } from "../refs.ts";
import { getStore, type CredentialStore } from "../store.ts";
import type { HttpMethod } from "../types.ts";
import { canonicalJson } from "./contracts.ts";

/** The only accounts this broker will act for: exact login → numeric account ID. */
export const GITHUB_ACCOUNT_REGISTRY: Readonly<Record<string, number>> = Object.freeze({
  echoomegaprime: 314902331,
  "ECHO-OMEGA-PRIME": 264607697,
  bobmcwilliams4: 235318155,
});

export const GITHUB_APP_ID_REF_ENV = "ECHO_VAULT_GITHUB_APP_ID_REF";
export const GITHUB_APP_KEY_REF_ENV = "ECHO_VAULT_GITHUB_APP_KEY_REF";
export const GITHUB_INSTALLATIONS_ENV = "ECHO_VAULT_GITHUB_INSTALLATIONS";

/** Cached installation tokens are served only while more than this remains. */
export const TOKEN_REFRESH_BEFORE_EXPIRY_MS = 5 * 60_000;
const JWT_BACKDATE_S = 60;
const JWT_LIFETIME_S = 9 * 60;
const USE_EXPIRY_SKEW_MS = 30_000;
const MAX_CACHE_ENTRIES = 256;
const MAX_SCOPED_REPOSITORIES = 500;
const USER_AGENT = "Echo-Credential-Broker/1.0";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type GithubPermissionLevel = "read" | "write" | "admin";

export interface GithubCredentialRequest {
  account_login: string;
  account_id: number;
  /** Non-secret label for logs/metadata, e.g. the capability ID. */
  purpose: string;
  /** Down-scope an installation token to these repository names (≤ 500). */
  repositories?: string[];
  repository_ids?: number[];
  /** Down-scope an installation token's permissions, e.g. { contents: "write" }. */
  permissions?: Record<string, GithubPermissionLevel>;
  /**
   * Broker-internal only (never copy from agent params): skip the installation
   * path because the operation is known not to accept installation tokens, or
   * because GitHub already refused one for it. Recorded as the fallback reason.
   */
  installation_unsupported_reason?: string;
}

export type GithubCredentialPath = "installation" | "pat_fallback";

/** Everything here is safe to log, return, or put in the ledger. */
export interface GithubCredentialMetadata {
  kind: "installation" | "pat";
  path: GithubCredentialPath;
  fallback_reason?: string;
  account_login: string;
  account_id: number;
  purpose: string;
  /** vault:// ref of the credential that authorised this: the app key, or the account PAT. */
  credential_ref: string;
  installation_id?: number;
  expires_at?: string;
  /** Permissions GitHub actually granted the installation token. */
  permissions?: Record<string, string>;
  repository_selection?: string;
  /** Derived from the PAT's documented prefix; never the PAT itself. */
  pat_kind?: "classic" | "fine_grained" | "unknown";
  cached?: boolean;
}

export interface GithubResponse {
  status: number;
  ok: boolean;
  /** Parsed JSON body, token-scrubbed and redacted. */
  json: unknown;
  /** Raw text (≤ 4 KiB) when the body is not JSON, scrubbed and redacted. */
  text: string | null;
}

export interface GithubRequestOptions {
  body?: unknown;
}

/** Authenticated GitHub access without the token: valid only inside `use()`. */
export interface GithubRequester {
  request(method: HttpMethod, path: string, opts?: GithubRequestOptions): Promise<GithubResponse>;
}

export interface GithubCredentialHandle extends Readonly<GithubCredentialMetadata> {
  use<T>(fn: (gh: GithubRequester) => Promise<T> | T): Promise<T>;
  metadata(): GithubCredentialMetadata;
  toJSON(): GithubCredentialMetadata;
}

export type GithubCredentialErrorCode =
  | "invalid_request"
  | "unknown_account"
  | "identity_mismatch"
  | "credential_unavailable"
  | "github_unavailable"
  | "credential_expired"
  | "requester_inactive"
  | "token_escape_blocked";

export class GithubCredentialError extends Error {
  readonly code: GithubCredentialErrorCode;
  readonly detail?: string;

  constructor(code: GithubCredentialErrorCode, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "GithubCredentialError";
    this.code = code;
    this.detail = detail;
  }
}

export interface GithubAppDeps {
  /** Canonical vault access. Tests MUST pass a store over FakeVaultBackend. */
  store?: Pick<CredentialStore, "resolveSecret">;
  /** Transport; defaults to globalThis.fetch. Only ever called with https://api.github.com URLs. */
  fetch?: typeof fetch;
  now?: () => number;
  env?: Readonly<Record<string, string | undefined>>;
  tokenCache?: InstallationTokenCache;
  registry?: Readonly<Record<string, number>>;
}

// ---------------------------------------------------------------------------
// Installation token cache (memory only, never persisted, never printed)
// ---------------------------------------------------------------------------

interface InstallationGrant {
  installation_id: number;
  expires_at: string;
  permissions?: Record<string, string>;
  repository_selection?: string;
}

interface CachedToken {
  token: string;
  expiresAtMs: number;
  grant: InstallationGrant;
}

type InstallationOutcome =
  | { ok: true; token: string; grant: InstallationGrant; cached: boolean }
  | { ok: false; reason: string };

export class InstallationTokenCache {
  private readonly entries = new Map<string, CachedToken>();
  private readonly inflight = new Map<string, Promise<InstallationOutcome>>();

  /** A token with more than TOKEN_REFRESH_BEFORE_EXPIRY_MS left, else null (and evicted). */
  get(key: string, nowMs: number): CachedToken | null {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (nowMs >= entry.expiresAtMs - TOKEN_REFRESH_BEFORE_EXPIRY_MS) {
      this.entries.delete(key);
      return null;
    }
    return entry;
  }

  set(key: string, entry: CachedToken, nowMs: number): void {
    if (this.entries.size >= MAX_CACHE_ENTRIES) {
      for (const [k, v] of this.entries) {
        if (nowMs >= v.expiresAtMs - TOKEN_REFRESH_BEFORE_EXPIRY_MS) this.entries.delete(k);
      }
      while (this.entries.size >= MAX_CACHE_ENTRIES) {
        const oldest = this.entries.keys().next().value;
        if (oldest === undefined) break;
        this.entries.delete(oldest);
      }
    }
    this.entries.set(key, entry);
  }

  pending(key: string): Promise<InstallationOutcome> | undefined {
    return this.inflight.get(key);
  }

  track(key: string, promise: Promise<InstallationOutcome>): Promise<InstallationOutcome> {
    this.inflight.set(key, promise);
    const done = () => {
      if (this.inflight.get(key) === promise) this.inflight.delete(key);
    };
    promise.then(done, done);
    return promise;
  }

  clear(): void {
    this.entries.clear();
    this.inflight.clear();
  }

  get size(): number {
    return this.entries.size;
  }

  toJSON(): { size: number } {
    return { size: this.entries.size };
  }

  [inspect.custom](): string {
    return `InstallationTokenCache { size: ${this.entries.size} }`;
  }
}

const defaultTokenCache = new InstallationTokenCache();

/** Drop every cached installation token (e.g. after rotating the app key). */
export function clearGithubTokenCache(): void {
  defaultTokenCache.clear();
}

// ---------------------------------------------------------------------------
// Scrubbing
// ---------------------------------------------------------------------------

/** Patterns redaction.ts misses today (see ledger.ts for the upstream proposal). */
const EXTRA_SECRET_RULES: ReadonlyArray<readonly [RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$/g, "[REDACTED_PRIVATE_KEY]"],
  [/gh[pousr]_[0-9]+_[A-Za-z0-9._-]{16,}/g, "[REDACTED_GITHUB_TOKEN]"],
  [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "[REDACTED_JWT]"],
];

function scrubText(value: string, secrets: readonly string[]): string {
  let out = value;
  for (const secret of secrets) {
    if (secret.length < 8) continue;
    const escaped = JSON.stringify(secret).slice(1, -1);
    for (const form of new Set([secret, escaped])) {
      if (out.includes(form)) out = out.split(form).join("[REDACTED_GITHUB_TOKEN]");
    }
  }
  for (const [re, replacement] of EXTRA_SECRET_RULES) out = out.replace(re, replacement);
  return redactString(out);
}

function scrubJson(value: unknown, secrets: readonly string[]): unknown {
  if (value === null || value === undefined) return value ?? null;
  try {
    return redactValue(JSON.parse(scrubText(JSON.stringify(value), secrets)));
  } catch {
    return { error: "unserializable_redacted" };
  }
}

function scrubResponse(res: GithubResponse, secrets: readonly string[]): GithubResponse {
  return {
    status: res.status,
    ok: res.ok,
    json: scrubJson(res.json, secrets),
    text: res.text === null ? null : scrubText(res.text, secrets),
  };
}

function scrubError(error: unknown, secrets: readonly string[]): Error {
  if (error instanceof GithubCredentialError) {
    const clean = new GithubCredentialError(error.code, error.detail ? scrubText(error.detail, secrets) : undefined);
    clean.stack = error.stack ? scrubText(error.stack, secrets) : undefined;
    return clean;
  }
  const message = error instanceof Error ? error.message : String(error);
  const clean = new Error(scrubText(message, secrets));
  if (error instanceof Error) {
    clean.name = error.name;
    clean.stack = error.stack ? scrubText(error.stack, secrets) : undefined;
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string") Object.assign(clean, { code: scrubText(code, secrets) });
  }
  return clean;
}

/** Deep search for any secret in a value, without invoking getters. */
function containsSecret(value: unknown, secrets: readonly string[], seen = new WeakSet<object>()): boolean {
  if (typeof value === "string") return secrets.some((s) => s.length >= 8 && value.includes(s));
  if (value === null || typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return containsSecret(Buffer.from(bytes).toString("utf8"), secrets, seen);
  }
  if (value instanceof Map) {
    for (const [k, v] of value) if (containsSecret(k, secrets, seen) || containsSecret(v, secrets, seen)) return true;
    return false;
  }
  if (value instanceof Set) {
    for (const v of value) if (containsSecret(v, secrets, seen)) return true;
    return false;
  }
  if (value instanceof Error && (containsSecret(value.message, secrets, seen) || containsSecret(value.stack, secrets, seen))) {
    return true;
  }
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if ("value" in descriptor && containsSecret(descriptor.value, secrets, seen)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Transport (api.github.com only; the only place an Authorization header exists)
// ---------------------------------------------------------------------------

interface ResolvedDeps {
  store: Pick<CredentialStore, "resolveSecret">;
  fetchImpl: typeof fetch;
  now: () => number;
  env: Readonly<Record<string, string | undefined>>;
  cache: InstallationTokenCache;
  registry: Readonly<Record<string, number>>;
}

function resolveDeps(deps: GithubAppDeps): ResolvedDeps {
  return {
    store: deps.store ?? getStore(),
    fetchImpl: deps.fetch ?? ((input, init) => globalThis.fetch(input, init)),
    now: deps.now ?? Date.now,
    env: deps.env ?? process.env,
    cache: deps.tokenCache ?? defaultTokenCache,
    registry: deps.registry ?? GITHUB_ACCOUNT_REGISTRY,
  };
}

interface GithubCall {
  method: HttpMethod;
  path: string;
  authorization: string;
  body?: unknown;
  /** Values to scrub from any error that escapes. */
  secrets: readonly string[];
}

/** Raw (unredacted) call — the result may hold a token and must stay inside this module. */
async function githubCall(ctx: ResolvedDeps, call: GithubCall): Promise<GithubResponse> {
  const policy = PROVIDER_POLICIES.github;
  if (typeof call.method !== "string" || !isAllowedMethod("github", call.method)) {
    throw new GithubCredentialError("invalid_request", "method_not_allowed");
  }
  const method = call.method.toUpperCase() as HttpMethod;
  let url: URL;
  try {
    if (typeof call.path !== "string") throw new Error("invalid_resource");
    url = buildProviderUrl("github", call.path);
    assertSafeDestination(url, "github");
  } catch (error) {
    throw new GithubCredentialError("invalid_request", scrubText(error instanceof Error ? error.message : "invalid_resource", call.secrets));
  }
  let payload: string | undefined;
  if (call.body !== undefined && method !== "GET") {
    payload = JSON.stringify(call.body);
    if (Buffer.byteLength(payload) > policy.maxRequestBytes) {
      throw new GithubCredentialError("invalid_request", "request_too_large");
    }
  }
  const headers = new Headers(githubAuthHeaders());
  headers.set("User-Agent", USER_AGENT);
  headers.set("Authorization", call.authorization);
  if (payload !== undefined) headers.set("Content-Type", "application/json");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), policy.timeoutMs);
  try {
    const res = await ctx.fetchImpl(url, { method, headers, body: payload, redirect: "error", signal: controller.signal });
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.byteLength > policy.maxResponseBytes) {
      throw new GithubCredentialError("github_unavailable", "response_too_large");
    }
    const text = buf.toString("utf8");
    let json: unknown = null;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
    }
    return { status: res.status, ok: res.ok, json, text: json === null && text ? text.slice(0, 4096) : null };
  } catch (error) {
    if (error instanceof GithubCredentialError) throw error;
    throw new GithubCredentialError("github_unavailable", scrubText(error instanceof Error ? error.message : String(error), call.secrets));
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

const REPO_NAME_RE = /^[A-Za-z0-9._-]{1,100}$/;
const PERMISSION_NAME_RE = /^[a-z][a-z_]{1,63}$/;
const PERMISSION_LEVELS: ReadonlySet<string> = new Set<GithubPermissionLevel>(["read", "write", "admin"]);
const PURPOSE_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const REASON_RE = /^[a-z0-9_]{1,64}$/;

/** GitHub repository name: [A-Za-z0-9._-]{1,100}, not "." / "..", no ".git" suffix. */
export function isValidRepoName(name: unknown): name is string {
  return (
    typeof name === "string" && REPO_NAME_RE.test(name) && name !== "." && name !== ".." && !name.toLowerCase().endsWith(".git")
  );
}

interface NormalizedScope {
  key: string;
  body: { repositories?: string[]; repository_ids?: number[]; permissions?: Record<string, GithubPermissionLevel> };
}

function invalid(detail: string): GithubCredentialError {
  return new GithubCredentialError("invalid_request", detail);
}

function validateRequest(req: GithubCredentialRequest, registry: Readonly<Record<string, number>>): NormalizedScope {
  if (!req || typeof req !== "object") throw invalid("request");
  if (typeof req.account_login !== "string" || !Object.hasOwn(registry, req.account_login)) {
    throw new GithubCredentialError("unknown_account", `account_login must be exactly one of: ${Object.keys(registry).join(", ")}`);
  }
  if (registry[req.account_login] !== req.account_id) {
    throw new GithubCredentialError("identity_mismatch", `account_id does not match the registry for ${req.account_login}`);
  }
  if (typeof req.purpose !== "string" || !PURPOSE_RE.test(req.purpose)) throw invalid("purpose");
  if (req.installation_unsupported_reason !== undefined && !REASON_RE.test(String(req.installation_unsupported_reason))) {
    throw invalid("installation_unsupported_reason");
  }
  const body: NormalizedScope["body"] = {};
  if (req.repositories !== undefined) {
    if (!Array.isArray(req.repositories) || req.repositories.length === 0 || req.repositories.length > MAX_SCOPED_REPOSITORIES) {
      throw invalid("repositories");
    }
    if (!req.repositories.every(isValidRepoName)) throw invalid("repositories");
    body.repositories = [...new Set(req.repositories)].sort();
  }
  if (req.repository_ids !== undefined) {
    if (!Array.isArray(req.repository_ids) || req.repository_ids.length === 0 || req.repository_ids.length > MAX_SCOPED_REPOSITORIES) {
      throw invalid("repository_ids");
    }
    if (!req.repository_ids.every((id) => Number.isSafeInteger(id) && id > 0)) throw invalid("repository_ids");
    body.repository_ids = [...new Set(req.repository_ids)].sort((a, b) => a - b);
  }
  if (req.permissions !== undefined) {
    const perms = req.permissions;
    if (!perms || typeof perms !== "object" || Array.isArray(perms) || Object.keys(perms).length === 0) throw invalid("permissions");
    const clean: Record<string, GithubPermissionLevel> = {};
    for (const [name, level] of Object.entries(perms)) {
      if (!PERMISSION_NAME_RE.test(name) || typeof level !== "string" || !PERMISSION_LEVELS.has(level)) throw invalid("permissions");
      clean[name] = level;
    }
    body.permissions = clean;
  }
  return { key: canonicalJson(body), body };
}

// ---------------------------------------------------------------------------
// App configuration (refs + installation map from env; values from the vault)
// ---------------------------------------------------------------------------

interface AppConfig {
  appIdRef?: string;
  keyRef?: string;
  installations: Record<string, number>;
  installationsError?: string;
}

function readAppConfig(env: ResolvedDeps["env"], registry: ResolvedDeps["registry"]): AppConfig {
  const config: AppConfig = { installations: {} };
  const appIdRef = env[GITHUB_APP_ID_REF_ENV]?.trim();
  const keyRef = env[GITHUB_APP_KEY_REF_ENV]?.trim();
  config.appIdRef = appIdRef ? parseVaultRef(appIdRef)?.raw : undefined;
  config.keyRef = keyRef ? parseVaultRef(keyRef)?.raw : undefined;
  const raw = env[GITHUB_INSTALLATIONS_ENV]?.trim();
  if (!raw) return config;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    config.installationsError = "installations_config_invalid";
    log.warn("github_installations_config_invalid", { env: GITHUB_INSTALLATIONS_ENV });
    return config;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    config.installationsError = "installations_config_invalid";
    return config;
  }
  for (const [login, value] of Object.entries(parsed as Record<string, unknown>)) {
    const id = typeof value === "number" ? value : typeof value === "string" && /^\d+$/.test(value) ? Number(value) : NaN;
    if (!Object.hasOwn(registry, login) || !Number.isSafeInteger(id) || id <= 0) {
      log.warn("github_installation_entry_ignored", { login: Object.hasOwn(registry, login) ? login : "(not in registry)" });
      continue;
    }
    config.installations[login] = id;
  }
  return config;
}

// ---------------------------------------------------------------------------
// App JWT
// ---------------------------------------------------------------------------

const APP_ID_RE = /^(?:[0-9]{1,12}|Iv[0-9A-Za-z.]{4,64})$/;

function parsePrivateKey(pem: string): KeyObject {
  // Vault values sometimes carry literal "\n" escapes instead of newlines.
  const normalized = !pem.includes("\n") && pem.includes("\\n") ? pem.replace(/\\n/g, "\n") : pem;
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: normalized.trim(), format: "pem" });
  } catch {
    throw new GithubCredentialError("credential_unavailable", "app_private_key_unparseable");
  }
  if (key.asymmetricKeyType !== "rsa") throw new GithubCredentialError("credential_unavailable", "app_private_key_not_rsa");
  return key;
}

/**
 * RS256 app JWT: iat = now − 60 s, exp = now + 9 min (GitHub's ceiling is 10),
 * iss = app ID (or client ID). Accepts PKCS#1 ("RSA PRIVATE KEY", what GitHub
 * issues) or PKCS#8 PEM.
 */
export async function createAppJwt(opts: { appId: string; privateKeyPem: string; nowMs: number }): Promise<string> {
  const appId = opts.appId.trim();
  if (!APP_ID_RE.test(appId)) throw new GithubCredentialError("credential_unavailable", "app_id_invalid");
  const key = parsePrivateKey(opts.privateKeyPem);
  const nowS = Math.floor(opts.nowMs / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setIssuedAt(nowS - JWT_BACKDATE_S)
    .setExpirationTime(nowS + JWT_LIFETIME_S)
    .setIssuer(appId)
    .sign(key);
}

// ---------------------------------------------------------------------------
// Installation path
// ---------------------------------------------------------------------------

function cleanPermissions(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (PERMISSION_NAME_RE.test(k) && typeof v === "string" && PERMISSION_LEVELS.has(v)) out[k] = v;
  }
  return out;
}

async function mintInstallationToken(
  ctx: ResolvedDeps,
  refs: { appIdRef: string; keyRef: string },
  installationId: number,
  req: GithubCredentialRequest,
  scope: NormalizedScope,
  cacheKey: string,
): Promise<InstallationOutcome> {
  const appId = (await ctx.store.resolveSecret(refs.appIdRef))?.trim();
  const pem = await ctx.store.resolveSecret(refs.keyRef);
  if (!appId || !pem) return { ok: false, reason: "app_credentials_unavailable" };
  let jwt: string;
  try {
    jwt = await createAppJwt({ appId, privateKeyPem: pem, nowMs: ctx.now() });
  } catch {
    return { ok: false, reason: "app_credentials_invalid" };
  }
  const secrets = [jwt, pem];
  const authorization = `Bearer ${jwt}`;

  // 1. The installation must belong to exactly this login AND numeric id.
  const inst = await githubCall(ctx, { method: "GET", path: `/app/installations/${installationId}`, authorization, secrets });
  if (inst.status >= 500) throw new GithubCredentialError("github_unavailable", `installation_lookup_http_${inst.status}`);
  if (inst.status === 401) return { ok: false, reason: "app_jwt_rejected" };
  if (inst.status === 404) return { ok: false, reason: "installation_not_found" };
  if (!inst.ok) return { ok: false, reason: `installation_lookup_http_${inst.status}` };
  const info = (inst.json ?? {}) as { account?: { login?: unknown; id?: unknown }; suspended_at?: unknown };
  if (info.account?.login !== req.account_login || info.account?.id !== req.account_id) {
    log.warn("github_installation_identity_mismatch", {
      installation_id: installationId,
      expected_login: req.account_login,
      expected_id: req.account_id,
      observed_login: typeof info.account?.login === "string" ? info.account.login : null,
      observed_id: typeof info.account?.id === "number" ? info.account.id : null,
    });
    throw new GithubCredentialError("identity_mismatch", `installation ${installationId} does not belong to ${req.account_login}`);
  }
  if (info.suspended_at) return { ok: false, reason: "installation_suspended" };

  // 2. Mint a down-scoped token.
  const res = await githubCall(ctx, {
    method: "POST",
    path: `/app/installations/${installationId}/access_tokens`,
    authorization,
    body: scope.body,
    secrets,
  });
  if (res.status >= 500) throw new GithubCredentialError("github_unavailable", `installation_token_http_${res.status}`);
  if (res.status === 401) return { ok: false, reason: "app_jwt_rejected" };
  if (res.status !== 201 && res.status !== 200) return { ok: false, reason: `installation_token_denied_http_${res.status}` };
  const body = (res.json ?? {}) as { token?: unknown; expires_at?: unknown; permissions?: unknown; repository_selection?: unknown };
  const expiresAtMs = typeof body.expires_at === "string" ? Date.parse(body.expires_at) : NaN;
  if (typeof body.token !== "string" || body.token.length < 8 || !Number.isFinite(expiresAtMs)) {
    throw new GithubCredentialError("github_unavailable", "installation_token_response_malformed");
  }
  const grant: InstallationGrant = { installation_id: installationId, expires_at: new Date(expiresAtMs).toISOString() };
  const permissions = cleanPermissions(body.permissions);
  if (permissions) grant.permissions = permissions;
  if (typeof body.repository_selection === "string") grant.repository_selection = body.repository_selection;
  ctx.cache.set(cacheKey, { token: body.token, expiresAtMs, grant }, ctx.now());
  return { ok: true, token: body.token, grant, cached: false };
}

async function installationToken(
  ctx: ResolvedDeps,
  refs: { appIdRef: string; keyRef: string },
  installationId: number,
  req: GithubCredentialRequest,
  scope: NormalizedScope,
): Promise<InstallationOutcome> {
  const cacheKey = `${installationId}|${scope.key}`;
  const hit = ctx.cache.get(cacheKey, ctx.now());
  if (hit) return { ok: true, token: hit.token, grant: hit.grant, cached: true };
  const pending = ctx.cache.pending(cacheKey);
  if (pending) return pending;
  return ctx.cache.track(cacheKey, mintInstallationToken(ctx, refs, installationId, req, scope, cacheKey));
}

// ---------------------------------------------------------------------------
// PAT fallback path
// ---------------------------------------------------------------------------

function patKind(pat: string): "classic" | "fine_grained" | "unknown" {
  if (pat.startsWith("github_pat_")) return "fine_grained";
  if (pat.startsWith("ghp_")) return "classic";
  return "unknown";
}

async function patHandle(ctx: ResolvedDeps, req: GithubCredentialRequest, reason: string): Promise<GithubCredentialHandle> {
  const ref = formatVaultRef("github", req.account_login);
  const pat = (await ctx.store.resolveSecret(ref))?.trim();
  if (!pat) throw new GithubCredentialError("credential_unavailable", `no usable credential at ${ref} (fallback reason: ${reason})`);
  const probe = await githubCall(ctx, { method: "GET", path: "/user", authorization: `Bearer ${pat}`, secrets: [pat] });
  if (probe.status === 401 || probe.status === 403) {
    throw new GithubCredentialError("credential_unavailable", `${ref} rejected by GitHub (http ${probe.status})`);
  }
  if (!probe.ok) throw new GithubCredentialError("github_unavailable", `user_probe_http_${probe.status}`);
  const user = (probe.json ?? {}) as { login?: unknown; id?: unknown };
  if (user.login !== req.account_login || user.id !== req.account_id) {
    log.warn("github_pat_identity_mismatch", {
      credential_ref: ref,
      expected_login: req.account_login,
      expected_id: req.account_id,
      observed_login: typeof user.login === "string" ? user.login : null,
      observed_id: typeof user.id === "number" ? user.id : null,
    });
    throw new GithubCredentialError("identity_mismatch", `${ref} does not authenticate as ${req.account_login} (${req.account_id})`);
  }
  return createHandle(pat, {
    kind: "pat",
    path: "pat_fallback",
    fallback_reason: reason,
    account_login: req.account_login,
    account_id: req.account_id,
    purpose: req.purpose,
    credential_ref: ref,
    pat_kind: patKind(pat),
  }, ctx);
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

function compact(meta: GithubCredentialMetadata): GithubCredentialMetadata {
  const out = { ...meta } as Record<string, unknown>;
  for (const key of Object.keys(out)) if (out[key] === undefined) delete out[key];
  if (meta.permissions) out.permissions = { ...meta.permissions };
  return out as unknown as GithubCredentialMetadata;
}

function createHandle(secret: string, metadata: GithubCredentialMetadata, ctx: ResolvedDeps): GithubCredentialHandle {
  const meta = compact(metadata);
  const secrets = [secret];
  const expiresAtMs = meta.expires_at ? Date.parse(meta.expires_at) : null;
  log.info("github_credential_issued", {
    purpose: meta.purpose,
    account: meta.account_login,
    path: meta.path,
    fallback_reason: meta.fallback_reason ?? null,
    installation_id: meta.installation_id ?? null,
    expires_at: meta.expires_at ?? null,
    cached: meta.cached ?? false,
    credential_ref: meta.credential_ref,
  });

  async function use<T>(fn: (gh: GithubRequester) => Promise<T> | T): Promise<T> {
    if (typeof fn !== "function") throw invalid("use() requires a callback");
    if (expiresAtMs !== null && ctx.now() >= expiresAtMs - USE_EXPIRY_SKEW_MS) {
      throw new GithubCredentialError("credential_expired", "request a new credential");
    }
    let active = true;
    const requester: GithubRequester = Object.freeze({
      async request(method: HttpMethod, path: string, opts: GithubRequestOptions = {}): Promise<GithubResponse> {
        if (!active) throw new GithubCredentialError("requester_inactive", "the requester is only valid inside use()");
        const raw = await githubCall(ctx, { method, path, authorization: `Bearer ${secret}`, body: opts?.body, secrets });
        return scrubResponse(raw, secrets);
      },
    });
    try {
      const out = await fn(requester);
      if (containsSecret(out, secrets)) {
        log.error("github_token_escape_blocked", { purpose: meta.purpose, account: meta.account_login, path: meta.path });
        throw new GithubCredentialError("token_escape_blocked", "the callback result contained credential material");
      }
      return out;
    } catch (error) {
      throw scrubError(error, secrets);
    } finally {
      active = false;
    }
  }

  const handle = {
    ...meta,
    use,
    metadata: () => compact(meta),
    toJSON: () => compact(meta),
    [inspect.custom]: () => compact(meta),
  };
  return Object.freeze(handle) as GithubCredentialHandle;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Obtain an opaque, short-lived GitHub credential handle for one exact account.
 * Throws GithubCredentialError (codes above); never returns or throws a token.
 */
export async function getGithubCredential(req: GithubCredentialRequest, deps: GithubAppDeps = {}): Promise<GithubCredentialHandle> {
  const ctx = resolveDeps(deps);
  const scope = validateRequest(req, ctx.registry);
  let reason: string;
  if (req.installation_unsupported_reason) {
    reason = req.installation_unsupported_reason;
  } else {
    const config = readAppConfig(ctx.env, ctx.registry);
    const installationId = config.installations[req.account_login];
    if (config.installationsError) reason = config.installationsError;
    else if (installationId === undefined) reason = "no_installation_configured";
    else if (!config.appIdRef || !config.keyRef) reason = "app_not_configured";
    else {
      const refs = { appIdRef: config.appIdRef, keyRef: config.keyRef };
      const outcome = await installationToken(ctx, refs, installationId, req, scope);
      if (outcome.ok) {
        return createHandle(outcome.token, {
          kind: "installation",
          path: "installation",
          account_login: req.account_login,
          account_id: req.account_id,
          purpose: req.purpose,
          credential_ref: refs.keyRef,
          installation_id: outcome.grant.installation_id,
          expires_at: outcome.grant.expires_at,
          permissions: outcome.grant.permissions,
          repository_selection: outcome.grant.repository_selection,
          cached: outcome.cached,
        }, ctx);
      }
      reason = outcome.reason;
    }
  }
  log.warn("github_credential_pat_fallback", { purpose: req.purpose, account: req.account_login, reason });
  return patHandle(ctx, req, reason);
}
