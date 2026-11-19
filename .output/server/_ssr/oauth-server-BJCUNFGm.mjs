import { r as __exportAll } from "../_runtime.mjs";
import { f as sanitizeError, o as log, r as __exportAll$1, u as registerSecretForRedaction } from "./log-BHJOU13W.mjs";
import { a as rateLimitKey, i as getDefaultRateLimitStore, n as MemoryRateLimitStore, o as withRateLimitStore, r as RateLimitUnavailableError, t as MAX_EVENTS_PER_KEY } from "./rate-limit-store-D2QvwAS2.mjs";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
//#region node_modules/.nitro/vite/services/ssr/assets/oauth-server-BJCUNFGm.js
var oauth_server_BJCUNFGm_exports = /* @__PURE__ */ __exportAll({
	a: () => canonicalScopes,
	c: () => oauthStore,
	i: () => buildWwwAuthenticate,
	l: () => oauth_server_exports,
	n: () => PROTECTED_RESOURCE_METADATA_PATH,
	o: () => configureOAuth,
	r: () => SUPPORTED_SCOPES,
	s: () => oauthNow,
	t: () => ACCESS_TOKEN_RE,
	u: () => verifyAccessToken
});
/** Keep expired token rows this long so refresh-token reuse is still detectable. */
var TOKEN_RETENTION_AFTER_EXPIRY_MS = 864e5;
var CODE_RETENTION_AFTER_EXPIRY_MS = 36e5;
var PENDING_RETENTION_AFTER_EXPIRY_MS = 36e5;
var HASH_RE = /^[0-9a-f]{64}$/;
function assertHash(value, what) {
	if (!HASH_RE.test(value)) throw new Error(`oauth_store_refused_unhashed_${what}`);
}
function num(v) {
	return typeof v === "number" ? v : Number(v);
}
function numOrNull(v) {
	return v === null || v === void 0 ? null : num(v);
}
function strArray(v) {
	const parsed = typeof v === "string" ? JSON.parse(v) : v;
	return Array.isArray(parsed) ? parsed.map(String) : [];
}
function toClient(r) {
	return {
		client_id: String(r.client_id),
		client_name: String(r.client_name),
		redirect_uris: strArray(r.redirect_uris),
		requested_scopes: strArray(r.requested_scopes),
		granted_scopes: strArray(r.granted_scopes),
		status: String(r.status),
		created_at: num(r.created_at),
		approved_at: numOrNull(r.approved_at),
		revoked_at: numOrNull(r.revoked_at)
	};
}
function toPending(r) {
	return {
		id_hash: String(r.id_hash),
		client_id: String(r.client_id),
		redirect_uri: String(r.redirect_uri),
		code_challenge: String(r.code_challenge),
		scopes: strArray(r.scopes),
		resource: String(r.resource),
		state: r.state === null || r.state === void 0 ? null : String(r.state),
		approval_id: String(r.approval_id),
		is_new_client: Boolean(r.is_new_client),
		status: String(r.status),
		created_at: num(r.created_at),
		expires_at: num(r.expires_at)
	};
}
function toCode(r) {
	return {
		code_hash: String(r.code_hash),
		client_id: String(r.client_id),
		redirect_uri: String(r.redirect_uri),
		code_challenge: String(r.code_challenge),
		scopes: strArray(r.scopes),
		resource: String(r.resource),
		family_id: String(r.family_id),
		created_at: num(r.created_at),
		expires_at: num(r.expires_at),
		used_at: numOrNull(r.used_at)
	};
}
function toToken(r) {
	return {
		token_hash: String(r.token_hash),
		kind: String(r.kind),
		client_id: String(r.client_id),
		family_id: String(r.family_id),
		scopes: strArray(r.scopes),
		resource: String(r.resource),
		created_at: num(r.created_at),
		expires_at: num(r.expires_at),
		used_at: numOrNull(r.used_at),
		revoked_at: numOrNull(r.revoked_at)
	};
}
async function defaultSqlProvider() {
	const { getSql } = await import("./db-YAhc1k3o.mjs");
	return getSql();
}
var SqlOAuthStore = class {
	provider;
	constructor(provider = defaultSqlProvider) {
		this.provider = provider;
	}
	async q(text, params = []) {
		return (await this.provider()).query(text, params);
	}
	async createClient(rec) {
		await this.q(`insert into vault_oauth_clients
         (client_id, client_name, redirect_uris, requested_scopes, granted_scopes, status, created_at, approved_at, revoked_at)
       values ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6, $7, $8, $9)`, [
			rec.client_id,
			rec.client_name,
			JSON.stringify(rec.redirect_uris),
			JSON.stringify(rec.requested_scopes),
			JSON.stringify(rec.granted_scopes),
			rec.status,
			rec.created_at,
			rec.approved_at,
			rec.revoked_at
		]);
	}
	async getClient(client_id) {
		const rows = await this.q(`select * from vault_oauth_clients where client_id = $1`, [client_id]);
		return rows[0] ? toClient(rows[0]) : null;
	}
	async listClients() {
		return (await this.q(`select * from vault_oauth_clients order by created_at asc, client_id asc`)).map(toClient);
	}
	async countClients() {
		return num((await this.q(`select count(*)::int as n from vault_oauth_clients`))[0]?.n ?? 0);
	}
	async updateClient(client_id, patch) {
		const sets = [];
		const params = [client_id];
		if (patch.granted_scopes !== void 0) {
			params.push(JSON.stringify(patch.granted_scopes));
			sets.push(`granted_scopes = $${params.length}::jsonb`);
		}
		if (patch.status !== void 0) {
			params.push(patch.status);
			sets.push(`status = $${params.length}`);
		}
		if (patch.approved_at !== void 0) {
			params.push(patch.approved_at);
			sets.push(`approved_at = $${params.length}`);
		}
		if (patch.revoked_at !== void 0) {
			params.push(patch.revoked_at);
			sets.push(`revoked_at = $${params.length}`);
		}
		if (sets.length === 0) return this.getClient(client_id);
		const rows = await this.q(`update vault_oauth_clients set ${sets.join(", ")} where client_id = $1 returning *`, params);
		return rows[0] ? toClient(rows[0]) : null;
	}
	async deleteStaleClients(before) {
		return (await this.q(`delete from vault_oauth_clients c
        where c.status in ('registered', 'denied')
          and c.created_at < $1
          and not exists (
            select 1 from vault_oauth_pending p
             where p.client_id = c.client_id and p.status = 'pending')
        returning c.client_id`, [before])).length;
	}
	async createPending(rec) {
		assertHash(rec.id_hash, "pending");
		await this.q(`insert into vault_oauth_pending
         (id_hash, client_id, redirect_uri, code_challenge, scopes, resource, state, approval_id,
          is_new_client, status, created_at, expires_at)
       values ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12)`, [
			rec.id_hash,
			rec.client_id,
			rec.redirect_uri,
			rec.code_challenge,
			JSON.stringify(rec.scopes),
			rec.resource,
			rec.state,
			rec.approval_id,
			rec.is_new_client,
			rec.status,
			rec.created_at,
			rec.expires_at
		]);
	}
	async getPending(id_hash) {
		const rows = await this.q(`select * from vault_oauth_pending where id_hash = $1`, [id_hash]);
		return rows[0] ? toPending(rows[0]) : null;
	}
	async claimPending(id_hash) {
		const rows = await this.q(`update vault_oauth_pending set status = 'completed'
        where id_hash = $1 and status = 'pending' returning *`, [id_hash]);
		return rows[0] ? toPending(rows[0]) : null;
	}
	async setPendingStatus(id_hash, status) {
		await this.q(`update vault_oauth_pending set status = $2 where id_hash = $1 and status = 'pending'`, [id_hash, status]);
	}
	async denyPendingForClient(client_id) {
		return (await this.q(`update vault_oauth_pending set status = 'denied'
        where client_id = $1 and status = 'pending' returning id_hash`, [client_id])).length;
	}
	async countActivePending(now) {
		return num((await this.q(`select count(*)::int as n from vault_oauth_pending where status = 'pending' and expires_at > $1`, [now]))[0]?.n ?? 0);
	}
	async expirePending(now) {
		return (await this.q(`update vault_oauth_pending set status = 'expired'
        where status = 'pending' and expires_at <= $1 returning id_hash`, [now])).length;
	}
	async saveCode(rec) {
		assertHash(rec.code_hash, "code");
		await this.q(`insert into vault_oauth_codes
         (code_hash, client_id, redirect_uri, code_challenge, scopes, resource, family_id,
          created_at, expires_at, used_at)
       values ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10)`, [
			rec.code_hash,
			rec.client_id,
			rec.redirect_uri,
			rec.code_challenge,
			JSON.stringify(rec.scopes),
			rec.resource,
			rec.family_id,
			rec.created_at,
			rec.expires_at,
			rec.used_at
		]);
	}
	async consumeCode(code_hash, now) {
		const won = await this.q(`update vault_oauth_codes set used_at = $2
        where code_hash = $1 and used_at is null returning *`, [code_hash, now]);
		if (won[0]) return {
			status: "ok",
			code: toCode(won[0])
		};
		const existing = await this.q(`select * from vault_oauth_codes where code_hash = $1`, [code_hash]);
		if (existing[0]) return {
			status: "reused",
			code: toCode(existing[0])
		};
		return { status: "not_found" };
	}
	async saveToken(rec) {
		assertHash(rec.token_hash, "token");
		await this.q(`insert into vault_oauth_tokens
         (token_hash, kind, client_id, family_id, scopes, resource, created_at, expires_at, used_at, revoked_at)
       values ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10)`, [
			rec.token_hash,
			rec.kind,
			rec.client_id,
			rec.family_id,
			JSON.stringify(rec.scopes),
			rec.resource,
			rec.created_at,
			rec.expires_at,
			rec.used_at,
			rec.revoked_at
		]);
	}
	async getToken(token_hash) {
		const rows = await this.q(`select * from vault_oauth_tokens where token_hash = $1`, [token_hash]);
		return rows[0] ? toToken(rows[0]) : null;
	}
	async markRefreshUsed(token_hash, now) {
		return (await this.q(`update vault_oauth_tokens set used_at = $2
        where token_hash = $1 and kind = 'refresh' and used_at is null and revoked_at is null
        returning token_hash`, [token_hash, now])).length === 1;
	}
	async revokeToken(token_hash, now) {
		return (await this.q(`update vault_oauth_tokens set revoked_at = $2
        where token_hash = $1 and revoked_at is null returning token_hash`, [token_hash, now])).length === 1;
	}
	async revokeFamily(family_id, now) {
		return (await this.q(`update vault_oauth_tokens set revoked_at = $2
        where family_id = $1 and revoked_at is null returning token_hash`, [family_id, now])).length;
	}
	async revokeClientTokens(client_id, now) {
		return (await this.q(`update vault_oauth_tokens set revoked_at = $2
        where client_id = $1 and revoked_at is null returning token_hash`, [client_id, now])).length;
	}
	async purgeExpired(now) {
		await this.q(`delete from vault_oauth_codes where expires_at < $1`, [now - CODE_RETENTION_AFTER_EXPIRY_MS]);
		await this.q(`delete from vault_oauth_pending where expires_at < $1`, [now - PENDING_RETENTION_AFTER_EXPIRY_MS]);
		await this.q(`delete from vault_oauth_tokens where expires_at < $1`, [now - TOKEN_RETENTION_AFTER_EXPIRY_MS]);
	}
};
var storeRef = globalThis;
/** The active store. Defaults to SQL (PGlite / Postgres via getSql()). */
function getOAuthStore() {
	storeRef.__echoVaultOAuthStore__ ??= new SqlOAuthStore();
	return storeRef.__echoVaultOAuthStore__;
}
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
var oauth_server_exports = /* @__PURE__ */ __exportAll$1({
	ACCESS_TOKEN_RE: () => ACCESS_TOKEN_RE,
	ACCESS_TOKEN_TTL_MS: () => ACCESS_TOKEN_TTL_MS,
	AUTHORIZATION_SERVER_METADATA_PATH: () => AUTHORIZATION_SERVER_METADATA_PATH,
	AUTHORIZE_PATH: () => AUTHORIZE_PATH,
	CODE_TTL_MS: () => CODE_TTL_MS,
	DEFAULT_REQUESTED_SCOPES: () => DEFAULT_REQUESTED_SCOPES,
	FailureRateLimiter: () => FailureRateLimiter,
	MCP_RESOURCE_PATH: () => MCP_RESOURCE_PATH,
	OAuthConfigError: () => OAuthConfigError,
	PENDING_TTL_MS: () => PENDING_TTL_MS,
	PROTECTED_RESOURCE_METADATA_PATH: () => PROTECTED_RESOURCE_METADATA_PATH,
	REFRESH_TOKEN_RE: () => REFRESH_TOKEN_RE,
	REFRESH_TOKEN_TTL_MS: () => REFRESH_TOKEN_TTL_MS,
	REGISTER_PATH: () => REGISTER_PATH,
	REVOKE_PATH: () => REVOKE_PATH,
	STALE_CLIENT_MS: () => STALE_CLIENT_MS,
	SUPPORTED_SCOPES: () => SUPPORTED_SCOPES,
	TOKEN_PATH: () => TOKEN_PATH,
	authorizationServerMetadata: () => authorizationServerMetadata,
	buildWwwAuthenticate: () => buildWwwAuthenticate,
	canonicalScopes: () => canonicalScopes,
	configureOAuth: () => configureOAuth,
	escapeHtml: () => escapeHtml,
	handleAuthorizationServerMetadata: () => handleAuthorizationServerMetadata,
	handleAuthorize: () => handleAuthorize,
	handlePreflight: () => handlePreflight,
	handleProtectedResourceMetadata: () => handleProtectedResourceMetadata,
	handleRegister: () => handleRegister,
	handleRevoke: () => handleRevoke,
	handleToken: () => handleToken,
	limiterKey: () => limiterKey,
	oauthNow: () => oauthNow,
	oauthStore: () => oauthStore,
	protectedResourceMetadata: () => protectedResourceMetadata,
	redirectUriProblem: () => redirectUriProblem,
	resolveOAuthConfig: () => resolveOAuthConfig,
	s256Challenge: () => s256Challenge,
	sha256Hex: () => sha256Hex,
	verifyAccessToken: () => verifyAccessToken
});
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
var SUPPORTED_SCOPES = [
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
	"audit.read"
];
/** Requested when a client asks for nothing specific. Read-only. */
var DEFAULT_REQUESTED_SCOPES = [
	"github.read",
	"cloudflare.read",
	"vault.read"
];
var ACCESS_TOKEN_TTL_MS = 36e5;
var REFRESH_TOKEN_TTL_MS = 2592e6;
var CODE_TTL_MS = 6e4;
var PENDING_TTL_MS = 6e5;
/** Never-approved registrations older than this are pruned to keep the client cap from filling with junk. */
var STALE_CLIENT_MS = 864e5;
var PURGE_INTERVAL_MS = 6e5;
var POLL_INTERVAL_SECONDS = 3;
var MCP_RESOURCE_PATH = "/api/mcp";
var PROTECTED_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource";
var AUTHORIZATION_SERVER_METADATA_PATH = "/.well-known/oauth-authorization-server";
var AUTHORIZE_PATH = "/api/oauth/authorize";
var TOKEN_PATH = "/api/oauth/token";
var REGISTER_PATH = "/api/oauth/register";
var REVOKE_PATH = "/api/oauth/revoke";
var MAX_BODY_BYTES = 16384;
var MAX_CLIENT_NAME = 100;
var MAX_REDIRECT_URIS = 10;
var MAX_REDIRECT_URI_LENGTH = 2048;
var MAX_STATE_LENGTH = 1024;
var B64URL_256 = "[A-Za-z0-9_-]{43}";
var ACCESS_TOKEN_RE = new RegExp(`^eva_${B64URL_256}$`);
var REFRESH_TOKEN_RE = new RegExp(`^evr_${B64URL_256}$`);
var CODE_RE = new RegExp(`^evc_${B64URL_256}$`);
var PENDING_RE = new RegExp(`^evp_${B64URL_256}$`);
var CLIENT_ID_RE = /^oc_[A-Za-z0-9_-]{22}$/;
var CODE_CHALLENGE_RE = new RegExp(`^${B64URL_256}$`);
/** RFC 7636 §4.1: 43–128 unreserved characters. */
var CODE_VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
var UNSAFE_NAME_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/;
var OAuthConfigError = class extends Error {
	constructor(message) {
		super(message);
		this.name = "OAuthConfigError";
	}
};
function isLoopbackHostname(hostname) {
	return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}
function intEnv(env, name, fallback, min, max) {
	const raw = env[name];
	if (raw === void 0 || raw.trim() === "") return fallback;
	const n = Number(raw.trim());
	if (!Number.isInteger(n) || n < min || n > max) {
		log.warn("oauth_env_invalid_using_default", {
			name,
			fallback
		});
		return fallback;
	}
	return n;
}
/**
* Resolve issuer + endpoint URLs from ECHO_VAULT_PUBLIC_URL.
* Throws OAuthConfigError when unset, malformed, not an origin, or not https
* (http is accepted only for loopback hosts and only outside NODE_ENV=production).
*/
function resolveOAuthConfig(env = process.env) {
	const raw = (env.ECHO_VAULT_PUBLIC_URL ?? "").trim();
	if (!raw) throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL is not set");
	if (/[?#\s]/.test(raw)) throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL must not contain a query, fragment, or whitespace");
	let url;
	try {
		url = new URL(raw);
	} catch {
		throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL is not a valid URL");
	}
	if (url.username || url.password) throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL must not contain credentials");
	if (url.pathname !== "/") throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL must be an origin (no path)");
	const httpsOk = url.protocol === "https:";
	const loopbackHttpOk = url.protocol === "http:" && isLoopbackHostname(url.hostname) && env.NODE_ENV !== "production";
	if (!httpsOk && !loopbackHttpOk) throw new OAuthConfigError("ECHO_VAULT_PUBLIC_URL must use https (http only for localhost outside production)");
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
		maxClients: intEnv(env, "ECHO_VAULT_OAUTH_MAX_CLIENTS", 256, 1, 1e5),
		maxPending: intEnv(env, "ECHO_VAULT_OAUTH_MAX_PENDING", 16, 1, 1e3)
	};
}
/**
* Counts failed attempts per key in a sliding window. State lives in a
* RateLimitStore (default: the shared SQL store), so the limit survives a
* restart and holds across server instances. Every method rejects with
* RateLimitUnavailableError when the store fails; callers fail closed.
*/
var FailureRateLimiter = class {
	now;
	maxFailures;
	windowMs;
	store;
	constructor(opts) {
		this.now = opts.now;
		this.maxFailures = Math.min(opts.maxFailures ?? 10, MAX_EVENTS_PER_KEY);
		this.windowMs = opts.windowMs ?? 3e5;
		this.store = opts.store ?? (opts.maxKeys !== void 0 ? new MemoryRateLimitStore({ maxKeys: opts.maxKeys }) : void 0);
	}
	backing() {
		return this.store ?? getDefaultRateLimitStore();
	}
	/** 0 when allowed; otherwise milliseconds until the oldest failure leaves the window. */
	async retryAfterMs(key) {
		const now = this.now();
		const { count, oldestAt } = await withRateLimitStore(this.backing(), "count", (s) => s.count(key, this.windowMs, now));
		if (count < this.maxFailures || oldestAt === null) return 0;
		return Math.max(1, oldestAt + this.windowMs - now);
	}
	async recordFailure(key) {
		const now = this.now();
		await withRateLimitStore(this.backing(), "hit", (s) => s.hit(key, this.windowMs, now));
	}
	async reset(key) {
		await withRateLimitStore(this.backing(), "reset", (s) => s.reset(key));
	}
};
var ctxRef = globalThis;
function newContext() {
	const ctx = {
		store: null,
		approver: null,
		clock: { now: () => Date.now() },
		env: process.env,
		limiter: void 0,
		rateLimitStore: void 0,
		lastPurge: 0
	};
	ctx.limiter = new FailureRateLimiter({ now: () => ctx.clock.now() });
	return ctx;
}
function ctx() {
	ctxRef.__echoVaultOAuthCtx__ ??= newContext();
	return ctxRef.__echoVaultOAuthCtx__;
}
/**
* Wire dependencies. The lead calls this once at server start with the
* Telegram-backed OwnerApprover; tests inject a MemoryOAuthStore, a fake
* approver, a fake clock, and an env object.
*/
function configureOAuth(deps) {
	const c = ctx();
	if (deps.store !== void 0) c.store = deps.store;
	if (deps.approver !== void 0) c.approver = deps.approver;
	if (deps.clock !== void 0) c.clock = deps.clock;
	if (deps.env !== void 0) c.env = deps.env;
	if (deps.rateLimitStore !== void 0) c.rateLimitStore = deps.rateLimitStore;
	if (deps.rateLimit !== void 0 || deps.clock !== void 0 || deps.rateLimitStore !== void 0) c.limiter = new FailureRateLimiter({
		now: () => c.clock.now(),
		...deps.rateLimit,
		store: c.rateLimitStore
	});
}
function oauthStore() {
	return ctx().store ?? getOAuthStore();
}
function oauthNow() {
	return ctx().clock.now();
}
function sha256Hex(value) {
	return createHash("sha256").update(value, "utf8").digest("hex");
}
/** RFC 7636 S256: BASE64URL(SHA256(ASCII(verifier))), no padding. */
function s256Challenge(verifier) {
	return createHash("sha256").update(verifier, "ascii").digest("base64url");
}
function pkceMatches(verifier, storedChallenge) {
	const computed = Buffer.from(s256Challenge(verifier), "utf8");
	const stored = Buffer.from(storedChallenge, "utf8");
	if (computed.length !== stored.length) return false;
	return timingSafeEqual(computed, stored);
}
function randomValue(prefix, bytes = 32) {
	return `${prefix}${randomBytes(bytes).toString("base64url")}`;
}
function canonicalScopes(list) {
	const set = new Set(list);
	return SUPPORTED_SCOPES.filter((s) => set.has(s));
}
function intersectScopes(a, b) {
	const bs = new Set(b);
	return canonicalScopes(a.filter((s) => bs.has(s)));
}
/** Parse a space-delimited scope string. `null` result = contains an unsupported scope. */
function parseScopeString(raw) {
	if (raw === null) return [];
	const parts = raw.split(" ").filter((s) => s.length > 0);
	for (const p of parts) if (!SUPPORTED_SCOPES.includes(p)) return null;
	return canonicalScopes(parts);
}
/** Normalize an RFC 8707 resource indicator for comparison (case-insensitive scheme/host, no trailing slash). */
function normalizeResource(value) {
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
function resourceMatches(value, cfg) {
	return normalizeResource(value) === cfg.resource;
}
function escapeHtml(value) {
	return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
var CORS_HEADERS = {
	"access-control-allow-origin": "*",
	"access-control-expose-headers": "www-authenticate, retry-after"
};
var SENSITIVE_HEADERS = {
	"cache-control": "no-store",
	pragma: "no-cache",
	"x-content-type-options": "nosniff",
	"referrer-policy": "no-referrer"
};
function json(body, status = 200, extra = {}) {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"content-type": "application/json; charset=utf-8",
			...SENSITIVE_HEADERS,
			...CORS_HEADERS,
			...extra
		}
	});
}
/** Standard OAuth error JSON. Descriptions are fixed strings — never request values. */
function oauthError(error, description, status = 400, extra = {}) {
	return json({
		error,
		error_description: description
	}, status, extra);
}
function configUnavailable() {
	return oauthError("temporarily_unavailable", "authorization server is not configured", 503);
}
async function readBody(req) {
	const declared = req.headers.get("content-length");
	if (declared && Number(declared) > MAX_BODY_BYTES) return null;
	const text = await req.text();
	return Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES ? null : text;
}
function parseForm(text) {
	const params = new URLSearchParams(text);
	let duplicate = false;
	for (const key of new Set(params.keys())) if (params.getAll(key).length > 1) duplicate = true;
	return {
		params,
		duplicate
	};
}
function isForm(req) {
	return (req.headers.get("content-type") ?? "").toLowerCase().includes("application/x-www-form-urlencoded");
}
async function maybePurge(store, now) {
	const c = ctx();
	if (now - c.lastPurge < PURGE_INTERVAL_MS) return;
	c.lastPurge = now;
	try {
		await store.purgeExpired(now);
	} catch (err) {
		log.warn("oauth_purge_failed", { error: sanitizeError(err).message });
	}
}
function internalError(where, err) {
	log.error("oauth_internal_error", {
		where,
		error: sanitizeError(err).message
	});
	return oauthError("server_error", "internal error", 500);
}
function protectedResourceMetadata(cfg) {
	return {
		resource: cfg.resource,
		authorization_servers: [cfg.issuer],
		scopes_supported: [...SUPPORTED_SCOPES],
		bearer_methods_supported: ["header"],
		resource_name: "ECHO Vault"
	};
}
function authorizationServerMetadata(cfg) {
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
		authorization_response_iss_parameter_supported: true
	};
}
function metadataResponse(body) {
	return new Response(JSON.stringify(body), {
		status: 200,
		headers: {
			"content-type": "application/json; charset=utf-8",
			"cache-control": "public, max-age=300",
			"x-content-type-options": "nosniff",
			...CORS_HEADERS
		}
	});
}
async function handleProtectedResourceMetadata(_req) {
	let cfg;
	try {
		cfg = resolveOAuthConfig(ctx().env);
	} catch {
		return configUnavailable();
	}
	return metadataResponse(protectedResourceMetadata(cfg));
}
async function handleAuthorizationServerMetadata(_req) {
	let cfg;
	try {
		cfg = resolveOAuthConfig(ctx().env);
	} catch {
		return configUnavailable();
	}
	return metadataResponse(authorizationServerMetadata(cfg));
}
/** CORS preflight for browser-based MCP clients (no cookies are ever used, so `*` is safe). */
function handlePreflight(_req) {
	return new Response(null, {
		status: 204,
		headers: {
			...CORS_HEADERS,
			"access-control-allow-methods": "GET, POST, OPTIONS",
			"access-control-allow-headers": "authorization, content-type, mcp-protocol-version",
			"access-control-max-age": "600"
		}
	});
}
/** Returns an error description, or null when the redirect URI is acceptable. */
function redirectUriProblem(raw) {
	if (typeof raw !== "string" || raw.length === 0) return "redirect_uri must be a non-empty string";
	if (raw.length > MAX_REDIRECT_URI_LENGTH) return "redirect_uri is too long";
	if (raw.includes("#")) return "redirect_uri must not contain a fragment";
	if (/[\s\u0000-\u001f\u007f]/.test(raw)) return "redirect_uri must not contain whitespace or control characters";
	let url;
	try {
		url = new URL(raw);
	} catch {
		return "redirect_uri must be an absolute URL";
	}
	if (url.username || url.password) return "redirect_uri must not contain credentials";
	if (url.protocol === "https:") return url.hostname ? null : "redirect_uri must have a host";
	if (url.protocol === "http:") return isLoopbackHostname(url.hostname) ? null : "http redirect_uri is allowed only for loopback (localhost, 127.0.0.1, [::1])";
	return "redirect_uri must use https (or http for loopback)";
}
async function handleRegister(req) {
	let cfg;
	try {
		cfg = resolveOAuthConfig(ctx().env);
	} catch {
		return configUnavailable();
	}
	if (req.method !== "POST") return oauthError("invalid_request", "use POST", 405, { allow: "POST, OPTIONS" });
	try {
		if (!(req.headers.get("content-type") ?? "").toLowerCase().includes("application/json")) return oauthError("invalid_client_metadata", "content-type must be application/json");
		const text = await readBody(req);
		if (text === null) return oauthError("invalid_client_metadata", "registration request is too large", 413);
		let body;
		try {
			body = JSON.parse(text);
		} catch {
			return oauthError("invalid_client_metadata", "body must be a JSON object");
		}
		if (!body || typeof body !== "object" || Array.isArray(body)) return oauthError("invalid_client_metadata", "body must be a JSON object");
		const meta = body;
		const uris = meta.redirect_uris;
		if (!Array.isArray(uris) || uris.length === 0) return oauthError("invalid_redirect_uri", "redirect_uris must be a non-empty array");
		if (uris.length > MAX_REDIRECT_URIS) return oauthError("invalid_redirect_uri", "too many redirect_uris");
		for (const u of uris) {
			const problem = redirectUriProblem(u);
			if (problem) return oauthError("invalid_redirect_uri", problem);
		}
		const redirectUris = [...new Set(uris)];
		if (meta.response_types !== void 0) {
			const rt = meta.response_types;
			if (!Array.isArray(rt) || rt.length === 0 || rt.some((v) => v !== "code")) return oauthError("invalid_client_metadata", "only response_type \"code\" is supported");
		}
		if (meta.grant_types !== void 0) {
			const gt = meta.grant_types;
			if (!Array.isArray(gt) || !gt.includes("authorization_code")) return oauthError("invalid_client_metadata", "grant_types must include authorization_code");
		}
		let clientName = "Unnamed client";
		if (meta.client_name !== void 0) {
			if (typeof meta.client_name !== "string") return oauthError("invalid_client_metadata", "client_name must be a string");
			const trimmed = meta.client_name.trim();
			if (trimmed.length > MAX_CLIENT_NAME) return oauthError("invalid_client_metadata", "client_name is too long");
			if (UNSAFE_NAME_CHARS.test(trimmed)) return oauthError("invalid_client_metadata", "client_name contains control or bidi characters");
			if (trimmed.length > 0) clientName = trimmed;
		}
		let requestedScopes = [];
		if (meta.scope !== void 0) {
			if (typeof meta.scope !== "string") return oauthError("invalid_client_metadata", "scope must be a string");
			requestedScopes = canonicalScopes(meta.scope.split(" "));
		}
		const store = oauthStore();
		const now = oauthNow();
		await store.deleteStaleClients(now - STALE_CLIENT_MS);
		if (await store.countClients() >= cfg.maxClients) {
			log.warn("oauth_client_cap_reached", { max: cfg.maxClients });
			return oauthError("temporarily_unavailable", "client registration limit reached", 429);
		}
		const record = {
			client_id: randomValue("oc_", 16),
			client_name: clientName,
			redirect_uris: redirectUris,
			requested_scopes: requestedScopes,
			granted_scopes: [],
			status: "registered",
			created_at: now,
			approved_at: null,
			revoked_at: null
		};
		await store.createClient(record);
		log.info("oauth_client_registered", {
			client_id: record.client_id,
			redirect_hosts: redirectUris.map((u) => new URL(u).host)
		});
		return json({
			client_id: record.client_id,
			client_id_issued_at: Math.floor(now / 1e3),
			client_name: record.client_name,
			redirect_uris: record.redirect_uris,
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
			token_endpoint_auth_method: "none",
			...requestedScopes.length ? { scope: requestedScopes.join(" ") } : {}
		}, 201);
	} catch (err) {
		return internalError("register", err);
	}
}
var PAGE_STYLE = "body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0b0d12;color:#e8eaf0;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}main{max-width:30rem;margin:1rem;padding:2rem;border:1px solid #2a2f3a;border-radius:12px;background:#141821}h1{font-size:1.25rem;margin:0 0 1rem}p,li{line-height:1.5;color:#b9bfcc}code{background:#1f2430;padding:.1rem .35rem;border-radius:4px;color:#e8eaf0}a{color:#8ab4ff}";
var PAGE_CSP = `default-src 'none'; style-src 'sha256-${createHash("sha256").update(PAGE_STYLE, "utf8").digest("base64")}'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
/**
* Render a minimal, script-free page. `paragraphs`/`after` are trusted HTML
* fragments built by this module with every dynamic value already escaped;
* `title`, `list` items and `refreshUrl` are escaped here.
*/
function htmlPage(opts) {
	const refresh = opts.refreshUrl ? `<meta http-equiv="refresh" content="${POLL_INTERVAL_SECONDS};url=${escapeHtml(opts.refreshUrl)}">` : "";
	const list = opts.list?.length ? `<ul>${opts.list.map((li) => `<li><code>${escapeHtml(li)}</code></li>`).join("")}</ul>` : "";
	const after = (opts.after ?? []).map((p) => `<p>${p}</p>`).join("");
	const manual = opts.refreshUrl ? `<p><a href="${escapeHtml(opts.refreshUrl)}">Check now</a></p>` : "";
	const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">${refresh}<title>${escapeHtml(opts.title)}</title><style>${PAGE_STYLE}</style></head><body><main><h1>${escapeHtml(opts.title)}</h1>` + opts.paragraphs.map((p) => `<p>${p}</p>`).join("") + list + after + manual + `</main></body></html>`;
	return new Response(html, {
		status: opts.status,
		headers: {
			"content-type": "text/html; charset=utf-8",
			...SENSITIVE_HEADERS,
			"content-security-policy": PAGE_CSP,
			"x-frame-options": "DENY"
		}
	});
}
/** An error page. `message` is plain text and is escaped here. Never redirects. */
function htmlError(status, title, message) {
	return htmlPage({
		status,
		title,
		paragraphs: [escapeHtml(message)]
	});
}
function redirectTo(location) {
	return new Response(null, {
		status: 302,
		headers: {
			location,
			...SENSITIVE_HEADERS
		}
	});
}
function redirectError(cfg, redirectUri, error, description, state) {
	const url = new URL(redirectUri);
	url.searchParams.set("error", error);
	url.searchParams.set("error_description", description);
	if (state !== null) url.searchParams.set("state", state);
	url.searchParams.set("iss", cfg.issuer);
	return redirectTo(url.toString());
}
function waitingPage(cfg, handle, clientName, redirectHost, scopes) {
	return htmlPage({
		status: 200,
		title: "Approve this connection on your phone",
		paragraphs: [
			`<strong>${escapeHtml(clientName)}</strong> wants to connect to ECHO Vault.`,
			`After approval it will be sent to <code>${escapeHtml(redirectHost)}</code>.`,
			"Requested access:"
		],
		list: scopes,
		after: ["Check your phone and approve or deny. Keep this page open — it refreshes automatically."],
		refreshUrl: `${cfg.authorizationEndpoint}?pending=${encodeURIComponent(handle)}`
	});
}
function deniedPage() {
	return htmlError(403, "Connection denied", "The owner denied this connection. You can close this window.");
}
function expiredPage() {
	return htmlError(400, "Request expired", "This connection request expired. Start the connection again from your app.");
}
function redirectHostOf(uri) {
	return new URL(uri).host;
}
var AUTHORIZE_SINGLE_PARAMS = [
	"response_type",
	"client_id",
	"redirect_uri",
	"code_challenge",
	"code_challenge_method",
	"state",
	"scope",
	"pending"
];
/**
* GET /api/oauth/authorize
*   - with OAuth params: validate, ask the owner, render the waiting page.
*   - with `pending=evp_…`: poll the owner decision; once approved, issue a
*     single-use code and 302 to the registered redirect_uri with code+state+iss.
*/
async function handleAuthorize(req) {
	let cfg;
	try {
		cfg = resolveOAuthConfig(ctx().env);
	} catch {
		return htmlError(503, "Unavailable", "This connector is not configured yet.");
	}
	if (req.method !== "GET") return htmlError(405, "Method not allowed", "Use GET.");
	try {
		const url = new URL(req.url);
		for (const k of AUTHORIZE_SINGLE_PARAMS) if (url.searchParams.getAll(k).length > 1) return htmlError(400, "Invalid request", "A parameter was repeated.");
		const pending = url.searchParams.get("pending");
		if (pending !== null) return await pollPending(cfg, pending);
		return await startAuthorization(cfg, url.searchParams);
	} catch (err) {
		log.error("oauth_internal_error", {
			where: "authorize",
			error: sanitizeError(err).message
		});
		return htmlError(500, "Something went wrong", "The authorization server hit an internal error.");
	}
}
async function startAuthorization(cfg, p) {
	const c = ctx();
	const store = oauthStore();
	const clientId = p.get("client_id");
	const client = clientId && CLIENT_ID_RE.test(clientId) ? await store.getClient(clientId) : null;
	if (!client) return htmlError(400, "Unknown client", "This application is not registered with ECHO Vault.");
	const redirectUri = p.get("redirect_uri");
	if (!redirectUri || !client.redirect_uris.includes(redirectUri)) return htmlError(400, "Invalid redirect", "redirect_uri does not exactly match a registered redirect URI.");
	if (client.status === "revoked" || client.status === "denied") return htmlError(403, "Connection refused", "The owner has denied or revoked this application.");
	const trusted = client.status === "approved";
	const stateRaw = p.get("state");
	const fail = (error, description) => trusted && (stateRaw === null || stateRaw.length <= MAX_STATE_LENGTH) ? redirectError(cfg, redirectUri, error, description, stateRaw) : htmlError(400, "Invalid authorization request", description);
	if (stateRaw !== null && stateRaw.length > MAX_STATE_LENGTH) return fail("invalid_request", "state is too long");
	if (p.get("response_type") !== "code") return fail("unsupported_response_type", "response_type must be code");
	const challenge = p.get("code_challenge");
	if (!challenge) return fail("invalid_request", "code_challenge is required (PKCE)");
	if (p.get("code_challenge_method") !== "S256") return fail("invalid_request", "code_challenge_method must be S256");
	if (!CODE_CHALLENGE_RE.test(challenge)) return fail("invalid_request", "code_challenge is malformed");
	for (const r of p.getAll("resource")) if (!resourceMatches(r, cfg)) return fail("invalid_target", "resource must be this server's MCP endpoint");
	const parsed = parseScopeString(p.get("scope"));
	if (parsed === null) return fail("invalid_scope", "unsupported scope requested");
	const requested = parsed.length ? parsed : client.requested_scopes.length ? canonicalScopes(client.requested_scopes) : [...DEFAULT_REQUESTED_SCOPES];
	const effective = trusted ? intersectScopes(requested, client.granted_scopes) : requested;
	if (effective.length === 0) return fail("invalid_scope", "none of the requested scopes are granted to this client");
	if (!c.approver) {
		log.error("oauth_owner_approver_missing", { client_id: client.client_id });
		return htmlError(503, "Approval unavailable", "Owner approval is not configured on this server.");
	}
	const now = oauthNow();
	await store.expirePending(now);
	if (await store.countActivePending(now) >= cfg.maxPending) {
		log.warn("oauth_pending_cap_reached", { max: cfg.maxPending });
		return htmlError(429, "Too many requests", "Too many connection requests are waiting for approval. Try again later.");
	}
	const redirectHost = redirectHostOf(redirectUri);
	const isNew = client.status === "registered";
	let approvalId;
	try {
		approvalId = (await c.approver.requestClientApproval({
			client_id: client.client_id,
			client_name: client.client_name,
			requested_scopes: effective,
			redirect_host: redirectHost,
			is_new_client: isNew
		}))?.approval_id;
	} catch (err) {
		log.error("oauth_owner_approval_request_failed", {
			client_id: client.client_id,
			error: sanitizeError(err).message
		});
		return htmlError(503, "Approval unavailable", "Could not reach the owner approval service. Try again later.");
	}
	if (typeof approvalId !== "string" || approvalId.length === 0) {
		log.error("oauth_owner_approval_request_invalid", { client_id: client.client_id });
		return htmlError(503, "Approval unavailable", "The owner approval service returned an invalid response.");
	}
	const handle = randomValue("evp_");
	const pendingRecord = {
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
		expires_at: now + PENDING_TTL_MS
	};
	await store.createPending(pendingRecord);
	log.info("oauth_authorization_pending", {
		client_id: client.client_id,
		approval_id: approvalId,
		is_new_client: isNew,
		scopes: effective,
		redirect_host: redirectHost
	});
	return waitingPage(cfg, handle, client.client_name, redirectHost, effective);
}
async function pollPending(cfg, handle) {
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
	let status;
	try {
		status = await c.approver.checkClientApproval(rec.approval_id);
	} catch (err) {
		log.warn("oauth_owner_approval_check_failed", {
			client_id: rec.client_id,
			error: sanitizeError(err).message
		});
		return waitingPage(cfg, handle, client.client_name, redirectHostOf(rec.redirect_uri), rec.scopes);
	}
	switch (status) {
		case "pending": return waitingPage(cfg, handle, client.client_name, redirectHostOf(rec.redirect_uri), rec.scopes);
		case "approved": return completeApproved(cfg, store, idHash, client, now);
		case "expired":
			await store.setPendingStatus(idHash, "expired");
			return expiredPage();
		default:
			await store.setPendingStatus(idHash, "denied");
			if (rec.is_new_client && client.status === "registered") await store.updateClient(client.client_id, { status: "denied" });
			log.warn("oauth_authorization_denied", {
				client_id: rec.client_id,
				approval_id: rec.approval_id
			});
			return deniedPage();
	}
}
async function completeApproved(cfg, store, idHash, client, now) {
	const claimed = await store.claimPending(idHash);
	if (!claimed) return htmlError(400, "Already completed", "This connection request was already completed.");
	let current = client;
	if (client.status === "registered") {
		current = await store.updateClient(client.client_id, {
			status: "approved",
			granted_scopes: canonicalScopes(claimed.scopes),
			approved_at: now
		});
		log.info("oauth_client_approved", {
			client_id: client.client_id,
			scopes: claimed.scopes
		});
	}
	if (!current || current.status !== "approved") return deniedPage();
	const scopes = intersectScopes(claimed.scopes, current.granted_scopes);
	if (scopes.length === 0) return redirectError(cfg, claimed.redirect_uri, "invalid_scope", "no granted scopes", claimed.state);
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
		used_at: null
	});
	log.info("oauth_code_issued", {
		client_id: claimed.client_id,
		scopes
	});
	const location = new URL(claimed.redirect_uri);
	location.searchParams.set("code", code);
	if (claimed.state !== null) location.searchParams.set("state", claimed.state);
	location.searchParams.set("iss", cfg.issuer);
	return redirectTo(location.toString());
}
/** Public-client identification: client_id from the form or a secret-less Basic header. */
function tokenClientId(req, params) {
	if (params.get("client_secret")) return { error: oauthError("invalid_client", "this server registers public clients only; client_secret is not accepted", 401) };
	let basicId = null;
	const auth = req.headers.get("authorization");
	if (auth) {
		const m = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(auth);
		if (!m) return { error: oauthError("invalid_client", "unsupported client authentication", 401) };
		const decoded = Buffer.from(m[1], "base64").toString("utf8");
		const idx = decoded.indexOf(":");
		if (idx < 0) return { error: oauthError("invalid_client", "malformed client authentication", 401) };
		let secret;
		try {
			basicId = decodeURIComponent(decoded.slice(0, idx).replace(/\+/g, " "));
			secret = decodeURIComponent(decoded.slice(idx + 1).replace(/\+/g, " "));
		} catch {
			return { error: oauthError("invalid_client", "malformed client authentication", 401) };
		}
		if (secret) return { error: oauthError("invalid_client", "this server registers public clients only; client_secret is not accepted", 401) };
	}
	const formId = params.get("client_id");
	if (basicId !== null && formId !== null && basicId !== formId) return { error: oauthError("invalid_request", "conflicting client_id values") };
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
function limiterKey(clientId) {
	return rateLimitKey("oauth.token", CLIENT_ID_RE.test(clientId) ? clientId : "malformed");
}
/** 503 for a token request that cannot be rate-checked: failed-attempt limits fail closed. */
function rateLimitUnavailable() {
	return oauthError("temporarily_unavailable", "rate_limit_unavailable: failed-attempt limits cannot be checked; retry later", 503, { "retry-after": "5" });
}
/**
* Count one failed attempt. The request is already being refused, so a store
* failure here is logged (withRateLimitStore) and does not change the answer;
* the next request fails closed at the check in handleToken.
*/
async function noteFailure(key) {
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
async function clearFailures(key) {
	try {
		await ctx().limiter.reset(key);
	} catch (err) {
		if (!(err instanceof RateLimitUnavailableError)) throw err;
		log.error("oauth_rate_limit_unavailable", { op: "reset" });
	}
}
async function handleToken(req) {
	let cfg;
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
		let retryMs;
		try {
			retryMs = await c.limiter.retryAfterMs(key);
		} catch (err) {
			if (!(err instanceof RateLimitUnavailableError)) throw err;
			log.error("oauth_rate_limit_unavailable", {
				op: "check",
				client_id: who.client_id.slice(0, 64)
			});
			return rateLimitUnavailable();
		}
		if (retryMs > 0) {
			log.warn("oauth_token_rate_limited", { client_id: who.client_id.slice(0, 64) });
			return oauthError("temporarily_unavailable", "too many failed attempts; retry later", 429, { "retry-after": String(Math.ceil(retryMs / 1e3)) });
		}
		const resource = params.get("resource");
		if (resource !== null && !resourceMatches(resource, cfg)) return oauthError("invalid_target", "resource must be this server's MCP endpoint");
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
async function invalidGrant(key, description) {
	await noteFailure(key);
	return oauthError("invalid_grant", description);
}
async function authorizationCodeGrant(cfg, store, params, clientId, key, now) {
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
		const revoked = await store.revokeFamily(consumed.code.family_id, now);
		log.warn("oauth_code_reuse_detected", {
			client_id: consumed.code.client_id,
			family_id: consumed.code.family_id,
			tokens_revoked: revoked
		});
		return invalidGrant(key, "authorization code was already used");
	}
	const rec = consumed.code;
	if (rec.client_id !== client.client_id) return invalidGrant(key, "authorization code was not issued to this client");
	if (rec.expires_at <= now) return invalidGrant(key, "authorization code expired");
	const redirectUri = params.get("redirect_uri");
	if (redirectUri !== null && redirectUri !== rec.redirect_uri) return invalidGrant(key, "redirect_uri does not match");
	if (rec.resource !== cfg.resource) return invalidGrant(key, "authorization code was issued for a different resource");
	if (!CODE_VERIFIER_RE.test(verifier) || !pkceMatches(verifier, rec.code_challenge)) return invalidGrant(key, "PKCE verification failed");
	if (client.status !== "approved") return invalidGrant(key, "client is not approved");
	const scopes = intersectScopes(rec.scopes, client.granted_scopes);
	if (scopes.length === 0) return oauthError("invalid_scope", "no granted scopes remain for this client");
	await clearFailures(key);
	return issueTokens(store, now, {
		client_id: client.client_id,
		family_id: rec.family_id,
		resource: rec.resource,
		accessScopes: scopes,
		refreshScopes: scopes
	});
}
async function refreshTokenGrant(store, params, clientId, key, now) {
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
		const revoked = await store.revokeFamily(rec.family_id, now);
		log.warn("oauth_refresh_reuse_detected", {
			client_id: rec.client_id,
			family_id: rec.family_id,
			tokens_revoked: revoked
		});
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
	if (!await store.markRefreshUsed(hash, now)) {
		const revoked = await store.revokeFamily(rec.family_id, now);
		log.warn("oauth_refresh_reuse_detected", {
			client_id: rec.client_id,
			family_id: rec.family_id,
			tokens_revoked: revoked
		});
		return invalidGrant(key, "refresh token was already used");
	}
	await clearFailures(key);
	return issueTokens(store, now, {
		client_id: client.client_id,
		family_id: rec.family_id,
		resource: rec.resource,
		accessScopes,
		refreshScopes: rec.scopes
	});
}
async function issueTokens(store, now, t) {
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
		revoked_at: null
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
		revoked_at: null
	});
	log.info("oauth_tokens_issued", {
		client_id: t.client_id,
		family_id: t.family_id,
		scopes: t.accessScopes
	});
	return json({
		access_token: access,
		token_type: "Bearer",
		expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1e3),
		refresh_token: refresh,
		scope: t.accessScopes.join(" ")
	});
}
async function handleRevoke(req) {
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
		let claimedClient = params.get("client_id");
		if (claimedClient === null) {
			const who = tokenClientId(req, params);
			if ("client_id" in who) claimedClient = who.client_id;
		}
		const ok = new Response(null, {
			status: 200,
			headers: {
				...SENSITIVE_HEADERS,
				...CORS_HEADERS
			}
		});
		if (!ACCESS_TOKEN_RE.test(token) && !REFRESH_TOKEN_RE.test(token)) return ok;
		const store = oauthStore();
		const now = oauthNow();
		const hash = sha256Hex(token);
		const rec = await store.getToken(hash);
		if (!rec || claimedClient !== null && claimedClient !== rec.client_id) return ok;
		if (rec.kind === "refresh") {
			const n = await store.revokeFamily(rec.family_id, now);
			log.info("oauth_token_revoked", {
				client_id: rec.client_id,
				kind: "refresh",
				family_id: rec.family_id,
				tokens_revoked: n
			});
		} else {
			await store.revokeToken(hash, now);
			log.info("oauth_token_revoked", {
				client_id: rec.client_id,
				kind: "access",
				family_id: rec.family_id
			});
		}
		return ok;
	} catch (err) {
		return internalError("revoke", err);
	}
}
/**
* Validate an "eva_…" access token against the hashed store: known, kind
* access, not revoked, not expired, audience == this MCP resource, client
* still approved. Effective scopes = token scopes ∩ client's current grant, so
* an owner narrowing a client's scopes takes effect immediately.
*/
async function verifyAccessToken(token) {
	let cfg;
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
		scopes: intersectScopes(rec.scopes, client.granted_scopes)
	};
}
/** RFC 9728 §5.1 challenge for 401 responses from the MCP endpoint. */
function buildWwwAuthenticate(opts = {}) {
	let cfg;
	try {
		cfg = resolveOAuthConfig(ctx().env);
	} catch {
		return "Bearer realm=\"echo-vault\"";
	}
	const parts = [`Bearer resource_metadata="${cfg.protectedResourceMetadataUrl}"`];
	if (opts.error) parts.push(`error="${opts.error}"`);
	const scope = opts.scope ? canonicalScopes(opts.scope) : [];
	if (scope.length) parts.push(`scope="${scope.join(" ")}"`);
	return parts.join(", ");
}
//#endregion
export { canonicalScopes as a, oauthStore as c, buildWwwAuthenticate as i, oauth_server_BJCUNFGm_exports as l, PROTECTED_RESOURCE_METADATA_PATH as n, configureOAuth as o, SUPPORTED_SCOPES as r, oauthNow as s, ACCESS_TOKEN_RE as t, verifyAccessToken as u };
