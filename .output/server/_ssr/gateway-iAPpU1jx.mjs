import { a as installProcessRedaction, c as redactString, f as sanitizeError, i as containsSecretPrefix, l as redactValue, n as INVARIANT, o as log, r as __exportAll, t as FORBIDDEN_TOOLS, u as registerSecretForRedaction } from "./log-BHJOU13W.mjs";
import { n as GateVaultBackend, t as GateUnavailableError } from "./backend-CFQmvqUZ.mjs";
import { d as getApproval, f as lookupCapability, h as sanitizeDisplayText, l as enforceRateLimits, m as requiredScope, n as approverTelegramId, o as consumeApproval, r as canonicalJson, s as createApproval, t as ApprovalError, u as evaluatePolicy } from "./approvals-vHr7W1Jg.mjs";
import { a as canonicalScopes, c as oauthStore, i as buildWwwAuthenticate, r as SUPPORTED_SCOPES, s as oauthNow, t as ACCESS_TOKEN_RE, u as verifyAccessToken } from "./oauth-server-BJCUNFGm.mjs";
import { a as ledgerHead, c as parseVaultRef, d as verifyLedger, i as isProviderId, l as redactLedgerText, n as formatVaultRef, r as getLedger, s as listLedger, t as appendLedger, u as scanLedger } from "./ledger-DtKvLmuw.mjs";
import { A as serializeJar, D as requestCard, E as refreshCookieJar, N as useEntry, O as resolveEntry, T as parseStoredJar, _ as listEntries, b as mergeSetCookie, c as describeJar, f as flagForReentry, g as jarRedactionForms, j as setRotationPolicy, k as secretFingerprint, m as getEntryMetadata, n as ENTRY_KINDS, o as cookieHeaderFor, p as getCardStatus, r as EntryError, s as deleteEntry, t as CardError, v as listRotationDue, w as openEntryVault } from "./cards-BG7l2-sJ.mjs";
import { S as revokeInjector, _ as mintTicket, a as assertSafeDestination, c as canonicalIp, d as injectResource, f as isAllowedMethod, g as listInjectors, h as kindForMode, i as PROVIDER_POLICIES, l as checkTargetOrigin, m as isPrivateOrLinkLocalIp, n as INJECT_MODES, p as isBlockedHost, r as InjectorError, s as buildProviderUrl, t as INJECT_CAPABILITY, u as enrollInjector, v as normalizeResourcePath, x as resolveInjector } from "./injector-BgOH-ggh.mjs";
import { n as callBotApi, t as TelegramApiError } from "./telegram-B-fJEnsh.mjs";
import { t as SignJWT } from "../_libs/jose.mjs";
import nodeHTTPS from "node:https";
import { createHash, createHmac, createPrivateKey, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { inspect } from "node:util";
//#region node_modules/.nitro/vite/services/ssr/assets/gateway-iAPpU1jx.js
var MAX_RECORDS = 500;
var records = [];
function recordAudit(entry) {
	const rec = redactValue({
		id: randomUUID(),
		timestamp: (/* @__PURE__ */ new Date()).toISOString(),
		...entry,
		error: entry.error ? redactString(entry.error) : void 0
	});
	records.unshift(rec);
	if (records.length > MAX_RECORDS) records.length = MAX_RECORDS;
	return rec;
}
function authorizationHeader(req) {
	return `${req.headerValuePrefix ?? "Bearer "}${req.secret}`;
}
async function authorizedProviderFetch(req) {
	const policy = PROVIDER_POLICIES[req.provider];
	assertSafeDestination(req.url, req.provider);
	if (req.body != null) {
		const serialized = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
		if (Buffer.byteLength(serialized) > policy.maxRequestBytes) throw Object.assign(/* @__PURE__ */ new Error("request_too_large"), { code: "request_too_large" });
	}
	const headers = new Headers();
	headers.set(req.headerName ?? "Authorization", authorizationHeader(req));
	headers.set("User-Agent", "Echo-Credential-Broker/1.0");
	if (req.accept) headers.set("Accept", req.accept);
	if (req.body != null && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
	if (req.extraHeaders) for (const [k, v] of Object.entries(req.extraHeaders)) {
		if (k.toLowerCase() === "authorization") continue;
		headers.set(k, v);
	}
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), policy.timeoutMs);
	try {
		const init = {
			method: req.method,
			headers,
			redirect: "error",
			signal: controller.signal
		};
		if (req.body != null && req.method !== "GET") init.body = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
		const res = await fetch(req.url, init);
		const buf = Buffer.from(await res.arrayBuffer());
		if (buf.byteLength > policy.maxResponseBytes) throw Object.assign(/* @__PURE__ */ new Error("response_too_large"), { code: "response_too_large" });
		const text = buf.toString("utf8");
		let json = null;
		if ((res.headers.get("content-type") ?? "").includes("json") || text.startsWith("{") || text.startsWith("[")) try {
			json = redactValue(JSON.parse(text));
		} catch {
			json = null;
		}
		return {
			status: res.status,
			ok: res.ok,
			json,
			text: json == null ? redactString(text).slice(0, 4096) : null
		};
	} catch (error) {
		throw sanitizeError(error);
	} finally {
		clearTimeout(timer);
	}
}
function githubAuthHeaders() {
	return {
		Accept: "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28"
	};
}
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
*/
var BYPASS_REASON = "echo-credential-broker: agent-facing opaque vault:// handle resolves through the canonical Master Vault; the raw secret is used server-side for one allowlisted provider call and never returned across the MCP/HTTP boundary.";
var CredentialStore = class {
	records = /* @__PURE__ */ new Map();
	backend;
	/**
	* @param backend Defaults to the REAL canonical vault (GateVaultBackend).
	*   Tests MUST pass a FakeVaultBackend — never exercise the real gate from
	*   a test, or a throwaway test secret can overwrite a production credential.
	*/
	constructor(backend = new GateVaultBackend()) {
		this.backend = backend;
	}
	/** Write a NEW credential through to the canonical vault (the one writer). */
	async put(input) {
		const secret = input.secret.trim();
		if (!secret) throw Object.assign(/* @__PURE__ */ new Error("empty_secret"), { code: "empty_secret" });
		registerSecretForRedaction(secret);
		const ref = formatVaultRef(input.provider, input.account);
		const result = await this.backend.put(input.provider, input.account, secret, `echo-credential-broker: ${input.source}`, BYPASS_REASON);
		const meta = {
			ref,
			provider: input.provider,
			account: input.account,
			type: input.type,
			status: "imported",
			last_verified: null,
			fingerprint: result.key_fingerprint ?? null,
			source: input.source
		};
		this.records.set(ref, {
			meta,
			coordinate: {
				service: input.provider,
				username: input.account
			}
		});
		log.info("credential_put", {
			ref,
			provider: input.provider,
			account: input.account,
			source: input.source
		});
		return { ...meta };
	}
	/**
	* Discovery only — raw locate candidates (service/username/key_shape),
	* NEVER a secret. Lets a caller disambiguate across the vault's real
	* accounts for a provider instead of being stuck with one hardcoded
	* default, without ever fetching a value.
	*/
	async find(query) {
		return this.backend.search(query, BYPASS_REASON);
	}
	getMetadata(ref) {
		const rec = this.records.get(ref);
		return rec ? { ...rec.meta } : null;
	}
	listMetadata() {
		return [...this.records.values()].map((r) => ({ ...r.meta }));
	}
	updateMetadata(ref, patch) {
		const rec = this.records.get(ref);
		if (!rec) return null;
		rec.meta = {
			...rec.meta,
			...patch,
			ref: rec.meta.ref
		};
		this.records.set(ref, rec);
		return { ...rec.meta };
	}
	/**
	* Register metadata for a ref this broker has not seen yet, by locating it
	* (metadata only — no secret fetch) in the canonical vault. Used so
	* `has()`/`vault_list` work for credentials that already live in Vault A
	* without requiring an explicit prior `put()` in THIS process.
	*/
	async discover(ref) {
		const parsed = parseVaultRef(ref);
		if (!parsed) return null;
		try {
			const coordinate = await this.backend.locate(parsed.provider, parsed.account, BYPASS_REASON);
			if (!coordinate) {
				log.debug("discover_not_found", {
					ref,
					provider: parsed.provider,
					account: parsed.account
				});
				return null;
			}
			const rec = {
				meta: {
					ref,
					provider: parsed.provider,
					account: parsed.account,
					type: "api_key",
					status: "imported",
					last_verified: null,
					fingerprint: null,
					source: `vault:${coordinate.service}/${coordinate.username}`
				},
				coordinate
			};
			this.records.set(ref, rec);
			log.debug("discover_ok", {
				ref,
				resolved_service: coordinate.service,
				resolved_username: coordinate.username
			});
			return rec;
		} catch (err) {
			if (err instanceof GateUnavailableError) {
				log.warn("discover_gate_unavailable", {
					ref,
					message: err.message
				});
				return null;
			}
			return null;
		}
	}
	/**
	* Resolve the raw secret LIVE from the canonical vault. NEVER return this
	* across an MCP / HTTP / UI boundary — callers must keep it on the stack.
	*/
	async resolveSecret(ref) {
		let rec = this.records.get(ref);
		if (!rec) rec = await this.discover(ref) ?? void 0;
		if (!rec) return null;
		if (rec.meta.status === "revoked") return null;
		const tryGet = async (service, username) => {
			try {
				const got = await this.backend.get(service, username, BYPASS_REASON);
				registerSecretForRedaction(got.secret);
				rec.coordinate = {
					service,
					username
				};
				rec.meta = {
					...rec.meta,
					fingerprint: got.key_fingerprint ?? rec.meta.fingerprint
				};
				this.records.set(ref, rec);
				return got.secret;
			} catch {
				return null;
			}
		};
		if (rec.coordinate) {
			const secret = await tryGet(rec.coordinate.service, rec.coordinate.username);
			if (secret) return secret;
			rec.coordinate = void 0;
		}
		const parsed = parseVaultRef(ref);
		if (!parsed) return null;
		const coordinate = await this.backend.locate(parsed.provider, parsed.account, BYPASS_REASON);
		if (!coordinate) return null;
		return tryGet(coordinate.service, coordinate.username);
	}
	/** Broker-local quarantine — does NOT touch the canonical vault. */
	async revoke(ref) {
		let rec = this.records.get(ref);
		if (!rec) rec = await this.discover(ref) ?? void 0;
		if (!rec) return false;
		rec.meta.status = "revoked";
		this.records.set(ref, rec);
		log.warn("credential_revoked_local_quarantine", { ref });
		return true;
	}
	async has(ref) {
		let rec = this.records.get(ref);
		if (!rec) rec = await this.discover(ref) ?? void 0;
		return Boolean(rec && rec.meta.status !== "revoked");
	}
	count() {
		return [...this.records.values()].filter((r) => r.meta.status !== "revoked").length;
	}
	clear() {
		this.records.clear();
	}
};
var singleton = new CredentialStore();
function getStore() {
	return singleton;
}
/**
* Startup discovery — populates the broker's LOCAL METADATA cache (never
* secret material) for the default provider/account refs by locating them in
* the canonical Master Vault.
*
* This used to sweep raw secret VALUES out of env vars (`GITHUB_TOKEN`,
* `OPENAI_API_KEY`, ...) and `/tmp/grok/connectors/*.token` sandbox files
* into an in-memory store on every boot — a second, ephemeral, disconnected
* credential store. That store is gone (see store.ts); there is nothing left
* to import FROM locally. What used to be "import" is now "discover what
* Vault A already has for the refs this broker exposes" — a metadata-only
* locate() sweep, so `vault_status` / `vault_list` have something to show
* immediately at startup without requiring a secret fetch first.
*
* Exported names/shapes are UNCHANGED (`ensureImported`, `importSandboxCredentials`,
* `ImportReport { imported, skipped }`) so broker.ts / tools.ts need no changes.
*/
if (!process.env.NODE_TEST_CONTEXT) installProcessRedaction();
/** The default vault:// refs this broker's built-in provider tools use (see providers.ts). */
var DEFAULT_REFS = [
	{
		provider: "github",
		account: "echoomegaprime"
	},
	{
		provider: "cloudflare",
		account: "global_api_key"
	},
	{
		provider: "openai",
		account: "api_key"
	},
	{
		provider: "stripe",
		account: "secret_key"
	},
	{
		provider: "xai",
		account: "api_key"
	}
];
/**
* Locate metadata (not secrets) for the default refs against the canonical
* vault, registering whatever is found into the store's local cache.
*/
async function importSandboxCredentials(store = getStore()) {
	const imported = [];
	const skipped = [];
	for (const { provider, account } of DEFAULT_REFS) {
		const ref = formatVaultRef(provider, account);
		if (!parseVaultRef(ref)) {
			skipped.push(ref);
			continue;
		}
		(await store.has(ref) ? imported : skipped).push(ref);
	}
	return {
		imported: unique(imported),
		skipped: unique(skipped)
	};
}
function unique(items) {
	return [...new Set(items)];
}
var importOnce = null;
function ensureImported(store = getStore()) {
	if (!importOnce) importOnce = importSandboxCredentials(store);
	return importOnce;
}
if (!process.env.NODE_TEST_CONTEXT) installProcessRedaction();
function fail(error, credential_ref, detail) {
	return redactValue({
		ok: false,
		error,
		credential_ref,
		detail
	});
}
async function resolveOrFail(ctx, credential_ref, provider) {
	const parsed = parseVaultRef(credential_ref);
	if (!parsed) return fail("invalid_credential_ref", credential_ref);
	if (parsed.provider !== provider) return fail("provider_mismatch", credential_ref);
	const store = ctx.store ?? getStore();
	const secret = await store.resolveSecret(parsed.raw);
	const meta = store.getMetadata(parsed.raw);
	if (!secret || !meta || meta.status === "revoked") return fail("credential_unavailable", parsed.raw);
	return {
		secret,
		meta
	};
}
async function useCredential(ctx, input) {
	const started = Date.now();
	const caller = ctx.caller || "unknown";
	if (!ctx.store) await ensureImported();
	const resolved = await resolveOrFail(ctx, input.credential_ref, input.provider);
	if ("ok" in resolved && resolved.ok === false) {
		recordAudit({
			caller,
			credential_ref: input.credential_ref,
			provider: input.provider,
			operation: String(input.operation),
			resource: input.resource,
			http_status: null,
			duration_ms: Date.now() - started,
			result: "error",
			error: resolved.error
		});
		return resolved;
	}
	const { secret, meta } = resolved;
	if (!isAllowedMethod(input.provider, String(input.operation))) return fail("operation_not_allowed", meta.ref);
	const method = String(input.operation).toUpperCase();
	let url;
	try {
		url = buildProviderUrl(input.provider, input.resource);
		assertSafeDestination(url, input.provider);
	} catch (error) {
		const clean = sanitizeError(error);
		recordAudit({
			caller,
			credential_ref: meta.ref,
			provider: input.provider,
			operation: method,
			resource: input.resource,
			http_status: null,
			duration_ms: Date.now() - started,
			result: "denied",
			error: clean.message
		});
		return fail(clean.message, meta.ref);
	}
	try {
		const extra = input.provider === "github" ? githubAuthHeaders() : void 0;
		const result = await authorizedProviderFetch({
			provider: input.provider,
			url,
			method,
			secret,
			extraHeaders: extra,
			body: input.body,
			accept: input.provider === "github" ? "application/vnd.github+json" : "application/json"
		});
		recordAudit({
			caller,
			credential_ref: meta.ref,
			provider: input.provider,
			operation: method,
			resource: input.resource,
			http_status: result.status,
			duration_ms: Date.now() - started,
			result: result.ok ? "ok" : "error",
			error: result.ok ? void 0 : `http_${result.status}`
		});
		return redactValue({
			ok: true,
			data: {
				status: result.status,
				body: result.json ?? result.text
			}
		});
	} catch (error) {
		const clean = sanitizeError(error);
		recordAudit({
			caller,
			credential_ref: meta.ref,
			provider: input.provider,
			operation: method,
			resource: input.resource,
			http_status: null,
			duration_ms: Date.now() - started,
			result: "error",
			error: clean.message
		});
		return fail("provider_request_failed", meta.ref, clean.message);
	}
}
var GITHUB_REF = "vault://github/echoomegaprime";
/**
* Check a `{status, body}` answer from useCredential before a typed tool reads
* it. Returns what to hand back instead, or null when the body is usable:
*   - a failure, or a 4xx/5xx answer: returned unchanged (v2/gateway.ts turns
*     the status into a tool error; it must never be reshaped into empty data);
*   - a 2xx answer whose body is not a JSON object/array: provider_malformed_response.
*/
function unreadable(res, credential_ref) {
	if (!res.ok) return res;
	const data = res.data;
	const status = typeof data?.status === "number" ? data.status : 0;
	if (status >= 400) return res;
	if (data?.body === null || typeof data?.body !== "object") return {
		ok: false,
		error: "provider_malformed_response",
		credential_ref,
		detail: `http_${status}: the response body was not JSON`
	};
	return null;
}
async function githubSecret(ctx, ref) {
	const secret = await (ctx.store ?? getStore()).resolveSecret(ref);
	if (!secret) return {
		ok: false,
		error: "credential_unavailable",
		credential_ref: ref
	};
	return {
		ok: true,
		data: secret
	};
}
async function githubGetUser(ctx, credential_ref = GITHUB_REF) {
	const resolved = await githubSecret(ctx, credential_ref);
	if (!resolved.ok) return resolved;
	try {
		const result = await authorizedProviderFetch({
			provider: "github",
			url: buildProviderUrl("github", "/user"),
			method: "GET",
			secret: resolved.data,
			extraHeaders: githubAuthHeaders(),
			accept: "application/vnd.github+json"
		});
		if (!result.ok || !result.json || typeof result.json !== "object") return {
			ok: false,
			error: "credential_unavailable",
			credential_ref,
			detail: `http_${result.status}`
		};
		const body = result.json;
		return redactValue({
			ok: true,
			data: {
				login: body.login ?? null,
				id: body.id ?? null,
				authenticated: Boolean(body.login)
			}
		});
	} catch (error) {
		return {
			ok: false,
			error: "credential_unavailable",
			credential_ref,
			detail: sanitizeError(error).message
		};
	}
}
async function githubGetRepository(ctx, input) {
	const ref = input.credential_ref ?? GITHUB_REF;
	return useCredential(ctx, {
		credential_ref: ref,
		provider: "github",
		operation: "GET",
		resource: `/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repo)}`
	}).then((res) => {
		const bad = unreadable(res, ref);
		if (bad) return bad;
		if (!res.ok) return res;
		const body = res.data;
		const repo = body.body ?? body;
		return redactValue({
			ok: true,
			data: {
				full_name: repo.full_name,
				name: repo.name,
				private: repo.private,
				description: repo.description,
				default_branch: repo.default_branch,
				html_url: repo.html_url,
				owner: repo.owner?.login,
				visibility: repo.visibility ?? (repo.private ? "private" : "public")
			}
		});
	});
}
async function githubGetFile(ctx, input) {
	const ref = input.credential_ref ?? GITHUB_REF;
	const qs = input.ref ? `?ref=${encodeURIComponent(input.ref)}` : "";
	const path = input.path.replace(/^\/+/, "");
	return useCredential(ctx, {
		credential_ref: ref,
		provider: "github",
		operation: "GET",
		resource: `/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repo)}/contents/${path}${qs}`
	}).then((res) => {
		const bad = unreadable(res, ref);
		if (bad) return bad;
		if (!res.ok) return res;
		const body = res.data.body ?? {};
		return redactValue({
			ok: true,
			data: {
				name: body.name,
				path: body.path,
				sha: body.sha,
				size: body.size,
				type: body.type,
				encoding: body.encoding,
				content: body.content,
				html_url: body.html_url
			}
		});
	});
}
async function githubListRepositories(ctx, input = {}) {
	const ref = input.credential_ref ?? GITHUB_REF;
	return useCredential(ctx, {
		credential_ref: ref,
		provider: "github",
		operation: "GET",
		resource: `/user/repos?per_page=${Math.min(Math.max(input.per_page ?? 30, 1), 100)}&sort=updated`
	}).then((res) => {
		const bad = unreadable(res, ref);
		if (bad) return bad;
		if (!res.ok) return res;
		const body = res.data.body;
		return redactValue({
			ok: true,
			data: { repositories: (Array.isArray(body) ? body : []).map((repo) => {
				const r = repo;
				return {
					full_name: r.full_name,
					private: r.private,
					description: r.description,
					updated_at: r.updated_at
				};
			}) }
		});
	});
}
async function githubCreateBranch(ctx, input) {
	return useCredential(ctx, {
		credential_ref: input.credential_ref ?? GITHUB_REF,
		provider: "github",
		operation: "POST",
		resource: `/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repo)}/git/refs`,
		body: {
			ref: `refs/heads/${input.branch}`,
			sha: input.from_sha
		}
	});
}
async function cloudflareZoneGet(ctx, input) {
	const ref = input.credential_ref ?? "vault://cloudflare/global_api_key";
	return useCredential(ctx, {
		credential_ref: ref,
		provider: "cloudflare",
		operation: "GET",
		resource: `/client/v4/zones/${encodeURIComponent(input.zone_id)}`
	}).then((res) => unreadable(res, ref) ?? res);
}
async function openaiAccountStatus(ctx, input = {}) {
	const ref = input.credential_ref ?? "vault://openai/api_key";
	return useCredential(ctx, {
		credential_ref: ref,
		provider: "openai",
		operation: "GET",
		resource: "/v1/models"
	}).then((res) => unreadable(res, ref) ?? res);
}
async function stripeBalance(ctx, input = {}) {
	const ref = input.credential_ref ?? "vault://stripe/secret_key";
	return useCredential(ctx, {
		credential_ref: ref,
		provider: "stripe",
		operation: "GET",
		resource: "/v1/balance"
	}).then((res) => unreadable(res, ref) ?? res);
}
async function xaiAccountStatus(ctx, input = {}) {
	const ref = input.credential_ref ?? "vault://xai/api_key";
	return useCredential(ctx, {
		credential_ref: ref,
		provider: "xai",
		operation: "GET",
		resource: "/v1/models"
	}).then((res) => unreadable(res, ref) ?? res);
}
if (!process.env.NODE_TEST_CONTEXT) installProcessRedaction();
async function vaultStatus(ctx) {
	const store = ctx.store ?? getStore();
	if (!ctx.store) await ensureImported();
	const report = ctx.store ? {
		imported: store.listMetadata().map((m) => m.ref),
		skipped: []
	} : await ensureImported();
	return redactValue({
		ok: true,
		data: {
			invariant: INVARIANT,
			imported: report.imported,
			credential_count: store.count(),
			redaction: "armed",
			fail_closed: true,
			get_secret: false,
			providers: Object.keys(PROVIDER_POLICIES)
		}
	});
}
async function vaultList(ctx) {
	const store = ctx.store ?? getStore();
	if (!ctx.store) await ensureImported();
	return redactValue({
		ok: true,
		data: { credentials: store.listMetadata() }
	});
}
async function vaultFind(ctx, query) {
	const store = ctx.store ?? getStore();
	if (!query || query.trim().length < 2) return {
		ok: false,
		error: "query_too_short"
	};
	const result = await store.find(query.trim());
	return redactValue({
		ok: true,
		data: {
			status: result.status,
			candidates: result.candidates.map((c) => ({
				service: c.actual_service,
				username: c.username,
				key_shape: c.key_shape
			})),
			hint: result.hint ?? null,
			did_you_mean: result.did_you_mean ?? []
		}
	});
}
async function vaultMetadata(ctx, credential_ref) {
	const store = ctx.store ?? getStore();
	if (!ctx.store) await ensureImported();
	const parsed = parseVaultRef(credential_ref);
	if (!parsed) return {
		ok: false,
		error: "invalid_credential_ref",
		credential_ref
	};
	const meta = store.getMetadata(parsed.raw);
	if (!meta) return {
		ok: false,
		error: "credential_unavailable",
		credential_ref: parsed.raw
	};
	return redactValue({
		ok: true,
		data: meta
	});
}
async function credentialHealth(ctx, credential_ref) {
	const store = ctx.store ?? getStore();
	if (!ctx.store) await ensureImported();
	const parsed = parseVaultRef(credential_ref);
	if (!parsed) return {
		ok: false,
		error: "invalid_credential_ref",
		credential_ref
	};
	if (!await store.has(parsed.raw)) return {
		ok: false,
		error: "credential_unavailable",
		credential_ref: parsed.raw
	};
	if (parsed.provider === "github") {
		const identity = await githubGetUser(ctx, parsed.raw);
		if (!identity.ok) {
			store.updateMetadata(parsed.raw, { status: "unhealthy" });
			return identity;
		}
		const data = identity.data;
		const expected = parsed.account;
		const status = data.login && data.login.toLowerCase() === expected.toLowerCase() ? "healthy" : "identity_mismatch";
		store.updateMetadata(parsed.raw, {
			status,
			last_verified: (/* @__PURE__ */ new Date()).toISOString(),
			account: data.login ?? expected
		});
		return redactValue({
			ok: true,
			data: {
				provider: "github",
				ref: parsed.raw,
				authenticated: Boolean(data.authenticated),
				account: data.login ?? null,
				account_id: data.id ?? null,
				status
			}
		});
	}
	store.updateMetadata(parsed.raw, {
		status: "imported",
		last_verified: (/* @__PURE__ */ new Date()).toISOString()
	});
	const meta = store.getMetadata(parsed.raw);
	return redactValue({
		ok: true,
		data: {
			provider: parsed.provider,
			ref: parsed.raw,
			authenticated: Boolean(meta),
			account: parsed.account,
			account_id: null,
			status: meta?.status ?? "imported"
		}
	});
}
var ENTRY_ID_PATTERN = /^ve_[0-9a-f]{32}$/;
function validKey(client_id, entry_id) {
	return typeof client_id === "string" && client_id.length > 0 && client_id.length <= 200 && typeof entry_id === "string" && ENTRY_ID_PATTERN.test(entry_id);
}
function validScope(host, path_prefix) {
	return typeof host === "string" && host.length > 0 && host.length <= 253 && typeof path_prefix === "string" && path_prefix.length > 0 && path_prefix.length <= 1024;
}
function toIso$1(v) {
	return v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString();
}
function toNum(v) {
	return v == null ? null : Number(v);
}
function rowToGrant(r) {
	return {
		client_id: String(r.client_id),
		entry_id: String(r.entry_id),
		host: String(r.host),
		path_prefix: String(r.path_prefix),
		approval_id: String(r.approval_id),
		granted_at: toIso$1(r.granted_at),
		expires_at: toIso$1(r.expires_at),
		max_uses: toNum(r.max_uses),
		uses_remaining: toNum(r.uses_remaining)
	};
}
var GRANT_COLUMNS = "client_id, entry_id, host, path_prefix, approval_id, granted_at, expires_at, max_uses, uses_remaining";
var PATH_MATCH = "($4::text = path_prefix or left($4::text, length(path_prefix) + 1) = path_prefix || '/')";
/** Postgres/PGLite store over `vault_entry_grants` (migrations/0006_vault_entry_grants.sql). */
var SqlEntryGrantStore = class {
	getSql;
	constructor(getSql) {
		this.getSql = getSql ?? (async () => {
			return (await import("./db-YAhc1k3o.mjs")).getSql();
		});
	}
	async find(client_id, entry_id, host, path, now) {
		if (!validKey(client_id, entry_id) || !validScope(host, path)) return null;
		const rows = await (await this.getSql()).query(`select ${GRANT_COLUMNS} from vault_entry_grants
        where client_id = $1 and entry_id = $2 and host = $3 and ${PATH_MATCH}
          and expires_at > $5::timestamptz and (uses_remaining is null or uses_remaining > 0)
        order by length(path_prefix) desc
        limit 1`, [
			client_id,
			entry_id,
			host,
			path,
			new Date(now).toISOString()
		]);
		return rows[0] ? rowToGrant(rows[0]) : null;
	}
	async consume(client_id, entry_id, host, path, now) {
		if (!validKey(client_id, entry_id) || !validScope(host, path)) return false;
		return (await (await this.getSql()).query(`update vault_entry_grants set uses_remaining = uses_remaining - 1
        where client_id = $1 and entry_id = $2 and host = $3 and ${PATH_MATCH}
          and expires_at > $5::timestamptz and (uses_remaining is null or uses_remaining > 0)
        returning client_id`, [
			client_id,
			entry_id,
			host,
			path,
			new Date(now).toISOString()
		])).length >= 1;
	}
	async add(grant) {
		if (!validKey(grant.client_id, grant.entry_id) || !validScope(grant.host, grant.path_prefix)) throw new Error("invalid_entry_grant");
		await (await this.getSql()).query(`insert into vault_entry_grants
         (client_id, entry_id, host, path_prefix, approval_id, granted_at, expires_at, max_uses, uses_remaining)
       values ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8::integer, $9::integer)
       on conflict (client_id, entry_id, host, path_prefix) do nothing`, [
			grant.client_id,
			grant.entry_id,
			grant.host,
			grant.path_prefix,
			grant.approval_id,
			grant.granted_at,
			grant.expires_at,
			grant.max_uses,
			grant.uses_remaining
		]);
	}
	async remove(client_id, entry_id, host, path_prefix) {
		if (!validKey(client_id, entry_id)) return false;
		const sql = await this.getSql();
		const narrow = host !== void 0 && path_prefix !== void 0;
		return (await sql.query(`delete from vault_entry_grants
        where client_id = $1 and entry_id = $2
          and ($3::boolean = false or (host = $4::text and path_prefix = $5::text))
        returning path_prefix`, [
			client_id,
			entry_id,
			narrow,
			host ?? null,
			path_prefix ?? null
		])).length >= 1;
	}
	async list(filter = {}) {
		return (await (await this.getSql()).query(`select ${GRANT_COLUMNS} from vault_entry_grants
        where ($1::text is null or client_id = $1::text) and ($2::text is null or entry_id = $2::text)
        order by granted_at desc`, [filter.client_id ?? null, filter.entry_id ?? null])).map(rowToGrant);
	}
};
var defaultStore$2 = null;
function getDefaultEntryGrantStore() {
	defaultStore$2 ??= new SqlEntryGrantStore();
	return defaultStore$2;
}
/**
* Owner action: withdraw a client's standing consent for one entry. With
* `host`/`path_prefix` it removes one narrow grant; without, every grant for
* the pair. The client's next covered use — read-only included — asks on
* Telegram again. Returns whether anything was removed.
*/
async function revokeEntryGrant(client_id, entry_id, store = getDefaultEntryGrantStore(), host, path_prefix) {
	const removed = await store.remove(client_id, entry_id, host, path_prefix);
	log.warn("vault_entry_grant_revoked", {
		client_id,
		entry_id,
		host,
		path_prefix,
		existed: removed
	});
	return removed;
}
async function listEntryGrants(filter = {}, store = getDefaultEntryGrantStore()) {
	return store.list(filter);
}
var DIGEST_DENIAL_BURST_ENV = "ECHO_VAULT_DIGEST_DENIAL_BURST";
/** Telegram sendMessage limit (see telegram.ts). */
var DIGEST_MAX_TEXT = 4096;
var DIGEST_TRUNCATED_TAIL = "…truncated";
var DAY_MS = 864e5;
var MAX_WINDOW_MS = 366 * DAY_MS;
var SCAN_BATCH = 1e3;
/** A `committing` row this fresh may simply still be running; it is not reported as orphaned yet. */
var ORPHAN_GRACE_MS = 12e4;
var CLAIM_STALE_MS = 6e5;
var ENTRY_REF_RE = /^vault:\/\/entry\/ve_[0-9a-f]{32}$/;
var MAX_CLIENTS = 100;
var MAX_ITEMS = 25;
var MAX_REASONS = 5;
var MAX_EXTRA_SECTIONS = 10;
var MAX_EXTRA_LINES = 20;
var TASK_LABEL_MAX = 48;
var RESULTS = [
	"ok",
	"error",
	"denied",
	"pending_approval",
	"committing"
];
var DigestError = class extends Error {
	code;
	constructor(code, message) {
		super(message);
		this.name = "DigestError";
		this.code = code;
	}
};
var DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;
/** A time needs an explicit zone: a bare local time would silently shift the window. */
var DATE_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/;
function parseInstant(value, field) {
	if (value === void 0 || value === null || value === "") return void 0;
	if (typeof value !== "string" || !(DATE_ONLY_RE.test(value) || DATE_TIME_RE.test(value))) throw new DigestError("invalid_window", `${field}: use YYYY-MM-DD (UTC) or an ISO time with Z or an offset`);
	const ms = Date.parse(value);
	if (!Number.isFinite(ms)) throw new DigestError("invalid_window", `${field}: not a real date`);
	return ms;
}
/**
* Neither bound → the previous full UTC day. One bound → the 24 h starting at
* `from` / ending at `to`. Both → exactly that, at most 366 days.
*/
function resolveDigestWindow(input = {}, nowMs = Date.now()) {
	const givenFrom = parseInstant(input.from, "from");
	const givenTo = parseInstant(input.to, "to");
	const previousMidnight = Math.floor(nowMs / DAY_MS) * DAY_MS;
	const to = givenTo ?? (givenFrom !== void 0 ? givenFrom + DAY_MS : previousMidnight);
	const from = givenFrom ?? to - DAY_MS;
	if (!(from < to)) throw new DigestError("invalid_window", "from must be before to");
	if (to - from > MAX_WINDOW_MS) throw new DigestError("invalid_window", "window is longer than 366 days");
	return {
		from: new Date(from).toISOString(),
		to: new Date(to).toISOString()
	};
}
function canonicalWindow(window) {
	return resolveDigestWindow({
		from: window?.from,
		to: window?.to
	});
}
function denialBurstThreshold(env = process.env) {
	const raw = env[DIGEST_DENIAL_BURST_ENV]?.trim();
	if (!raw || !/^[0-9]{1,9}$/.test(raw)) return 10;
	const n = Number(raw);
	return n >= 1 ? n : 10;
}
/** Scrub like the ledger does, strip control/bidi characters, collapse whitespace, clip. */
function safe(value, max, entropy) {
	return sanitizeDisplayText(redactLedgerText(String(value ?? ""), { entropy }), max);
}
function rowRef(row) {
	return {
		seq: row.seq,
		timestamp: safe(row.timestamp, 30, false),
		client_id: safe(row.client_id, 80, false),
		capability: safe(row.capability, 80, false),
		resource: safe(row.resource, 120, true)
	};
}
function inWindow(iso, fromMs, toMs) {
	const ms = typeof iso === "string" ? Date.parse(iso) : NaN;
	return Number.isFinite(ms) && ms >= fromMs && ms < toMs;
}
async function runExtraSections(window, deps) {
	const out = [];
	for (const provider of (deps.extraSections ?? []).slice(0, MAX_EXTRA_SECTIONS)) try {
		const section = await provider({ ...window }, deps);
		const lines = Array.isArray(section?.lines) ? section.lines : [];
		out.push({
			title: safe(section?.title, 60, true) || "Section",
			lines: lines.slice(0, MAX_EXTRA_LINES).map((line) => safe(line, 200, true)).filter((line) => line.length > 0)
		});
	} catch {
		log.warn("vault_digest_section_failed", { index: out.length });
		out.push({
			title: "Section unavailable",
			lines: ["This section could not be built."]
		});
	}
	return out;
}
/** Build the structured digest for `[from, to)`. Throws only when the ledger cannot be read. */
async function buildDigest(window, deps = {}) {
	const win = canonicalWindow(window);
	const fromMs = Date.parse(win.from);
	const toMs = Date.parse(win.to);
	const env = deps.env ?? process.env;
	const nowMs = (deps.now ?? Date.now)();
	const scan = deps.ledger ? (after, limit) => deps.ledger.scan(after, limit) : scanLedger;
	const verify = deps.ledger ? () => deps.ledger.verify() : verifyLedger;
	const seenBefore = /* @__PURE__ */ new Set();
	const clients = /* @__PURE__ */ new Map();
	const byResult = Object.fromEntries(RESULTS.map((r) => [r, 0]));
	const requested = /* @__PURE__ */ new Set();
	const granted = /* @__PURE__ */ new Set();
	const approvalDenied = /* @__PURE__ */ new Set();
	const approvalExpired = /* @__PURE__ */ new Set();
	const tier2 = [];
	const deniedReasons = /* @__PURE__ */ new Map();
	const committing = [];
	const unavailableRows = [];
	/** Highest seq of an outcome (ok/error) row, per approval and per (client, capability, resource). */
	const outcomeSeq = /* @__PURE__ */ new Map();
	const outcomeKey = (row) => row.approval_id ? `a:${row.approval_id}` : `r:${row.client_id}\u0000${row.capability}\u0000${row.resource}`;
	let total = 0;
	let after = 0;
	for (;;) {
		const batch = await scan(after, SCAN_BATCH);
		if (batch.length === 0) break;
		for (const row of batch) {
			const ts = Date.parse(row.timestamp);
			if (!Number.isFinite(ts)) continue;
			if (ts < fromMs) {
				seenBefore.add(row.client_id);
				continue;
			}
			if (row.result === "ok" || row.result === "error") {
				const key = outcomeKey(row);
				if ((outcomeSeq.get(key) ?? 0) < row.seq) outcomeSeq.set(key, row.seq);
			}
			if (ts >= toMs) continue;
			total += 1;
			if (row.result in byResult) byResult[row.result] += 1;
			let acc = clients.get(row.client_id);
			if (!acc) {
				acc = {
					actions: 0,
					denied: 0,
					errors: 0,
					entries: /* @__PURE__ */ new Set(),
					firstSeen: row.timestamp
				};
				clients.set(row.client_id, acc);
			}
			acc.actions += 1;
			if (row.result === "denied") acc.denied += 1;
			if (row.result === "error") acc.errors += 1;
			if (row.credential_ref && ENTRY_REF_RE.test(row.credential_ref)) acc.entries.add(row.credential_ref);
			if (row.approval_id) {
				if (row.result === "pending_approval" && !row.error) requested.add(row.approval_id);
				if (row.decision === "escalate" && row.result !== "pending_approval" && row.result !== "denied") granted.add(row.approval_id);
				if (row.error === "approval_denied") approvalDenied.add(row.approval_id);
				if (row.error === "approval_expired") approvalExpired.add(row.approval_id);
			}
			if (row.tier === 2 && row.result === "ok") tier2.push(row);
			if (row.result === "denied") {
				const reason = safe(row.error || "(no reason recorded)", 80, true) || "(no reason recorded)";
				deniedReasons.set(reason, (deniedReasons.get(reason) ?? 0) + 1);
			}
			if (row.result === "committing") committing.push(row);
			if (typeof row.error === "string" && row.error.includes("ledger_unavailable")) unavailableRows.push(row);
		}
		const last = batch[batch.length - 1].seq;
		if (!(last > after)) break;
		after = last;
	}
	const threshold = denialBurstThreshold(env);
	const sortedClients = [...clients.entries()].sort((a, b) => b[1].actions - a[1].actions || (a[0] < b[0] ? -1 : 1));
	const orphans = committing.filter((row) => (outcomeSeq.get(outcomeKey(row)) ?? 0) <= row.seq && Date.parse(row.timestamp) <= nowMs - ORPHAN_GRACE_MS);
	let chain;
	try {
		chain = await verify();
	} catch {
		log.error("vault_digest_verify_failed", {});
		chain = {
			ok: false,
			reason: "verify_unavailable"
		};
	}
	const unavailable = [];
	let needsReentry = [];
	try {
		needsReentry = (await listEntries({}, deps.cards)).filter((e) => e.status === "needs_reentry" && inWindow(e.updated_at, fromMs, toMs)).map((e) => ({
			label: safe(e.label, 120, true),
			flagged_at: safe(e.updated_at, 30, false)
		}));
	} catch {
		log.warn("vault_digest_source_unavailable", { source: "entries" });
		unavailable.push("entries");
	}
	const grants = {
		created: 0,
		active: 0
	};
	try {
		for (const g of await (deps.grants ?? getDefaultEntryGrantStore()).list()) {
			if (inWindow(g.granted_at, fromMs, toMs)) grants.created += 1;
			const exp = Date.parse(g.expires_at);
			if (Number.isFinite(exp) && exp > nowMs && (g.uses_remaining === null || g.uses_remaining > 0)) grants.active += 1;
		}
	} catch {
		log.warn("vault_digest_source_unavailable", { source: "grants" });
		unavailable.push("grants");
	}
	const newClients = sortedClients.filter(([id]) => !seenBefore.has(id)).map(([id, acc]) => ({
		client_id: safe(id, 80, false),
		first_seen: safe(acc.firstSeen, 30, false)
	}));
	const bursts = sortedClients.filter(([, acc]) => acc.denied >= threshold).map(([id, acc]) => ({
		client_id: safe(id, 80, false),
		denied: acc.denied,
		threshold
	}));
	const digest = {
		window: win,
		generated_at: new Date(nowMs).toISOString(),
		total_actions: total,
		by_result: byResult,
		clients: sortedClients.slice(0, MAX_CLIENTS).map(([id, acc]) => ({
			client_id: safe(id, 80, false),
			actions: acc.actions,
			denied: acc.denied,
			errors: acc.errors,
			entries_used: acc.entries.size
		})),
		clients_omitted: Math.max(0, sortedClients.length - MAX_CLIENTS),
		approvals: {
			requested: requested.size,
			granted: granted.size,
			denied: approvalDenied.size,
			expired: approvalExpired.size
		},
		tier2_mutations: {
			count: tier2.length,
			items: tier2.slice(0, MAX_ITEMS).map((row) => {
				const label = row.task ? safe(row.task, TASK_LABEL_MAX, true) : "";
				return label ? {
					...rowRef(row),
					label
				} : rowRef(row);
			})
		},
		top_denied_reasons: [...deniedReasons.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, MAX_REASONS).map(([reason, count]) => ({
			reason,
			count
		})),
		needs_reentry: needsReentry.slice(0, MAX_ITEMS),
		grants,
		anomalies: {
			new_clients: newClients.slice(0, MAX_ITEMS),
			denial_bursts: bursts.slice(0, MAX_ITEMS),
			orphan_committing: orphans.slice(0, MAX_ITEMS).map((row) => ({
				...rowRef(row),
				approval_ref: safe((row.approval_id ?? "").slice(0, 8), 8, false) || "none"
			})),
			ledger_unavailable: {
				count: unavailableRows.length,
				items: unavailableRows.slice(0, MAX_ITEMS).map(rowRef)
			}
		},
		anomaly_count: (chain.ok ? 0 : 1) + newClients.length + bursts.length + orphans.length + unavailableRows.length,
		chain,
		extra: await runExtraSections(win, deps),
		unavailable
	};
	return redactValue(digest);
}
function windowLabel(window) {
	const from = safe(window.from, 30, false);
	const to = safe(window.to, 30, false);
	const fromMs = Date.parse(from);
	if (from.endsWith("T00:00:00.000Z") && Date.parse(to) - fromMs === DAY_MS) return `${from.slice(0, 10)} (UTC day)`;
	return `${from} to ${to} (UTC)`;
}
function when(iso) {
	return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(iso) ? `${iso.slice(5, 10)} ${iso.slice(11, 16)}` : "?";
}
function chainLine(chain) {
	if (chain.ok) return `Ledger chain: OK (${chain.count} rows verified)`;
	if ("broken_at_seq" in chain) return `Ledger chain: BROKEN at seq ${chain.broken_at_seq} (${safe(chain.reason, 80, true)})`;
	return "Ledger chain: NOT VERIFIED (verification unavailable)";
}
function capList(lines, max, noun) {
	return lines.length > max ? [...lines.slice(0, max), `… and ${lines.length - max} more ${noun}`] : lines;
}
function plural(n, one, many = `${one}s`) {
	return `${n} ${n === 1 ? one : many}`;
}
function capText(text) {
	if (text.length <= 4096) return text;
	const tail = `\n${DIGEST_TRUNCATED_TAIL}`;
	const budget = DIGEST_MAX_TEXT - tail.length;
	let kept = "";
	for (const line of text.split("\n")) {
		const next = kept ? `${kept}\n${line}` : line;
		if (next.length > budget) break;
		kept = next;
	}
	return `${(kept || text.slice(0, budget)).trimEnd()}${tail}`;
}
/**
* Plain text for Telegram (no parse_mode): most important first — chain
* verdict and anomalies, then totals, clients and the detail sections. Control
* characters stripped, redacted, hard-capped at 4096 characters.
*/
function formatDigest(digest) {
	const d = digest;
	const a = d.anomalies;
	const blocks = [[
		"ECHO Vault daily digest",
		`Window: ${windowLabel(d.window)}`,
		chainLine(d.chain)
	]];
	const anomalies = [];
	if (!d.chain.ok) anomalies.push("broken_at_seq" in d.chain ? `! LEDGER CHAIN BROKEN at seq ${d.chain.broken_at_seq}: the audit trail was altered or damaged` : "! Ledger chain could not be verified");
	anomalies.push(...capList(a.orphan_committing.map((o) => `! Authorized mutation never reported: ${o.capability} on ${o.resource} by ${o.client_id} (seq ${o.seq}, approval ${o.approval_ref})`), 5, "unreported mutations"));
	if (a.ledger_unavailable.count > 0) {
		const first = a.ledger_unavailable.items[0];
		anomalies.push(`! Ledger unavailable: ${plural(a.ledger_unavailable.count, "event")}${first ? `, first at seq ${first.seq} (${first.client_id}, ${first.capability})` : ""}`);
	}
	anomalies.push(...capList(a.denial_bursts.map((b) => `! Denial burst: ${b.client_id}, ${plural(b.denied, "denial")} (threshold ${b.threshold})`), 5, "denial bursts"));
	anomalies.push(...capList(a.new_clients.map((c) => `! New client: ${c.client_id} (first seen ${when(c.first_seen)})`), 5, "new clients"));
	if (anomalies.length > 0) blocks.push([`ANOMALIES (${d.anomaly_count})`, ...anomalies]);
	if (d.total_actions === 0) blocks[0].push("No activity in this window.");
	else {
		const r = d.by_result;
		blocks.push([
			"TOTALS",
			`Actions: ${d.total_actions} (ok ${r.ok}, error ${r.error}, denied ${r.denied}, pending approval ${r.pending_approval}, committing ${r.committing})`,
			`Approvals: requested ${d.approvals.requested}, granted ${d.approvals.granted}, denied ${d.approvals.denied}, expired ${d.approvals.expired}`
		]);
		const clientLines = d.clients.map((c) => `${c.client_id}: ${plural(c.actions, "action")}, ${c.denied} denied, ${plural(c.errors, "error")}, ${plural(c.entries_used, "entry", "entries")}`);
		const hidden = Math.max(0, clientLines.length - 12) + d.clients_omitted;
		blocks.push([
			`CLIENTS (${d.clients.length + d.clients_omitted})`,
			...clientLines.slice(0, 12),
			...hidden > 0 ? [`… and ${hidden} more clients`] : []
		]);
		if (d.tier2_mutations.count > 0) {
			const lines = d.tier2_mutations.items.map((m) => `${when(m.timestamp)} ${m.client_id}: ${m.capability} on ${m.resource}${m.label ? ` ("${m.label}")` : ""}`);
			const more = d.tier2_mutations.count - Math.min(lines.length, 10);
			blocks.push([
				`TIER-2 MUTATIONS (${d.tier2_mutations.count})`,
				...lines.slice(0, 10),
				...more > 0 ? [`… and ${more} more`] : []
			]);
		}
		if (d.top_denied_reasons.length > 0) blocks.push(["TOP DENIED REASONS", ...d.top_denied_reasons.map((x) => `${x.count}x ${x.reason}`)]);
	}
	if (d.needs_reentry.length > 0) blocks.push([`NEEDS RE-ENTRY (${d.needs_reentry.length})`, ...capList(d.needs_reentry.map((e) => e.label), 10, "entries")]);
	if (d.total_actions > 0 || d.grants.created > 0) blocks.push(["CONSENT GRANTS", `Created ${d.grants.created}, active now ${d.grants.active}`]);
	if (d.unavailable.length > 0) blocks.push([`Not included (source unavailable): ${d.unavailable.map((s) => safe(s, 20, false)).join(", ")}`]);
	for (const section of d.extra) blocks.push([safe(section.title, 60, true).toUpperCase(), ...section.lines.map((line) => safe(line, 200, true))]);
	const text = blocks.map((lines) => lines.map((line) => sanitizeDisplayText(line, 400)).join("\n")).join("\n\n");
	return capText(redactString(text));
}
function toIsoOrNull(v) {
	return v == null ? null : v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString();
}
/** Postgres/PGLite store over `vault_digest_state` (migrations/0009_vault_digest_state.sql). */
var SqlDigestStateStore = class {
	getSql;
	constructor(getSql) {
		this.getSql = getSql ?? (async () => {
			return (await import("./db-YAhc1k3o.mjs")).getSql();
		});
	}
	async claim(window, nowMs, staleBeforeMs) {
		const sql = await this.getSql();
		if ((await sql.query(`insert into vault_digest_state (window_from, window_to, status, claimed_at)
       values ($1::text, $2::text, 'sending', $3::timestamptz)
       on conflict (window_from, window_to) do update set claimed_at = excluded.claimed_at
         where vault_digest_state.status = 'sending' and vault_digest_state.claimed_at < $4::timestamptz
       returning window_from`, [
			window.from,
			window.to,
			new Date(nowMs).toISOString(),
			new Date(staleBeforeMs).toISOString()
		])).length === 1) return "claimed";
		return (await sql.query("select status from vault_digest_state where window_from = $1::text and window_to = $2::text", [window.from, window.to]))[0]?.status === "sent" ? "already_sent" : "in_progress";
	}
	async markSent(window, messageId, nowMs) {
		if ((await (await this.getSql()).query(`update vault_digest_state set status = 'sent', sent_at = $3::timestamptz, message_id = $4::bigint
        where window_from = $1::text and window_to = $2::text
        returning window_from`, [
			window.from,
			window.to,
			new Date(nowMs).toISOString(),
			messageId
		])).length !== 1) throw new Error("digest_state_missing_claim");
	}
	async release(window) {
		await (await this.getSql()).query("delete from vault_digest_state where window_from = $1::text and window_to = $2::text and status = 'sending'", [window.from, window.to]);
	}
	async lastSent() {
		const r = (await (await this.getSql()).query(`select window_from, window_to, status, claimed_at, sent_at, message_id from vault_digest_state
        where status = 'sent' order by window_to desc, window_from desc limit 1`))[0];
		if (!r) return null;
		return {
			from: String(r.window_from),
			to: String(r.window_to),
			status: "sent",
			claimed_at: toIsoOrNull(r.claimed_at) ?? "",
			sent_at: toIsoOrNull(r.sent_at),
			message_id: r.message_id == null ? null : Number(r.message_id)
		};
	}
};
var defaultStateStore = null;
function getDefaultDigestStateStore() {
	defaultStateStore ??= new SqlDigestStateStore();
	return defaultStateStore;
}
async function deliver(window, deps, prebuilt) {
	const state = deps.state ?? getDefaultDigestStateStore();
	const env = deps.env ?? process.env;
	const now = deps.now ?? Date.now;
	let claim;
	try {
		claim = await state.claim(window, now(), now() - CLAIM_STALE_MS);
	} catch {
		log.error("vault_digest_state_unavailable", {
			from: window.from,
			to: window.to
		});
		return {
			sent: false,
			reason: "state_unavailable",
			window
		};
	}
	if (claim !== "claimed") return {
		sent: false,
		reason: claim,
		window
	};
	const release = async () => {
		await state.release(window).catch(() => log.error("vault_digest_release_failed", {
			from: window.from,
			to: window.to
		}));
	};
	let text;
	try {
		text = formatDigest(prebuilt ?? await buildDigest(window, deps));
	} catch {
		await release();
		log.error("vault_digest_build_failed", {
			from: window.from,
			to: window.to
		});
		return {
			sent: false,
			reason: "build_failed",
			window
		};
	}
	let messageId;
	try {
		const chatId = approverTelegramId(env);
		if (!chatId) throw new TelegramApiError("sendMessage", "telegram_approver_missing");
		const result = await callBotApi("sendMessage", {
			chat_id: chatId,
			text,
			link_preview_options: { is_disabled: true }
		}, {
			fetch: deps.fetch,
			env
		});
		messageId = typeof result?.message_id === "number" ? result.message_id : 0;
	} catch (err) {
		await release();
		const detail = err instanceof TelegramApiError ? err.code : "telegram_error";
		log.warn("vault_digest_send_failed", {
			from: window.from,
			to: window.to,
			code: detail
		});
		return {
			sent: false,
			reason: "telegram_failed",
			window,
			detail
		};
	}
	let recorded = true;
	try {
		await state.markSent(window, messageId, now());
	} catch {
		recorded = false;
		log.error("vault_digest_mark_sent_failed", {
			from: window.from,
			to: window.to
		});
	}
	log.info("vault_digest_sent", {
		from: window.from,
		to: window.to,
		message_id: messageId,
		recorded
	});
	return {
		sent: true,
		message_id: messageId,
		window,
		recorded
	};
}
/** Send a digest that was already built (admin_digest_now with send=true). Same once-per-window rule. */
async function sendDigest(digest, deps = {}) {
	let window;
	try {
		window = canonicalWindow(digest.window);
	} catch {
		return {
			sent: false,
			reason: "invalid_window"
		};
	}
	return deliver(window, deps, digest);
}
/**
* entry_transfer ("opaque credential transfer"): the pure parts.
*
* The tool hands one entry's secret to another service: the DESTINATION entry
* authenticates one HTTPS request to its own site, and the SOURCE entry's
* secret replaces a placeholder in the JSON body. The agent never sees either
* value. gateway.ts (entryTransferPlan) owns policy, approval, the two
* useEntry calls and the request; this module only validates the agent's
* arguments and builds the outgoing body.
*
* Nothing here logs, and no error message echoes body content: the body is
* agent-supplied text that the owner has not seen yet.
*/
var TRANSFER_CAPABILITY = "vault.entry.transfer";
var TRANSFER_PLACEHOLDER = "{{vault:source}}";
var TRANSFER_METHODS = [
	"POST",
	"PUT",
	"PATCH"
];
/** Kinds whose secret is one opaque string another service can hold. */
var TRANSFER_SOURCE_KINDS = ["api_key", "oauth_token"];
/** Kinds that can authenticate the request to the destination (no cookie jar, no operator secret). */
var TRANSFER_DESTINATION_KINDS = [
	"api_key",
	"oauth_token",
	"password"
];
var MAX_DEPTH = 32;
var MAX_KEY_DISPLAY = 40;
var MAX_PATH_DISPLAY = 120;
var PLAIN_KEY = /^[A-Za-z_$][A-Za-z0-9_$-]*$/;
/** A refusal of the agent's arguments. `message` is safe to return: it never contains body content. */
var TransferInputError = class extends Error {
	constructor(message) {
		super(message);
		this.name = "TransferInputError";
	}
};
function isPlainObject(v) {
	return !!v && typeof v === "object" && !Array.isArray(v);
}
/** One step of the placeholder's location, for the owner: `.key`, `["odd key"]` or `[3]`. Keys are sanitized and clipped. */
function segment(key, first) {
	if (typeof key === "number") return `[${key}]`;
	const shown = sanitizeDisplayText(key, MAX_KEY_DISPLAY);
	if (PLAIN_KEY.test(key) && shown === key) return first ? shown : `.${shown}`;
	return `[${JSON.stringify(shown)}]`;
}
/**
* Find the placeholder in a JSON body. It must be the ENTIRE value of exactly
* one string field (any depth, arrays included): not part of a longer string,
* not in a key, not zero times, not twice. Returns its location as a
* dotted/indexed path (`value`, `config.keys[0].secret`).
*/
function locatePlaceholder(body) {
	if (!isPlainObject(body)) throw new TransferInputError("body must be a JSON object");
	const found = [];
	const walk = (value, path, depth) => {
		if (depth > MAX_DEPTH) throw new TransferInputError("body is nested too deeply");
		if (typeof value === "string") {
			if (value === "{{vault:source}}") found.push(path);
			else if (value.includes("{{vault:source}}")) throw new TransferInputError(`${TRANSFER_PLACEHOLDER} must be the entire value of a string field, not part of a longer string`);
			return;
		}
		if (Array.isArray(value)) {
			value.forEach((item, i) => walk(item, `${path}${segment(i, false)}`, depth + 1));
			return;
		}
		if (isPlainObject(value)) for (const [key, child] of Object.entries(value)) {
			if (key.includes("{{vault:source}}")) throw new TransferInputError(`${TRANSFER_PLACEHOLDER} is not allowed in an object key`);
			walk(child, `${path}${segment(key, path === "")}`, depth + 1);
		}
	};
	walk(body, "", 0);
	if (found.length === 0) throw new TransferInputError(`body must contain ${TRANSFER_PLACEHOLDER} as the value of one string field`);
	if (found.length > 1) throw new TransferInputError(`body must contain ${TRANSFER_PLACEHOLDER} exactly once`);
	const path = found[0];
	return { path: path.length > MAX_PATH_DISPLAY ? `${path.slice(0, 119)}…` : path };
}
var HEADER_NAME = /^[a-z][a-z0-9-]{0,39}$/;
/** Headers the destination secret may never be sent as: they route, frame or already authenticate the request. */
var FORBIDDEN_HEADERS = /* @__PURE__ */ new Set([
	"host",
	"cookie",
	"set-cookie",
	"content-length",
	"content-type",
	"transfer-encoding",
	"connection",
	"authorization",
	"proxy-authorization",
	"te",
	"upgrade",
	"via",
	"forwarded"
]);
var FORBIDDEN_HEADER_PREFIXES = ["x-forwarded-", "sec-"];
/**
* `to_auth`: absent (or `{scheme:"default"}`) → what entry_use does for the
* entry kind. `{scheme:"header", name}` → the destination secret is sent as
* that request header instead of the Authorization header. The name is
* lower-cased and checked against a strict pattern and a deny list.
*/
function parseTransferAuth(value) {
	if (value === void 0 || value === null) return { scheme: "default" };
	if (!isPlainObject(value)) throw new TransferInputError("to_auth must be an object");
	for (const key of Object.keys(value)) if (key !== "scheme" && key !== "name") throw new TransferInputError("to_auth: only scheme and name are allowed");
	if (value.scheme === "default") {
		if (value.name !== void 0) throw new TransferInputError("to_auth: name is only for scheme \"header\"");
		return { scheme: "default" };
	}
	if (value.scheme !== "header") throw new TransferInputError("to_auth.scheme must be \"header\" (or omit to_auth)");
	if (typeof value.name !== "string") throw new TransferInputError("to_auth.name: a header name is required");
	const name = value.name.toLowerCase();
	if (!HEADER_NAME.test(name)) throw new TransferInputError("to_auth.name: not a valid header name (a letter, then letters, digits or hyphens; 40 at most)");
	if (FORBIDDEN_HEADERS.has(name) || FORBIDDEN_HEADER_PREFIXES.some((p) => name.startsWith(p))) throw new TransferInputError("to_auth.name: that header cannot carry a credential");
	return {
		scheme: "header",
		name
	};
}
/**
* The outgoing body: `template` is the agent's body exactly as it was hashed
* for the approval (JSON text with the placeholder still in it). The one
* placeholder value becomes the secret; JSON.stringify does the escaping.
* The result is a secret: it is sent, never logged, stored or returned.
*/
function buildTransferBody(template, sourceSecret) {
	return JSON.stringify(JSON.parse(template), (_key, value) => value === "{{vault:source}}" ? sourceSecret : value);
}
/**
* Other spellings of the transferred secret that a destination might echo
* back: URL-encoded, base64 (padded and unpadded), base64url and JSON-escaped.
* The caller arms each for redaction (redaction.ts matches literal strings
* only). The secret itself is armed by cards.ts when it is loaded.
*/
function transferRedactionForms(secret) {
	const forms = /* @__PURE__ */ new Set();
	const add = (form) => {
		if (form !== secret && form.length > 0) forms.add(form);
	};
	add(encodeURIComponent(secret));
	const bytes = Buffer.from(secret, "utf8");
	const b64 = bytes.toString("base64");
	add(b64);
	add(b64.replace(/=+$/, ""));
	add(bytes.toString("base64url"));
	add(JSON.stringify(secret).slice(1, -1));
	return [...forms];
}
var BEARER_RE = /^Bearer +(\S+) *$/i;
/**
* Authenticate a remote MCP request. Accepts ONLY `Authorization: Bearer eva_…`
* validated against the hashed token store. Any other header — including
* `x-echo-agent: claude` — is ignored. Returns null on any failure (fail closed).
*/
async function authenticateRequest(headers) {
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
function wwwAuthenticateHeader(opts) {
	return buildWwwAuthenticate(opts ?? {});
}
function iso(ms) {
	return ms === null ? null : new Date(ms).toISOString();
}
function view(rec) {
	return {
		client_id: rec.client_id,
		client_name: rec.client_name,
		redirect_uris: [...rec.redirect_uris],
		status: rec.status,
		requested_scopes: [...rec.requested_scopes],
		granted_scopes: [...rec.granted_scopes],
		created_at: new Date(rec.created_at).toISOString(),
		approved_at: iso(rec.approved_at),
		revoked_at: iso(rec.revoked_at)
	};
}
async function listClients() {
	return (await oauthStore().listClients()).map(view);
}
/**
* Owner kill switch: mark the client revoked, drop its grant, revoke every
* access/refresh token it holds, and deny its pending authorizations.
* A revoked client cannot be re-approved; it must re-register (new client_id).
*/
async function revokeClient(client_id) {
	const store = oauthStore();
	const now = oauthNow();
	if (!await store.getClient(client_id)) return {
		ok: false,
		tokens_revoked: 0
	};
	await store.updateClient(client_id, {
		status: "revoked",
		granted_scopes: [],
		revoked_at: now
	});
	const tokensRevoked = await store.revokeClientTokens(client_id, now);
	await store.denyPendingForClient(client_id);
	log.warn("oauth_client_revoked", {
		client_id,
		tokens_revoked: tokensRevoked
	});
	return {
		ok: true,
		tokens_revoked: tokensRevoked
	};
}
/**
* Owner sets an approved client's granted scopes. Narrowing takes effect on
* existing tokens immediately (authenticateRequest intersects with the current
* grant); widening applies to tokens issued afterwards.
* Throws "unknown_scope", "client_not_found", or "client_not_approved".
*/
async function setClientScopes(client_id, scopes) {
	if (!Array.isArray(scopes) || scopes.some((s) => !SUPPORTED_SCOPES.includes(s))) throw new Error("unknown_scope");
	const store = oauthStore();
	const existing = await store.getClient(client_id);
	if (!existing) throw new Error("client_not_found");
	if (existing.status !== "approved") throw new Error("client_not_approved");
	const granted = canonicalScopes(scopes);
	const updated = await store.updateClient(client_id, { granted_scopes: granted });
	if (!updated) throw new Error("client_not_found");
	log.info("oauth_client_scopes_set", {
		client_id,
		scopes: granted
	});
	return view(updated);
}
/**
* Owner console storage (migrations/0011_vault_owner_console.sql).
*
* Four record kinds: passkeys (credential id, PUBLIC key, counter, transports),
* WebAuthn challenges, console sessions and the single bootstrap code.
* Challenges, session tokens and the bootstrap code are held as sha256 hex
* only; the raw values never reach a store. Nothing here is a vault secret.
*
* Times are epoch milliseconds from the caller's clock (same convention as
* rate-limit-store.ts), so the memory and SQL stores behave identically under
* an injected clock. Every multi-condition transition is ONE statement (the
* shared `Sql` surface has no transactions):
*   - takeChallenge        delete … returning            (single use)
*   - touchSession         update … where still valid    (idle + absolute expiry)
*   - consumeBootstrapCode update … where unconsumed and unexpired
*   - deletePasskeyUnlessLast: the delete requires another passkey row and
*     locks it (`for update`), so two concurrent removals cannot both succeed
*     and leave the console with no passkey.
*/
function sha256Hex(value) {
	return createHash("sha256").update(value).digest("hex");
}
var HEX64 = /^[0-9a-f]{64}$/;
var HEX32 = /^[0-9a-f]{32}$/;
var CREDENTIAL_ID = /^[A-Za-z0-9_-]{16,1366}$/;
var PUBLIC_KEY = /^[A-Za-z0-9_-]{32,8192}$/;
var TRANSPORT = /^[a-z][a-z-]{1,15}$/;
var MINTED_BY = /^local:[a-z0-9][a-z0-9._-]{0,63}$/;
function invalid$1(field) {
	return /* @__PURE__ */ new Error(`owner_console_invalid_${field}`);
}
/** Keeps only well-formed transport hints (at most 8); anything else is dropped. */
function cleanTransports(input) {
	if (!Array.isArray(input)) return [];
	const out = [];
	for (const t of input) {
		if (typeof t === "string" && TRANSPORT.test(t) && !out.includes(t)) out.push(t);
		if (out.length === 8) break;
	}
	return out;
}
function checkPasskey(rec) {
	if (!CREDENTIAL_ID.test(rec.credential_id)) throw invalid$1("credential_id");
	if (!PUBLIC_KEY.test(rec.public_key)) throw invalid$1("public_key");
	if (!Number.isInteger(rec.counter) || rec.counter < 0 || rec.counter > 4294967295) throw invalid$1("counter");
	if (rec.transports.length > 8 || !rec.transports.every((t) => TRANSPORT.test(t))) throw invalid$1("transports");
	if (typeof rec.label !== "string" || rec.label.length < 1 || rec.label.length > 64) throw invalid$1("label");
}
function checkChallenge(rec) {
	if (!HEX64.test(rec.challenge_hash)) throw invalid$1("challenge_hash");
	if ((rec.purpose === "stepup" || rec.purpose === "add_passkey") !== (rec.session_id !== null)) throw invalid$1("challenge_session");
	if (rec.session_id !== null && !HEX32.test(rec.session_id)) throw invalid$1("challenge_session");
	if (!(rec.expires_at > rec.created_at)) throw invalid$1("challenge_expiry");
}
function checkSession(rec) {
	if (!HEX32.test(rec.id)) throw invalid$1("session_id");
	if (!HEX64.test(rec.token_hash)) throw invalid$1("token_hash");
	if (rec.user_agent.length > 200) throw invalid$1("user_agent");
}
function checkBootstrap(rec) {
	if (!HEX64.test(rec.code_hash)) throw invalid$1("code_hash");
	if (!MINTED_BY.test(rec.minted_by)) throw invalid$1("minted_by");
	if (!(rec.expires_at > rec.created_at)) throw invalid$1("bootstrap_expiry");
}
var num = (v) => Number(v);
var numOrNull = (v) => v === null || v === void 0 ? null : Number(v);
function passkeyRow(r) {
	return {
		credential_id: String(r.credential_id),
		public_key: String(r.public_key),
		counter: num(r.counter),
		transports: String(r.transports ?? "") === "" ? [] : String(r.transports).split(","),
		label: String(r.label),
		created_at: num(r.created_at),
		last_used_at: numOrNull(r.last_used_at),
		flagged_at: numOrNull(r.flagged_at),
		flag_reason: r.flag_reason === "counter_regression" ? "counter_regression" : null
	};
}
function sessionRow(r) {
	return {
		id: String(r.id),
		token_hash: String(r.token_hash),
		credential_id: String(r.credential_id),
		created_at: num(r.created_at),
		last_seen_at: num(r.last_seen_at),
		absolute_expires_at: num(r.absolute_expires_at),
		step_up_at: numOrNull(r.step_up_at),
		revoked_at: numOrNull(r.revoked_at),
		user_agent: String(r.user_agent ?? "")
	};
}
var SESSION_LIVE = "revoked_at is null and last_seen_at > $1::bigint - $2::bigint and absolute_expires_at > $1::bigint";
/** Postgres / PGlite store over the vault_console_* tables. */
var SqlOwnerConsoleStore = class {
	kind = "sql";
	getSql;
	constructor(getSql) {
		this.getSql = getSql ?? (async () => {
			return (await import("./db-YAhc1k3o.mjs")).getSql();
		});
	}
	async q(text, params = []) {
		return (await this.getSql()).query(text, params);
	}
	async listPasskeys() {
		return (await this.q("select * from vault_console_passkeys order by created_at, credential_id")).map(passkeyRow);
	}
	async getPasskey(credentialId) {
		const rows = await this.q("select * from vault_console_passkeys where credential_id = $1", [credentialId]);
		return rows[0] ? passkeyRow(rows[0]) : null;
	}
	async insertPasskey(rec) {
		checkPasskey(rec);
		return (await this.q(`insert into vault_console_passkeys (credential_id, public_key, counter, transports, label, created_at)
       values ($1, $2, $3, $4, $5, $6) on conflict (credential_id) do nothing returning credential_id`, [
			rec.credential_id,
			rec.public_key,
			rec.counter,
			rec.transports.join(","),
			rec.label,
			rec.created_at
		])).length === 1;
	}
	async updatePasskeyUse(credentialId, counter, usedAt) {
		await this.q("update vault_console_passkeys set counter = $2, last_used_at = $3 where credential_id = $1", [
			credentialId,
			counter,
			usedAt
		]);
	}
	async flagPasskey(credentialId, reason, at) {
		await this.q("update vault_console_passkeys set flagged_at = $3, flag_reason = $2 where credential_id = $1", [
			credentialId,
			reason,
			at
		]);
	}
	async deletePasskeyUnlessLast(credentialId) {
		if ((await this.q(`delete from vault_console_passkeys p
        where p.credential_id = $1
          and exists (select 1 from vault_console_passkeys o where o.credential_id <> $1 for update)
       returning p.credential_id`, [credentialId])).length === 1) return "deleted";
		return await this.getPasskey(credentialId) ? "last" : "not_found";
	}
	async putChallenge(rec) {
		checkChallenge(rec);
		await this.q("insert into vault_console_challenges (challenge_hash, purpose, session_id, created_at, expires_at) values ($1, $2, $3, $4, $5)", [
			rec.challenge_hash,
			rec.purpose,
			rec.session_id,
			rec.created_at,
			rec.expires_at
		]);
	}
	async takeChallenge(challengeHash) {
		const r = (await this.q("delete from vault_console_challenges where challenge_hash = $1 returning *", [challengeHash]))[0];
		if (!r) return null;
		return {
			challenge_hash: String(r.challenge_hash),
			purpose: String(r.purpose),
			session_id: r.session_id === null || r.session_id === void 0 ? null : String(r.session_id),
			created_at: num(r.created_at),
			expires_at: num(r.expires_at)
		};
	}
	async pruneChallenges(now) {
		return (await this.q("delete from vault_console_challenges where expires_at <= $1 returning challenge_hash", [now])).length;
	}
	async insertSession(rec) {
		checkSession(rec);
		await this.q(`insert into vault_console_sessions
         (id, token_hash, credential_id, created_at, last_seen_at, absolute_expires_at, step_up_at, revoked_at, user_agent)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [
			rec.id,
			rec.token_hash,
			rec.credential_id,
			rec.created_at,
			rec.last_seen_at,
			rec.absolute_expires_at,
			rec.step_up_at,
			rec.revoked_at,
			rec.user_agent
		]);
	}
	async touchSession(tokenHash, now, idleMs) {
		const rows = await this.q(`update vault_console_sessions set last_seen_at = greatest(last_seen_at, $1::bigint)
        where token_hash = $3 and ${SESSION_LIVE} returning *`, [
			now,
			idleMs,
			tokenHash
		]);
		return rows[0] ? sessionRow(rows[0]) : null;
	}
	async listSessions(now, idleMs) {
		return (await this.q(`select * from vault_console_sessions where ${SESSION_LIVE} order by created_at, id`, [now, idleMs])).map(sessionRow);
	}
	async markStepUp(sessionId, at) {
		await this.q("update vault_console_sessions set step_up_at = $2 where id = $1", [sessionId, at]);
	}
	async revokeSession(sessionId, at) {
		return (await this.q("update vault_console_sessions set revoked_at = $2 where id = $1 and revoked_at is null returning id", [sessionId, at])).length === 1;
	}
	async pruneSessions(now, idleMs) {
		return (await this.q(`delete from vault_console_sessions where not (${SESSION_LIVE}) returning id`, [now, idleMs])).length;
	}
	async setBootstrapCode(rec) {
		checkBootstrap(rec);
		await this.q(`insert into vault_console_bootstrap (id, code_hash, minted_by, created_at, expires_at, consumed_at)
       values (1, $1, $2, $3, $4, null)
       on conflict (id) do update set code_hash = excluded.code_hash, minted_by = excluded.minted_by,
         created_at = excluded.created_at, expires_at = excluded.expires_at, consumed_at = null`, [
			rec.code_hash,
			rec.minted_by,
			rec.created_at,
			rec.expires_at
		]);
	}
	async checkBootstrapCode(codeHash, now) {
		return (await this.q("select 1 as ok from vault_console_bootstrap where id = 1 and code_hash = $1 and consumed_at is null and expires_at > $2", [codeHash, now])).length === 1;
	}
	async consumeBootstrapCode(codeHash, now) {
		return (await this.q(`update vault_console_bootstrap set consumed_at = $2
        where id = 1 and code_hash = $1 and consumed_at is null and expires_at > $2 returning id`, [codeHash, now])).length === 1;
	}
};
var defaultStore$1 = null;
/** SQL by default (Postgres when DATABASE_URL is set, otherwise the embedded PGlite). */
function getDefaultOwnerConsoleStore() {
	defaultStore$1 ??= new SqlOwnerConsoleStore();
	return defaultStore$1;
}
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
var OWNER_CLIENT_ID_PATTERN = /^owner:[0-9a-f]{12}$/;
/** Read scopes for the tier-0 tools the console renders (audit_list, audit_verify). Admin tools need no scope: see the gateway carve-out. */
var OWNER_SCOPES = Object.freeze(["audit.read", "vault.read"]);
var minted = /* @__PURE__ */ new WeakSet();
/** `owner:<first 12 hex of sha256(credential id bytes)>`. */
function ownerClientId(credentialId) {
	return `owner:${createHash("sha256").update(Buffer.from(credentialId, "base64url")).digest("hex").slice(0, 12)}`;
}
/** ONLY for owner-console.ts, after it authenticated a console session. */
function mintOwnerIdentity(credentialId) {
	const identity = Object.freeze({
		client_id: ownerClientId(credentialId),
		name: "Owner (console)",
		kind: "owner",
		scopes: Object.freeze([...OWNER_SCOPES])
	});
	minted.add(identity);
	return identity;
}
function isMintedOwnerIdentity(identity) {
	return typeof identity === "object" && identity !== null && minted.has(identity);
}
var BOOTSTRAP_TTL_MS = 9e5;
/** `evb_` + 32 base64url chars = 192 random bits. */
var BOOTSTRAP_CODE_PATTERN = /^evb_[A-Za-z0-9_-]{32}$/;
function bootstrapCodeHash(code) {
	return sha256Hex(`echo-vault-console-bootstrap-v1:${code}`);
}
/**
* Mint the one active bootstrap code, replacing any earlier one. Local stdio
* identity only: anything else throws `local_only` (the gateway also refuses
* before it gets here).
*/
async function mintBootstrapCode(identity, deps = {}) {
	if (identity?.kind !== "local") throw new Error("local_only");
	const store = deps.store ?? getDefaultOwnerConsoleStore();
	const now = (deps.now ?? Date.now)();
	const code = `evb_${randomBytes(24).toString("base64url")}`;
	await store.setBootstrapCode({
		code_hash: bootstrapCodeHash(code),
		minted_by: identity.client_id,
		created_at: now,
		expires_at: now + BOOTSTRAP_TTL_MS,
		consumed_at: null
	});
	return {
		code,
		expires_at: new Date(now + BOOTSTRAP_TTL_MS).toISOString(),
		ttl_seconds: BOOTSTRAP_TTL_MS / 1e3
	};
}
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
/** The only accounts this broker will act for: exact login → numeric account ID. */
var GITHUB_ACCOUNT_REGISTRY = Object.freeze({
	echoomegaprime: 314902331,
	"ECHO-OMEGA-PRIME": 264607697,
	bobmcwilliams4: 235318155
});
var GITHUB_APP_ID_REF_ENV = "ECHO_VAULT_GITHUB_APP_ID_REF";
var GITHUB_APP_KEY_REF_ENV = "ECHO_VAULT_GITHUB_APP_KEY_REF";
var GITHUB_INSTALLATIONS_ENV = "ECHO_VAULT_GITHUB_INSTALLATIONS";
var JWT_BACKDATE_S = 60;
var JWT_LIFETIME_S = 540;
var USE_EXPIRY_SKEW_MS = 3e4;
var MAX_CACHE_ENTRIES = 256;
var MAX_SCOPED_REPOSITORIES = 500;
var USER_AGENT = "Echo-Credential-Broker/1.0";
var GithubCredentialError = class extends Error {
	code;
	detail;
	constructor(code, detail) {
		super(detail ? `${code}: ${detail}` : code);
		this.name = "GithubCredentialError";
		this.code = code;
		this.detail = detail;
	}
};
var InstallationTokenCache = class {
	entries = /* @__PURE__ */ new Map();
	inflight = /* @__PURE__ */ new Map();
	/** A token with more than TOKEN_REFRESH_BEFORE_EXPIRY_MS left, else null (and evicted). */
	get(key, nowMs) {
		const entry = this.entries.get(key);
		if (!entry) return null;
		if (nowMs >= entry.expiresAtMs - 3e5) {
			this.entries.delete(key);
			return null;
		}
		return entry;
	}
	set(key, entry, nowMs) {
		if (this.entries.size >= MAX_CACHE_ENTRIES) {
			for (const [k, v] of this.entries) if (nowMs >= v.expiresAtMs - 3e5) this.entries.delete(k);
			while (this.entries.size >= MAX_CACHE_ENTRIES) {
				const oldest = this.entries.keys().next().value;
				if (oldest === void 0) break;
				this.entries.delete(oldest);
			}
		}
		this.entries.set(key, entry);
	}
	pending(key) {
		return this.inflight.get(key);
	}
	track(key, promise) {
		this.inflight.set(key, promise);
		const done = () => {
			if (this.inflight.get(key) === promise) this.inflight.delete(key);
		};
		promise.then(done, done);
		return promise;
	}
	clear() {
		this.entries.clear();
		this.inflight.clear();
	}
	get size() {
		return this.entries.size;
	}
	toJSON() {
		return { size: this.entries.size };
	}
	[inspect.custom]() {
		return `InstallationTokenCache { size: ${this.entries.size} }`;
	}
};
var defaultTokenCache = new InstallationTokenCache();
/** Patterns redaction.ts misses today (see ledger.ts for the upstream proposal). */
var EXTRA_SECRET_RULES = [
	[/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"],
	[/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$/g, "[REDACTED_PRIVATE_KEY]"],
	[/gh[pousr]_[0-9]+_[A-Za-z0-9._-]{16,}/g, "[REDACTED_GITHUB_TOKEN]"],
	[/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "[REDACTED_JWT]"]
];
function scrubText(value, secrets) {
	let out = value;
	for (const secret of secrets) {
		if (secret.length < 8) continue;
		const escaped = JSON.stringify(secret).slice(1, -1);
		for (const form of /* @__PURE__ */ new Set([secret, escaped])) if (out.includes(form)) out = out.split(form).join("[REDACTED_GITHUB_TOKEN]");
	}
	for (const [re, replacement] of EXTRA_SECRET_RULES) out = out.replace(re, replacement);
	return redactString(out);
}
function scrubJson(value, secrets) {
	if (value === null || value === void 0) return value ?? null;
	try {
		return redactValue(JSON.parse(scrubText(JSON.stringify(value), secrets)));
	} catch {
		return { error: "unserializable_redacted" };
	}
}
function scrubResponse(res, secrets) {
	return {
		status: res.status,
		ok: res.ok,
		json: scrubJson(res.json, secrets),
		text: res.text === null ? null : scrubText(res.text, secrets)
	};
}
function scrubError(error, secrets) {
	if (error instanceof GithubCredentialError) {
		const clean = new GithubCredentialError(error.code, error.detail ? scrubText(error.detail, secrets) : void 0);
		clean.stack = error.stack ? scrubText(error.stack, secrets) : void 0;
		return clean;
	}
	const message = error instanceof Error ? error.message : String(error);
	const clean = new Error(scrubText(message, secrets));
	if (error instanceof Error) {
		clean.name = error.name;
		clean.stack = error.stack ? scrubText(error.stack, secrets) : void 0;
		const code = error.code;
		if (typeof code === "string") Object.assign(clean, { code: scrubText(code, secrets) });
	}
	return clean;
}
/** Deep search for any secret in a value, without invoking getters. */
function containsSecret(value, secrets, seen = /* @__PURE__ */ new WeakSet()) {
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
	if (value instanceof Error && (containsSecret(value.message, secrets, seen) || containsSecret(value.stack, secrets, seen))) return true;
	for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) if ("value" in descriptor && containsSecret(descriptor.value, secrets, seen)) return true;
	return false;
}
function resolveDeps(deps) {
	return {
		store: deps.store ?? getStore(),
		fetchImpl: deps.fetch ?? ((input, init) => globalThis.fetch(input, init)),
		now: deps.now ?? Date.now,
		env: deps.env ?? process.env,
		cache: deps.tokenCache ?? defaultTokenCache,
		registry: deps.registry ?? GITHUB_ACCOUNT_REGISTRY
	};
}
/** Raw (unredacted) call — the result may hold a token and must stay inside this module. */
async function githubCall(ctx, call) {
	const policy = PROVIDER_POLICIES.github;
	if (typeof call.method !== "string" || !isAllowedMethod("github", call.method)) throw new GithubCredentialError("invalid_request", "method_not_allowed");
	const method = call.method.toUpperCase();
	let url;
	try {
		if (typeof call.path !== "string") throw new Error("invalid_resource");
		url = buildProviderUrl("github", call.path);
		assertSafeDestination(url, "github");
	} catch (error) {
		throw new GithubCredentialError("invalid_request", scrubText(error instanceof Error ? error.message : "invalid_resource", call.secrets));
	}
	let payload;
	if (call.body !== void 0 && method !== "GET") {
		payload = JSON.stringify(call.body);
		if (Buffer.byteLength(payload) > policy.maxRequestBytes) throw new GithubCredentialError("invalid_request", "request_too_large");
	}
	const headers = new Headers(githubAuthHeaders());
	headers.set("User-Agent", USER_AGENT);
	headers.set("Authorization", call.authorization);
	if (payload !== void 0) headers.set("Content-Type", "application/json");
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), policy.timeoutMs);
	try {
		const res = await ctx.fetchImpl(url, {
			method,
			headers,
			body: payload,
			redirect: "error",
			signal: controller.signal
		});
		const buf = Buffer.from(await res.arrayBuffer());
		if (buf.byteLength > policy.maxResponseBytes) throw new GithubCredentialError("github_unavailable", "response_too_large");
		const text = buf.toString("utf8");
		let json = null;
		if (text) try {
			json = JSON.parse(text);
		} catch {
			json = null;
		}
		return {
			status: res.status,
			ok: res.ok,
			json,
			text: json === null && text ? text.slice(0, 4096) : null
		};
	} catch (error) {
		if (error instanceof GithubCredentialError) throw error;
		throw new GithubCredentialError("github_unavailable", scrubText(error instanceof Error ? error.message : String(error), call.secrets));
	} finally {
		clearTimeout(timer);
	}
}
var REPO_NAME_RE = /^[A-Za-z0-9._-]{1,100}$/;
var PERMISSION_NAME_RE = /^[a-z][a-z_]{1,63}$/;
var PERMISSION_LEVELS = /* @__PURE__ */ new Set([
	"read",
	"write",
	"admin"
]);
var PURPOSE_RE = /^[A-Za-z0-9._:-]{1,128}$/;
var REASON_RE = /^[a-z0-9_]{1,64}$/;
/** GitHub repository name: [A-Za-z0-9._-]{1,100}, not "." / "..", no ".git" suffix. */
function isValidRepoName(name) {
	return typeof name === "string" && REPO_NAME_RE.test(name) && name !== "." && name !== ".." && !name.toLowerCase().endsWith(".git");
}
function invalid(detail) {
	return new GithubCredentialError("invalid_request", detail);
}
function validateRequest(req, registry) {
	if (!req || typeof req !== "object") throw invalid("request");
	if (typeof req.account_login !== "string" || !Object.hasOwn(registry, req.account_login)) throw new GithubCredentialError("unknown_account", `account_login must be exactly one of: ${Object.keys(registry).join(", ")}`);
	if (registry[req.account_login] !== req.account_id) throw new GithubCredentialError("identity_mismatch", `account_id does not match the registry for ${req.account_login}`);
	if (typeof req.purpose !== "string" || !PURPOSE_RE.test(req.purpose)) throw invalid("purpose");
	if (req.installation_unsupported_reason !== void 0 && !REASON_RE.test(String(req.installation_unsupported_reason))) throw invalid("installation_unsupported_reason");
	const body = {};
	if (req.repositories !== void 0) {
		if (!Array.isArray(req.repositories) || req.repositories.length === 0 || req.repositories.length > MAX_SCOPED_REPOSITORIES) throw invalid("repositories");
		if (!req.repositories.every(isValidRepoName)) throw invalid("repositories");
		body.repositories = [...new Set(req.repositories)].sort();
	}
	if (req.repository_ids !== void 0) {
		if (!Array.isArray(req.repository_ids) || req.repository_ids.length === 0 || req.repository_ids.length > MAX_SCOPED_REPOSITORIES) throw invalid("repository_ids");
		if (!req.repository_ids.every((id) => Number.isSafeInteger(id) && id > 0)) throw invalid("repository_ids");
		body.repository_ids = [...new Set(req.repository_ids)].sort((a, b) => a - b);
	}
	if (req.permissions !== void 0) {
		const perms = req.permissions;
		if (!perms || typeof perms !== "object" || Array.isArray(perms) || Object.keys(perms).length === 0) throw invalid("permissions");
		const clean = {};
		for (const [name, level] of Object.entries(perms)) {
			if (!PERMISSION_NAME_RE.test(name) || typeof level !== "string" || !PERMISSION_LEVELS.has(level)) throw invalid("permissions");
			clean[name] = level;
		}
		body.permissions = clean;
	}
	return {
		key: canonicalJson(body),
		body
	};
}
function readAppConfig(env, registry) {
	const config = { installations: {} };
	const appIdRef = env[GITHUB_APP_ID_REF_ENV]?.trim();
	const keyRef = env[GITHUB_APP_KEY_REF_ENV]?.trim();
	config.appIdRef = appIdRef ? parseVaultRef(appIdRef)?.raw : void 0;
	config.keyRef = keyRef ? parseVaultRef(keyRef)?.raw : void 0;
	const raw = env[GITHUB_INSTALLATIONS_ENV]?.trim();
	if (!raw) return config;
	let parsed;
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
	for (const [login, value] of Object.entries(parsed)) {
		const id = typeof value === "number" ? value : typeof value === "string" && /^\d+$/.test(value) ? Number(value) : NaN;
		if (!Object.hasOwn(registry, login) || !Number.isSafeInteger(id) || id <= 0) {
			log.warn("github_installation_entry_ignored", { login: Object.hasOwn(registry, login) ? login : "(not in registry)" });
			continue;
		}
		config.installations[login] = id;
	}
	return config;
}
var APP_ID_RE = /^(?:[0-9]{1,12}|Iv[0-9A-Za-z.]{4,64})$/;
function parsePrivateKey(pem) {
	const normalized = !pem.includes("\n") && pem.includes("\\n") ? pem.replace(/\\n/g, "\n") : pem;
	let key;
	try {
		key = createPrivateKey({
			key: normalized.trim(),
			format: "pem"
		});
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
async function createAppJwt(opts) {
	const appId = opts.appId.trim();
	if (!APP_ID_RE.test(appId)) throw new GithubCredentialError("credential_unavailable", "app_id_invalid");
	const key = parsePrivateKey(opts.privateKeyPem);
	const nowS = Math.floor(opts.nowMs / 1e3);
	return new SignJWT({}).setProtectedHeader({
		alg: "RS256",
		typ: "JWT"
	}).setIssuedAt(nowS - JWT_BACKDATE_S).setExpirationTime(nowS + JWT_LIFETIME_S).setIssuer(appId).sign(key);
}
function cleanPermissions(value) {
	if (!value || typeof value !== "object" || Array.isArray(value)) return void 0;
	const out = {};
	for (const [k, v] of Object.entries(value)) if (PERMISSION_NAME_RE.test(k) && typeof v === "string" && PERMISSION_LEVELS.has(v)) out[k] = v;
	return out;
}
async function mintInstallationToken(ctx, refs, installationId, req, scope, cacheKey) {
	const appId = (await ctx.store.resolveSecret(refs.appIdRef))?.trim();
	const pem = await ctx.store.resolveSecret(refs.keyRef);
	if (!appId || !pem) return {
		ok: false,
		reason: "app_credentials_unavailable"
	};
	let jwt;
	try {
		jwt = await createAppJwt({
			appId,
			privateKeyPem: pem,
			nowMs: ctx.now()
		});
	} catch {
		return {
			ok: false,
			reason: "app_credentials_invalid"
		};
	}
	const secrets = [jwt, pem];
	const authorization = `Bearer ${jwt}`;
	const inst = await githubCall(ctx, {
		method: "GET",
		path: `/app/installations/${installationId}`,
		authorization,
		secrets
	});
	if (inst.status >= 500) throw new GithubCredentialError("github_unavailable", `installation_lookup_http_${inst.status}`);
	if (inst.status === 401) return {
		ok: false,
		reason: "app_jwt_rejected"
	};
	if (inst.status === 404) return {
		ok: false,
		reason: "installation_not_found"
	};
	if (!inst.ok) return {
		ok: false,
		reason: `installation_lookup_http_${inst.status}`
	};
	const info = inst.json ?? {};
	if (info.account?.login !== req.account_login || info.account?.id !== req.account_id) {
		log.warn("github_installation_identity_mismatch", {
			installation_id: installationId,
			expected_login: req.account_login,
			expected_id: req.account_id,
			observed_login: typeof info.account?.login === "string" ? info.account.login : null,
			observed_id: typeof info.account?.id === "number" ? info.account.id : null
		});
		throw new GithubCredentialError("identity_mismatch", `installation ${installationId} does not belong to ${req.account_login}`);
	}
	if (info.suspended_at) return {
		ok: false,
		reason: "installation_suspended"
	};
	const res = await githubCall(ctx, {
		method: "POST",
		path: `/app/installations/${installationId}/access_tokens`,
		authorization,
		body: scope.body,
		secrets
	});
	if (res.status >= 500) throw new GithubCredentialError("github_unavailable", `installation_token_http_${res.status}`);
	if (res.status === 401) return {
		ok: false,
		reason: "app_jwt_rejected"
	};
	if (res.status !== 201 && res.status !== 200) return {
		ok: false,
		reason: `installation_token_denied_http_${res.status}`
	};
	const body = res.json ?? {};
	const expiresAtMs = typeof body.expires_at === "string" ? Date.parse(body.expires_at) : NaN;
	if (typeof body.token !== "string" || body.token.length < 8 || !Number.isFinite(expiresAtMs)) throw new GithubCredentialError("github_unavailable", "installation_token_response_malformed");
	const grant = {
		installation_id: installationId,
		expires_at: new Date(expiresAtMs).toISOString()
	};
	const permissions = cleanPermissions(body.permissions);
	if (permissions) grant.permissions = permissions;
	if (typeof body.repository_selection === "string") grant.repository_selection = body.repository_selection;
	ctx.cache.set(cacheKey, {
		token: body.token,
		expiresAtMs,
		grant
	}, ctx.now());
	return {
		ok: true,
		token: body.token,
		grant,
		cached: false
	};
}
async function installationToken(ctx, refs, installationId, req, scope) {
	const cacheKey = `${installationId}|${scope.key}`;
	const hit = ctx.cache.get(cacheKey, ctx.now());
	if (hit) return {
		ok: true,
		token: hit.token,
		grant: hit.grant,
		cached: true
	};
	const pending = ctx.cache.pending(cacheKey);
	if (pending) return pending;
	return ctx.cache.track(cacheKey, mintInstallationToken(ctx, refs, installationId, req, scope, cacheKey));
}
function patKind(pat) {
	if (pat.startsWith("github_pat_")) return "fine_grained";
	if (pat.startsWith("ghp_")) return "classic";
	return "unknown";
}
async function patHandle(ctx, req, reason) {
	const ref = formatVaultRef("github", req.account_login);
	const pat = (await ctx.store.resolveSecret(ref))?.trim();
	if (!pat) throw new GithubCredentialError("credential_unavailable", `no usable credential at ${ref} (fallback reason: ${reason})`);
	const probe = await githubCall(ctx, {
		method: "GET",
		path: "/user",
		authorization: `Bearer ${pat}`,
		secrets: [pat]
	});
	if (probe.status === 401 || probe.status === 403) throw new GithubCredentialError("credential_unavailable", `${ref} rejected by GitHub (http ${probe.status})`);
	if (!probe.ok) throw new GithubCredentialError("github_unavailable", `user_probe_http_${probe.status}`);
	const user = probe.json ?? {};
	if (user.login !== req.account_login || user.id !== req.account_id) {
		log.warn("github_pat_identity_mismatch", {
			credential_ref: ref,
			expected_login: req.account_login,
			expected_id: req.account_id,
			observed_login: typeof user.login === "string" ? user.login : null,
			observed_id: typeof user.id === "number" ? user.id : null
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
		pat_kind: patKind(pat)
	}, ctx);
}
function compact(meta) {
	const out = { ...meta };
	for (const key of Object.keys(out)) if (out[key] === void 0) delete out[key];
	if (meta.permissions) out.permissions = { ...meta.permissions };
	return out;
}
function createHandle(secret, metadata, ctx) {
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
		credential_ref: meta.credential_ref
	});
	async function use(fn) {
		if (typeof fn !== "function") throw invalid("use() requires a callback");
		if (expiresAtMs !== null && ctx.now() >= expiresAtMs - USE_EXPIRY_SKEW_MS) throw new GithubCredentialError("credential_expired", "request a new credential");
		let active = true;
		const requester = Object.freeze({ async request(method, path, opts = {}) {
			if (!active) throw new GithubCredentialError("requester_inactive", "the requester is only valid inside use()");
			return scrubResponse(await githubCall(ctx, {
				method,
				path,
				authorization: `Bearer ${secret}`,
				body: opts?.body,
				secrets
			}), secrets);
		} });
		try {
			const out = await fn(requester);
			if (containsSecret(out, secrets)) {
				log.error("github_token_escape_blocked", {
					purpose: meta.purpose,
					account: meta.account_login,
					path: meta.path
				});
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
		[inspect.custom]: () => compact(meta)
	};
	return Object.freeze(handle);
}
/**
* Obtain an opaque, short-lived GitHub credential handle for one exact account.
* Throws GithubCredentialError (codes above); never returns or throws a token.
*/
async function getGithubCredential(req, deps = {}) {
	const ctx = resolveDeps(deps);
	const scope = validateRequest(req, ctx.registry);
	let reason;
	if (req.installation_unsupported_reason) reason = req.installation_unsupported_reason;
	else {
		const config = readAppConfig(ctx.env, ctx.registry);
		const installationId = config.installations[req.account_login];
		if (config.installationsError) reason = config.installationsError;
		else if (installationId === void 0) reason = "no_installation_configured";
		else if (!config.appIdRef || !config.keyRef) reason = "app_not_configured";
		else {
			const refs = {
				appIdRef: config.appIdRef,
				keyRef: config.keyRef
			};
			const outcome = await installationToken(ctx, refs, installationId, req, scope);
			if (outcome.ok) return createHandle(outcome.token, {
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
				cached: outcome.cached
			}, ctx);
			reason = outcome.reason;
		}
	}
	log.warn("github_credential_pat_fallback", {
		purpose: req.purpose,
		account: req.account_login,
		reason
	});
	return patHandle(ctx, req, reason);
}
/**
* Vault v2 GitHub capabilities, built on github-app.ts. Each handler takes
* `(params, { client, deps })`, validates `params` strictly (unknown keys are
* refused; only `approval_id` is tolerated and ignored), acts for exactly one
* account from GITHUB_ACCOUNT_REGISTRY, and returns
* `{ ok, data | error, audit }` with no secret material. `audit` carries the
* non-secret facts the integrator should put in the ledger (credential_ref,
* credential path + fallback reason, last GitHub HTTP status).
*
* Grounded in GitHub's REST docs (fetched 2026-11-14):
*  - Transfer (`POST /repos/{owner}/{repo}/transfer`, body `new_owner`
*    required, `new_name` / `team_ids` optional, 202 Accepted). Among
*    fine-grained tokens it lists ONLY GitHub App *user* access tokens
*    ("Administration" write) — not installation tokens, not fine-grained
*    PATs — so it always runs on the owner's PAT (a classic PAT is needed).
*    A personal → personal transfer must be accepted by the new owner within
*    one day; the 202 response still shows the original owner.
*  - Contents (`PUT …/contents/{path}`: message + base64 content required,
*    `sha` required when updating, `branch` defaults to the default branch;
*    `.github/workflows/*` additionally needs Workflows write).
*  - Pulls (`POST …/pulls`: `head` and `base` required, `draft` optional;
*    draft PRs in private repos need a paid plan).
* Installation tokens are down-scoped to the one repository and the minimum
* permissions for each action; if GitHub answers 403 "Resource not accessible
* by integration", the action is retried once on the exact-identity PAT. Every
* handler performs its single write as its LAST GitHub call, so that retry
* can never repeat a write that succeeded.
*/
var CapabilityError = class extends Error {
	code;
	constructor(code, detail) {
		super(detail);
		this.code = code;
	}
};
/** GitHub login / org name: alphanumerics and single inner hyphens, ≤ 39 chars. */
var OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
var REF_FORBIDDEN_CHARS = /[\u0000- \u007f~^:?*[\\]/;
var SHA_RE$1 = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
var BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
function isValidGithubOwner(value) {
	return typeof value === "string" && OWNER_RE.test(value);
}
/** `git check-ref-format`-style branch name check (no `refs/` prefix, ≤ 255 chars). */
function isValidBranchName(value) {
	if (typeof value !== "string" || value.length === 0 || value.length > 255) return false;
	if (value === "HEAD" || value === "@" || value.startsWith("refs/") || value.startsWith("-")) return false;
	if (REF_FORBIDDEN_CHARS.test(value) || value.includes("..") || value.includes("@{") || value.includes("//")) return false;
	if (value.startsWith("/") || value.endsWith("/") || value.endsWith(".")) return false;
	return value.split("/").every((part) => part.length > 0 && !part.startsWith(".") && !part.endsWith(".lock"));
}
/**
* Validate a repository file path and return it URL-encoded per segment, or
* null. Refuses traversal (`.`/`..`), empty segments, leading/trailing `/`,
* backslashes, control characters, `%`, and anything under `.git/`.
*/
function encodeContentPath(value) {
	if (typeof value !== "string" || value.length === 0 || value.length > 1024) return null;
	if (value.includes("\\") || value.includes("%") || /[\u0000-\u001f\u007f]/.test(value)) return null;
	const segments = value.split("/");
	if (segments.some((s) => s === "" || s === "." || s === "..")) return null;
	if (segments[0].toLowerCase() === ".git") return null;
	return segments.map(encodeURIComponent).join("/");
}
/** Writing workflows lets repository code read repository secrets in CI — refused for agents. */
function isWorkflowPath(path) {
	return /^\.github\/workflows\//i.test(path);
}
/** Branch prefixes treated as agent-owned scratch space. */
var DEFAULT_AGENT_BRANCH_PREFIXES = Object.freeze(["agent/", "claude/"]);
/**
* Pure: classify a contents write so the integrator can choose the capability
* ID / tier (default-branch writes are tier 2). An empty branch means GitHub's
* default, so it classifies as "default_branch". Comparison is exact (git
* branch names are case-sensitive).
*/
function classifyContentsWrite(input) {
	const strip = (b) => typeof b === "string" ? b.trim().replace(/^refs\/heads\//, "") : "";
	const branch = strip(input.branch);
	if (!branch || branch === strip(input.default_branch)) return "default_branch";
	return (input.agent_branch_prefixes ?? DEFAULT_AGENT_BRANCH_PREFIXES).some((p) => p.length > 0 && branch.startsWith(p) && branch.length > p.length) ? "agent_branch" : "other_branch";
}
var IGNORED_PARAM_KEYS = /* @__PURE__ */ new Set(["approval_id"]);
function readParams(params, allowed) {
	if (!params || typeof params !== "object" || Array.isArray(params)) throw new CapabilityError("invalid_params", "params must be an object");
	for (const key of Object.keys(params)) if (!allowed.includes(key) && !IGNORED_PARAM_KEYS.has(key)) throw new CapabilityError("invalid_params", `unknown param: ${key.slice(0, 64)}`);
	return params;
}
function registeredOwner(p, key) {
	const value = p[key];
	if (!isValidGithubOwner(value)) throw new CapabilityError("invalid_params", `${key}: not a valid GitHub login`);
	if (!Object.hasOwn(GITHUB_ACCOUNT_REGISTRY, value)) throw new CapabilityError(`${key}_not_allowed`, `${key} must be exactly one of: ${Object.keys(GITHUB_ACCOUNT_REGISTRY).join(", ")}`);
	return value;
}
function repoName(p, key) {
	const value = p[key];
	if (!isValidRepoName(value)) throw new CapabilityError("invalid_params", `${key}: not a valid repository name`);
	return value;
}
function branchName(p, key) {
	const value = p[key];
	if (!isValidBranchName(value)) throw new CapabilityError("invalid_params", `${key}: not a valid branch name`);
	return value;
}
var SECRET_PLACEHOLDER_RE = /\[REDACTED_(?:GITHUB_TOKEN|OPENAI_KEY|STRIPE_KEY|XAI_KEY|PRIVATE_KEY|SECRET)\]/g;
/** Provider tokens, private keys, or a value registered with redaction.ts — not mere mentions of "Authorization". */
function looksSecret(text) {
	if (containsSecretPrefix(text) || /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text) || /gh[pousr]_[0-9]+_[A-Za-z0-9._-]{16,}/.test(text)) return true;
	const before = text.match(SECRET_PLACEHOLDER_RE)?.length ?? 0;
	return (redactString(text).match(SECRET_PLACEHOLDER_RE)?.length ?? 0) > before;
}
function boundedText(p, key, max, required) {
	const value = p[key];
	if (value === void 0 && !required) return void 0;
	if (typeof value !== "string" || required && !value.trim() || value.length > max) throw new CapabilityError("invalid_params", `${key}: expected a string of at most ${max} characters`);
	if (looksSecret(value)) throw new CapabilityError("content_contains_secret", `${key} contains credential-shaped text; refusing to publish it`);
	return value;
}
var repoPath = (owner, repo) => `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
function recordCredential(audit, meta) {
	audit.credential_ref = meta.credential_ref;
	audit.credential_path = meta.path;
	audit.fallback_reason = meta.fallback_reason;
	audit.installation_id = meta.installation_id;
}
function integrationDenied(res) {
	const message = res.json?.message;
	return res.status === 403 && typeof message === "string" && /resource not accessible by integration/i.test(message);
}
/**
* Run `fn` with a credential for `req`. If an installation token is refused
* with "Resource not accessible by integration", retry once on the PAT path.
* `fn` must make its only write as its last request (see header).
*/
async function withGithub(req, ctx, audit, fn) {
	const run = async (handle) => {
		recordCredential(audit, handle.metadata());
		let denied = false;
		return {
			result: await handle.use((gh) => fn({ async request(method, path, opts) {
				const res = await gh.request(method, path, opts);
				audit.http_status = res.status;
				if (integrationDenied(res)) denied = true;
				return res;
			} }, handle.metadata())),
			denied
		};
	};
	const first = await getGithubCredential(req, ctx.deps);
	const attempt = await run(first);
	if (!attempt.denied || first.kind !== "installation") return attempt.result;
	log.warn("github_installation_denied_retrying_with_pat", {
		purpose: req.purpose,
		account: req.account_login
	});
	return (await run(await getGithubCredential({
		...req,
		installation_unsupported_reason: "installation_forbidden_for_operation"
	}, ctx.deps))).result;
}
function githubFailure(res, audit, hint) {
	audit.http_status = res.status;
	const message = res.json?.message;
	const detail = [typeof message === "string" ? redactString(message).slice(0, 300) : void 0, hint].filter(Boolean).join(" — ");
	return {
		ok: false,
		error: `github_http_${res.status}`,
		detail: detail || void 0,
		audit
	};
}
function str(value) {
	return typeof value === "string" ? value : void 0;
}
function defineCapability(id, impl) {
	return async (params, ctx) => {
		const started = Date.now();
		const audit = {};
		let result;
		try {
			if (!ctx?.client || typeof ctx.client.client_id !== "string" || !ctx.client.client_id) throw new CapabilityError("invalid_client", "an authenticated client identity is required");
			result = await impl(params, ctx, audit);
		} catch (error) {
			if (error instanceof CapabilityError) result = {
				ok: false,
				error: error.code,
				detail: error.message,
				audit
			};
			else if (error instanceof GithubCredentialError) result = {
				ok: false,
				error: error.code,
				detail: error.detail,
				audit
			};
			else result = {
				ok: false,
				error: "github_request_failed",
				detail: sanitizeError(error).message.slice(0, 300),
				audit
			};
		}
		log.info("github_capability", {
			capability: id,
			client_id: ctx?.client?.client_id ?? null,
			ok: result.ok,
			error: result.ok ? null : result.error,
			http_status: result.audit.http_status ?? null,
			credential_path: result.audit.credential_path ?? null,
			fallback_reason: result.audit.fallback_reason ?? null,
			duration_ms: Date.now() - started
		});
		for (const key of Object.keys(result.audit)) if (result.audit[key] === void 0) delete result.audit[key];
		return redactValue(result);
	};
}
function safeRepo(json) {
	const r = json ?? {};
	const owner = r.owner ?? {};
	return {
		full_name: str(r.full_name),
		name: str(r.name),
		owner: str(owner.login),
		owner_type: str(owner.type),
		private: typeof r.private === "boolean" ? r.private : void 0,
		visibility: str(r.visibility),
		default_branch: str(r.default_branch),
		archived: typeof r.archived === "boolean" ? r.archived : void 0,
		html_url: str(r.html_url),
		description: str(r.description)
	};
}
/** github.repo.read — repository metadata. */
var githubRepoGet = defineCapability("github.repo.read", async (params, ctx, audit) => {
	const p = readParams(params, ["owner", "repo"]);
	const owner = registeredOwner(p, "owner");
	const repo = repoName(p, "repo");
	return withGithub({
		account_login: owner,
		account_id: GITHUB_ACCOUNT_REGISTRY[owner],
		purpose: "github.repo.read",
		repositories: [repo],
		permissions: { metadata: "read" }
	}, ctx, audit, async (gh) => {
		const res = await gh.request("GET", repoPath(owner, repo));
		if (!res.ok) return githubFailure(res, audit);
		return {
			ok: true,
			data: safeRepo(res.json),
			audit
		};
	});
});
/** github.repo.transfer — move a repository between registry accounts. */
var githubRepoTransfer = defineCapability("github.repo.transfer", async (params, ctx, audit) => {
	const p = readParams(params, [
		"owner",
		"repo",
		"new_owner",
		"new_name"
	]);
	const owner = registeredOwner(p, "owner");
	const repo = repoName(p, "repo");
	const newOwner = registeredOwner(p, "new_owner");
	const newName = p.new_name === void 0 ? void 0 : repoName(p, "new_name");
	if (owner === newOwner) throw new CapabilityError("invalid_params", "new_owner must differ from owner (that is a rename, not a transfer)");
	return withGithub({
		account_login: owner,
		account_id: GITHUB_ACCOUNT_REGISTRY[owner],
		purpose: "github.repo.transfer",
		installation_unsupported_reason: "transfer_requires_user_token"
	}, ctx, audit, async (gh, cred) => {
		const target = await gh.request("GET", `/users/${encodeURIComponent(newOwner)}`);
		if (!target.ok) return githubFailure(target, audit, "new_owner lookup failed");
		const t = target.json ?? {};
		if (t.login !== newOwner || t.id !== GITHUB_ACCOUNT_REGISTRY[newOwner]) return {
			ok: false,
			error: "identity_mismatch",
			detail: `new_owner ${newOwner} does not resolve to account ${GITHUB_ACCOUNT_REGISTRY[newOwner]}`,
			audit
		};
		const body = { new_owner: newOwner };
		if (newName) body.new_name = newName;
		const res = await gh.request("POST", `${repoPath(owner, repo)}/transfer`, { body });
		if (!res.ok) return githubFailure(res, audit, cred.pat_kind === "fine_grained" && (res.status === 403 || res.status === 404) ? "GitHub documents this endpoint for App user tokens only; a fine-grained PAT is likely insufficient — use a classic PAT" : void 0);
		const r = res.json ?? {};
		const sourceType = str(r.owner?.type);
		const targetType = str(t.type);
		const requiresAcceptance = sourceType && targetType ? sourceType === "User" && targetType === "User" : null;
		return {
			ok: true,
			data: {
				status: res.status,
				accepted_for_processing: res.status === 202,
				full_name: str(r.full_name),
				html_url: str(r.html_url),
				from: `${owner}/${repo}`,
				to: `${newOwner}/${newName ?? repo}`,
				source_owner_type: sourceType,
				target_owner_type: targetType,
				requires_new_owner_acceptance: requiresAcceptance,
				note: requiresAcceptance === false ? "GitHub transfers asynchronously; the response still shows the original owner. Transfers into an organization need repo-creation permission there and can be blocked by organization policy." : "GitHub may require the new owner to accept: a personal-account to personal-account transfer emails the new owner, who must accept within one day or the invitation expires. Until then the repository stays at the original owner."
			},
			audit
		};
	});
});
/** github.contents.write — create/update one file; refuses the default branch unless allow_default_branch: true. */
var githubContentsWrite = defineCapability("github.contents.write", async (params, ctx, audit) => {
	const p = readParams(params, [
		"owner",
		"repo",
		"path",
		"branch",
		"content_base64",
		"message",
		"sha",
		"allow_default_branch"
	]);
	const owner = registeredOwner(p, "owner");
	const repo = repoName(p, "repo");
	const path = p.path;
	const encodedPath = encodeContentPath(path);
	if (!encodedPath || typeof path !== "string") throw new CapabilityError("invalid_params", "path: not a valid repository file path");
	if (isWorkflowPath(path)) throw new CapabilityError("workflow_path_refused", "writing .github/workflows/* would let CI read repository secrets; refused for agents");
	const branch = branchName(p, "branch");
	const message = boundedText(p, "message", 4096, true);
	if (p.sha !== void 0 && (typeof p.sha !== "string" || !SHA_RE$1.test(p.sha))) throw new CapabilityError("invalid_params", "sha: expected a blob SHA");
	if (p.allow_default_branch !== void 0 && typeof p.allow_default_branch !== "boolean") throw new CapabilityError("invalid_params", "allow_default_branch: expected a boolean");
	if (typeof p.content_base64 !== "string") throw new CapabilityError("invalid_params", "content_base64: expected a base64 string");
	const content = p.content_base64.replace(/[\r\n]/g, "");
	if (content.length % 4 !== 0 || !BASE64_RE.test(content)) throw new CapabilityError("invalid_params", "content_base64: not valid base64");
	if (content.length > PROVIDER_POLICIES.github.maxRequestBytes - 8192) throw new CapabilityError("content_too_large", "content exceeds the broker request limit");
	if (looksSecret(Buffer.from(content, "base64").toString("utf8"))) throw new CapabilityError("content_contains_secret", "file content contains credential-shaped text; refusing to commit it");
	return withGithub({
		account_login: owner,
		account_id: GITHUB_ACCOUNT_REGISTRY[owner],
		purpose: "github.contents.write",
		repositories: [repo],
		permissions: {
			contents: "write",
			metadata: "read"
		}
	}, ctx, audit, async (gh) => {
		const repoRes = await gh.request("GET", repoPath(owner, repo));
		if (!repoRes.ok) return githubFailure(repoRes, audit);
		const defaultBranch = str(repoRes.json?.default_branch);
		if (!defaultBranch) return {
			ok: false,
			error: "default_branch_unknown",
			audit
		};
		const classification = classifyContentsWrite({
			branch,
			default_branch: defaultBranch
		});
		if (classification === "default_branch" && p.allow_default_branch !== true) return {
			ok: false,
			error: "default_branch_write_refused",
			detail: `${branch} is the default branch of ${owner}/${repo}; writing it requires allow_default_branch: true (tier 2)`,
			audit
		};
		const body = {
			message,
			content,
			branch
		};
		if (typeof p.sha === "string") body.sha = p.sha;
		const put = await gh.request("PUT", `${repoPath(owner, repo)}/contents/${encodedPath}`, { body });
		if (!put.ok) return githubFailure(put, audit);
		const j = put.json ?? {};
		return {
			ok: true,
			data: {
				full_name: `${owner}/${repo}`,
				path: str(j.content?.path) ?? path,
				branch,
				classification,
				default_branch: defaultBranch,
				created: put.status === 201,
				content_sha: str(j.content?.sha),
				commit_sha: str(j.commit?.sha),
				commit_html_url: str(j.commit?.html_url)
			},
			audit
		};
	});
});
/** github.pr.create_draft — open a draft pull request within one repository. */
var githubPrCreateDraft = defineCapability("github.pr.create_draft", async (params, ctx, audit) => {
	const p = readParams(params, [
		"owner",
		"repo",
		"title",
		"head",
		"base",
		"body"
	]);
	const owner = registeredOwner(p, "owner");
	const repo = repoName(p, "repo");
	const title = boundedText(p, "title", 256, true);
	const prBody = boundedText(p, "body", 65536, false);
	const head = branchName(p, "head");
	const requestedBase = p.base === void 0 ? void 0 : branchName(p, "base");
	if (requestedBase !== void 0 && requestedBase === head) throw new CapabilityError("invalid_params", "head and base must differ");
	return withGithub({
		account_login: owner,
		account_id: GITHUB_ACCOUNT_REGISTRY[owner],
		purpose: "github.pr.create_draft",
		repositories: [repo],
		permissions: {
			pull_requests: "write",
			metadata: "read"
		}
	}, ctx, audit, async (gh) => {
		let base = requestedBase;
		if (base === void 0) {
			const repoRes = await gh.request("GET", repoPath(owner, repo));
			if (!repoRes.ok) return githubFailure(repoRes, audit);
			base = str(repoRes.json?.default_branch);
			if (!base) return {
				ok: false,
				error: "default_branch_unknown",
				audit
			};
			if (base === head) return {
				ok: false,
				error: "invalid_params",
				detail: "head is the default branch; nothing to propose",
				audit
			};
		}
		const body = {
			title,
			head,
			base,
			draft: true
		};
		if (prBody !== void 0) body.body = prBody;
		const res = await gh.request("POST", `${repoPath(owner, repo)}/pulls`, { body });
		if (!res.ok) return githubFailure(res, audit);
		const pr = res.json ?? {};
		return {
			ok: true,
			data: {
				number: typeof pr.number === "number" ? pr.number : void 0,
				html_url: str(pr.html_url),
				draft: typeof pr.draft === "boolean" ? pr.draft : void 0,
				state: str(pr.state),
				head: str(pr.head?.ref) ?? head,
				base: str(pr.base?.ref) ?? base
			},
			audit
		};
	});
});
/** Capability ID → handler. */
var GITHUB_CAPABILITIES = Object.freeze({
	"github.repo.read": githubRepoGet,
	"github.repo.transfer": githubRepoTransfer,
	"github.contents.write": githubContentsWrite,
	"github.pr.create_draft": githubPrCreateDraft
});
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
/**
* Sanitized rotation/purge failure. `code` is a short stable code; the message
* is fixed text. `providerRotated` = the provider has (or may have) already
* invalidated the old secret.
*/
var RotationError = class extends EntryError {
	providerRotated;
	constructor(code, message, providerRotated = false) {
		super(code, message);
		this.name = "RotationError";
		this.providerRotated = providerRotated;
	}
};
var CODE_PATTERN = /^[a-z0-9_]{1,64}$/;
var ROTATOR_TIMEOUT_MS = 15e3;
var MAX_PROVIDER_BODY_BYTES = 65536;
var PUT_BACKOFF_MS = 250;
/** The code of the worst case: the provider rotated, the new secret is not in the vault. */
var ROTATED_BUT_NOT_STORED = "rotated_but_not_stored";
var CLOUDFLARE_API = "https://api.cloudflare.com/client/v4";
var CLOUDFLARE_TOKEN_ID = /^[0-9a-f]{32}$/;
function isCloudflareSite(site) {
	return site === "cloudflare.com" || site.endsWith(".cloudflare.com");
}
async function readCapped(res, limit) {
	const buf = Buffer.from(await res.arrayBuffer());
	if (buf.length > limit) throw new Error("too large");
	return buf.toString("utf8");
}
var registry = [{
	provider: "cloudflare",
	supports(entry) {
		return entry.kind === "api_key" && isCloudflareSite(entry.site) && typeof entry.provider_token_id === "string" && CLOUDFLARE_TOKEN_ID.test(entry.provider_token_id);
	},
	async rotate(currentSecret, entry, deps) {
		if (!this.supports(entry)) throw new RotationError("rotation_unsupported", "This entry cannot be auto-rotated");
		let res;
		try {
			res = await deps.fetch(`${CLOUDFLARE_API}/user/tokens/${entry.provider_token_id}/value`, {
				method: "PUT",
				headers: {
					authorization: `Bearer ${currentSecret}`,
					"content-type": "application/json",
					accept: "application/json"
				},
				body: "{}",
				redirect: "error",
				signal: AbortSignal.timeout(deps.timeoutMs)
			});
		} catch {
			throw new RotationError("provider_unreachable", "The provider could not be reached");
		}
		if (!res.ok) {
			await res.body?.cancel().catch(() => void 0);
			throw new RotationError(`provider_http_${res.status}`, "The provider refused the rotation");
		}
		let value;
		let success;
		try {
			const parsed = JSON.parse(await readCapped(res, MAX_PROVIDER_BODY_BYTES));
			value = parsed?.result;
			success = parsed?.success;
			if (typeof value === "string") registerSecretForRedaction(value);
		} catch {
			throw new RotationError(ROTATED_BUT_NOT_STORED, "The provider rotated the secret but its answer was unreadable", true);
		}
		if (success !== true || typeof value !== "string" || value.trim().length < 8) throw new RotationError(ROTATED_BUT_NOT_STORED, "The provider answered 2xx without a usable new secret", true);
		return { newSecret: value.trim() };
	}
}];
function findRotator(entry, rotators = registry) {
	for (const r of rotators) try {
		if (r.supports(entry)) return r;
	} catch {}
	return null;
}
var DEFAULT_ACTOR = "local:rotation";
var inFlight = /* @__PURE__ */ new Set();
function actorOf(deps) {
	const a = deps.actor;
	return typeof a === "string" && a.length > 0 && a.length <= 200 ? a : DEFAULT_ACTOR;
}
function resourceOf(row) {
	return row ? `entry:${row.site}/${row.account}` : "entry:unknown";
}
function refOf(row) {
	return row ? `vault://entry/${row.id}` : void 0;
}
function safeCode(err, fallback) {
	const code = err instanceof EntryError ? err.code : fallback;
	return CODE_PATTERN.test(code) ? code : fallback;
}
async function setError(v, id, code) {
	await v.entries.setRotationError(id, CODE_PATTERN.test(code) ? code : "rotation_failed", v.nowIso).catch(() => null);
}
/**
* Auto-rotate one entry now (any rotation_mode: the owner may force it).
* Throws RotationError/EntryError with a short code; see the module header for
* the ordering and the worst case.
*/
async function rotateEntry(id, deps = {}) {
	const v = openEntryVault(deps);
	const started = Date.now();
	const actor = actorOf(deps);
	const row = typeof id === "string" && /^ve_[0-9a-f]{32}$/.test(id) ? await v.entries.get(id) : null;
	const rotator = row ? findRotator(row, deps.rotators) : null;
	const ledgerRow = (result, error) => ({
		client_id: actor,
		capability: "vault.entry.rotate",
		resource: resourceOf(row),
		credential_ref: refOf(row),
		decision: "allow",
		tier: 3,
		result,
		error,
		duration_ms: Date.now() - started,
		task: rotator ? `auto-rotate (${rotator.provider})` : "auto-rotate"
	});
	/** Record the failed attempt (ledger + last_rotation_error) and throw. */
	const fail = async (err) => {
		const code = safeCode(err, "rotation_failed");
		if (row && row.status !== "deleted") await setError(v, row.id, code);
		await v.ledger(ledgerRow("error", code), false);
		log.warn("vault_entry_rotation_failed", {
			entry_id: row?.id ?? "unknown",
			site: row?.site,
			error: code
		});
		throw err;
	};
	if (!row || row.status === "deleted") return fail(new RotationError("entry_not_found", "No such entry"));
	if (row.status !== "active") return fail(new RotationError("entry_needs_reentry", "This entry needs its secret re-entered; it cannot be rotated"));
	if (!rotator) return fail(new RotationError("rotation_unsupported", "No rotator supports this entry (site, kind or provider_token_id)"));
	if (inFlight.has(row.id)) return fail(new RotationError("rotation_in_progress", "This entry is already being rotated"));
	inFlight.add(row.id);
	try {
		let current;
		try {
			current = await v.readSecret(row);
		} catch (err) {
			return await fail(err instanceof EntryError ? err : new RotationError("vault_unavailable", "The vault could not be reached"));
		}
		let next;
		try {
			const out = await rotator.rotate(current, row, {
				fetch: deps.rotatorFetch ?? globalThis.fetch,
				timeoutMs: ROTATOR_TIMEOUT_MS
			});
			next = typeof out?.newSecret === "string" ? out.newSecret : "";
			if (next) registerSecretForRedaction(next);
		} catch (err) {
			const e = err instanceof RotationError ? err : new RotationError("rotator_failed", "The rotator failed");
			if (e.providerRotated) return await lost(v, row, e, ledgerRow);
			return await fail(e);
		}
		if (next === current) return await fail(new RotationError("provider_returned_same_secret", "The provider returned the same secret"));
		if (next.length < 8 || next.length > 4096) return await lost(v, row, new RotationError(ROTATED_BUT_NOT_STORED, "The provider rotated the secret but returned nothing storable", true), ledgerRow);
		const sleep = deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
		let stored = false;
		for (let attempt = 1; attempt <= 5 && !stored; attempt += 1) try {
			await v.writeSecret(row, next);
			stored = true;
		} catch {
			log.error("vault_entry_rotation_put_retry", {
				entry_id: row.id,
				attempt,
				of: 5
			});
			if (attempt < 5) await sleep(PUT_BACKOFF_MS * 2 ** (attempt - 1));
		}
		if (!stored) return await lost(v, row, new RotationError(ROTATED_BUT_NOT_STORED, "The provider rotated the secret but the vault could not store the new one; re-enter a fresh credential", true), ledgerRow);
		const warnings = [];
		const fingerprint = secretFingerprint(next);
		let updated = null;
		for (let attempt = 0; attempt < 2 && !updated; attempt += 1) updated = await v.entries.replaceSecretMeta(row.id, fingerprint, next.length, v.nowIso).catch(() => null);
		if (!updated) {
			warnings.push("metadata_update_failed");
			log.error("vault_entry_rotation_metadata_stale", { entry_id: row.id });
		}
		try {
			await v.ledger(ledgerRow("ok"), true);
		} catch {
			warnings.push("ledger_unavailable");
		}
		log.info("vault_entry_rotated", {
			entry_id: row.id,
			site: row.site,
			provider: rotator.provider,
			warnings: warnings.join(",")
		});
		return {
			entry: updated ?? row,
			provider: rotator.provider,
			warnings
		};
	} finally {
		inFlight.delete(row.id);
	}
}
/** The worst case: surface it loudly, stop the dead token being used, record it, throw. */
async function lost(v, row, err, ledgerRow) {
	log.error("vault_entry_rotation_SECRET_LOST", {
		entry_id: row.id,
		site: row.site,
		error: ROTATED_BUT_NOT_STORED,
		action: "roll the token again at the provider and re-enter it on a card"
	});
	await v.entries.flag(row.id, "auto-rotation: the provider rotated the secret but the new one was not stored; re-enter a fresh one", v.nowIso).catch(() => null);
	await setError(v, row.id, ROTATED_BUT_NOT_STORED);
	await v.ledger(ledgerRow("error", ROTATED_BUT_NOT_STORED), false);
	throw new RotationError(ROTATED_BUT_NOT_STORED, err.message, true);
}
/**
* Owner action: set the rotation policy. mode "auto" is refused unless a
* registered rotator supports the entry with the resulting provider_token_id,
* so an entry can never sit in "auto" with nothing able to rotate it.
*/
async function setEntryRotation(id, policy, deps = {}) {
	const v = openEntryVault(deps);
	const current = typeof id === "string" && /^ve_[0-9a-f]{32}$/.test(id) ? await v.entries.get(id) : null;
	if (!current || current.status === "deleted") throw new EntryError("entry_not_found", "No such entry");
	if (policy?.mode === "auto") {
		const tokenId = policy.provider_token_id === void 0 ? current.provider_token_id : policy.provider_token_id === null ? null : String(policy.provider_token_id).trim();
		if (!findRotator({
			...current,
			provider_token_id: tokenId
		}, deps.rotators)) throw new RotationError("rotation_unsupported", "No rotator supports this entry. Auto-rotation currently covers Cloudflare API tokens (site cloudflare.com, kind api_key, provider_token_id = the 32-hex token ID). Use mode manual.");
	}
	const entry = await setRotationPolicy(id, policy, deps);
	return {
		entry,
		auto_supported: findRotator(entry, deps.rotators) !== null
	};
}
/**
* Irreversibly destroy an entry (active, needs_reentry or soft-deleted): the
* stored secret, the row, its cards and every consent grant. Idempotent until
* the row is gone: a failed purge can simply be run again. Throws EntryError
* with a short code and reports success only after the secret is destroyed and
* the purge is in the ledger.
*/
async function purgeEntry(id, deps = {}) {
	const v = openEntryVault(deps);
	const started = Date.now();
	const actor = actorOf(deps);
	const row = typeof id === "string" && /^ve_[0-9a-f]{32}$/.test(id) ? await v.entries.get(id) : null;
	const ledgerRow = (result, error) => ({
		client_id: actor,
		capability: "vault.entry.purge",
		resource: resourceOf(row),
		credential_ref: refOf(row),
		decision: "allow",
		tier: 3,
		result,
		error,
		duration_ms: Date.now() - started
	});
	const fail = async (err) => {
		await v.ledger(ledgerRow("error", safeCode(err, "purge_failed")), false);
		log.error("vault_entry_purge_failed", {
			entry_id: row?.id ?? "unknown",
			site: row?.site,
			error: safeCode(err, "purge_failed")
		});
		throw err;
	};
	if (!row) return fail(new EntryError("entry_not_found", "No such entry"));
	if (row.status !== "deleted") {
		if (!await v.entries.markDeleted(row.id, v.nowIso).catch(() => null)) return fail(new EntryError("entry_store_failed", "The entry could not be marked deleted"));
	}
	let how;
	try {
		how = await v.destroySecret(row);
	} catch (err) {
		return fail(err instanceof EntryError ? err : new EntryError("purge_secret_not_destroyed", "The secret could not be destroyed"));
	}
	try {
		await v.ledger(ledgerRow("ok"), true);
	} catch {
		log.error("vault_entry_purge_unrecorded", { entry_id: row.id });
		throw new EntryError("ledger_unavailable", "The secret was destroyed but the purge could not be recorded; the entry row is kept (deleted). Run the purge again.");
	}
	try {
		const grants = deps.grants ?? getDefaultEntryGrantStore();
		const held = await grants.list({ entry_id: row.id });
		let grantsRemoved = 0;
		for (const clientId of new Set(held.map((g) => g.client_id))) if (await grants.remove(clientId, row.id)) grantsRemoved += held.filter((g) => g.client_id === clientId).length;
		if ((await grants.list({ entry_id: row.id })).length > 0) throw new Error("grants remain");
		const cardsRemoved = await v.cards.deleteForEntry(row.id);
		if (!await v.entries.hardDelete(row.id) && await v.entries.get(row.id)) throw new Error("row remains");
		log.warn("vault_entry_purged", {
			entry_id: row.id,
			site: row.site,
			secret_disposal: how,
			grants_removed: grantsRemoved
		});
		return {
			purged: true,
			entry_id: row.id,
			site: row.site,
			account: row.account,
			secret_disposal: how,
			grants_removed: grantsRemoved,
			cards_removed: cardsRemoved
		};
	} catch {
		return fail(new EntryError("purge_cleanup_failed", "The secret was destroyed but the entry's rows could not all be removed. Run the purge again."));
	}
}
/**
* DNS-pinned HTTPS transport for requests that carry a credential.
*
* The problem it closes: "resolve the host, check the addresses, then
* fetch(url)" resolves the name twice. A DNS-rebinding attacker answers the
* first lookup (the one that is checked) with a public address and the second
* (the one that is used) with 127.0.0.1, 169.254.169.254 or an RFC 1918
* address, and the request, Authorization header included, goes inside.
*
* `pinnedFetch` never resolves anything. The caller hands it the addresses it
* already validated; the connection is made through a `lookup` that can only
* answer with those, and after the TLS handshake the socket's remote address
* is checked again before a single request byte (headers included) is written.
*
*   - SNI and the Host header are the original hostname, so the certificate
*     is verified against the hostname, exactly as with a normal request.
*     TLS verification is never relaxed here.
*   - Redirects are not followed: the 3xx and its Location go back to the
*     caller untouched.
*   - One fresh connection per request (`agent: false`): no pooled socket to
*     an address validated for an earlier request can be reused.
*   - A timeout covers connect + TLS + headers + body, and the body is
*     streamed and abandoned past `maxResponseBytes`.
*   - Every failure is a fixed code. No error text is built from request
*     headers or bodies, so a secret cannot ride out in an exception.
*/
var DEFAULT_TIMEOUT_MS = 12e3;
var DEFAULT_MAX_RESPONSE_BYTES = 1048576;
/** Statuses for which the Response constructor refuses a body. */
var NULL_BODY_STATUS = /* @__PURE__ */ new Set([
	204,
	205,
	304
]);
/** An error whose message is a fixed code. `detail` is a Node error code (ECONNREFUSED, CERT_HAS_EXPIRED…), never free text. */
var PinnedFetchError = class extends Error {
	code;
	detail;
	constructor(code, detail) {
		super(code);
		this.name = code === "request_timeout" ? "TimeoutError" : "PinnedFetchError";
		this.code = code;
		if (detail) this.detail = detail;
	}
};
function nodeErrorCode(err) {
	const code = err?.code;
	return typeof code === "string" && /^[A-Z0-9_]{1,64}$/.test(code) ? code : void 0;
}
/**
* A `lookup` that ignores the hostname and answers only from `addresses`.
* Exported for tests; `pinnedFetch` is the only production caller.
*/
function pinnedLookup(addresses) {
	const records = addresses.map((address) => ({
		address,
		family: isIP(address)
	}));
	return (_hostname, options, callback) => {
		const wanted = typeof options === "object" && options !== null && (options.family === 4 || options.family === 6) ? options.family : 0;
		const usable = wanted ? records.filter((r) => r.family === wanted) : records;
		if (usable.length === 0) {
			callback(Object.assign(/* @__PURE__ */ new Error("hostname_not_allowed"), { code: "ENOTFOUND" }), "", 0);
			return;
		}
		if (typeof options === "object" && options !== null && options.all) callback(null, usable.map((r) => ({ ...r })));
		else callback(null, usable[0].address, usable[0].family);
	};
}
/**
* One HTTPS request to `url`, connected only to one of `options.addresses`.
* Resolves with a standard `Response` whose body is already bounded by
* `maxResponseBytes`. Rejects with a `PinnedFetchError`:
*   hostname_not_allowed  bad URL, an address that is not a public IP literal,
*                         or a socket that connected outside the pinned set
*   request_timeout       the deadline passed (name: "TimeoutError")
*   response_too_large    the body exceeded the cap
*   request_aborted       the caller's signal fired
*   site_request_failed   connect / TLS / protocol failure (`detail` = Node code)
*/
var pinnedFetch = async (input, init, options) => {
	let url;
	try {
		url = input instanceof URL ? input : new URL(input);
	} catch {
		throw new PinnedFetchError("hostname_not_allowed");
	}
	if (url.protocol !== "https:" || url.username || url.password || !url.hostname) throw new PinnedFetchError("hostname_not_allowed");
	const hostname = url.hostname.replace(/^\[(.*)\]$/, "$1");
	const allowPrivate = options.testOnly?.allowPrivateAddresses === true;
	const pinned = /* @__PURE__ */ new Map();
	for (const address of options.addresses) {
		const canonical = isIP(address) ? canonicalIp(address) : null;
		if (!canonical) throw new PinnedFetchError("hostname_not_allowed");
		if (!allowPrivate && isPrivateOrLinkLocalIp(address)) throw new PinnedFetchError("hostname_not_allowed");
		pinned.set(canonical, address);
	}
	if (pinned.size === 0) throw new PinnedFetchError("hostname_not_allowed");
	if (isIP(hostname)) {
		const literal = canonicalIp(hostname);
		if (!literal || !pinned.has(literal)) throw new PinnedFetchError("hostname_not_allowed");
	}
	const headers = new Headers(init.headers ?? void 0);
	headers.delete("host");
	headers.delete("content-length");
	headers.delete("transfer-encoding");
	headers.set("connection", "close");
	headers.set("accept-encoding", "identity");
	const method = (init.method ?? "GET").toUpperCase();
	const body = init.body === void 0 || init.body === null ? null : typeof init.body === "string" ? Buffer.from(init.body, "utf8") : Buffer.from(init.body);
	if (body) headers.set("content-length", String(body.byteLength));
	const headerList = {};
	headers.forEach((value, name) => {
		headerList[name] = value;
	});
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const maxBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
	const signal = init.signal ?? null;
	if (signal?.aborted) throw new PinnedFetchError(signal.reason instanceof Error && signal.reason.name === "TimeoutError" ? "request_timeout" : "request_aborted");
	return new Promise((resolve, reject) => {
		let settled = false;
		let req = null;
		const cleanup = () => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", onAbort);
		};
		const fail = (error) => {
			if (settled) return;
			settled = true;
			cleanup();
			req?.destroy();
			reject(error);
		};
		const succeed = (response) => {
			if (settled) return;
			settled = true;
			cleanup();
			resolve(response);
		};
		const onAbort = () => fail(new PinnedFetchError(signal?.reason instanceof Error && signal.reason.name === "TimeoutError" ? "request_timeout" : "request_aborted"));
		const timer = setTimeout(() => fail(new PinnedFetchError("request_timeout")), timeoutMs);
		signal?.addEventListener("abort", onAbort, { once: true });
		try {
			req = nodeHTTPS.request({
				protocol: "https:",
				host: hostname,
				servername: isIP(hostname) ? void 0 : hostname,
				port: url.port ? Number(url.port) : 443,
				method,
				path: `${url.pathname}${url.search}`,
				headers: headerList,
				agent: false,
				lookup: options.testOnly?.lookup ?? pinnedLookup([...pinned.values()]),
				...options.testOnly?.ca ? { ca: options.testOnly.ca } : {}
			});
		} catch (err) {
			fail(new PinnedFetchError("site_request_failed", nodeErrorCode(err)));
			return;
		}
		const request = req;
		request.once("socket", (socket) => {
			const verifyThenSend = () => {
				const remote = socket.remoteAddress ? canonicalIp(socket.remoteAddress) : null;
				if (!remote || !pinned.has(remote) || !allowPrivate && isPrivateOrLinkLocalIp(remote)) {
					socket.destroy();
					fail(new PinnedFetchError("hostname_not_allowed"));
					return;
				}
				try {
					options.onConnect?.(remote);
				} catch {}
				if (settled) return;
				request.end(body ?? void 0);
			};
			socket.once("secureConnect", verifyThenSend);
		});
		request.once("error", (err) => fail(new PinnedFetchError("site_request_failed", nodeErrorCode(err))));
		request.once("response", (res) => {
			const responseHeaders = new Headers();
			for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) try {
				responseHeaders.append(res.rawHeaders[i], res.rawHeaders[i + 1]);
			} catch {}
			const status = res.statusCode ?? 0;
			if (status < 200 || status > 599) {
				fail(new PinnedFetchError("site_request_failed", "BAD_STATUS"));
				return;
			}
			const declared = Number(res.headers["content-length"]);
			if (method !== "HEAD" && Number.isFinite(declared) && declared > maxBytes) {
				fail(new PinnedFetchError("response_too_large"));
				return;
			}
			const chunks = [];
			let total = 0;
			res.on("data", (chunk) => {
				total += chunk.byteLength;
				if (total > maxBytes) {
					fail(new PinnedFetchError("response_too_large"));
					return;
				}
				chunks.push(chunk);
			});
			res.once("error", (err) => fail(new PinnedFetchError("site_request_failed", nodeErrorCode(err))));
			res.once("aborted", () => fail(new PinnedFetchError("site_request_failed", "ECONNRESET")));
			res.once("end", () => {
				const noBody = method === "HEAD" || NULL_BODY_STATUS.has(status) || total === 0;
				try {
					succeed(new Response(noBody ? null : Buffer.concat(chunks), {
						status,
						headers: responseHeaders
					}));
				} catch {
					fail(new PinnedFetchError("site_request_failed", "BAD_RESPONSE"));
				}
			});
		});
	});
};
/**
* Vault v2 ledger anchoring — publish the chain head OUTSIDE the database.
*
* `ledger.ts` proves the chain is internally consistent. It cannot see two
* attacks by someone with database access: deleting the newest N rows (the
* remaining prefix is still a valid chain) and rebuilding the whole chain.
* Both change what the head is, so a copy of the head kept where the database
* writer cannot reach it exposes them.
*
* The anchor is one Telegram message to the owner's chat (the same bot and
* chat as approvals). Its whole text is one machine-parseable line:
*
*   ECHO-VAULT-ANCHOR v1 seq=<n> hash=<64 hex> rows=<n> at=<ISO-8601 UTC ms> mac=<64 hex>
*   ECHO-VAULT-ANCHOR v1 seq=<n> hash=<64 hex> rows=<n> at=<ISO-8601 UTC ms> unsigned
*
* `mac` = HMAC-SHA256(ECHO_VAULT_ANCHOR_KEY, everything before " mac="), hex.
* Without the key the line ends in the literal word `unsigned`. The Telegram
* message id is the external receipt. Only seq, the chain hash, the row count
* and a timestamp leave the process — never a ledger row's payload, never a
* secret. The key is server-only: keep it out of the database.
*
* `vault_ledger_anchors` (migrations/0008) is a local INDEX of what was sent.
* It lives in the same database as the ledger, so it is not the proof — the
* message is. Verify a line copied from Telegram with `verifyAgainstAnchor`.
*
* Verdicts:
*   ok                     the ledger still has the anchored row with the anchored hash, and at least as many rows
*   rewritten              the row at the anchored seq has a different hash (or is gone while later rows exist)
*   truncated              the ledger ends before the anchored seq / has fewer rows, and the anchor is authentic
*                          (valid mac, or it matches a local anchor record)
*   anchor_ahead_of_ledger same shortfall, but the anchor could not be authenticated (unsigned or no key
*                          configured, and no local record): truncation, or a line from another vault / a forgery
*   anchor_mac_invalid     a key is configured and the line's mac is missing or wrong
*/
var ANCHOR_KEY_ENV = "ECHO_VAULT_ANCHOR_KEY";
var ANCHOR_CHANNEL_TELEGRAM = "telegram";
var ANCHOR_PREFIX = "ECHO-VAULT-ANCHOR v1";
var ALERT_PREFIX = "ECHO-VAULT-ANCHOR ALERT v1";
var MIN_ANCHOR_KEY_LENGTH = 32;
var MAX_LINE_LENGTH = 400;
var COUNT_BATCH = 1e3;
var ANCHOR_LINE_RE = /^ECHO-VAULT-ANCHOR v1 seq=([1-9][0-9]{0,15}) hash=([0-9a-f]{64}) rows=([1-9][0-9]{0,15}) at=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z) (?:mac=([0-9a-f]{64})|unsigned)$/;
/** Fixed alert vocabulary: nothing derived from a ledger row is ever sent. */
var ALERT_REASONS = /* @__PURE__ */ new Set([
	"seq_gap",
	"prev_hash_mismatch",
	"hash_mismatch",
	"hmac_missing",
	"hmac_mismatch",
	"truncated",
	"rewritten",
	"anchor_ahead_of_ledger"
]);
/** Fixed-code failure; the message never carries key material or upstream text. */
var AnchorError = class extends Error {
	code;
	constructor(code) {
		super(code);
		this.name = "AnchorError";
		this.code = code;
	}
};
/** The anchor key, or null when unset. Throws `anchor_key_too_short` rather than silently signing weakly or not at all. */
function readAnchorKey(env = process.env) {
	const raw = env[ANCHOR_KEY_ENV];
	if (raw === void 0 || raw === "") return null;
	if (raw.length < MIN_ANCHOR_KEY_LENGTH) throw new AnchorError("anchor_key_too_short");
	registerSecretForRedaction(raw);
	return Buffer.from(raw, "utf8");
}
function signedPart(anchor) {
	return `${ANCHOR_PREFIX} seq=${anchor.seq} hash=${anchor.hash} rows=${anchor.row_count} at=${anchor.at}`;
}
/** HMAC-SHA256 hex over the line up to (not including) " mac=". */
function computeAnchorMac(key, anchor) {
	return createHmac("sha256", key).update(signedPart(anchor), "utf8").digest("hex");
}
/** The exact Telegram message text. */
function formatAnchorLine(anchor, key) {
	return `${signedPart(anchor)} ${key ? `mac=${computeAnchorMac(key, anchor)}` : "unsigned"}`;
}
function validIso(at) {
	const ms = Date.parse(at);
	return Number.isFinite(ms) && new Date(ms).toISOString() === at;
}
/**
* Strict parser: the input must be exactly one anchor line — no surrounding
* whitespace, no extra fields, canonical numbers and timestamp. Anything else
* returns null.
*/
function parseAnchorLine(text) {
	if (typeof text !== "string" || text.length > MAX_LINE_LENGTH) return null;
	const m = ANCHOR_LINE_RE.exec(text);
	if (!m) return null;
	const seq = Number(m[1]);
	const rowCount = Number(m[3]);
	if (!Number.isSafeInteger(seq) || !Number.isSafeInteger(rowCount)) return null;
	if (rowCount > seq) return null;
	if (!validIso(m[4])) return null;
	const anchor = {
		seq,
		hash: m[2],
		row_count: rowCount,
		at: m[4]
	};
	if (m[5] !== void 0) anchor.mac = m[5];
	return anchor;
}
function hexEqual(a, b) {
	const ab = Buffer.from(a, "utf8");
	const bb = Buffer.from(b, "utf8");
	return ab.length === bb.length && timingSafeEqual(ab, bb);
}
async function countRows(store) {
	let count = 0;
	let afterSeq = 0;
	for (;;) {
		const batch = await store.scanAscending(afterSeq, COUNT_BATCH);
		if (batch.length === 0) return count;
		count += batch.length;
		afterSeq = batch[batch.length - 1].seq;
	}
}
async function rowHashAt(store, seq) {
	const [row] = await store.scanAscending(seq - 1, 1);
	return row && row.seq === seq ? row.hash : null;
}
var COLUMNS = "seq, hash, row_count, anchored_at, channel, external_id, mac";
function toIso(value) {
	return (value instanceof Date ? value : new Date(String(value))).toISOString();
}
function rowToRecord(row) {
	const record = {
		seq: Number(row.seq),
		hash: String(row.hash),
		row_count: Number(row.row_count),
		anchored_at: toIso(row.anchored_at),
		channel: String(row.channel),
		external_id: String(row.external_id)
	};
	if (row.mac != null) record.mac = String(row.mac);
	return record;
}
/** Postgres/PGlite index over `vault_ledger_anchors` (migrations/0008_vault_ledger_anchors.sql). */
var SqlAnchorStore = class {
	kind = "sql";
	getSql;
	constructor(getSql) {
		this.getSql = getSql ?? (async () => {
			return (await import("./db-YAhc1k3o.mjs")).getSql();
		});
	}
	async insert(r) {
		return (await (await this.getSql()).query(`INSERT INTO vault_ledger_anchors (${COLUMNS})
       VALUES ($1::bigint, $2::text, $3::bigint, $4::timestamptz, $5::text, $6::text, $7::text)
       ON CONFLICT (seq, channel) DO NOTHING
       RETURNING seq`, [
			r.seq,
			r.hash,
			r.row_count,
			r.anchored_at,
			r.channel,
			r.external_id,
			r.mac ?? null
		])).length === 1 ? "inserted" : "exists";
	}
	async latest(channel) {
		const rows = await (await this.getSql()).query(`SELECT ${COLUMNS} FROM vault_ledger_anchors WHERE channel = $1::text ORDER BY seq DESC LIMIT 1`, [channel]);
		return rows[0] ? rowToRecord(rows[0]) : null;
	}
	async find(seq, channel) {
		const rows = await (await this.getSql()).query(`SELECT ${COLUMNS} FROM vault_ledger_anchors WHERE seq = $1::bigint AND channel = $2::text`, [seq, channel]);
		return rows[0] ? rowToRecord(rows[0]) : null;
	}
};
var defaultStore = null;
/** The process-wide index: SQL (Neon/Postgres or PGlite via getSql) unless replaced. */
function getDefaultAnchorStore() {
	defaultStore ??= new SqlAnchorStore();
	return defaultStore;
}
/**
* Compare an anchor with the ledger as it is now. See the module header for
* the verdicts. Throws only for storage errors and `anchor_key_too_short`.
*/
async function verifyAgainstAnchor(anchor, store, opts = {}) {
	const check = {
		verdict: "ok",
		mac_checked: false,
		known_locally: false,
		head_seq: (await store.head())?.seq ?? 0
	};
	const done = (verdict) => ({
		...check,
		verdict
	});
	const key = opts.skipMac ? null : readAnchorKey(opts.env ?? process.env);
	if (key) {
		if (!anchor.mac || !hexEqual(anchor.mac, computeAnchorMac(key, anchor))) return done("anchor_mac_invalid");
		check.mac_checked = true;
	}
	if (opts.anchors) {
		const known = await opts.anchors.find(anchor.seq, opts.channel ?? "telegram");
		check.known_locally = !!known && known.hash === anchor.hash && known.row_count === anchor.row_count;
	}
	const authentic = check.mac_checked || check.known_locally || opts.skipMac === true;
	const hashAtSeq = await rowHashAt(store, anchor.seq);
	if (hashAtSeq === null) {
		if (check.head_seq < anchor.seq) return done(authentic ? "truncated" : "anchor_ahead_of_ledger");
		return done("rewritten");
	}
	if (!hexEqual(hashAtSeq, anchor.hash)) return done("rewritten");
	if ((opts.rowCount ?? await countRows(store)) < anchor.row_count) return done("truncated");
	return done("ok");
}
function recordToAnchor(record) {
	const anchor = {
		seq: record.seq,
		hash: record.hash,
		row_count: record.row_count,
		at: record.anchored_at
	};
	if (record.mac !== void 0) anchor.mac = record.mac;
	return anchor;
}
function errorCode(err, fallback) {
	if (err instanceof TelegramApiError || err instanceof AnchorError) return err.code;
	return fallback;
}
async function sendOwnerMessage(text, deps) {
	const env = deps.env ?? process.env;
	const chatId = approverTelegramId(env);
	if (!chatId) throw new TelegramApiError("sendMessage", "telegram_approver_missing");
	const id = (await callBotApi("sendMessage", {
		chat_id: chatId,
		text,
		link_preview_options: { is_disabled: true }
	}, {
		fetch: deps.fetch,
		env
	}))?.message_id;
	if (typeof id !== "number" || !Number.isSafeInteger(id) || id <= 0) throw new TelegramApiError("sendMessage", "telegram_no_message_id");
	return String(id);
}
/** ALERT instead of an anchor. Fixed vocabulary + a sequence number; best effort. */
async function sendAlert(reason, seq, deps) {
	const code = ALERT_REASONS.has(reason) ? reason : "chain_invalid";
	const at = new Date((deps.now ?? Date.now)()).toISOString();
	const text = [`${ALERT_PREFIX} reason=${code} seq=${Number.isSafeInteger(seq) && seq >= 0 ? seq : 0} at=${at}`, "ECHO Vault: the audit ledger failed verification. No anchor was recorded. Investigate before trusting the audit log."].join("\n");
	log.error("ledger_anchor_alert", {
		reason: code,
		seq
	});
	try {
		await sendOwnerMessage(text, deps);
		return true;
	} catch (err) {
		log.error("ledger_anchor_alert_failed", { code: errorCode(err, "unknown") });
		return false;
	}
}
/**
* Verify the chain, then publish its head to the owner's Telegram chat and
* record the receipt. Never throws.
*
*  - broken chain, or a ledger that no longer matches the newest recorded
*    anchor (truncated / rewritten) → an ALERT message, no anchor, `ok:false`
*  - head unchanged since the newest anchor → `unchanged`, nothing sent
*  - Telegram failure → `ok:false`, nothing recorded
*/
async function anchorHead(deps = {}) {
	const env = deps.env ?? process.env;
	const channel = ANCHOR_CHANNEL_TELEGRAM;
	let key;
	try {
		key = readAnchorKey(env);
	} catch (err) {
		return {
			ok: false,
			error: errorCode(err, "anchor_key_invalid")
		};
	}
	let ledger;
	let count;
	try {
		ledger = deps.ledger ?? getLedger();
		const verification = await ledger.verify();
		if (!verification.ok) {
			const reason = verification.reason.split(":")[0];
			const alertSent = await sendAlert(reason, verification.broken_at_seq, deps);
			return {
				ok: false,
				error: "ledger_unverified",
				reason: ALERT_REASONS.has(reason) ? reason : "chain_invalid",
				seq: verification.broken_at_seq,
				alert_sent: alertSent
			};
		}
		count = verification.count;
	} catch (err) {
		log.error("ledger_anchor_failed", { code: errorCode(err, "ledger_unavailable") });
		return {
			ok: false,
			error: errorCode(err, "ledger_unavailable")
		};
	}
	const anchors = deps.anchors ?? getDefaultAnchorStore();
	let last;
	let headHash;
	try {
		last = await anchors.latest(channel);
		headHash = count > 0 ? await rowHashAt(ledger.store, count) : null;
		if (last) {
			const check = await verifyAgainstAnchor(recordToAnchor(last), ledger.store, {
				rowCount: count,
				skipMac: true
			});
			if (check.verdict !== "ok") {
				const alertSent = await sendAlert(check.verdict, last.seq, deps);
				return {
					ok: false,
					error: `ledger_${check.verdict}`,
					reason: check.verdict,
					seq: last.seq,
					alert_sent: alertSent
				};
			}
		}
	} catch (err) {
		log.error("ledger_anchor_failed", { code: errorCode(err, "anchor_store_unavailable") });
		return {
			ok: false,
			error: errorCode(err, "anchor_store_unavailable")
		};
	}
	if (count === 0) return {
		ok: true,
		status: "empty"
	};
	if (headHash === null) return {
		ok: false,
		error: "ledger_changed_during_verify"
	};
	if (last && last.seq === count && last.hash === headHash) return {
		ok: true,
		status: "unchanged",
		seq: last.seq,
		anchored_at: last.anchored_at,
		channel,
		external_id: last.external_id
	};
	const anchor = {
		seq: count,
		hash: headHash,
		row_count: count,
		at: new Date((deps.now ?? Date.now)()).toISOString()
	};
	let externalId;
	try {
		externalId = await sendOwnerMessage(formatAnchorLine(anchor, key), deps);
	} catch (err) {
		log.error("ledger_anchor_failed", { code: errorCode(err, "telegram_error") });
		return {
			ok: false,
			error: errorCode(err, "telegram_error")
		};
	}
	const record = {
		seq: anchor.seq,
		hash: anchor.hash,
		row_count: anchor.row_count,
		anchored_at: anchor.at,
		channel,
		external_id: externalId
	};
	if (key) record.mac = computeAnchorMac(key, anchor);
	try {
		await anchors.insert(record);
	} catch {
		log.error("ledger_anchor_failed", {
			code: "anchor_record_failed",
			seq: anchor.seq,
			external_id: externalId
		});
		return {
			ok: false,
			error: "anchor_record_failed",
			seq: anchor.seq,
			external_id: externalId
		};
	}
	log.info("ledger_anchored", {
		seq: anchor.seq,
		channel,
		external_id: externalId,
		signed: key !== null
	});
	return {
		ok: true,
		status: "anchored",
		...anchor,
		signed: key !== null,
		channel,
		external_id: externalId
	};
}
/** Verdict for the newest recorded anchor (audit_verify), or null when nothing was anchored yet. */
async function newestAnchorVerdict(deps = {}, rowCount) {
	const last = await (deps.anchors ?? getDefaultAnchorStore()).latest(ANCHOR_CHANNEL_TELEGRAM);
	if (!last) return null;
	const store = (deps.ledger ?? getLedger()).store;
	const check = await verifyAgainstAnchor(recordToAnchor(last), store, {
		env: deps.env,
		rowCount
	});
	const verdict = check.verdict === "anchor_ahead_of_ledger" ? "truncated" : check.verdict;
	return {
		seq: last.seq,
		anchored_at: last.anchored_at,
		verdict
	};
}
/** Check a line copied from Telegram. Returns null when the line is malformed. */
async function verifyAnchorLine(line, deps = {}) {
	const anchor = parseAnchorLine(typeof line === "string" ? line.trim() : line);
	if (!anchor) return null;
	const store = (deps.ledger ?? getLedger()).store;
	return {
		...await verifyAgainstAnchor(anchor, store, {
			env: deps.env,
			anchors: deps.anchors ?? getDefaultAnchorStore()
		}),
		anchor: {
			seq: anchor.seq,
			hash: anchor.hash,
			row_count: anchor.row_count,
			at: anchor.at,
			signed: anchor.mac !== void 0
		}
	};
}
/**
* Vault v2 gateway — the ONE entry point for every tool call, on every
* transport (HTTP MCP, REST, stdio). Nothing else may execute a tool.
*
*   dispatchTool(identity, name, args)
*     1. tool name → { capability, resource, params } (a "plan"; no side effects
*        beyond metadata lookups)
*     2. evaluatePolicy(request), then the awaited enforceRateLimits(…)
*     3. deny      → ledger(denied), { ok:false, error:<reason> }
*        escalate  → with args.approval_id: consumeApproval(id, request) must be
*                    "ok" (single use, same client, same params, unexpired);
*                    without: createApproval → Telegram, ledger(pending_approval),
*                    { ok:false, error:"approval_required", approval_id, expires_at }
*        allow     → run
*     4. ledger(ok | error). A result that cannot be ledgered is not returned.
*
* `identity` comes from the transport's authentication (OAuth bearer token,
* workload token, the local stdio process, or the owner's passkey console
* session) — never from a caller-supplied header or argument. An `owner`
* identity is accepted only when owner-console.ts minted that very object
* (owner-identity.ts); no HTTP transport can produce one. `approval_id` is never part of the digested params, so a
* retry with the approval hashes to the same request the owner approved.
*
* Tiers come from policy-engine.ts. Three rules live here because they depend
* on the tool rather than the capability:
*
*   Generic proxy (`credential_use`, `provider_request`): the broker cannot
*   know what an arbitrary request does, so it classifies by HTTP method only.
*   GET/HEAD → `<provider>.api.read` (tier 0). Anything else →
*   `<provider>.api.write` (tier 2: every single request is approved on
*   Telegram), except Stripe, where a non-GET is a payment operation
*   (`payment.stripe.write`, tier 3: refused). There is no tier-1 carve-out
*   inside the proxy: reversible writes have their own tools
*   (github_create_branch, github_create_or_update_file, github_create_draft_pr)
*   whose handlers validate what is written.
*
*   Entry use (`entry_use`): one HTTPS request to the entry's own site with
*   the secret injected server-side. GET/HEAD → `vault.entry.use.read`
*   (tier 0) PLUS consent: a read-only use is allowed without a prompt only
*   when the client holds a matching, unexpired, unspent grant
*   (entry-grants.ts) scoped to that exact entry, host and request path (or a
*   path under it); otherwise the first such read needs one Telegram approval,
*   which creates a narrow grant (host + path_prefix, TTL ECHO_VAULT_GRANT_TTL_MS,
*   cap ECHO_VAULT_GRANT_MAX_USES). Each later covered read spends one use. The
*   owner withdraws a grant with revokeEntryGrant. Any other method →
*   `vault.entry.use.write` (tier 2): approved per request, every time, and it
*   neither needs nor creates a grant. A 401 from the site (bad credential)
*   flags that one entry for re-entry; a 403 (forbidden) returns site_forbidden
*   and leaves the entry active.
*
*   Entry transfer (`entry_transfer`, entry-transfer.ts): one POST/PUT/PATCH
*   to the DESTINATION entry's own site, authenticated with that entry, whose
*   JSON body carries the SOURCE entry's secret in the one field the agent
*   marked with a placeholder. `vault.entry.transfer` (tier 2): approved per
*   request, every time, no grant. The approval binds both entries, the
*   request, the body (with the placeholder) and the field. Neither secret is
*   returned; a 401 flags the destination entry only.
*
*   Contents write (`github_create_or_update_file`): policy-engine.ts makes
*   `agent/*` branches tier 1 and every other branch tier 2. The handler
*   (github-capabilities.ts, classifyContentsWrite) refuses the repository's
*   default branch unless this gateway passes allow_default_branch, which it
*   does only when an approval for this exact request was consumed.
*
* Secrets: results pass through redaction before they are returned; ledger
* rows are sanitized by ledger.ts; approval summaries by approvals.ts. Entry
* metadata returned to agents omits the secret's fingerprint and length.
*/
var gateway_exports = /* @__PURE__ */ __exportAll({
	INVARIANT: () => INVARIANT,
	TOOL_DEFINITIONS: () => TOOL_DEFINITIONS,
	dispatchTool: () => dispatchTool,
	grantConfig: () => grantConfig,
	isForbiddenToolName: () => isForbiddenToolName,
	listTools: () => listTools
});
/** Consent-grant TTL and use cap from the environment (change #1). */
var GRANT_TTL_DEFAULT_MS = 864e5;
var GRANT_MAX_USES_DEFAULT = 500;
function grantConfig(env = process.env) {
	const ttlRaw = env.ECHO_VAULT_GRANT_TTL_MS?.trim();
	let ttlMs = GRANT_TTL_DEFAULT_MS;
	if (ttlRaw) {
		const n = Number(ttlRaw);
		if (Number.isFinite(n) && n >= 1) ttlMs = Math.floor(n);
	}
	const usesRaw = env.ECHO_VAULT_GRANT_MAX_USES?.trim();
	let maxUses = GRANT_MAX_USES_DEFAULT;
	if (usesRaw) {
		if (usesRaw.toLowerCase() === "unlimited") maxUses = null;
		else {
			const n = Number(usesRaw);
			if (Number.isInteger(n) && n >= 0) maxUses = n;
		}
	}
	return {
		ttlMs,
		maxUses
	};
}
var APPROVAL_ID_PROP = {
	type: "string",
	description: "Only when retrying after an `approval_required` result: the approval_id it returned. Send the SAME arguments; the approval is single-use and bound to them."
};
var CREDENTIAL_REF_PROP = {
	type: "string",
	description: "Opaque vault://<provider>/<account> reference. Never a secret value."
};
var OWNER_PROP = {
	type: "string",
	description: "GitHub owner login."
};
var REPO_PROP = {
	type: "string",
	description: "Repository name."
};
var HTTP_METHODS = [
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"PATCH",
	"DELETE"
];
var PROVIDERS = [
	"github",
	"cloudflare",
	"openai",
	"stripe",
	"xai"
];
var ENTRY_USE_CONTENT_TYPES = [
	"application/json",
	"application/x-www-form-urlencoded",
	"text/plain"
];
function schema(properties, required = []) {
	return {
		type: "object",
		properties: {
			...properties,
			approval_id: APPROVAL_ID_PROP
		},
		required,
		additionalProperties: false
	};
}
var PROXY_NOTE = " GET is a read (tier 0). Any other method is tier 2: it returns `approval_required` and runs only after the owner approves that exact request; Stripe writes are refused.";
var TOOL_DEFINITIONS = Object.freeze([
	{
		name: "vault_status",
		description: "Broker status and invariant. Tier 0, scope vault.read. Never returns secrets.",
		inputSchema: schema({})
	},
	{
		name: "vault_list",
		description: "List opaque vault:// credential references with metadata only. Tier 0, scope vault.read.",
		inputSchema: schema({})
	},
	{
		name: "vault_find",
		description: "Search the canonical vault for candidate credentials by name. Returns service/username candidates only. Tier 0, scope vault.read.",
		inputSchema: schema({ query: {
			type: "string",
			minLength: 2
		} }, ["query"])
	},
	{
		name: "vault_metadata",
		description: "Metadata for one vault:// reference. Tier 0, scope vault.read.",
		inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP }, ["credential_ref"])
	},
	{
		name: "credential_health",
		description: "Verify a credential with a provider identity check (GitHub: GET /user). Returns account metadata. Tier 0, scope vault.read.",
		inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP }, ["credential_ref"])
	},
	{
		name: "github_get_user",
		description: "GitHub identity check via GET /user. Returns login and id. Tier 0, scope github.read.",
		inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP })
	},
	{
		name: "github_get_repository",
		description: "Repository metadata. Tier 0, scope github.read.",
		inputSchema: schema({
			credential_ref: CREDENTIAL_REF_PROP,
			owner: OWNER_PROP,
			repo: REPO_PROP
		}, ["owner", "repo"])
	},
	{
		name: "github_get_file",
		description: "Read one file from a repository. Tier 0, scope github.read.",
		inputSchema: schema({
			credential_ref: CREDENTIAL_REF_PROP,
			owner: OWNER_PROP,
			repo: REPO_PROP,
			path: { type: "string" },
			ref: {
				type: "string",
				description: "Branch, tag or commit SHA. Default: the default branch."
			}
		}, [
			"owner",
			"repo",
			"path"
		])
	},
	{
		name: "github_list_repositories",
		description: "Repositories visible to the GitHub credential. Tier 0, scope github.read.",
		inputSchema: schema({
			credential_ref: CREDENTIAL_REF_PROP,
			per_page: {
				type: "integer",
				minimum: 1,
				maximum: 100
			}
		})
	},
	{
		name: "github_create_branch",
		description: "Create a branch from a commit SHA. Tier 1 (reversible), scope github.write.",
		inputSchema: schema({
			credential_ref: CREDENTIAL_REF_PROP,
			owner: OWNER_PROP,
			repo: REPO_PROP,
			branch: {
				type: "string",
				description: "New branch name, without refs/heads/."
			},
			from_sha: {
				type: "string",
				pattern: "^[0-9a-f]{40}$"
			}
		}, [
			"owner",
			"repo",
			"branch",
			"from_sha"
		])
	},
	{
		name: "github_create_or_update_file",
		description: "Create or update one file. Scope github.write. Tier 1 on an `agent/*` branch; any other branch is tier 2 (returns `approval_required`; the owner approves that exact write, which is also the only way to write the default branch). Owner must be a registered account. Refuses .github/workflows/* and secret-shaped content.",
		inputSchema: schema({
			owner: OWNER_PROP,
			repo: REPO_PROP,
			path: { type: "string" },
			branch: {
				type: "string",
				description: "Target branch (required), without refs/heads/."
			},
			message: {
				type: "string",
				maxLength: 4096
			},
			content_base64: {
				type: "string",
				description: "File content, base64."
			},
			sha: {
				type: "string",
				description: "Blob SHA of the file being replaced (required when updating)."
			}
		}, [
			"owner",
			"repo",
			"path",
			"branch",
			"message",
			"content_base64"
		])
	},
	{
		name: "github_create_draft_pr",
		description: "Open a draft pull request within one repository. Tier 1, scope github.write. Owner must be a registered account.",
		inputSchema: schema({
			owner: OWNER_PROP,
			repo: REPO_PROP,
			title: {
				type: "string",
				maxLength: 256
			},
			head: {
				type: "string",
				description: "Branch with the changes."
			},
			base: {
				type: "string",
				description: "Branch to merge into. Default: the default branch."
			},
			body: {
				type: "string",
				maxLength: 65536
			}
		}, [
			"owner",
			"repo",
			"title",
			"head"
		])
	},
	{
		name: "github_repo_transfer",
		description: "Transfer a repository between the owner's registered GitHub accounts. Tier 2, scope github.write: returns `approval_required`; after the owner approves on Telegram, call again with the same arguments plus approval_id.",
		inputSchema: schema({
			owner: OWNER_PROP,
			repo: REPO_PROP,
			new_owner: { type: "string" },
			new_name: { type: "string" }
		}, [
			"owner",
			"repo",
			"new_owner"
		])
	},
	{
		name: "cloudflare_zone_get",
		description: "Fetch a Cloudflare zone by id. Tier 0, scope cloudflare.read.",
		inputSchema: schema({
			credential_ref: CREDENTIAL_REF_PROP,
			zone_id: { type: "string" }
		}, ["zone_id"])
	},
	{
		name: "openai_account_status",
		description: "List OpenAI models as an account-status probe. Tier 0, scope openai.read.",
		inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP })
	},
	{
		name: "xai_account_status",
		description: "Probe the xAI account via GET /v1/models. Tier 0, scope xai.read.",
		inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP })
	},
	{
		name: "stripe_balance",
		description: "Fetch the Stripe balance. Tier 0, scope stripe.read.",
		inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP })
	},
	{
		name: "credential_use",
		description: "One authenticated request to an allowlisted provider API using a vault:// reference; the credential is injected server-side." + PROXY_NOTE,
		inputSchema: schema({
			credential_ref: CREDENTIAL_REF_PROP,
			provider: {
				type: "string",
				enum: PROVIDERS
			},
			operation: {
				type: "string",
				enum: HTTP_METHODS,
				description: "HTTP method."
			},
			resource: {
				type: "string",
				description: "Path on the provider's API host, starting with /."
			},
			body: { description: "JSON request body (non-GET only)." }
		}, [
			"credential_ref",
			"provider",
			"operation",
			"resource"
		])
	},
	{
		name: "provider_request",
		description: "Same as credential_use with method/path naming. No caller-supplied Authorization header, no arbitrary hosts." + PROXY_NOTE,
		inputSchema: schema({
			credential_ref: CREDENTIAL_REF_PROP,
			provider: {
				type: "string",
				enum: PROVIDERS
			},
			method: {
				type: "string",
				enum: HTTP_METHODS
			},
			path: {
				type: "string",
				description: "Path on the provider's API host, starting with /."
			},
			body: { description: "JSON request body (non-GET only)." }
		}, [
			"credential_ref",
			"provider",
			"method",
			"path"
		])
	},
	{
		name: "entry_list",
		description: "List credential entries (site, account, purpose, kind, status) — metadata only, never a secret. A site can have several accounts. Tier 0, scope vault.read.",
		inputSchema: schema({
			site: {
				type: "string",
				description: "Limit to one site, e.g. github.com."
			},
			query: {
				type: "string",
				description: "Case-insensitive substring of the entry label."
			}
		})
	},
	{
		name: "entry_request_card",
		description: "Ask the owner to type a credential you do not have (or re-enter one that stopped working). The owner gets a single-use link on Telegram; you get only a card_id. Poll entry_card_status. Tier 1, scope vault.write. kind \"cookie\" asks for a browser session: the owner pastes that account's cookies for the site (several accounts per site are separate entries).",
		inputSchema: schema({
			site: {
				type: "string",
				description: "Domain, e.g. github.com."
			},
			account: {
				type: "string",
				description: "Username or email, if known."
			},
			purpose: {
				type: "string",
				description: "Short tag, e.g. personal."
			},
			kind: {
				type: "string",
				enum: ENTRY_KINDS
			},
			reason: {
				type: "string",
				description: "Why you need it; shown to the owner.",
				maxLength: 300
			},
			entry_id: {
				type: "string",
				description: "Re-enter the secret of this existing entry."
			}
		}, [
			"site",
			"kind",
			"reason"
		])
	},
	{
		name: "entry_card_status",
		description: "Status of a card you requested: pending, completed (with entry metadata) or expired. Tier 0, scope vault.read.",
		inputSchema: schema({ card_id: { type: "string" } }, ["card_id"])
	},
	{
		name: "entry_use",
		description: "Use a credential entry without seeing it: one HTTPS request to the entry's own site (host = the site or api.<site>) with the secret injected server-side (api_key / oauth_token: Authorization: Bearer; password: HTTP Basic with the account; cookie: a Cookie header chosen from the stored session cookies for that host and path, and no Authorization header — a cookie entry may also target a subdomain of its site that one of its stored cookies covers, and fails with no_cookie_for_host before any request when nothing matches). Returns status and a redacted body; response headers such as Set-Cookie are never returned (a cookie entry's rotated session cookies are stored server-side). GET/HEAD need scope vault.read and the owner's consent, scoped to this entry, host and path: the first such read returns `approval_required`; later reads to that host at that path or under it run without a prompt until the grant expires or its uses run out. Other methods need scope vault.write and are approved per request. A 401 from the site flags that entry for re-entry (site_rejected_credential); a 403 returns site_forbidden and leaves the entry active.",
		inputSchema: schema({
			site: {
				type: "string",
				description: "Domain of the entry, e.g. github.com."
			},
			account: {
				type: "string",
				description: "Which account on that site. Default: the site's default entry."
			},
			kind: {
				type: "string",
				enum: ENTRY_KINDS,
				description: "Only needed when the account has entries of several kinds."
			},
			method: {
				type: "string",
				enum: HTTP_METHODS
			},
			host: {
				type: "string",
				description: "Exactly the site or api.<site>. Default: the site."
			},
			url_path: {
				type: "string",
				description: "Path and query, starting with /."
			},
			body: { description: "Request body for non-GET: a JSON value, or a string sent as is." },
			content_type: {
				type: "string",
				enum: ENTRY_USE_CONTENT_TYPES,
				description: "For a string body. Default text/plain."
			},
			task: {
				type: "string",
				description: "What you are doing and why. Required; recorded in the audit ledger.",
				maxLength: 300
			}
		}, [
			"site",
			"method",
			"url_path",
			"task"
		])
	},
	{
		name: "entry_transfer",
		description: `Hand a stored credential to another service the owner also has an entry for, without seeing it: one HTTPS request (POST, PUT or PATCH) to the DESTINATION entry's own site (host = that site or api.<site>), authenticated with the destination entry exactly as entry_use would, or with its secret in the request header named by to_auth. The body is a JSON object in which exactly one string field has the value ${TRANSFER_PLACEHOLDER}; the broker replaces that value with the SOURCE entry's secret server-side. Source entries: api_key or oauth_token. Destination entries: api_key, oauth_token or password. Neither secret is ever returned: the result is the status and a redacted body, and no response headers. Needs scope vault.write and the owner's Telegram approval on EVERY call (there is no standing grant): the first call returns \`approval_required\`; call again with the same arguments plus approval_id. The destination service receives the source secret and may store it. A 401 from the destination flags the destination entry for re-entry (site_rejected_credential); a 403 returns site_forbidden and leaves both entries active.`,
		inputSchema: schema({
			from_site: {
				type: "string",
				description: "Domain of the SOURCE entry: the credential being handed over, e.g. x.ai."
			},
			from_account: {
				type: "string",
				description: "Which account on the source site. Default: the site's default entry."
			},
			from_kind: {
				type: "string",
				enum: ENTRY_KINDS,
				description: "Only needed when the source account has entries of several kinds. Must be api_key or oauth_token."
			},
			to_site: {
				type: "string",
				description: "Domain of the DESTINATION entry: the service that receives the credential and whose entry authenticates the request."
			},
			to_account: {
				type: "string",
				description: "Which account on the destination site. Default: the site's default entry."
			},
			to_kind: {
				type: "string",
				enum: ENTRY_KINDS,
				description: "Only needed when the destination account has entries of several kinds. Must be api_key, oauth_token or password."
			},
			method: {
				type: "string",
				enum: TRANSFER_METHODS
			},
			host: {
				type: "string",
				description: "Exactly the destination site or api.<site>. Default: the destination site."
			},
			url_path: {
				type: "string",
				description: "Path and query on the destination, starting with /."
			},
			body: {
				type: "object",
				description: `JSON object sent to the destination. Exactly one string field, at any depth, must have the value ${TRANSFER_PLACEHOLDER} (the whole value, not part of a longer string, not a key).`
			},
			to_auth: {
				type: "object",
				description: "How the destination secret authenticates. Omit for the entry_use default. { \"scheme\": \"header\", \"name\": \"<header-name>\" } sends it as that request header instead of the Authorization header (api_key / oauth_token destinations only).",
				properties: {
					scheme: {
						type: "string",
						enum: ["default", "header"]
					},
					name: { type: "string" }
				},
				required: ["scheme"],
				additionalProperties: false
			},
			task: {
				type: "string",
				description: "What you are doing and why. Required; shown to the owner and recorded in the audit ledger.",
				maxLength: 300
			}
		}, [
			"from_site",
			"to_site",
			"method",
			"url_path",
			"body",
			"task"
		])
	},
	{
		name: "entry_inject",
		description: "Ask for a stored credential to be placed into the OWNER'S OWN BROWSER by an enrolled injector (the owner's browser extension) — you never see it. mode \"cookies\" sets the session cookies of a cookie entry for target_origin; mode \"field\" types the password of a password entry into the field the owner's page shows. target_origin must be https://<host> where host is the entry's site or a subdomain of it. Tier 2, scope vault.write: EVERY call needs the owner's Telegram approval of that exact request (there is no standing grant). The first call returns `approval_required`; call again with the same arguments plus approval_id to get a single-use ticket (120 s) that only the bound injector can redeem. The result is the ticket and metadata, never a secret.",
		inputSchema: schema({
			site: {
				type: "string",
				description: "Domain of the entry, e.g. github.com."
			},
			account: {
				type: "string",
				description: "Which account on that site. Default: the site's default entry of the kind the mode needs."
			},
			target_origin: {
				type: "string",
				description: "https://<host>: the entry's site or a subdomain of it. Lower case, no port, path or query."
			},
			mode: {
				type: "string",
				enum: INJECT_MODES,
				description: "cookies: a cookie entry. field: a password entry."
			},
			injector_id: {
				type: "string",
				description: "Which enrolled injector. May be omitted when exactly one is enrolled."
			},
			task: {
				type: "string",
				description: "What you are doing and why. Required; shown to the owner and recorded in the audit ledger.",
				maxLength: 300
			}
		}, [
			"site",
			"target_origin",
			"mode",
			"task"
		])
	},
	{
		name: "approval_status",
		description: "Status of an approval you were asked to wait for: pending, approved, denied, expired or consumed. Tier 0, scope vault.read.",
		inputSchema: {
			type: "object",
			properties: { approval_id: {
				type: "string",
				description: "The approval_id from an `approval_required` result."
			} },
			required: ["approval_id"],
			additionalProperties: false
		}
	},
	{
		name: "audit_list",
		description: "Recent ledger entries (who, what, decision, result). Secrets are never recorded. Tier 0, scope audit.read.",
		inputSchema: schema({
			limit: {
				type: "integer",
				minimum: 1,
				maximum: 1e3
			},
			client_id: { type: "string" },
			capability: { type: "string" }
		})
	},
	{
		name: "audit_verify",
		description: "Recompute the ledger's hash chain and report whether it is intact, plus how the ledger compares with the newest externally anchored head (`anchor.verdict`: ok / truncated / rewritten / anchor_mac_invalid; `anchor: null` when nothing was anchored yet). Tier 0, scope audit.read.",
		inputSchema: schema({})
	},
	{
		name: "admin_anchor_now",
		description: "OWNER ONLY (local stdio or the passkey console): verify the ledger and publish its head (seq, chain hash, row count) to the owner's Telegram chat as an external anchor. Sends nothing when the head has not moved. Any remote caller is refused (tier 3).",
		inputSchema: schema({})
	},
	{
		name: "admin_verify_anchor",
		description: "OWNER ONLY (local stdio or the passkey console): check an `ECHO-VAULT-ANCHOR v1 …` line copied from Telegram against the current ledger. Verdict: ok / truncated / rewritten / anchor_mac_invalid / anchor_ahead_of_ledger. Any remote caller is refused (tier 3).",
		inputSchema: schema({ line: {
			type: "string",
			maxLength: 400,
			description: "The full anchor message text."
		} }, ["line"])
	},
	{
		name: "admin_list_clients",
		description: "OWNER ONLY (local stdio or the passkey console): list the OAuth clients, their status and granted scopes. Any remote/OAuth/workload caller is refused (tier 3).",
		inputSchema: schema({})
	},
	{
		name: "admin_set_client_scopes",
		description: "OWNER ONLY (local stdio or the passkey console): set an approved client's granted scopes. Any remote caller is refused (tier 3).",
		inputSchema: schema({
			client_id: { type: "string" },
			scopes: {
				type: "array",
				items: { type: "string" },
				description: "The scopes to grant, e.g. [\"github.read\"]."
			}
		}, ["client_id", "scopes"])
	},
	{
		name: "admin_revoke_client",
		description: "OWNER ONLY (local stdio or the passkey console): revoke a client (kill switch): drop its grant and tokens. Any remote caller is refused (tier 3).",
		inputSchema: schema({ client_id: { type: "string" } }, ["client_id"])
	},
	{
		name: "admin_list_grants",
		description: "OWNER ONLY (local stdio or the passkey console): list entry consent grants (metadata only), optionally filtered by client or entry. Any remote caller is refused (tier 3).",
		inputSchema: schema({
			client_id: { type: "string" },
			entry_id: { type: "string" }
		})
	},
	{
		name: "admin_revoke_grant",
		description: "OWNER ONLY (local stdio or the passkey console): revoke a client's consent for an entry — one narrow grant (give host + path_prefix) or all grants for the pair. The client's next read re-prompts. Any remote caller is refused (tier 3).",
		inputSchema: schema({
			client_id: { type: "string" },
			entry_id: { type: "string" },
			host: {
				type: "string",
				description: "Only this host's grant."
			},
			path_prefix: {
				type: "string",
				description: "Only the grant with this exact path_prefix (requires host)."
			}
		}, ["client_id", "entry_id"])
	},
	{
		name: "admin_list_entries",
		description: "OWNER ONLY (local stdio or the passkey console): list credential entries with full metadata (including fingerprint and length). Still never a secret value. Any remote caller is refused (tier 3).",
		inputSchema: schema({
			site: {
				type: "string",
				description: "Limit to one site."
			},
			query: {
				type: "string",
				description: "Case-insensitive substring of the entry label."
			}
		})
	},
	{
		name: "admin_set_rotation",
		description: "OWNER ONLY (local stdio or the passkey console): set an entry's rotation policy. mode manual = re-enter on a card; mode auto = the provider rotator rolls it (Cloudflare API tokens: provider_token_id is the 32-hex token ID, never the token). Metadata only. Any remote caller is refused (tier 3).",
		inputSchema: schema({
			entry_id: { type: "string" },
			mode: {
				type: "string",
				enum: ["manual", "auto"]
			},
			interval_days: {
				type: "integer",
				minimum: 1,
				maximum: 3650,
				description: "Rotate every N days. Omit to keep the current interval."
			},
			provider_token_id: {
				type: "string",
				description: "The provider's NON-SECRET token ID. Omit to keep the current one."
			}
		}, ["entry_id", "mode"])
	},
	{
		name: "admin_rotate_entry",
		description: "OWNER ONLY (local stdio or the passkey console): auto-rotate one entry now through its provider rotator. The new secret goes straight to the vault; the result is metadata only. Any remote caller is refused (tier 3).",
		inputSchema: schema({ entry_id: { type: "string" } }, ["entry_id"])
	},
	{
		name: "admin_rotation_due",
		description: "OWNER ONLY (local stdio or the passkey console): list entries whose rotation is due (metadata only). Any remote caller is refused (tier 3).",
		inputSchema: schema({})
	},
	{
		name: "admin_purge_entry",
		description: "OWNER ONLY (local stdio or the passkey console): IRREVERSIBLY destroy an entry — its stored secret, its row, its cards and all consent grants. confirm must be exactly \"PURGE <entry_id>\". Any remote caller is refused (tier 3).",
		inputSchema: schema({
			entry_id: { type: "string" },
			confirm: { type: "string" }
		}, ["entry_id", "confirm"])
	},
	{
		name: "admin_digest_now",
		description: "OWNER ONLY (local stdio or the passkey console): build the audit digest for a window (default: the previous full UTC day) from ledger rows and entry/grant metadata, and return it. With send=true it is also sent to the owner on Telegram, at most once per window. Any remote caller is refused (tier 3).",
		inputSchema: schema({
			from: {
				type: "string",
				description: "Window start (inclusive): YYYY-MM-DD (UTC) or an ISO time with Z/offset."
			},
			to: {
				type: "string",
				description: "Window end (exclusive), same formats."
			},
			send: {
				type: "boolean",
				description: "Also send it on Telegram. Default false."
			}
		})
	},
	{
		name: "admin_delete_entry",
		description: "OWNER ONLY (local stdio or the passkey console): soft-delete an entry (status deleted; agents can no longer use it; the stored secret stays until admin_purge_entry). Metadata only. Any remote caller is refused (tier 3).",
		inputSchema: schema({ entry_id: { type: "string" } }, ["entry_id"])
	},
	{
		name: "admin_request_reentry",
		description: "OWNER ONLY (local stdio or the passkey console): send the owner a single-use card link (Telegram) to re-type the secret of an existing entry. Returns the card id and expiry only. Any remote caller is refused (tier 3).",
		inputSchema: schema({
			entry_id: { type: "string" },
			reason: {
				type: "string",
				maxLength: 300,
				description: "Shown on the card. Default: requested from the owner console."
			}
		}, ["entry_id"])
	},
	{
		name: "admin_enroll_injector",
		description: "OWNER ONLY (local stdio or the passkey console, with a fresh passkey confirmation there): enroll a browser injector. public_key_jwk is the P-256 ECDH PUBLIC key the extension shows (kty EC, crv P-256, x, y); a private key is refused. Returns the injector id and its injector_token ONCE (stored only as a hash); paste both into the extension. Any remote caller is refused (tier 3).",
		inputSchema: schema({
			name: {
				type: "string",
				description: "A name for this browser, e.g. \"desktop chrome\".",
				maxLength: 64
			},
			public_key_jwk: { description: "The public JWK as an object (or its JSON text)." }
		}, ["name", "public_key_jwk"])
	},
	{
		name: "admin_list_injectors",
		description: "OWNER ONLY (local stdio or the passkey console): list enrolled browser injectors (id, name, public key thumbprint, status, times). Never a token. Any remote caller is refused (tier 3).",
		inputSchema: schema({})
	},
	{
		name: "admin_revoke_injector",
		description: "OWNER ONLY (local stdio or the passkey console): revoke a browser injector. Its token stops working at once and its outstanding tickets can no longer be redeemed. Any remote caller is refused (tier 3).",
		inputSchema: schema({ injector_id: { type: "string" } }, ["injector_id"])
	},
	{
		name: "admin_console_bootstrap",
		description: "LOCAL STDIO ONLY: mint the one-time owner-console enrollment code (15 minutes, single use, replaces any earlier code). It is returned ONCE in this result and stored only as a hash; type it on /console/enroll to register a passkey. Refused for every other identity, including an owner console session (tier 3).",
		inputSchema: schema({})
	},
	{
		name: "credential_rotate",
		description: "Tier 3: always refused. Rotating a credential is a human-only operation on the canonical vault.",
		inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP })
	},
	{
		name: "credential_revoke",
		description: "Tier 3: always refused. Revoking a credential is a human-only operation on the canonical vault.",
		inputSchema: schema({ credential_ref: CREDENTIAL_REF_PROP })
	}
]);
function listTools() {
	return TOOL_DEFINITIONS.map((t) => ({ ...t }));
}
var ToolInputError = class extends Error {
	code;
	constructor(code, detail) {
		super(detail);
		this.code = code;
	}
};
var MAX_RESOURCE = 512;
var SHA_RE = /^[0-9a-f]{40}$/;
/**
* Tool names that would hand a secret to the caller. Refused before anything
* else, whatever the arguments, in addition to the fixed FORBIDDEN_TOOLS list.
*/
var REVEAL_LIKE = /(?:^|[_.-])(?:reveal|unwrap|unmask|decrypt|dump|export|exfiltrate|plaintext)(?:[_.-]|$)|(?:get|read|show|fetch|print|copy|view)[_.-]?(?:secret|token|pat|password|passwd|private[_.-]?key|credential|api[_.-]?key)s?(?:[_.-]|$)|(?:secret|password|token|credential)[_.-](?:get|read|show|reveal|value|plaintext)/i;
function isForbiddenToolName(name) {
	return FORBIDDEN_TOOLS.includes(name) || REVEAL_LIKE.test(name);
}
function isRecord(v) {
	return !!v && typeof v === "object" && !Array.isArray(v);
}
function sha256(text) {
	return createHash("sha256").update(text, "utf8").digest("hex");
}
function clip(text, max) {
	return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
/** Check args against the tool's published schema: unknown keys, missing required, wrong primitive types. */
function checkArgs(def, a) {
	const props = def.inputSchema.properties ?? {};
	for (const key of Object.keys(a)) if (!Object.hasOwn(props, key)) throw new ToolInputError("invalid_arguments", `unknown argument: ${clip(key, 64)}`);
	for (const key of def.inputSchema.required ?? []) if (a[key] === void 0 || a[key] === null || a[key] === "") throw new ToolInputError("invalid_arguments", `missing required argument: ${key}`);
	for (const [key, value] of Object.entries(a)) {
		if (value === void 0) continue;
		const spec = props[key];
		const type = spec.type;
		if (!(type === void 0 || type === "string" && typeof value === "string" || type === "integer" && typeof value === "number" && Number.isInteger(value) || type === "number" && typeof value === "number" && Number.isFinite(value) || type === "boolean" && typeof value === "boolean" || type === "object" && isRecord(value) || type === "array" && Array.isArray(value))) throw new ToolInputError("invalid_arguments", `${key}: expected ${type}`);
		if (spec.enum && !spec.enum.includes(typeof value === "string" && key === "method" ? value.toUpperCase() : value)) {
			if (!(key === "operation" && typeof value === "string" && spec.enum.includes(value.toUpperCase()))) throw new ToolInputError("invalid_arguments", `${key}: must be one of ${spec.enum.join(", ")}`);
		}
	}
}
function optStr(a, key) {
	const v = a[key];
	return typeof v === "string" && v !== "" ? v : void 0;
}
function reqStr(a, key) {
	const v = optStr(a, key);
	if (v === void 0) throw new ToolInputError("invalid_arguments", `missing required argument: ${key}`);
	return v;
}
/** A vault:// ref that belongs to `provider` (a secret must never be sent to another provider's host). */
function providerRef(a, provider, fallback) {
	const raw = optStr(a, "credential_ref") ?? fallback;
	const parsed = parseVaultRef(raw);
	if (!parsed) throw new ToolInputError("invalid_credential_ref", "credential_ref must look like vault://<provider>/<account>");
	if (parsed.provider !== provider) throw new ToolInputError("provider_mismatch", `credential_ref must be a vault://${provider}/… reference for this tool`);
	return parsed.raw;
}
function anyRef(a) {
	const parsed = parseVaultRef(reqStr(a, "credential_ref"));
	if (!parsed) throw new ToolInputError("invalid_credential_ref", "credential_ref must look like vault://<provider>/<account>");
	return parsed.raw;
}
function githubRepoResource(a) {
	const owner = a.owner;
	const repo = a.repo;
	if (!isValidGithubOwner(owner)) throw new ToolInputError("invalid_arguments", "owner: not a valid GitHub login");
	if (!isValidRepoName(repo)) throw new ToolInputError("invalid_arguments", "repo: not a valid repository name");
	return {
		owner,
		repo,
		resource: `github:${owner}/${repo}`
	};
}
/** A provider's 4xx/5xx answer as a tool failure: a stable code, the status and the (redacted) error body. */
function providerHttpFailure(status, body, credentialRef) {
	const out = {
		ok: false,
		error: status === 401 ? "provider_rejected_credential" : status === 403 ? "provider_forbidden" : status === 429 ? "provider_rate_limited" : status >= 500 ? "provider_unavailable" : "provider_http_error",
		detail: `The provider answered ${status}.`,
		status
	};
	if (body !== void 0 && body !== null && body !== "") out.body = typeof body === "string" ? clip(body, 2e3) : body;
	if (credentialRef) out.credential_ref = credentialRef;
	return out;
}
/** Outcome of a v1 executor ({ok, data|error, credential_ref?, detail?}). */
function fromV1(result, credentialRef) {
	const r = isRecord(result) ? result : {
		ok: false,
		error: "internal_error"
	};
	const audit = {};
	if (credentialRef) audit.credential_ref = credentialRef;
	if (r.ok === true) {
		const status = isRecord(r.data) && typeof r.data.status === "number" ? r.data.status : void 0;
		if (status !== void 0 && status >= 100 && status <= 599) audit.http_status = status;
		if (audit.http_status !== void 0 && audit.http_status >= 400) return {
			result: providerHttpFailure(audit.http_status, r.data.body, credentialRef),
			audit
		};
		return {
			result: {
				ok: true,
				data: r.data
			},
			audit
		};
	}
	const out = {
		ok: false,
		error: typeof r.error === "string" ? r.error : "internal_error"
	};
	if (typeof r.detail === "string") out.detail = r.detail;
	if (typeof r.credential_ref === "string") out.credential_ref = r.credential_ref;
	return {
		result: out,
		audit
	};
}
function fromGithub(result) {
	const audit = {
		credential_ref: result.audit.credential_ref,
		http_status: result.audit.http_status,
		credential_path: result.audit.credential_path,
		fallback_reason: result.audit.fallback_reason
	};
	if (result.ok) return {
		result: {
			ok: true,
			data: result.data
		},
		audit
	};
	const out = {
		ok: false,
		error: result.error
	};
	if (result.detail) out.detail = result.detail;
	return {
		result: out,
		audit
	};
}
/** Entry metadata as agents see it: no fingerprint, no secret length. */
function agentEntryView(e) {
	const out = {
		id: e.id,
		ref: e.ref,
		site: e.site,
		account: e.account,
		purpose: e.purpose,
		label: e.label,
		kind: e.kind,
		is_default: e.is_default,
		status: e.status,
		created_at: e.created_at,
		updated_at: e.updated_at,
		last_used_at: e.last_used_at,
		last_verified_at: e.last_verified_at
	};
	if (e.reentry_reason) out.reentry_reason = e.reentry_reason;
	return out;
}
function entryFailure(err) {
	if (err instanceof EntryError || err instanceof CardError) return {
		ok: false,
		error: err.code,
		detail: err.message
	};
	return {
		ok: false,
		error: "internal_error",
		detail: clip(sanitizeError(err).message, 300)
	};
}
function proxyPlan(a, env, keys) {
	const providerRaw = reqStr(a, "provider");
	if (!isProviderId(providerRaw)) throw new ToolInputError("invalid_arguments", "provider: unknown provider");
	const provider = providerRaw;
	const method = reqStr(a, keys.method).toUpperCase();
	if (!HTTP_METHODS.includes(method)) throw new ToolInputError("invalid_arguments", `${keys.method}: unsupported HTTP method`);
	const ref = providerRef(a, provider, "");
	let path;
	try {
		path = normalizeResourcePath(reqStr(a, keys.path));
	} catch (err) {
		throw new ToolInputError(clip(sanitizeError(err).message, 64) || "invalid_resource", "path must be a relative path starting with /");
	}
	const host = PROVIDER_POLICIES[provider].hosts[0];
	const pathname = new URL(`https://${host}${path}`).pathname;
	const repo = provider === "github" ? /^\/repos\/([^/]+)\/([^/]+)(?:\/|$)/.exec(pathname) : null;
	const resource = clip(repo ? `github:${decodeURIComponent(repo[1])}/${decodeURIComponent(repo[2])}` : `${provider}:${pathname}`, MAX_RESOURCE);
	const read = method === "GET" || method === "HEAD";
	const capability = read ? `${provider}.api.read` : provider === "stripe" ? "payment.stripe.write" : `${provider}.api.write`;
	const body = read ? void 0 : a.body;
	const bodyText = body === void 0 ? void 0 : typeof body === "string" ? body : JSON.stringify(body);
	const params = {
		credential_ref: ref,
		provider,
		method,
		path
	};
	if (bodyText !== void 0) params.body_sha256 = sha256(bodyText);
	return {
		capability,
		resource,
		params,
		summary: `${method} https://${host}${clip(path, 200)} using ${ref}${bodyText !== void 0 ? ` (body ${Buffer.byteLength(bodyText)} bytes)` : ""}`,
		run: async () => fromV1(await useCredential(env.broker, {
			credential_ref: ref,
			provider,
			operation: method,
			resource: path,
			body
		}), ref)
	};
}
/** A syntactically valid lower-case hostname (used for a cookie entry's subdomain host). */
var SUBDOMAIN_HOST = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
var ENTRY_USE_LIMITS = {
	maxRequestBytes: 262144,
	maxResponseBytes: 1048576,
	timeoutMs: 12e3,
	maxTextChars: 16384
};
async function defaultResolveHost(host) {
	return (await lookup(host, { all: true })).map((f) => f.address);
}
async function readLimited(res, limit) {
	if (!res.body) return Buffer.alloc(0);
	const reader = res.body.getReader();
	const chunks = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > limit) {
			await reader.cancel().catch(() => void 0);
			throw new Error("response_too_large");
		}
		chunks.push(value);
	}
	return Buffer.concat(chunks);
}
/** A refusal decided before any network activity; `code` becomes the tool error. */
var SitePreflightError = class extends Error {
	code;
	constructor(code) {
		super(code);
		this.name = "SitePreflightError";
		this.code = code;
	}
};
/**
* Runs INSIDE cards.useEntry: the only code that holds the secret. Returns
* status + redacted body; never headers (Set-Cookie and friends can be
* credentials). Redirects are not followed, so the Authorization header can
* never be replayed to another host.
*/
async function siteRequest(secret, entry, req, deps) {
	const url = new URL(`https://${req.host}${req.path}`);
	if (url.protocol !== "https:" || url.hostname !== req.host || url.username || url.password || url.port) throw new Error("hostname_not_allowed");
	if (isBlockedHost(url.hostname)) throw new Error("hostname_not_allowed");
	let jar = null;
	let cookieHeader = null;
	const cookieCtx = {
		host: url.hostname,
		path: url.pathname,
		now: (deps.now ?? Date.now)(),
		site: entry.site
	};
	if (entry.kind === "cookie") {
		try {
			jar = parseStoredJar(secret);
		} catch {
			throw new SitePreflightError("cookie_jar_invalid");
		}
		for (const form of jarRedactionForms(jar)) registerSecretForRedaction(form);
		cookieHeader = cookieHeaderFor(jar, cookieCtx);
		if (cookieHeader === null) throw new SitePreflightError("no_cookie_for_host");
		registerSecretForRedaction(cookieHeader);
	}
	let addresses;
	try {
		addresses = await (deps.resolveHost ?? defaultResolveHost)(url.hostname);
	} catch {
		throw new Error("dns_lookup_failed");
	}
	if (addresses.length === 0) throw new Error("dns_lookup_failed");
	if (addresses.some((ip) => isIP(ip) === 0 || isBlockedHost(ip) || isPrivateOrLinkLocalIp(ip))) throw new Error("hostname_not_allowed");
	const pinnedAddresses = [...new Set(addresses)];
	const headers = new Headers({
		"user-agent": "Echo-Credential-Broker/2.0",
		accept: "application/json, text/plain;q=0.9, */*;q=0.5"
	});
	if (entry.kind === "cookie") headers.set("cookie", cookieHeader);
	else if (entry.kind === "password") {
		const basic = Buffer.from(`${entry.account}:${secret}`, "utf8").toString("base64");
		registerSecretForRedaction(basic);
		headers.set("authorization", `Basic ${basic}`);
	} else if (req.authHeader) headers.set(req.authHeader, secret);
	else headers.set("authorization", `Bearer ${secret}`);
	if (entry.kind !== "cookie") {
		const encoded = encodeURIComponent(secret);
		if (encoded !== secret) registerSecretForRedaction(encoded);
	}
	const init = {
		method: req.method,
		headers,
		redirect: "manual",
		signal: AbortSignal.timeout(ENTRY_USE_LIMITS.timeoutMs)
	};
	if (req.bodyText !== void 0) {
		headers.set("content-type", req.contentType ?? "text/plain");
		init.body = req.bodyText;
	}
	let res;
	if (deps.fetch) {
		req.onConnect?.();
		res = await deps.fetch(url, init);
	} else res = await (deps.pinnedFetch ?? pinnedFetch)(url, {
		method: req.method,
		headers,
		body: req.bodyText,
		signal: init.signal
	}, {
		addresses: pinnedAddresses,
		timeoutMs: ENTRY_USE_LIMITS.timeoutMs,
		maxResponseBytes: ENTRY_USE_LIMITS.maxResponseBytes,
		onConnect: (address) => {
			req.onConnect?.();
			log.info("vault_entry_use_connected", {
				entry_id: entry.id,
				host: url.hostname,
				address
			});
		}
	});
	if (jar && res.status !== 401) {
		const setCookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
		if (setCookies.length > 0) {
			const merged = mergeSetCookie(jar, setCookies, cookieCtx);
			for (const form of jarRedactionForms(merged.jar)) registerSecretForRedaction(form);
			if (merged.changed && req.persistJar) await req.persistJar(serializeJar(merged.jar), describeJar(merged.jar, entry.site)).catch(() => void 0);
		}
	}
	const raw = await readLimited(res, ENTRY_USE_LIMITS.maxResponseBytes);
	const text = redactString(raw.toString("utf8"));
	const contentType = res.headers.get("content-type");
	let body = null;
	let truncated = false;
	if (text.length > 0) {
		let parsed;
		let isJson = false;
		if ((contentType ?? "").includes("json") || text.startsWith("{") || text.startsWith("[")) try {
			parsed = JSON.parse(text);
			isJson = true;
		} catch {
			isJson = false;
		}
		if (isJson) body = parsed;
		else {
			truncated = text.length > ENTRY_USE_LIMITS.maxTextChars;
			body = text.slice(0, ENTRY_USE_LIMITS.maxTextChars);
		}
	}
	const out = {
		status: res.status,
		content_type: contentType ? clip(redactString(contentType), 200) : null,
		body
	};
	const location = res.status >= 300 && res.status < 400 ? res.headers.get("location") : null;
	if (location) out.location = clip(redactString(location), 500);
	if (truncated) out.truncated = true;
	return out;
}
function injectorDeps(env) {
	const d = env.deps.injector ?? {};
	return {
		...d,
		now: d.now ?? env.deps.now,
		cards: d.cards ?? env.deps.cards,
		ledger: d.ledger ?? env.deps.ledger
	};
}
var INJECTOR_ERROR_DETAIL = {
	invalid_target_origin: "target_origin must be exactly https://<host>: lower case, no port, path, query or credentials",
	target_origin_not_allowed: "target_origin must be the entry's own site or a subdomain of it",
	mode_kind_mismatch: "mode \"cookies\" needs a cookie entry and mode \"field\" needs a password entry",
	entry_not_active: "this entry needs its secret re-entered (or was deleted) before it can be injected",
	injector_not_found: "no active injector with that id",
	no_injector_enrolled: "the owner has not enrolled a browser injector",
	injector_required: "several injectors are enrolled; pass injector_id",
	invalid_public_key: "public_key_jwk must be a P-256 ECDH public JWK (kty EC, crv P-256, x, y)",
	private_key_not_allowed: "that JWK contains a private key; send only the public key",
	invalid_name: "name: 1 to 64 characters",
	too_many_injectors: "too many active injectors; revoke one first",
	key_already_enrolled: "an active injector already uses this public key"
};
function injectorInputError(err) {
	if (err instanceof InjectorError) throw new ToolInputError(err.code, INJECTOR_ERROR_DETAIL[err.code] ?? err.code);
	throw err;
}
/**
* `entry_inject`: tier 2 (`vault.entry.inject`), so EVERY call is escalated and
* needs a request-bound, single-use approval; no consent grant is involved.
* Everything that can be refused without the owner is refused here, before an
* approval is requested: the origin, the mode/kind pairing, the entry's state,
* the injector. The run mints the ticket and writes its own ok row — no ticket
* without that row (injector.ts mintTicket).
*/
async function entryInjectPlan(a, env) {
	const capability = INJECT_CAPABILITY;
	const task = sanitizeDisplayText(reqStr(a, "task"), 300);
	if (!task) throw new ToolInputError("invalid_task", "task: describe what you are doing and why");
	const mode = reqStr(a, "mode");
	if (!INJECT_MODES.includes(mode)) throw new ToolInputError("invalid_arguments", `mode: must be one of ${INJECT_MODES.join(", ")}`);
	const targetOrigin = reqStr(a, "target_origin");
	const siteArg = reqStr(a, "site");
	const accountArg = optStr(a, "account");
	const injectorArg = optStr(a, "injector_id");
	const scope = requiredScope(capability);
	if (!scope || !env.identity.scopes.includes(scope)) return {
		capability,
		resource: clip(`entry:${sanitizeDisplayText(siteArg, 253) || "?"}/${accountArg ? sanitizeDisplayText(accountArg, 200) : "default"}`, MAX_RESOURCE),
		params: {
			mode,
			task
		},
		summary: "",
		task,
		run: async () => ({ result: {
			ok: false,
			error: "missing_scope"
		} })
	};
	const wanted = kindForMode(mode);
	let entry;
	try {
		entry = await resolveEntry({
			site: siteArg,
			account: accountArg,
			kind: wanted
		}, env.deps.cards);
	} catch (err) {
		if (!(err instanceof EntryError)) throw err;
		if (err.code === "entry_not_found") {
			if (await resolveEntry({
				site: siteArg,
				account: accountArg
			}, env.deps.cards).then(() => true, (e) => e instanceof EntryError && e.code === "ambiguous_entry")) throw new ToolInputError("mode_kind_mismatch", INJECTOR_ERROR_DETAIL.mode_kind_mismatch);
		}
		throw new ToolInputError(err.code, err.message);
	}
	if (entry.kind !== wanted) throw new ToolInputError("mode_kind_mismatch", INJECTOR_ERROR_DETAIL.mode_kind_mismatch);
	let injector;
	try {
		checkTargetOrigin(targetOrigin, entry.site);
		if (entry.status !== "active") throw new InjectorError("entry_not_active");
		injector = await resolveInjector(injectorArg, injectorDeps(env));
	} catch (err) {
		injectorInputError(err);
	}
	const resource = clip(injectResource(entry.site, entry.account, injector.injector_id), MAX_RESOURCE);
	const what = mode === "cookies" ? "the session cookies" : "the password";
	return {
		capability,
		resource,
		params: {
			entry_id: entry.id,
			mode,
			target_origin: targetOrigin,
			injector_id: injector.injector_id,
			task
		},
		summary: `Put ${what} of "${entry.label}" into YOUR browser at ${targetOrigin} through injector "${sanitizeDisplayText(injector.name, 64)}" (${injector.injector_id}). Single use, 120 s. Task: ${task}`,
		task,
		run: async (ctx) => {
			if (!ctx.approved || !ctx.approvalId) return { result: {
				ok: false,
				error: "approval_required"
			} };
			const ledger = env.deps.ledger ?? appendLedger;
			try {
				const current = await getEntryMetadata(entry.id, env.deps.cards);
				if (!current || current.status !== "active") throw new InjectorError("entry_not_active");
				const minted = await mintTicket({
					client_id: env.identity.client_id,
					entry: current,
					mode,
					target_origin: targetOrigin,
					injector_id: injector.injector_id,
					approval_id: ctx.approvalId,
					record: () => ledger({
						client_id: env.identity.client_id,
						capability,
						resource,
						decision: "escalate",
						tier: ctx.decision.tier,
						result: "ok",
						approval_id: ctx.approvalId,
						credential_ref: current.ref,
						task
					})
				}, injectorDeps(env));
				return {
					ledgered: true,
					audit: { credential_ref: current.ref },
					result: {
						ok: true,
						data: minted
					}
				};
			} catch (err) {
				const code = err instanceof InjectorError ? err.code : "internal_error";
				if (code === "ledger_unavailable") return {
					ledgered: true,
					result: {
						ok: false,
						error: "ledger_unavailable",
						action_performed: false,
						detail: "Refused: the ticket could not be recorded in the audit ledger, so none was issued."
					}
				};
				return {
					audit: { credential_ref: entry.ref },
					result: {
						ok: false,
						error: code,
						detail: INJECTOR_ERROR_DETAIL[code]
					}
				};
			}
		}
	};
}
async function entryUsePlan(a, env) {
	const method = reqStr(a, "method").toUpperCase();
	if (!HTTP_METHODS.includes(method)) throw new ToolInputError("invalid_arguments", "method: unsupported HTTP method");
	const read = method === "GET" || method === "HEAD";
	const capability = read ? "vault.entry.use.read" : "vault.entry.use.write";
	const task = sanitizeDisplayText(reqStr(a, "task"), 300);
	if (!task) throw new ToolInputError("invalid_task", "task: describe what you are doing and why");
	let path;
	try {
		path = normalizeResourcePath(reqStr(a, "url_path"));
	} catch {
		throw new ToolInputError("invalid_arguments", "url_path must be a relative path starting with /");
	}
	if (a.kind !== void 0 && !ENTRY_KINDS.includes(a.kind)) throw new ToolInputError("invalid_arguments", `kind: must be one of ${ENTRY_KINDS.join(", ")}`);
	if (read && a.body !== void 0) throw new ToolInputError("invalid_arguments", "body is not allowed with GET/HEAD");
	const bodyText = a.body === void 0 ? void 0 : typeof a.body === "string" ? a.body : JSON.stringify(a.body);
	if (bodyText !== void 0 && Buffer.byteLength(bodyText) > ENTRY_USE_LIMITS.maxRequestBytes) throw new ToolInputError("request_too_large", "body exceeds the broker request limit");
	const contentType = bodyText === void 0 ? void 0 : typeof a.body === "string" ? optStr(a, "content_type") ?? "text/plain" : "application/json";
	const siteArg = reqStr(a, "site");
	const accountArg = optStr(a, "account");
	const unresolved = (reason) => ({
		capability,
		resource: clip(`entry:${sanitizeDisplayText(siteArg, 253) || "?"}/${accountArg ? sanitizeDisplayText(accountArg, 200) : "default"}`, MAX_RESOURCE),
		params: {
			method,
			url_path: path,
			task
		},
		summary: "",
		task,
		run: async () => ({ result: {
			ok: false,
			error: reason
		} })
	});
	const scope = requiredScope(capability);
	if (!scope || !env.identity.scopes.includes(scope)) return unresolved("missing_scope");
	let entry;
	try {
		entry = await resolveEntry({
			site: siteArg,
			account: accountArg,
			kind: a.kind
		}, env.deps.cards);
	} catch (err) {
		if (err instanceof EntryError) throw new ToolInputError(err.code, err.message);
		throw err;
	}
	if (entry.kind === "operator_secret") throw new ToolInputError("entry_kind_not_usable", "operator_secret entries cannot be injected into a request");
	const host = (optStr(a, "host") ?? entry.site).trim().toLowerCase();
	const cookieSubdomain = entry.kind === "cookie" && host.endsWith(`.${entry.site}`) && SUBDOMAIN_HOST.test(host);
	if (host !== entry.site && host !== `api.${entry.site}` && !cookieSubdomain) throw new ToolInputError("hostname_not_allowed", entry.kind === "cookie" ? `host must be ${entry.site}, api.${entry.site} or a subdomain of ${entry.site} covered by a stored cookie` : `host must be ${entry.site} or api.${entry.site}`);
	if (isBlockedHost(host)) throw new ToolInputError("hostname_not_allowed", "that host is not reachable through the broker");
	const params = {
		entry_id: entry.id,
		method,
		host,
		url_path: path,
		task
	};
	if (bodyText !== void 0) {
		params.body_sha256 = sha256(bodyText);
		params.content_type = contentType;
	}
	const grantPath = path.split(/[?#]/)[0];
	const what = `${method} https://${host}${clip(path, 160)}${bodyText !== void 0 ? ` (body ${Buffer.byteLength(bodyText)} bytes)` : ""}`;
	let summary;
	if (read) {
		const { ttlMs, maxUses } = grantConfig(env.deps.env);
		const expiresIso = new Date((env.deps.now ?? Date.now)() + ttlMs).toISOString();
		const scopeLine = `Approving also lets this client make GET/HEAD requests to https://${host}${clip(grantPath, 160)}${grantPath === "/" ? " (that exact path only)" : "(/*)"} with this entry, without asking again, until ${expiresIso}${maxUses === null ? "" : ` or ${maxUses} uses`}.`;
		summary = `FIRST USE of "${entry.label}" by this client: ${what}. Task: ${task}. ${scopeLine}`;
	} else summary = `Use "${entry.label}": ${what}. Task: ${task}`;
	return {
		capability,
		resource: clip(`entry:${entry.site}/${entry.account}`, MAX_RESOURCE),
		params,
		summary,
		task,
		consentEntryId: read ? entry.id : void 0,
		consentHost: read ? host : void 0,
		consentPath: read ? grantPath : void 0,
		run: async (ctx) => {
			const ledger = env.deps.ledger ?? appendLedger;
			let seen = null;
			let ledgered = false;
			const audit = { credential_ref: entry.ref };
			const status = () => seen?.status;
			const is401 = () => status() === 401;
			const is403 = () => status() === 403;
			let preflight = null;
			const persistJar = async (jarJson, summary) => {
				await refreshCookieJar(entry.id, env.identity, jarJson, summary, {
					...env.deps.cards,
					ledger: (row) => ledger(row)
				});
			};
			try {
				const used = await useEntry(entry.id, env.identity, task, async (secret, meta) => {
					let response;
					try {
						response = await siteRequest(secret, meta, {
							host,
							method,
							path,
							bodyText,
							contentType,
							persistJar
						}, env.deps);
					} catch (err) {
						if (err instanceof SitePreflightError) preflight = err.code;
						throw err;
					}
					seen = { status: response.status };
					if (is401()) await flagForReentry(meta.id, `${host} answered ${response.status} to ${method}`, env.deps.cards).catch(() => {
						log.error("vault_entry_flag_failed", { entry_id: meta.id });
					});
					return response;
				}, {
					...env.deps.cards,
					decision: ctx.decision.decision,
					tier: ctx.decision.tier,
					approval_id: ctx.approvalId,
					ledger: async (input) => {
						ledgered = true;
						const row = {
							...input,
							capability,
							task
						};
						const s = status();
						if (s !== void 0) row.http_status = s;
						if (preflight) {
							row.result = "error";
							row.error = preflight;
						} else if (is401()) {
							row.result = "error";
							row.error = "site_rejected_credential";
						} else if (is403()) {
							row.result = "error";
							row.error = "site_forbidden";
						}
						await ledger(row);
					}
				});
				const response = used.result;
				audit.http_status = response.status;
				if (is401()) return {
					ledgered,
					audit,
					result: {
						ok: false,
						error: "site_rejected_credential",
						detail: `${host} answered ${response.status}. This entry is now flagged; ask the owner to re-enter it with entry_request_card (entry_id).`,
						status: response.status,
						entry_id: entry.id,
						entry_flagged_for_reentry: true
					}
				};
				if (is403()) return {
					ledgered,
					audit,
					result: {
						ok: false,
						error: "site_forbidden",
						detail: `${host} answered ${response.status}. The credential was accepted but this request is not allowed; the entry is unchanged.`,
						status: response.status,
						body: response.body,
						entry_id: entry.id
					}
				};
				return {
					ledgered,
					audit,
					result: {
						ok: true,
						data: {
							entry: agentEntryView(used.entry),
							...response
						}
					}
				};
			} catch (err) {
				if (preflight) {
					const detail = preflight === "no_cookie_for_host" ? `No stored cookie of this entry applies to https://${host}${clip(path.split(/[?#]/)[0], 160)} (domain, path or expiry). Nothing was sent.` : "The stored cookie jar of this entry could not be read. Ask the owner to re-enter it with entry_request_card (entry_id).";
					return {
						ledgered,
						audit,
						result: {
							ok: false,
							error: preflight,
							detail,
							entry_id: entry.id
						}
					};
				}
				return {
					ledgered,
					audit,
					result: entryFailure(err)
				};
			}
		}
	};
}
var TRANSFER_PREFLIGHT_DETAIL = {
	request_too_large: "The body with the credential in place exceeds the broker request limit. Nothing was sent.",
	entry_secret_unprotectable: "A stored secret is too short to be redacted reliably, so it is not transferred. Nothing was sent."
};
/**
* `entry_transfer`: tier 2 (`vault.entry.transfer`), so EVERY call is escalated
* and approved by the owner; there is no consent grant. Both secrets exist only
* inside the two nested cards.useEntry callbacks below: the source entry is
* opened first, the destination entry inside it, and the request is made
* inside the destination's callback. Each entry therefore gets its own ledger
* row and last-used update, and the source's row is written last, with the
* real outcome (never "ok" when the destination could not be used).
*/
async function entryTransferPlan(a, env) {
	const capability = TRANSFER_CAPABILITY;
	const method = reqStr(a, "method").toUpperCase();
	if (!TRANSFER_METHODS.includes(method)) throw new ToolInputError("invalid_arguments", `method: must be one of ${TRANSFER_METHODS.join(", ")}`);
	const task = sanitizeDisplayText(reqStr(a, "task"), 300);
	if (!task) throw new ToolInputError("invalid_task", "task: describe what you are doing and why");
	let path;
	try {
		path = normalizeResourcePath(reqStr(a, "url_path"));
	} catch {
		throw new ToolInputError("invalid_arguments", "url_path must be a relative path starting with /");
	}
	for (const key of ["from_kind", "to_kind"]) if (a[key] !== void 0 && !ENTRY_KINDS.includes(a[key])) throw new ToolInputError("invalid_arguments", `${key}: must be one of ${ENTRY_KINDS.join(", ")}`);
	const sourceKindError = () => new ToolInputError("entry_kind_not_transferable", `only ${TRANSFER_SOURCE_KINDS.join(" and ")} entries can be transferred`);
	const destinationKindError = () => new ToolInputError("entry_kind_not_usable", `the destination entry must be one of ${TRANSFER_DESTINATION_KINDS.join(", ")}`);
	if (a.from_kind !== void 0 && !TRANSFER_SOURCE_KINDS.includes(a.from_kind)) throw sourceKindError();
	if (a.to_kind !== void 0 && !TRANSFER_DESTINATION_KINDS.includes(a.to_kind)) throw destinationKindError();
	let template;
	let placeholderPath;
	let toAuth;
	try {
		if (!isRecord(a.body)) throw new TransferInputError("body must be a JSON object");
		try {
			template = JSON.stringify(a.body);
		} catch {
			throw new TransferInputError("body must be a JSON object");
		}
		if (Buffer.byteLength(template) > ENTRY_USE_LIMITS.maxRequestBytes) throw new ToolInputError("request_too_large", "body exceeds the broker request limit");
		placeholderPath = locatePlaceholder(JSON.parse(template)).path;
		toAuth = parseTransferAuth(a.to_auth);
	} catch (err) {
		if (err instanceof TransferInputError) throw new ToolInputError("invalid_arguments", err.message);
		throw err;
	}
	const authHeader = toAuth.scheme === "header" ? toAuth.name : void 0;
	const fromSite = reqStr(a, "from_site");
	const toSite = reqStr(a, "to_site");
	const fromAccount = optStr(a, "from_account");
	const toAccount = optStr(a, "to_account");
	const shown = (site, account) => `entry:${sanitizeDisplayText(site, 253) || "?"}/${account ? sanitizeDisplayText(account, 200) : "default"}`;
	const unresolved = (reason) => ({
		capability,
		resource: clip(`${shown(fromSite, fromAccount)}=>${shown(toSite, toAccount)}`, MAX_RESOURCE),
		params: {
			method,
			url_path: path,
			task
		},
		summary: "",
		task,
		run: async () => ({ result: {
			ok: false,
			error: reason
		} })
	});
	const scope = requiredScope(capability);
	if (!scope || !env.identity.scopes.includes(scope)) return unresolved("missing_scope");
	const resolve = async (role, site, account) => {
		try {
			return await resolveEntry({
				site,
				account,
				kind: a[`${role}_kind`]
			}, env.deps.cards);
		} catch (err) {
			if (err instanceof EntryError) throw new ToolInputError(err.code, `${role}_site: ${err.message}`);
			throw err;
		}
	};
	const from = await resolve("from", fromSite, fromAccount);
	if (!TRANSFER_SOURCE_KINDS.includes(from.kind)) throw sourceKindError();
	const to = await resolve("to", toSite, toAccount);
	if (!TRANSFER_DESTINATION_KINDS.includes(to.kind)) throw destinationKindError();
	if (authHeader && to.kind === "password") throw new ToolInputError("invalid_arguments", "to_auth: a header is only for api_key and oauth_token destination entries");
	if (from.id === to.id) throw new ToolInputError("invalid_arguments", "the source and the destination must be different entries");
	const host = (optStr(a, "host") ?? to.site).trim().toLowerCase();
	if (host !== to.site && host !== `api.${to.site}`) throw new ToolInputError("hostname_not_allowed", `host must be ${to.site} or api.${to.site}`);
	if (isBlockedHost(host)) throw new ToolInputError("hostname_not_allowed", "that host is not reachable through the broker");
	const params = {
		from_entry_id: from.id,
		to_entry_id: to.id,
		method,
		host,
		url_path: path,
		body_sha256: sha256(template),
		placeholder_path: placeholderPath,
		to_auth_scheme: toAuth.scheme,
		task
	};
	if (authHeader) params.to_auth_header = authHeader;
	const head = `TRANSFER the secret of "${sanitizeDisplayText(from.label, 60)}" into ${method} https://${host}${clip(path, 100)}, JSON field ${placeholderPath}, authenticated as "${sanitizeDisplayText(to.label, 60)}"${authHeader ? `, sent in header ${authHeader}` : ""}. ${to.site} will receive and may store this secret. Task: `;
	const summary = `${head}${clip(task, Math.max(40, 500 - head.length))}`;
	const resource = clip(`entry:${from.site}/${from.account}=>entry:${to.site}/${to.account}`, MAX_RESOURCE);
	const pathname = path.split(/[?#]/)[0];
	const rowResource = (role) => clip(`entry:${from.site}/${from.account} (${from.id}) => entry:${to.site}/${to.account} (${to.id}) [${role}] ${method} https://${host}${clip(pathname, 200)} field ${placeholderPath}`, 1024);
	return {
		capability,
		resource,
		params,
		summary,
		task,
		run: async (ctx) => {
			const ledger = env.deps.ledger ?? appendLedger;
			let seen = null;
			/** The request reached the point of leaving the broker; without a response read back, delivery is unknown. */
			let connected = false;
			let ledgered = false;
			let preflight = null;
			/** Why the destination side failed (its entry could not be used, the request failed, or its row could not be written). */
			let destinationFailure = null;
			let destination = to;
			const audit = { credential_ref: to.ref };
			const status = () => seen?.status;
			const refuse = (code) => {
				preflight = code;
				throw new SitePreflightError(code);
			};
			const rowWriter = (role) => async (input) => {
				ledgered = true;
				const row = {
					...input,
					capability,
					task,
					resource: rowResource(role)
				};
				const s = status();
				if (s !== void 0) row.http_status = s;
				if (preflight) {
					row.result = "error";
					row.error = preflight;
				} else if (s === 401) {
					row.result = "error";
					row.error = "site_rejected_credential";
				} else if (s === 403) {
					row.result = "error";
					row.error = "site_forbidden";
				} else if (role === "source" && destinationFailure !== null) {
					row.result = "error";
					row.error = `transfer_failed: ${destinationFailure instanceof EntryError ? destinationFailure.code : "internal_error"}`;
				}
				await ledger(row);
			};
			const useOpts = (role) => ({
				...env.deps.cards,
				decision: ctx.decision.decision,
				tier: ctx.decision.tier,
				approval_id: ctx.approvalId,
				ledger: rowWriter(role)
			});
			try {
				const used = await useEntry(from.id, env.identity, task, async (sourceSecret) => {
					try {
						const inner = await useEntry(to.id, env.identity, task, async (destinationSecret, meta) => {
							if (sourceSecret.trim().length < 8 || destinationSecret.trim().length < 8) refuse("entry_secret_unprotectable");
							for (const form of transferRedactionForms(sourceSecret)) registerSecretForRedaction(form);
							const bodyText = buildTransferBody(template, sourceSecret);
							if (Buffer.byteLength(bodyText) > ENTRY_USE_LIMITS.maxRequestBytes) refuse("request_too_large");
							let response;
							try {
								response = await siteRequest(destinationSecret, meta, {
									host,
									method,
									path,
									bodyText,
									contentType: "application/json",
									authHeader,
									onConnect: () => void (connected = true)
								}, env.deps);
							} catch (err) {
								if (err instanceof SitePreflightError) preflight = err.code;
								throw err;
							}
							seen = { status: response.status };
							if (response.status === 401) await flagForReentry(meta.id, `${host} answered ${response.status} to ${method}`, env.deps.cards).catch(() => {
								log.error("vault_entry_flag_failed", { entry_id: meta.id });
							});
							const out = {
								status: response.status,
								body: response.body
							};
							if (response.truncated) out.truncated = true;
							return out;
						}, useOpts("destination"));
						destination = inner.entry;
						return inner.result;
					} catch (err) {
						destinationFailure = err;
						throw err;
					}
				}, useOpts("source"));
				const response = used.result;
				audit.http_status = response.status;
				if (response.status === 401) return {
					ledgered,
					audit,
					result: {
						ok: false,
						error: "site_rejected_credential",
						detail: `${host} answered ${response.status}. The destination entry is now flagged; ask the owner to re-enter it with entry_request_card (entry_id). The source entry is unchanged.`,
						status: response.status,
						entry_id: to.id,
						entry_flagged_for_reentry: true
					}
				};
				if (response.status === 403) return {
					ledgered,
					audit,
					result: {
						ok: false,
						error: "site_forbidden",
						detail: `${host} answered ${response.status}. The destination credential was accepted but this request is not allowed; both entries are unchanged.`,
						status: response.status,
						body: response.body,
						entry_id: to.id
					}
				};
				return {
					ledgered,
					audit,
					result: {
						ok: true,
						data: {
							from: agentEntryView(used.entry),
							to: agentEntryView(destination),
							...response
						}
					}
				};
			} catch (err) {
				const requestSent = seen !== null ? true : connected ? "unknown" : false;
				if (preflight) return {
					ledgered,
					audit,
					result: {
						ok: false,
						error: preflight,
						detail: TRANSFER_PREFLIGHT_DETAIL[preflight] ?? "Nothing was sent.",
						request_sent: false
					}
				};
				const failedSide = destinationFailure !== null ? "destination" : "source";
				const failure = entryFailure(destinationFailure ?? err);
				return {
					ledgered,
					audit,
					result: {
						...failure,
						failed_entry: failedSide,
						entry_id: failedSide === "destination" ? to.id : from.id,
						request_sent: requestSent
					}
				};
			}
		}
	};
}
var GITHUB_DEFAULT_REF = "vault://github/echoomegaprime";
var BOOTSTRAP_CAPABILITY = "vault.admin.console.bootstrap";
var PLANNERS = Object.freeze({
	vault_status: (_a, env) => ({
		capability: "vault.status",
		resource: "vault:status",
		params: {},
		summary: "Read broker status",
		run: async () => fromV1(await vaultStatus(env.broker))
	}),
	vault_list: (_a, env) => ({
		capability: "vault.list",
		resource: "vault:*",
		params: {},
		summary: "List credential references",
		run: async () => fromV1(await vaultList(env.broker))
	}),
	vault_find: (a, env) => {
		const query = reqStr(a, "query");
		return {
			capability: "vault.find",
			resource: "vault:*",
			params: { query },
			summary: `Search the vault for "${clip(query, 80)}"`,
			run: async () => fromV1(await vaultFind(env.broker, query))
		};
	},
	vault_metadata: (a, env) => {
		const ref = anyRef(a);
		return {
			capability: "vault.metadata",
			resource: ref,
			params: { credential_ref: ref },
			summary: `Read metadata of ${ref}`,
			run: async () => fromV1(await vaultMetadata(env.broker, ref), ref)
		};
	},
	credential_health: (a, env) => {
		const ref = anyRef(a);
		return {
			capability: "vault.credential.health",
			resource: ref,
			params: { credential_ref: ref },
			summary: `Check that ${ref} still authenticates`,
			run: async () => fromV1(await credentialHealth(env.broker, ref), ref)
		};
	},
	github_get_user: (a, env) => {
		const ref = providerRef(a, "github", GITHUB_DEFAULT_REF);
		return {
			capability: "github.user.read",
			resource: "github:user",
			params: { credential_ref: ref },
			summary: `GitHub identity check with ${ref}`,
			run: async () => fromV1(await githubGetUser(env.broker, ref), ref)
		};
	},
	github_get_repository: (a, env) => {
		const ref = providerRef(a, "github", GITHUB_DEFAULT_REF);
		const { owner, repo, resource } = githubRepoResource(a);
		return {
			capability: "github.repo.read",
			resource,
			params: {
				credential_ref: ref,
				owner,
				repo
			},
			summary: `Read repository ${owner}/${repo}`,
			run: async () => fromV1(await githubGetRepository(env.broker, {
				credential_ref: ref,
				owner,
				repo
			}), ref)
		};
	},
	github_get_file: (a, env) => {
		const ref = providerRef(a, "github", GITHUB_DEFAULT_REF);
		const { owner, repo, resource } = githubRepoResource(a);
		const path = reqStr(a, "path");
		const gitRef = optStr(a, "ref");
		return {
			capability: "github.contents.read",
			resource,
			params: {
				credential_ref: ref,
				owner,
				repo,
				path,
				ref: gitRef
			},
			summary: `Read ${clip(path, 120)} from ${owner}/${repo}`,
			run: async () => fromV1(await githubGetFile(env.broker, {
				credential_ref: ref,
				owner,
				repo,
				path,
				ref: gitRef
			}), ref)
		};
	},
	github_list_repositories: (a, env) => {
		const ref = providerRef(a, "github", GITHUB_DEFAULT_REF);
		const perPage = typeof a.per_page === "number" ? a.per_page : void 0;
		return {
			capability: "github.repo.list",
			resource: "github:user/repos",
			params: {
				credential_ref: ref,
				per_page: perPage
			},
			summary: `List repositories visible to ${ref}`,
			run: async () => fromV1(await githubListRepositories(env.broker, {
				credential_ref: ref,
				per_page: perPage
			}), ref)
		};
	},
	github_create_branch: (a, env) => {
		const ref = providerRef(a, "github", GITHUB_DEFAULT_REF);
		const { owner, repo, resource } = githubRepoResource(a);
		const branch = a.branch;
		if (!isValidBranchName(branch)) throw new ToolInputError("invalid_arguments", "branch: not a valid branch name");
		const fromSha = reqStr(a, "from_sha");
		if (!SHA_RE.test(fromSha)) throw new ToolInputError("invalid_arguments", "from_sha: expected a 40-character commit SHA");
		return {
			capability: "github.branch.create",
			resource,
			params: {
				credential_ref: ref,
				owner,
				repo,
				branch,
				from_sha: fromSha
			},
			summary: `Create branch ${branch} in ${owner}/${repo} at ${fromSha.slice(0, 12)}`,
			run: async () => fromV1(await githubCreateBranch(env.broker, {
				credential_ref: ref,
				owner,
				repo,
				branch,
				from_sha: fromSha
			}), ref)
		};
	},
	github_create_or_update_file: (a, env) => {
		const { owner, repo, resource } = githubRepoResource(a);
		const path = reqStr(a, "path");
		const branch = a.branch;
		if (!isValidBranchName(branch)) throw new ToolInputError("invalid_arguments", "branch: not a valid branch name");
		const message = reqStr(a, "message");
		const content = reqStr(a, "content_base64");
		const sha = optStr(a, "sha");
		return {
			capability: "github.contents.write",
			resource,
			params: {
				owner,
				repo,
				path,
				branch,
				sha,
				message_sha256: sha256(message),
				content_sha256: sha256(content)
			},
			summary: `Write ${clip(path, 120)} to ${owner}/${repo} on branch "${branch}" (not an agent/* branch; this may be the default branch). Commit message: ${clip(message, 120)}`,
			run: async (ctx) => {
				const params = {
					owner,
					repo,
					path,
					branch,
					message,
					content_base64: content
				};
				if (sha !== void 0) params.sha = sha;
				if (ctx.approved) params.allow_default_branch = true;
				return fromGithub(await GITHUB_CAPABILITIES["github.contents.write"](params, {
					client: env.identity,
					deps: env.deps.github
				}));
			}
		};
	},
	github_create_draft_pr: (a, env) => {
		const { owner, repo, resource } = githubRepoResource(a);
		const title = reqStr(a, "title");
		const head = reqStr(a, "head");
		const base = optStr(a, "base");
		const body = optStr(a, "body");
		return {
			capability: "github.pr.create_draft",
			resource,
			params: {
				owner,
				repo,
				title,
				head,
				base,
				body_sha256: body === void 0 ? void 0 : sha256(body)
			},
			summary: `Open a draft PR in ${owner}/${repo}: ${head} → ${base ?? "default branch"} — ${clip(title, 120)}`,
			run: async () => {
				const params = {
					owner,
					repo,
					title,
					head
				};
				if (base !== void 0) params.base = base;
				if (body !== void 0) params.body = body;
				return fromGithub(await GITHUB_CAPABILITIES["github.pr.create_draft"](params, {
					client: env.identity,
					deps: env.deps.github
				}));
			}
		};
	},
	github_repo_transfer: (a, env) => {
		const { owner, repo, resource } = githubRepoResource(a);
		const newOwner = reqStr(a, "new_owner");
		const newName = optStr(a, "new_name");
		return {
			capability: "github.repo.transfer",
			resource,
			params: {
				owner,
				repo,
				new_owner: newOwner,
				new_name: newName
			},
			summary: `TRANSFER repository ${owner}/${repo} to ${clip(newOwner, 60)}${newName ? ` as ${clip(newName, 100)}` : ""}`,
			run: async () => {
				const params = {
					owner,
					repo,
					new_owner: newOwner
				};
				if (newName !== void 0) params.new_name = newName;
				return fromGithub(await GITHUB_CAPABILITIES["github.repo.transfer"](params, {
					client: env.identity,
					deps: env.deps.github
				}));
			}
		};
	},
	cloudflare_zone_get: (a, env) => {
		const ref = providerRef(a, "cloudflare", "vault://cloudflare/global_api_key");
		const zone = reqStr(a, "zone_id");
		return {
			capability: "cloudflare.zone.read",
			resource: clip(`cloudflare:zone/${sanitizeDisplayText(zone, 80)}`, MAX_RESOURCE),
			params: {
				credential_ref: ref,
				zone_id: zone
			},
			summary: `Read Cloudflare zone ${clip(zone, 40)}`,
			run: async () => fromV1(await cloudflareZoneGet(env.broker, {
				credential_ref: ref,
				zone_id: zone
			}), ref)
		};
	},
	openai_account_status: (a, env) => {
		const ref = providerRef(a, "openai", "vault://openai/api_key");
		return {
			capability: "openai.account.read",
			resource: "openai:account",
			params: { credential_ref: ref },
			summary: "Probe the OpenAI account",
			run: async () => fromV1(await openaiAccountStatus(env.broker, { credential_ref: ref }), ref)
		};
	},
	xai_account_status: (a, env) => {
		const ref = providerRef(a, "xai", "vault://xai/api_key");
		return {
			capability: "xai.account.read",
			resource: "xai:account",
			params: { credential_ref: ref },
			summary: "Probe the xAI account",
			run: async () => fromV1(await xaiAccountStatus(env.broker, { credential_ref: ref }), ref)
		};
	},
	stripe_balance: (a, env) => {
		const ref = providerRef(a, "stripe", "vault://stripe/secret_key");
		return {
			capability: "stripe.balance.read",
			resource: "stripe:balance",
			params: { credential_ref: ref },
			summary: "Read the Stripe balance",
			run: async () => fromV1(await stripeBalance(env.broker, { credential_ref: ref }), ref)
		};
	},
	credential_use: (a, env) => proxyPlan(a, env, {
		method: "operation",
		path: "resource"
	}),
	provider_request: (a, env) => proxyPlan(a, env, {
		method: "method",
		path: "path"
	}),
	entry_list: (a, env) => {
		const site = optStr(a, "site");
		const query = optStr(a, "query");
		return {
			capability: "vault.entry.list",
			resource: clip(`entry:${site ? sanitizeDisplayText(site, 253) : "*"}`, MAX_RESOURCE),
			params: {
				site,
				query
			},
			summary: "List credential entries (metadata only)",
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: { entries: (await listEntries({
							site,
							query
						}, env.deps.cards)).map(agentEntryView) }
					} };
				} catch (err) {
					return { result: entryFailure(err) };
				}
			}
		};
	},
	entry_request_card: (a, env) => {
		const site = reqStr(a, "site");
		const account = optStr(a, "account");
		const purpose = optStr(a, "purpose");
		const kind = reqStr(a, "kind");
		const reason = reqStr(a, "reason");
		const entryId = optStr(a, "entry_id");
		return {
			capability: "vault.card.request",
			resource: clip(`entry:${sanitizeDisplayText(site, 253) || "?"}/${account ? sanitizeDisplayText(account, 200) : "*"}`, MAX_RESOURCE),
			params: {
				site,
				account,
				purpose,
				kind,
				reason,
				entry_id: entryId
			},
			summary: `Ask the owner to enter a ${kind} for ${clip(site, 80)}${account ? ` (${clip(account, 80)})` : ""}: ${clip(reason, 200)}`,
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: {
							...await requestCard({
								client: env.identity,
								site,
								account,
								purpose,
								kind,
								reason,
								entry_id: entryId
							}, {
								...env.deps.cards,
								ledger: async () => void 0
							}),
							next: "The owner received a single-use link. Poll entry_card_status; when it is completed, use the entry with entry_use."
						}
					} };
				} catch (err) {
					return { result: entryFailure(err) };
				}
			}
		};
	},
	entry_card_status: (a, env) => {
		const cardId = reqStr(a, "card_id");
		return {
			capability: "vault.card.status",
			resource: clip(`card:${sanitizeDisplayText(cardId, 64) || "?"}`, MAX_RESOURCE),
			params: { card_id: cardId },
			summary: "Read the status of a credential card",
			run: async () => {
				try {
					const status = await getCardStatus(cardId, {
						...env.deps.cards,
						client: env.identity
					});
					const data = {
						card_id: status.card_id,
						status: status.status,
						expires_at: status.expires_at
					};
					if (status.entry_id) data.entry_id = status.entry_id;
					if (status.entry) data.entry = agentEntryView(status.entry);
					return {
						result: {
							ok: true,
							data
						},
						audit: status.entry ? { credential_ref: status.entry.ref } : void 0
					};
				} catch (err) {
					return { result: entryFailure(err) };
				}
			}
		};
	},
	entry_use: entryUsePlan,
	approval_status: (a, env) => {
		const id = reqStr(a, "approval_id");
		return {
			capability: "vault.approval.status",
			resource: clip(`approval:${sanitizeDisplayText(id, 32) || "?"}`, MAX_RESOURCE),
			params: { approval_id: id },
			summary: "Read the status of an approval",
			run: async () => {
				const record = await getApproval(id, env.deps.approvals);
				if (!record || record.client_id !== env.identity.client_id) return { result: {
					ok: false,
					error: "approval_not_found"
				} };
				const data = {
					approval_id: record.id,
					status: record.status,
					capability: record.capability,
					resource: record.resource,
					created_at: record.created_at,
					expires_at: record.expires_at
				};
				if (record.decided_at) data.decided_at = record.decided_at;
				return { result: {
					ok: true,
					data
				} };
			}
		};
	},
	audit_list: (a, env) => {
		const limit = typeof a.limit === "number" ? a.limit : 100;
		const clientId = optStr(a, "client_id");
		const capability = optStr(a, "capability");
		return {
			capability: "audit.read",
			resource: "ledger",
			params: {
				limit,
				client_id: clientId,
				capability
			},
			summary: "Read the audit ledger",
			run: async () => {
				return { result: {
					ok: true,
					data: { records: await (env.deps.listLedger ?? listLedger)({
						limit,
						client_id: clientId,
						capability
					}) }
				} };
			}
		};
	},
	audit_verify: (_a, env) => ({
		capability: "audit.verify",
		resource: "ledger",
		params: {},
		summary: "Verify the audit ledger's hash chain",
		run: async () => {
			const verification = await (env.deps.verifyLedger ?? verifyLedger)();
			const head = await (env.deps.ledgerHead ?? ledgerHead)();
			let anchor = null;
			let anchorError;
			try {
				anchor = await newestAnchorVerdict(env.deps.anchor, verification.ok ? verification.count : void 0);
			} catch {
				anchorError = "anchor_check_unavailable";
			}
			return { result: {
				ok: true,
				data: {
					...verification,
					head,
					anchor,
					...anchorError ? { anchor_error: anchorError } : {}
				}
			} };
		}
	}),
	admin_anchor_now: (_a, env) => ({
		capability: "vault.admin.ledger.anchor",
		resource: "ledger:anchor",
		params: {},
		summary: "Anchor the ledger head to Telegram",
		run: async () => {
			const outcome = await anchorHead(env.deps.anchor);
			if (outcome.ok) return { result: {
				ok: true,
				data: outcome
			} };
			const { ok: _ok, ...failure } = outcome;
			return { result: {
				ok: false,
				...failure
			} };
		}
	}),
	admin_verify_anchor: (a, env) => {
		const line = reqStr(a, "line");
		return {
			capability: "vault.admin.ledger.verify_anchor",
			resource: "ledger:anchor",
			params: {},
			summary: "Check an anchor line against the ledger",
			run: async () => {
				try {
					const check = await verifyAnchorLine(line, env.deps.anchor);
					if (!check) return { result: {
						ok: false,
						error: "anchor_line_invalid"
					} };
					return { result: {
						ok: true,
						data: check
					} };
				} catch (err) {
					return { result: {
						ok: false,
						error: "internal_error",
						detail: clip(sanitizeError(err).message, 300)
					} };
				}
			}
		};
	},
	admin_list_clients: (_a, _env) => ({
		capability: "vault.admin.clients.list",
		resource: "vault:clients",
		params: {},
		summary: "List OAuth clients",
		run: async () => {
			try {
				return { result: {
					ok: true,
					data: { clients: await listClients() }
				} };
			} catch (err) {
				return { result: {
					ok: false,
					error: "internal_error",
					detail: clip(sanitizeError(err).message, 300)
				} };
			}
		}
	}),
	admin_set_client_scopes: (a) => {
		const clientId = reqStr(a, "client_id");
		const scopes = Array.isArray(a.scopes) ? a.scopes : void 0;
		if (!scopes || !scopes.every((s) => typeof s === "string")) throw new ToolInputError("invalid_arguments", "scopes: must be an array of strings");
		return {
			capability: "vault.admin.clients.scopes",
			resource: clip(`vault:client/${sanitizeDisplayText(clientId, 120)}`, MAX_RESOURCE),
			params: {
				client_id: clientId,
				scopes: [...scopes]
			},
			summary: `Set granted scopes for ${clip(clientId, 80)}`,
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: { client: await setClientScopes(clientId, scopes) }
					} };
				} catch (err) {
					return { result: {
						ok: false,
						error: err instanceof Error ? err.message : "internal_error"
					} };
				}
			}
		};
	},
	admin_revoke_client: (a) => {
		const clientId = reqStr(a, "client_id");
		return {
			capability: "vault.admin.clients.revoke",
			resource: clip(`vault:client/${sanitizeDisplayText(clientId, 120)}`, MAX_RESOURCE),
			params: { client_id: clientId },
			summary: `Revoke client ${clip(clientId, 80)}`,
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: await revokeClient(clientId)
					} };
				} catch (err) {
					return { result: {
						ok: false,
						error: "internal_error",
						detail: clip(sanitizeError(err).message, 300)
					} };
				}
			}
		};
	},
	admin_list_grants: (a, env) => {
		const clientId = optStr(a, "client_id");
		const entryId = optStr(a, "entry_id");
		return {
			capability: "vault.admin.grants.list",
			resource: "vault:grants",
			params: {
				client_id: clientId,
				entry_id: entryId
			},
			summary: "List entry consent grants",
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: { grants: await listEntryGrants({
							client_id: clientId,
							entry_id: entryId
						}, env.deps.grants ?? getDefaultEntryGrantStore()) }
					} };
				} catch (err) {
					return { result: {
						ok: false,
						error: "internal_error",
						detail: clip(sanitizeError(err).message, 300)
					} };
				}
			}
		};
	},
	admin_revoke_grant: (a, env) => {
		const clientId = reqStr(a, "client_id");
		const entryId = reqStr(a, "entry_id");
		const host = optStr(a, "host");
		const pathPrefix = optStr(a, "path_prefix");
		if (pathPrefix !== void 0 && host === void 0) throw new ToolInputError("invalid_arguments", "path_prefix requires host");
		return {
			capability: "vault.admin.grants.revoke",
			resource: clip(`vault:grant/${sanitizeDisplayText(clientId, 120)}/${sanitizeDisplayText(entryId, 40)}`, MAX_RESOURCE),
			params: {
				client_id: clientId,
				entry_id: entryId,
				host,
				path_prefix: pathPrefix
			},
			summary: `Revoke consent of ${clip(clientId, 60)} for ${clip(entryId, 40)}${host ? ` on ${clip(host, 60)}${pathPrefix ? ` ${clip(pathPrefix, 80)}` : ""}` : ""}`,
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: { removed: await revokeEntryGrant(clientId, entryId, env.deps.grants ?? getDefaultEntryGrantStore(), host, pathPrefix) }
					} };
				} catch (err) {
					return { result: {
						ok: false,
						error: "internal_error",
						detail: clip(sanitizeError(err).message, 300)
					} };
				}
			}
		};
	},
	admin_list_entries: (a, env) => {
		const site = optStr(a, "site");
		const query = optStr(a, "query");
		return {
			capability: "vault.admin.entries.list",
			resource: clip(`entry:${site ? sanitizeDisplayText(site, 253) : "*"}`, MAX_RESOURCE),
			params: {
				site,
				query
			},
			summary: "List credential entries (owner view)",
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: { entries: await listEntries({
							site,
							query
						}, env.deps.cards) }
					} };
				} catch (err) {
					return { result: entryFailure(err) };
				}
			}
		};
	},
	admin_set_rotation: (a, env) => {
		const entryId = reqStr(a, "entry_id");
		const mode = reqStr(a, "mode");
		const intervalDays = typeof a.interval_days === "number" ? a.interval_days : void 0;
		const providerTokenId = optStr(a, "provider_token_id");
		return {
			capability: "vault.admin.entries.rotation.set",
			resource: clip(`vault:entry/${sanitizeDisplayText(entryId, 40)}`, MAX_RESOURCE),
			params: {
				entry_id: entryId,
				mode,
				interval_days: intervalDays,
				provider_token_id: providerTokenId
			},
			summary: `Set rotation policy of ${clip(entryId, 40)}`,
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: await setEntryRotation(entryId, {
							mode,
							interval_days: intervalDays,
							provider_token_id: providerTokenId
						}, rotationDeps(env))
					} };
				} catch (err) {
					return { result: entryFailure(err) };
				}
			}
		};
	},
	admin_rotate_entry: (a, env) => {
		const entryId = reqStr(a, "entry_id");
		return {
			capability: "vault.admin.entries.rotate",
			resource: clip(`vault:entry/${sanitizeDisplayText(entryId, 40)}`, MAX_RESOURCE),
			params: { entry_id: entryId },
			summary: `Rotate ${clip(entryId, 40)} now`,
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: await rotateEntry(entryId, rotationDeps(env))
					} };
				} catch (err) {
					return { result: entryFailure(err) };
				}
			}
		};
	},
	admin_rotation_due: (_a, env) => ({
		capability: "vault.admin.entries.rotation.due",
		resource: "entry:*",
		params: {},
		summary: "List entries due for rotation",
		run: async () => {
			try {
				return { result: {
					ok: true,
					data: { entries: await listRotationDue((env.deps.now ?? Date.now)(), env.deps.cards) }
				} };
			} catch (err) {
				return { result: entryFailure(err) };
			}
		}
	}),
	admin_purge_entry: (a, env) => {
		const entryId = reqStr(a, "entry_id");
		const confirm = reqStr(a, "confirm");
		return {
			capability: "vault.admin.entries.purge",
			resource: clip(`vault:entry/${sanitizeDisplayText(entryId, 40)}`, MAX_RESOURCE),
			params: { entry_id: entryId },
			summary: `PURGE ${clip(entryId, 40)} (irreversible)`,
			run: async () => {
				if (confirm !== `PURGE ${entryId}`) return { result: {
					ok: false,
					error: "confirmation_required",
					detail: "confirm must be exactly \"PURGE <entry_id>\""
				} };
				try {
					return { result: {
						ok: true,
						data: await purgeEntry(entryId, rotationDeps(env))
					} };
				} catch (err) {
					return { result: entryFailure(err) };
				}
			}
		};
	},
	admin_digest_now: (a, env) => {
		const digestDeps = {
			cards: env.deps.cards,
			grants: env.deps.grants,
			env: env.deps.env,
			now: env.deps.now,
			...env.deps.digest
		};
		let window;
		try {
			window = resolveDigestWindow({
				from: optStr(a, "from"),
				to: optStr(a, "to")
			}, (digestDeps.now ?? Date.now)());
		} catch (err) {
			throw new ToolInputError("invalid_arguments", err instanceof DigestError ? err.message : "invalid window");
		}
		const send = a.send === true;
		return {
			capability: "vault.admin.digest",
			resource: clip(`vault:digest/${window.from}/${window.to}`, MAX_RESOURCE),
			params: {
				from: window.from,
				to: window.to,
				send
			},
			summary: "Build the audit digest",
			run: async () => {
				try {
					const digest = await buildDigest(window, digestDeps);
					const data = {
						digest,
						text: formatDigest(digest)
					};
					if (send) data.send = await sendDigest(digest, digestDeps);
					return { result: {
						ok: true,
						data
					} };
				} catch (err) {
					return { result: {
						ok: false,
						error: "internal_error",
						detail: clip(sanitizeError(err).message, 300)
					} };
				}
			}
		};
	},
	admin_delete_entry: (a, env) => {
		const entryId = reqStr(a, "entry_id");
		return {
			capability: "vault.admin.entries.delete",
			resource: clip(`vault:entry/${sanitizeDisplayText(entryId, 40)}`, MAX_RESOURCE),
			params: { entry_id: entryId },
			summary: `Soft-delete ${clip(entryId, 40)}`,
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: { entry: await deleteEntry(entryId, env.deps.cards) }
					} };
				} catch (err) {
					return { result: entryFailure(err) };
				}
			}
		};
	},
	admin_request_reentry: (a, env) => {
		const entryId = reqStr(a, "entry_id");
		const reason = optStr(a, "reason") ?? "Re-entry requested from the owner console";
		return {
			capability: "vault.admin.entries.reentry",
			resource: clip(`vault:entry/${sanitizeDisplayText(entryId, 40)}`, MAX_RESOURCE),
			params: {
				entry_id: entryId,
				reason
			},
			summary: `Send a re-entry card for ${clip(entryId, 40)}`,
			run: async () => {
				try {
					const entry = await getEntryMetadata(entryId, env.deps.cards);
					if (!entry || entry.status === "deleted") return { result: {
						ok: false,
						error: "entry_not_found"
					} };
					return { result: {
						ok: true,
						data: await requestCard({
							client: env.identity,
							site: entry.site,
							kind: entry.kind,
							reason,
							entry_id: entry.id
						}, {
							...env.deps.cards,
							ledger: async () => void 0
						})
					} };
				} catch (err) {
					return { result: entryFailure(err) };
				}
			}
		};
	},
	entry_inject: (a, env) => entryInjectPlan(a, env),
	entry_transfer: entryTransferPlan,
	admin_enroll_injector: (a, env) => {
		const name = reqStr(a, "name");
		const jwk = a.public_key_jwk;
		if (typeof jwk !== "string" && !isRecord(jwk) || jwk === "") throw new ToolInputError("invalid_public_key", INJECTOR_ERROR_DETAIL.invalid_public_key);
		return {
			capability: "vault.admin.injector.enroll",
			resource: "vault:injectors",
			params: {},
			summary: "Enroll a browser injector",
			run: async () => {
				try {
					const { injector, token } = await enrollInjector({
						name,
						public_key_jwk: jwk
					}, injectorDeps(env));
					return { result: {
						ok: true,
						data: {
							...injector,
							injector_token: token,
							next: "Paste injector_id and injector_token into the extension now. The token is shown once and stored only as a hash; to replace it, revoke this injector and enroll again."
						}
					} };
				} catch (err) {
					const code = err instanceof InjectorError ? err.code : "internal_error";
					return { result: {
						ok: false,
						error: code,
						detail: INJECTOR_ERROR_DETAIL[code]
					} };
				}
			}
		};
	},
	admin_list_injectors: (_a, env) => ({
		capability: "vault.admin.injector.list",
		resource: "vault:injectors",
		params: {},
		summary: "List browser injectors",
		run: async () => {
			try {
				return { result: {
					ok: true,
					data: { injectors: await listInjectors(injectorDeps(env)) }
				} };
			} catch {
				return { result: {
					ok: false,
					error: "internal_error"
				} };
			}
		}
	}),
	admin_revoke_injector: (a, env) => {
		const id = reqStr(a, "injector_id");
		return {
			capability: "vault.admin.injector.revoke",
			resource: clip(`vault:injector/${sanitizeDisplayText(id, 40)}`, MAX_RESOURCE),
			params: { injector_id: id },
			summary: `Revoke browser injector ${clip(sanitizeDisplayText(id, 40), 40)}`,
			run: async () => {
				try {
					return { result: {
						ok: true,
						data: {
							injector_id: id,
							revoked: await revokeInjector(id, injectorDeps(env))
						}
					} };
				} catch (err) {
					const code = err instanceof InjectorError ? err.code : "internal_error";
					return { result: {
						ok: false,
						error: code,
						detail: INJECTOR_ERROR_DETAIL[code]
					} };
				}
			}
		};
	},
	admin_console_bootstrap: (_a, env) => ({
		capability: BOOTSTRAP_CAPABILITY,
		resource: "vault:console/bootstrap",
		params: {},
		summary: "Mint the owner-console enrollment code",
		run: async () => {
			try {
				const minted = await mintBootstrapCode(env.identity, {
					...env.deps.now ? { now: env.deps.now } : {},
					...env.deps.console
				});
				return { result: {
					ok: true,
					data: {
						bootstrap_code: minted.code,
						expires_at: minted.expires_at,
						ttl_seconds: minted.ttl_seconds,
						next: "Open /console/enroll on the console origin, type this code and register a passkey. Single use; minting again replaces it."
					}
				} };
			} catch (err) {
				return { result: {
					ok: false,
					error: err instanceof Error && err.message === "local_only" ? "tier3_human_only" : "internal_error"
				} };
			}
		}
	}),
	credential_rotate: (a) => tier3Plan("vault.secret.rotate", a),
	credential_revoke: (a) => tier3Plan("vault.secret.delete", a)
});
/** Wiring for rotation.ts: the gateway's entry stores, grant store and transport, ledgered under the caller. */
function rotationDeps(env) {
	return {
		...env.deps.cards,
		rotatorFetch: env.deps.fetch,
		grants: env.deps.grants,
		actor: env.identity.client_id,
		...env.deps.now ? { now: env.deps.now } : {}
	};
}
/** Tier 3: the policy engine always denies; `run` exists only to fail closed if that ever changed. */
function tier3Plan(capability, a) {
	const ref = parseVaultRef(optStr(a, "credential_ref") ?? "")?.raw;
	return {
		capability,
		resource: ref ?? "vault:*",
		params: { credential_ref: ref },
		summary: "",
		run: async () => ({ result: {
			ok: false,
			error: "tier3_human_only"
		} })
	};
}
var DEFINITIONS_BY_NAME = new Map(TOOL_DEFINITIONS.map((t) => [t.name, t]));
function validIdentity(identity) {
	const i = identity;
	return !!i && typeof i === "object" && typeof i.client_id === "string" && i.client_id.length > 0 && i.client_id.length <= 200 && (i.kind === "owner" ? isMintedOwnerIdentity(i) && OWNER_CLIENT_ID_PATTERN.test(i.client_id) : (i.kind === "oauth" || i.kind === "local" || i.kind === "workload") && !i.client_id.startsWith("owner:")) && Array.isArray(i.scopes) && i.scopes.every((s) => typeof s === "string");
}
/**
* Execute one tool call for an authenticated client. Never throws; never
* returns secret material. See the module header for the flow.
*/
async function dispatchTool(identity, name, args, deps = {}) {
	if (!validIdentity(identity)) return {
		ok: false,
		error: "unauthenticated"
	};
	const started = Date.now();
	const ledger = deps.ledger ?? appendLedger;
	const toolName = typeof name === "string" ? name : "";
	const base = { client_id: identity.client_id };
	/** Best effort: a refusal is still a refusal when the ledger is down. */
	const record = async (row) => {
		try {
			await ledger({
				...row,
				duration_ms: Date.now() - started
			});
			return true;
		} catch (err) {
			log.error("vault_gateway_ledger_failed", {
				capability: row.capability,
				client_id: row.client_id,
				result: row.result,
				error: err?.code ?? "ledger_error"
			});
			return false;
		}
	};
	const finish = (result) => redactValue(result);
	try {
		if (isForbiddenToolName(toolName)) {
			await record({
				...base,
				capability: "vault.secret.reveal",
				resource: clip(`tool:${sanitizeDisplayText(toolName, 64) || "?"}`, MAX_RESOURCE),
				decision: "deny",
				tier: 3,
				result: "denied",
				error: "tool_forbidden"
			});
			return finish({
				ok: false,
				error: "tool_forbidden"
			});
		}
		const definition = DEFINITIONS_BY_NAME.get(toolName);
		const planner = definition ? PLANNERS[toolName] : void 0;
		if (!definition || !planner) {
			await record({
				...base,
				capability: "vault.tool.unknown",
				resource: clip(`tool:${sanitizeDisplayText(toolName, 64) || "?"}`, MAX_RESOURCE),
				decision: "deny",
				tier: 3,
				result: "denied",
				error: "unknown_tool"
			});
			return finish({
				ok: false,
				error: "unknown_tool"
			});
		}
		const raw = args === void 0 || args === null ? {} : args;
		let approvalId;
		let plan;
		try {
			if (!isRecord(raw)) throw new ToolInputError("invalid_arguments", "arguments must be an object");
			checkArgs(definition, raw);
			const a = { ...raw };
			if (toolName !== "approval_status") {
				approvalId = typeof a.approval_id === "string" && a.approval_id ? a.approval_id : void 0;
				delete a.approval_id;
			}
			plan = await planner(a, {
				identity,
				deps,
				broker: {
					caller: identity.client_id,
					store: deps.store
				}
			});
		} catch (err) {
			const code = err instanceof ToolInputError ? err.code : "internal_error";
			const detail = err instanceof ToolInputError ? err.message : clip(sanitizeError(err).message, 300);
			await record({
				...base,
				capability: `tool.${toolName}`,
				resource: `tool:${toolName}`,
				decision: "deny",
				tier: 0,
				result: "error",
				error: `${code}: ${detail}`
			});
			return finish({
				ok: false,
				error: code,
				detail
			});
		}
		const request = {
			client: identity,
			capability: plan.capability,
			resource: plan.resource,
			params: plan.params
		};
		let decision = evaluatePolicy(request, deps.rules);
		decision = await enforceRateLimits(request, decision, deps.rules, deps.policy);
		const adminIdentity = identity.kind === "local" || identity.kind === "owner" && plan.capability !== BOOTSTRAP_CAPABILITY;
		if (plan.capability.startsWith("vault.admin.") && decision.decision === "deny" && adminIdentity) {
			log.warn("vault_admin_owner_allow", {
				capability: plan.capability,
				client_id: identity.client_id,
				kind: identity.kind
			});
			decision = {
				decision: "allow",
				tier: decision.tier,
				reason: identity.kind === "local" ? "owner_local" : "owner_console"
			};
		}
		const row = {
			...base,
			capability: plan.capability,
			resource: plan.resource,
			decision: decision.decision,
			tier: decision.tier,
			task: plan.task
		};
		if (decision.decision === "deny") {
			await record({
				...row,
				result: "denied",
				error: decision.reason
			});
			return finish({
				ok: false,
				error: decision.reason,
				tier: decision.tier
			});
		}
		const grants = deps.grants ?? getDefaultEntryGrantStore();
		const nowMs = (deps.now ?? Date.now)();
		const grant = decision.decision === "allow" && plan.consentEntryId !== void 0 && plan.consentHost && plan.consentPath ? await grants.find(identity.client_id, plan.consentEntryId, plan.consentHost, plan.consentPath, nowMs) : null;
		const needsConsent = decision.decision === "allow" && plan.consentEntryId !== void 0 && grant === null;
		let approved = false;
		if (decision.decision === "escalate" || needsConsent) {
			const ledgerDecision = "escalate";
			if (!approvalId) {
				let approval;
				try {
					approval = await createApproval(request, plan.summary || `${plan.capability} on ${plan.resource}`, deps.approvals);
				} catch (err) {
					const code = err instanceof ApprovalError ? err.code : "approval_error";
					await record({
						...row,
						decision: ledgerDecision,
						result: "error",
						error: `approval_unavailable: ${code}`
					});
					return finish({
						ok: false,
						error: "approval_unavailable",
						detail: code
					});
				}
				await record({
					...row,
					decision: ledgerDecision,
					result: "pending_approval",
					approval_id: approval.id
				});
				return finish({
					ok: false,
					error: "approval_required",
					approval_id: approval.id,
					expires_at: approval.expires_at,
					tier: decision.tier,
					detail: needsConsent ? "The owner must approve this client's first use of this entry on Telegram. Then call again with the same arguments plus approval_id." : "The owner must approve this exact request on Telegram. Then call again with the same arguments plus approval_id. Use approval_status to check."
				});
			}
			const consumed = await consumeApproval(approvalId, request, deps.approvals);
			if (consumed !== "ok") {
				await record({
					...row,
					decision: ledgerDecision,
					result: consumed === "pending" ? "pending_approval" : "denied",
					approval_id: approvalId,
					error: `approval_${consumed}`
				});
				return finish({
					ok: false,
					error: `approval_${consumed}`,
					approval: consumed,
					approval_id: approvalId,
					tier: decision.tier
				});
			}
			approved = true;
			if (needsConsent && plan.consentEntryId && plan.consentHost && plan.consentPath) {
				const { ttlMs, maxUses } = grantConfig(deps.env);
				await grants.add({
					client_id: identity.client_id,
					entry_id: plan.consentEntryId,
					host: plan.consentHost,
					path_prefix: plan.consentPath,
					approval_id: approvalId,
					granted_at: new Date(nowMs).toISOString(),
					expires_at: new Date(nowMs + ttlMs).toISOString(),
					max_uses: maxUses,
					uses_remaining: maxUses
				});
				log.info("vault_entry_grant_created", {
					client_id: identity.client_id,
					entry_id: plan.consentEntryId,
					host: plan.consentHost,
					path_prefix: plan.consentPath,
					approval_id: approvalId
				});
			}
		} else if (grant && plan.consentEntryId && plan.consentHost && plan.consentPath) await grants.consume(identity.client_id, plan.consentEntryId, plan.consentHost, plan.consentPath, nowMs);
		const runRow = {
			...row,
			decision: approved ? "escalate" : decision.decision,
			approval_id: approved ? approvalId : void 0
		};
		const isEntryUse = plan.capability.startsWith("vault.entry.use.");
		const isRead = lookupCapability(plan.capability)?.access === "read";
		if (approved && !isEntryUse && !isRead) {
			if (!await record({
				...runRow,
				result: "committing"
			})) return finish({
				ok: false,
				error: "ledger_unavailable",
				action_performed: false,
				detail: "Refused: the authorization could not be recorded before acting."
			});
		}
		let outcome;
		try {
			outcome = await plan.run({
				decision: {
					...decision,
					decision: runRow.decision
				},
				approved,
				approvalId: approved ? approvalId : void 0
			});
		} catch (err) {
			outcome = { result: {
				ok: false,
				error: "internal_error",
				detail: clip(sanitizeError(err).message, 300)
			} };
		}
		const result = outcome.result;
		if (!outcome.ledgered) {
			const status = outcome.audit?.http_status;
			const failed = !result.ok || status !== void 0 && status >= 400;
			if (!await record({
				...runRow,
				result: failed ? "error" : "ok",
				credential_ref: outcome.audit?.credential_ref,
				http_status: status,
				credential_path: outcome.audit?.credential_path,
				fallback_reason: outcome.audit?.fallback_reason,
				error: !result.ok ? result.error : failed ? `http_${status}` : void 0
			})) return finish({
				ok: false,
				error: "ledger_unavailable",
				detail: result.ok ? "The action ran but could not be recorded in the audit ledger, so its result is withheld." : "The action failed and could not be recorded in the audit ledger.",
				action_performed: result.ok
			});
		}
		return finish(result);
	} catch (err) {
		log.error("vault_gateway_internal_error", {
			tool: toolName,
			client_id: identity.client_id,
			error: clip(sanitizeError(err).message, 200)
		});
		return finish({
			ok: false,
			error: "internal_error"
		});
	}
}
//#endregion
export { bootstrapCodeHash as a, cleanTransports as c, authenticateRequest as d, wwwAuthenticateHeader as f, BOOTSTRAP_CODE_PATTERN as i, getDefaultOwnerConsoleStore as l, gateway_exports as n, mintOwnerIdentity as o, listTools as r, ownerClientId as s, dispatchTool as t, sha256Hex as u };
