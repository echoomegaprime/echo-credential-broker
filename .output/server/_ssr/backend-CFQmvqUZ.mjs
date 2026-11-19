import { r as __exportAll } from "../_runtime.mjs";
import { o as log, r as __exportAll$1 } from "./log-BHJOU13W.mjs";
import { createHmac, randomBytes } from "node:crypto";
//#region node_modules/.nitro/vite/services/ssr/assets/backend-CFQmvqUZ.js
var backend_CFQmvqUZ_exports = /* @__PURE__ */ __exportAll({
	n: () => backend_exports,
	r: () => GateUnavailableError,
	t: () => GateVaultBackend
});
var GateSigningError = class extends Error {
	code;
	constructor(code, message) {
		super(message);
		this.name = "GateSigningError";
		this.code = code;
	}
};
/** Code-point order, which is how Python sorts `str` keys (UTF-16 unit order differs for astral characters). */
function byCodePoint(a, b) {
	const x = Array.from(a);
	const y = Array.from(b);
	const n = Math.min(x.length, y.length);
	for (let i = 0; i < n; i++) {
		const d = x[i].codePointAt(0) - y[i].codePointAt(0);
		if (d !== 0) return d;
	}
	return x.length - y.length;
}
/** A JSON string literal the way Python writes it with ensure_ascii=True. */
function pyString(s) {
	return JSON.stringify(s).replace(/[\u0080-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
/** `json.dumps(value, sort_keys=True, separators=(",", ":"))`, for the JSON subset the gate is sent. */
function pythonCanonicalJson(value) {
	if (value === null) return "null";
	switch (typeof value) {
		case "string": return pyString(value);
		case "boolean": return value ? "true" : "false";
		case "number":
			if (!Number.isSafeInteger(value)) throw new GateSigningError("gate_params_unsignable", "gate params may only contain safe integers as numbers");
			return String(value);
		case "object": {
			if (Array.isArray(value)) return `[${value.map((v) => pythonCanonicalJson(v === void 0 ? null : v)).join(",")}]`;
			const obj = value;
			return `{${Object.keys(obj).filter((k) => obj[k] !== void 0).sort(byCodePoint).map((k) => `${pyString(k)}:${pythonCanonicalJson(obj[k])}`).join(",")}}`;
		}
		default: throw new GateSigningError("gate_params_unsignable", `gate params cannot contain a ${typeof value}`);
	}
}
/**
* The `auth` block for one gate call. `secretHex` is the per-key `secret_hmac` the gate
* holds for `apiKey`; it never leaves this function except as the HMAC key.
*/
function signGateRequest(secretHex, apiKey, capability, params, opts = {}) {
	const hex = secretHex.trim();
	if (!/^(?:[0-9a-fA-F]{2}){16,}$/.test(hex)) throw new GateSigningError("gate_hmac_secret_invalid", "ECHO_SDK_HMAC_SECRET must be hex, at least 16 bytes");
	if (!apiKey) throw new GateSigningError("gate_api_key_missing", "cannot sign a gate request without the API key");
	const ts = opts.ts ?? Math.floor(Date.now() / 1e3);
	const nonce = opts.nonce ?? randomBytes(16).toString("hex");
	if (!Number.isSafeInteger(ts) || !/^[A-Za-z0-9_-]{8,128}$/.test(nonce)) throw new GateSigningError("gate_auth_fields_invalid", "invalid ts or nonce for a gate signature");
	const canonical = `v1|${apiKey}|${capability}|${pythonCanonicalJson(params)}|${nonce}|${ts}`;
	return {
		hmac: createHmac("sha256", Buffer.from(hex, "hex")).update(canonical, "utf8").digest("hex"),
		nonce,
		ts
	};
}
/**
* Thin client for the ECHO SDK gate's `echo.vault.*` capabilities — the
* canonical Master Vault ("Vault A"), PyNaCl SecretBox at rest, on FORGE.
*
* This is the ONLY place this repo talks to the gate. Shapes below are
* verified live against the gate (2026-08-24), not guessed:
*
*   locate({service}) -> { status: EXACT|AMBIGUOUS|NOT_FOUND, candidates[],
*                           get_with?: {service, username}, did_you_mean?[] }
*   get({service, username}) -> { secret, key_fingerprint, updated_at, ... }
*   put({service, username, secret, note}) -> { stored, version, key_fingerprint }
*
* Doctrine: LOCATE, THEN GET — never hand-guess a (service, username) pair.
* `locate` returns coordinates, never a secret, and never picks for you.
*/
var GATE_URL = (process.env.ECHO_SDK_GATE_URL || "https://forge.echo-op.com").replace(/\/+$/, "");
var API_KEY = process.env.ECHO_SDK_API_KEY || "";
/** Per-key `secret_hmac` the gate holds for ECHO_SDK_API_KEY (hex). Signs every call; required for tier 2+. */
var HMAC_SECRET = process.env.ECHO_SDK_HMAC_SECRET || "";
var TIMEOUT_MS = 1e4;
/**
* Capabilities the gate registers at danger tier 2 or higher. It answers these with
* 423 `hmac_required_for_tier2_plus` unless the envelope is signed (gate-hmac.ts), so an
* unsigned call is refused here, with a reason an operator can act on, before any byte
* (including the secret of a put) leaves this process.
*/
var SIGNATURE_REQUIRED = /* @__PURE__ */ new Set(["echo.vault.put"]);
/** The gate's own short error code from a refusal body (`{detail:{error}}`), if it has one. Never a value. */
function gateErrorCode(body) {
	const code = (body?.detail)?.error;
	return typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? code : void 0;
}
/** Safe-to-log view of gate params — `secret` is the one field that must never reach a log line. */
function safeParams(params) {
	const { secret: _secret, ...rest } = params;
	return rest;
}
var GateUnavailableError = class extends Error {
	constructor(message) {
		super(message);
		this.name = "GateUnavailableError";
	}
};
/**
* Invoke one `echo.vault.*` capability through the gate. Fails CLOSED: any
* network error, timeout, non-2xx, or malformed envelope throws — callers
* must never treat a failed gate call as "credential absent" (that would
* silently make a live outage look like a missing credential).
*/
async function invoke(capability, params, bypassReason) {
	const started = Date.now();
	if (!API_KEY) {
		log.error("gate_call_no_key", {
			capability,
			params: safeParams(params)
		});
		throw new GateUnavailableError("ECHO_SDK_API_KEY is not configured — refusing to call the vault gate without auth.");
	}
	if (!HMAC_SECRET && SIGNATURE_REQUIRED.has(capability)) {
		log.error("gate_call_unsigned", {
			capability,
			params: safeParams(params)
		});
		throw new GateUnavailableError(`ECHO_SDK_HMAC_SECRET is not configured — the gate refuses ${capability} (tier 2) without a signed envelope.`);
	}
	let auth;
	if (HMAC_SECRET) try {
		auth = signGateRequest(HMAC_SECRET, API_KEY, capability, params);
	} catch (error) {
		const code = error instanceof GateSigningError ? error.code : "gate_signing_failed";
		log.error("gate_call_signing_failed", {
			capability,
			params: safeParams(params),
			code
		});
		throw new GateUnavailableError(`could not sign the gate call ${capability}: ${code}`);
	}
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
	try {
		const res = await fetch(`${GATE_URL}/sdk/invoke`, {
			method: "POST",
			headers: {
				"X-Echo-API-Key": API_KEY,
				"Content-Type": "application/json"
			},
			body: JSON.stringify({
				envelope_version: 1,
				capability,
				params,
				context: { bypass_reason: bypassReason },
				...auth ? { auth } : {}
			}),
			signal: controller.signal
		});
		const envelope = await res.json();
		const durationMs = Date.now() - started;
		if (!res.ok || envelope.status !== "ok" || envelope.result?.status_code < 200 || envelope.result?.status_code >= 300) {
			log.warn("gate_call_failed", {
				capability,
				params: safeParams(params),
				http_status: res.status,
				gate_error: gateErrorCode(envelope),
				signed: Boolean(auth),
				envelope_status: envelope.status,
				body_status: envelope.result?.status_code,
				run_id: envelope.run_id,
				duration_ms: durationMs
			});
			throw new GateUnavailableError(`vault gate call failed: ${capability} -> http ${res.status} / envelope ${envelope.status} / body ${envelope.result?.status_code}`);
		}
		log.debug("gate_call_ok", {
			capability,
			params: safeParams(params),
			run_id: envelope.run_id,
			duration_ms: durationMs
		});
		return envelope.result.body;
	} catch (error) {
		if (error instanceof GateUnavailableError) throw error;
		log.error("gate_call_unreachable", {
			capability,
			params: safeParams(params),
			message: error.message,
			duration_ms: Date.now() - started
		});
		throw new GateUnavailableError(`vault gate unreachable calling ${capability}: ${error.message}`);
	} finally {
		clearTimeout(timer);
	}
}
async function vaultLocate(service, bypassReason) {
	return invoke("echo.vault.locate", { service }, bypassReason);
}
async function vaultGet(service, username, bypassReason) {
	return invoke("echo.vault.get", {
		service,
		username
	}, bypassReason);
}
async function vaultPut(service, username, secret, note, bypassReason) {
	return invoke("echo.vault.put", {
		service,
		username,
		secret,
		note
	}, bypassReason);
}
/**
* Doctrine-documented canonical vault names that a bare provider-id locate
* query does NOT surface (verified live 2026-08-24: `locate("github")`
* returns 7 legacy-clutter candidates and `GitHub_echoomegaprime_PAT` is not
* among them — the vault indexes exact historical names, not fuzzy matches).
* This is NOT a guess: it is the exact name doctrine names as "THE ONLY
* GITHUB ACCOUNT FOR NEW WORK". Keyed by `${provider}/${account}`.
*/
var CANONICAL_LOCATE_QUERY = { "github/echoomegaprime": "GitHub_echoomegaprime_PAT" };
/**
* Resolve a (locate-query, account-hint) pair to ONE definite (service,
* username) coordinate against the canonical vault. Never guesses across
* AMBIGUOUS candidates without a matching hint — that is exactly the bug
* doctrine already hit once (an un-hinted `get("google")` silently returning
* one arbitrary credential of 43).
*/
async function resolveCoordinate(locateQuery, accountHint, bypassReason) {
	const canonical = CANONICAL_LOCATE_QUERY[`${locateQuery}/${accountHint}`];
	const loc = await vaultLocate(canonical ?? locateQuery, bypassReason);
	if (loc.status === "EXACT" && loc.get_with) return loc.get_with;
	if (loc.status === "AMBIGUOUS") {
		const hint = accountHint.trim().toLowerCase();
		const match = loc.candidates.find((c) => c.username.toLowerCase() === hint || c.actual_service.toLowerCase().includes(hint));
		if (match) return {
			service: match.actual_service,
			username: match.username
		};
		return null;
	}
	return null;
}
/**
* Pluggable backend seam for CredentialStore. The production default
* (`GateVaultBackend`) hits the REAL canonical Master Vault over the SDK
* gate. `FakeVaultBackend` is an in-memory stand-in for tests — tests must
* NEVER exercise `GateVaultBackend` against production Vault A (writing a
* throwaway test secret under a real ref like `vault://github/echoomegaprime`
* would clobber the actual credential every other service depends on).
*/
var backend_exports = /* @__PURE__ */ __exportAll$1({ GateVaultBackend: () => GateVaultBackend });
var GateVaultBackend = class {
	put(service, username, secret, note, bypassReason) {
		return vaultPut(service, username, secret, note, bypassReason);
	}
	get(service, username, bypassReason) {
		return vaultGet(service, username, bypassReason);
	}
	locate(locateQuery, accountHint, bypassReason) {
		return resolveCoordinate(locateQuery, accountHint, bypassReason);
	}
	search(query, bypassReason) {
		return vaultLocate(query, bypassReason);
	}
};
//#endregion
export { GateVaultBackend as n, backend_CFQmvqUZ_exports as r, GateUnavailableError as t };
