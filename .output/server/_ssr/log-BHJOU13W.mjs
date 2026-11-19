import { r as __exportAll$1 } from "../_runtime.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/log-BHJOU13W.js
var log_BHJOU13W_exports = /* @__PURE__ */ __exportAll$1({
	a: () => redactString,
	c: () => safeJson,
	d: () => INVARIANT,
	f: () => __exportAll,
	i: () => installProcessRedaction,
	l: () => sanitizeError,
	n: () => log_exports,
	o: () => redactValue,
	r: () => containsSecretPrefix,
	s: () => registerSecretForRedaction,
	t: () => log,
	u: () => FORBIDDEN_TOOLS
});
var __defProp = Object.defineProperty;
var __exportAll = (all, no_symbols) => {
	let target = {};
	for (var name in all) __defProp(target, name, {
		get: all[name],
		enumerable: true
	});
	if (!no_symbols) __defProp(target, Symbol.toStringTag, { value: "Module" });
	return target;
};
var INVARIANT = "Agents may USE credentials. Agents may NEVER READ credentials.";
var FORBIDDEN_TOOLS = [
	"get_secret",
	"get_token",
	"get_pat",
	"get_password",
	"get_private_key",
	"read_secret",
	"read_credential",
	"export_vault",
	"dump_vault",
	"dump_credentials",
	"reveal_credential",
	"unwrap_secret"
];
var SENSITIVE_RESPONSE_KEYS = /* @__PURE__ */ new Set([
	"token",
	"secret",
	"password",
	"private_key",
	"refresh_token",
	"cookie",
	"authorization_header",
	"authorization",
	"access_token",
	"id_token",
	"client_secret",
	"api_key",
	"pat"
]);
var knownSecrets = /* @__PURE__ */ new Set();
var PLACEHOLDERS = {
	github: "[REDACTED_GITHUB_TOKEN]",
	openai: "[REDACTED_OPENAI_KEY]",
	stripe: "[REDACTED_STRIPE_KEY]",
	xai: "[REDACTED_XAI_KEY]",
	cloudflare: "[REDACTED_CLOUDFLARE_TOKEN]",
	bearer: "Bearer [REDACTED]",
	authorization: "Authorization: [REDACTED]",
	jwt: "[REDACTED_JWT]",
	privateKey: "[REDACTED_PRIVATE_KEY]",
	cookie: "[REDACTED_COOKIE]",
	session: "[REDACTED_SESSION]",
	refresh: "[REDACTED_REFRESH_TOKEN]",
	generic: "[REDACTED_SECRET]"
};
var PATTERN_RULES = [
	{
		re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
		replacement: PLACEHOLDERS.privateKey
	},
	{
		re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*$/g,
		replacement: PLACEHOLDERS.privateKey
	},
	{
		re: /(?<![A-Za-z0-9])ghs_[0-9]+_[A-Za-z0-9._-]{20,}/g,
		replacement: PLACEHOLDERS.github
	},
	{
		re: /(?<![A-Za-z0-9])(?:ev[acpr]|ewk)_[A-Za-z0-9_-]{43,}/g,
		replacement: "[REDACTED_VAULT_TOKEN]"
	},
	{
		re: /(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}\b/g,
		replacement: PLACEHOLDERS.github
	},
	{
		re: /(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,}\b/g,
		replacement: PLACEHOLDERS.github
	},
	{
		re: /(?<![A-Za-z0-9])sk-live-[A-Za-z0-9]{16,}\b/g,
		replacement: PLACEHOLDERS.stripe
	},
	{
		re: /(?<![A-Za-z0-9])sk-test-[A-Za-z0-9]{16,}\b/g,
		replacement: PLACEHOLDERS.stripe
	},
	{
		re: /(?<![A-Za-z0-9])sk-[A-Za-z0-9]{20,}\b/g,
		replacement: PLACEHOLDERS.openai
	},
	{
		re: /(?<![A-Za-z0-9])xai-[A-Za-z0-9_-]{20,}\b/g,
		replacement: PLACEHOLDERS.xai
	},
	{
		re: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
		replacement: PLACEHOLDERS.bearer
	},
	{
		re: /\bAuthorization\s*:\s*[^\r\n]+/gi,
		replacement: PLACEHOLDERS.authorization
	},
	{
		re: /\bx-access-token\s*[:=]\s*\S+/gi,
		replacement: "[REDACTED_ACCESS_TOKEN]"
	},
	{
		re: /(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
		replacement: PLACEHOLDERS.jwt
	},
	{
		re: /\b(?:refresh_token)\s*[:=]\s*[^\s;&]+/gi,
		replacement: `refresh_token=${PLACEHOLDERS.refresh}`
	},
	{
		re: /\b(?:sessionid|session_id|session)\s*[:=]\s*[^\s;&]+/gi,
		replacement: `session=${PLACEHOLDERS.session}`
	},
	{
		re: /\b(?:Set-Cookie|Cookie)\s*:\s*[^\r\n]+/gi,
		replacement: `Cookie: ${PLACEHOLDERS.cookie}`
	}
];
function placeholderForSecret(secret) {
	if (/^github_pat_|^gh[pousr]_/.test(secret)) return PLACEHOLDERS.github;
	if (/^sk-live-|^sk-test-/.test(secret)) return PLACEHOLDERS.stripe;
	if (/^sk-/.test(secret)) return PLACEHOLDERS.openai;
	if (/^xai-/.test(secret)) return PLACEHOLDERS.xai;
	return PLACEHOLDERS.generic;
}
function registerSecretForRedaction(secret) {
	const trimmed = secret.trim();
	if (trimmed.length >= 8) knownSecrets.add(trimmed);
}
function redactString(input) {
	let out = input;
	if (knownSecrets.size > 0) {
		const secrets = [...knownSecrets].sort((a, b) => b.length - a.length);
		for (const secret of secrets) if (secret && out.includes(secret)) out = out.split(secret).join(placeholderForSecret(secret));
	}
	for (const rule of PATTERN_RULES) out = out.replace(rule.re, rule.replacement);
	return out;
}
/**
* Redact a JSON-serializable value: sensitive keys are blanked and every
* string (keys included) passes through redactString. Works leaf by leaf, so a
* greedy rule such as `Authorization: …` can only consume the string it is in,
* never the JSON around it. Anything that is not plain JSON data fails closed.
*/
function redactValue(value) {
	if (value == null) return value;
	if (typeof value === "string") return redactString(value);
	if (typeof value !== "object") return value;
	try {
		return redactTree(JSON.parse(JSON.stringify(value)));
	} catch {
		return { error: "unserializable_redacted" };
	}
}
function redactTree(value) {
	if (typeof value === "string") return redactString(value);
	if (Array.isArray(value)) return value.map(redactTree);
	if (value && typeof value === "object") {
		const out = {};
		for (const [key, val] of Object.entries(value)) {
			const safeKey = redactString(key);
			out[safeKey] = SENSITIVE_RESPONSE_KEYS.has(key.toLowerCase()) ? PLACEHOLDERS.generic : redactTree(val);
		}
		return out;
	}
	return value;
}
function sanitizeError(error) {
	if (error instanceof Error) {
		const clean = new Error(redactString(error.message));
		clean.name = error.name;
		if (error.stack) clean.stack = redactString(error.stack);
		return clean;
	}
	return new Error(redactString(String(error)));
}
function safeJson(value) {
	try {
		const leafRedacted = JSON.stringify(redactValue(value));
		if (leafRedacted === void 0) return "null";
		const again = redactString(leafRedacted);
		if (again === leafRedacted) return leafRedacted;
		try {
			JSON.parse(again);
			return again;
		} catch {
			return leafRedacted;
		}
	} catch {
		return "{\"error\":\"unserializable_redacted\"}";
	}
}
var processHookInstalled = false;
var originalWrites = {};
function wrapStream(stream, key) {
	if (originalWrites[key]) return;
	const orig = stream.write.bind(stream);
	originalWrites[key] = orig;
	stream.write = ((chunk, encoding, cb) => {
		try {
			if (typeof chunk === "string") chunk = redactString(chunk);
			else if (chunk instanceof Uint8Array) {
				const enc = typeof encoding === "string" && encoding !== "buffer" ? encoding : "utf8";
				chunk = Buffer.from(redactString(Buffer.from(chunk).toString(enc)));
			}
		} catch {
			chunk = "[REDACTED_OUTPUT]\n";
		}
		return orig(chunk, encoding, cb);
	});
}
function installProcessRedaction() {
	if (processHookInstalled) return;
	processHookInstalled = true;
	wrapStream(process.stdout, "stdout");
	wrapStream(process.stderr, "stderr");
	const origConsoleError = console.error.bind(console);
	console.error = (...args) => {
		origConsoleError(...args.map((arg) => typeof arg === "string" ? redactString(arg) : redactValue(arg)));
	};
	const origConsoleLog = console.log.bind(console);
	console.log = (...args) => {
		origConsoleLog(...args.map((arg) => typeof arg === "string" ? redactString(arg) : redactValue(arg)));
	};
	const origConsoleWarn = console.warn.bind(console);
	console.warn = (...args) => {
		origConsoleWarn(...args.map((arg) => typeof arg === "string" ? redactString(arg) : redactValue(arg)));
	};
	process.on("uncaughtException", (err) => {
		const clean = sanitizeError(err);
		origConsoleError("[vault] uncaughtException", clean.message);
	});
}
function containsSecretPrefix(text) {
	return /\bgithub_pat_[A-Za-z0-9_]{8,}/.test(text) || /\bgh[pousr]_[A-Za-z0-9]{8,}/.test(text) || /\bsk-[A-Za-z0-9]{12,}/.test(text);
}
/**
* Structured, secret-safe logging for the vault layer. Every line is one JSON
* object on stderr — never stdout, which the stdio MCP transport owns for
* protocol frames. Values pass through `redactString` first, so a secret that
* accidentally lands in a log field is caught by the same redaction armed
* everywhere else in this broker, not a second, weaker copy of that logic.
*/
var log_exports = /* @__PURE__ */ __exportAll({ log: () => log });
function emit(level, event, fields = {}) {
	const safeFields = {};
	for (const [k, v] of Object.entries(fields)) safeFields[k] = typeof v === "string" ? redactString(v) : v;
	const line = JSON.stringify({
		ts: (/* @__PURE__ */ new Date()).toISOString(),
		level,
		component: "echo-credential-broker",
		event,
		...safeFields
	});
	process.stderr.write(line + "\n");
}
var log = {
	debug: (event, fields) => {
		if (process.env.ECHO_VAULT_DEBUG === "1") emit("debug", event, fields);
	},
	info: (event, fields) => emit("info", event, fields),
	warn: (event, fields) => emit("warn", event, fields),
	error: (event, fields) => emit("error", event, fields)
};
//#endregion
export { installProcessRedaction as a, redactString as c, safeJson as d, sanitizeError as f, containsSecretPrefix as i, redactValue as l, INVARIANT as n, log as o, __exportAll as r, log_BHJOU13W_exports as s, FORBIDDEN_TOOLS as t, registerSecretForRedaction as u };
