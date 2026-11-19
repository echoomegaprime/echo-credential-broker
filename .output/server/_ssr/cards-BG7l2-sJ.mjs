import { c as redactString, i as containsSecretPrefix, l as redactValue, o as log, u as registerSecretForRedaction } from "./log-BHJOU13W.mjs";
import { a as constantTimeEqual, h as sanitizeDisplayText, n as approverTelegramId } from "./approvals-vHr7W1Jg.mjs";
import { t as appendLedger } from "./ledger-DtKvLmuw.mjs";
import { createHash, randomBytes } from "node:crypto";
//#region node_modules/.nitro/vite/services/ssr/assets/cards-BG7l2-sJ.js
/** A fixed code. The message is the code: no submitted text ever rides in it. */
var CookieInputError = class extends Error {
	code;
	constructor(code) {
		super(code);
		this.name = "CookieInputError";
		this.code = code;
	}
};
var MAX_COOKIE_INPUT_CHARS = 131072;
/** Cap of the canonical stored JSON, i.e. the secret length limit of a `cookie` entry. */
var MAX_COOKIE_JAR_CHARS = 32768;
var MAX_SET_COOKIE_CHARS = 8192;
var TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
var VALUE_RE = /^[\x20-\x3a\x3c-\x7e]*$/;
var PATH_RE = /^\/[\x21-\x3a\x3c-\x7e]*$/;
var HOST_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
/** NOT the Public Suffix List — a short list of common multi-label suffixes. See the file header. */
var MULTI_LABEL_SUFFIXES = new Set("co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk sch.uk com.au net.au org.au edu.au gov.au id.au co.nz net.nz org.nz govt.nz ac.nz co.jp ne.jp or.jp ac.jp go.jp com.br net.br org.br gov.br com.cn net.cn org.cn gov.cn edu.cn co.in net.in org.in gov.in ac.in co.za org.za com.mx org.mx gob.mx com.ar com.tr com.sg com.hk com.tw co.kr or.kr co.il com.ua com.pl co.id com.my com.ph com.vn co.th com.co com.pe com.ve com.eg com.sa com.ng co.ke com.pk com.bd github.io githubusercontent.com gitlab.io herokuapp.com vercel.app netlify.app pages.dev workers.dev web.app firebaseapp.com appspot.com cloudfront.net azurewebsites.net blogspot.com s3.amazonaws.com onrender.com fly.dev glitch.me repl.co ngrok.io ngrok-free.app r2.dev deno.dev surge.sh now.sh".split(" "));
/** True for a name no cookie may be scoped to: no dot (bare TLD / single label) or a listed suffix. */
function isPublicSuffix(domain) {
	return !domain.includes(".") || MULTI_LABEL_SUFFIXES.has(domain);
}
function isIpLike(host) {
	return /^\d+$/.test(host.slice(host.lastIndexOf(".") + 1)) || host.includes(":");
}
/** RFC 6265 §5.1.3. `domain` has no leading dot. */
function domainMatches(host, domain) {
	if (!host || !domain) return false;
	if (host === domain) return true;
	return host.endsWith(`.${domain}`) && !isIpLike(host);
}
/** RFC 6265 §5.1.4. */
function pathMatches(requestPath, cookiePath) {
	if (requestPath === cookiePath) return true;
	if (!requestPath.startsWith(cookiePath)) return false;
	return cookiePath.endsWith("/") || requestPath.charAt(cookiePath.length) === "/";
}
function requestPathname(path) {
	const p = (path ?? "/").split(/[?#]/)[0];
	return p.startsWith("/") ? p : "/";
}
/** RFC 6265 §5.1.4 default-path of a request path. */
function defaultPath(requestPath) {
	const p = requestPathname(requestPath);
	const last = p.lastIndexOf("/");
	return last <= 0 ? "/" : p.slice(0, last);
}
function fail(code) {
	throw new CookieInputError(code);
}
function checkName(name) {
	if (typeof name !== "string" || name.length === 0 || name.length > 128 || !TOKEN_RE.test(name)) fail("invalid_cookie_name");
	return name;
}
function checkValue(value) {
	if (typeof value !== "string") fail("invalid_cookie_value");
	const v = value;
	if (v.length > 4096) fail("cookie_value_too_long");
	if (!VALUE_RE.test(v) || v !== v.trim()) fail("invalid_cookie_value");
	return v;
}
function checkPath(path) {
	if (path === void 0 || path === null || path === "") return "/";
	if (typeof path !== "string" || path.length > 1024 || !PATH_RE.test(path)) fail("invalid_cookie_path");
	return path;
}
/** "" (no domain) or a validated lower-case host without the leading dot. */
function checkDomain(domain) {
	if (domain === void 0 || domain === null || domain === "") return "";
	if (typeof domain !== "string") fail("invalid_cookie_domain");
	const d = domain.trim().toLowerCase().replace(/^\./, "").replace(/\.$/, "");
	if (!HOST_RE.test(d) || isIpLike(d)) fail("invalid_cookie_domain");
	if (isPublicSuffix(d)) fail("public_suffix_domain");
	return d;
}
function checkExpiry(raw) {
	if (raw === void 0 || raw === null || raw === "") return null;
	let seconds;
	if (typeof raw === "number") seconds = raw;
	else if (typeof raw === "string") {
		const t = raw.trim();
		if (/^session$/i.test(t)) return null;
		seconds = /^-?\d+(\.\d+)?$/.test(t) ? Number(t) : Date.parse(t) / 1e3;
	} else return fail("invalid_cookie_expiry");
	if (!Number.isFinite(seconds)) fail("invalid_cookie_expiry");
	if (seconds <= 0) return null;
	if (seconds > 1e11) seconds /= 1e3;
	return Math.floor(seconds);
}
function rawFromHeader(text) {
	if (/[\r\n]/.test(text)) fail("invalid_cookie_header");
	const body = text.replace(/^cookie\s*:/i, "");
	const out = [];
	for (const part of body.split(";")) {
		const pair = part.trim();
		if (!pair) continue;
		const eq = pair.indexOf("=");
		if (eq <= 0) fail("invalid_cookie_header");
		out.push({
			name: pair.slice(0, eq).trim(),
			value: pair.slice(eq + 1).trim(),
			domain: "",
			path: "/",
			secure: false,
			httpOnly: false,
			hostOnly: true,
			expires: null
		});
	}
	return out;
}
function rawFromJson(value) {
	return (Array.isArray(value) ? value : value && typeof value === "object" && Array.isArray(value.cookies) ? value.cookies : fail("invalid_cookie_json")).map((item) => {
		if (!item || typeof item !== "object" || Array.isArray(item)) fail("invalid_cookie_json");
		const o = item;
		const session = o.session === true;
		return {
			name: o.name,
			value: o.value,
			domain: o.domain,
			path: o.path,
			secure: o.secure === true,
			httpOnly: o.httpOnly === true,
			hostOnly: typeof o.hostOnly === "boolean" ? o.hostOnly : void 0,
			expires: session ? null : o.expirationDate ?? o.expires ?? o.expiry ?? null
		};
	});
}
function rawFromNetscape(text) {
	const out = [];
	for (const rawLine of text.split(/\r?\n/)) {
		let line = rawLine;
		let httpOnly = false;
		if (line.startsWith("#HttpOnly_")) {
			httpOnly = true;
			line = line.slice(10);
		} else if (line.trim() === "" || line.startsWith("#")) continue;
		const f = line.split("	");
		if (f.length < 6 || f.length > 7) fail("invalid_cookies_txt");
		const flag = f[1].trim().toUpperCase();
		const secure = f[3].trim().toUpperCase();
		if (!["TRUE", "FALSE"].includes(flag) || !["TRUE", "FALSE"].includes(secure) || !/^\d{1,16}$/.test(f[4].trim())) fail("invalid_cookies_txt");
		if (f[0].trim() === "") fail("invalid_cookie_domain");
		out.push({
			name: f[5],
			value: f[6] ?? "",
			domain: f[0].trim(),
			path: f[2],
			secure: secure === "TRUE",
			httpOnly,
			hostOnly: flag === "FALSE",
			expires: Number(f[4].trim())
		});
	}
	return out;
}
function sameIdentity(a, b, site) {
	return a.name === b.name && a.path === b.path && (a.domain || site) === (b.domain || site);
}
/**
* Parse what the owner pasted. Accepts a string in any of the three formats, or
* an already-decoded JSON array (the card page's JSON submit). Throws
* CookieInputError with a short code; never includes input text in an error.
*/
function parseCookieInput(input, opts = {}) {
	const site = opts.site ?? "";
	const nowSec = Math.floor((opts.now ?? Date.now()) / 1e3);
	let raw;
	let format;
	if (typeof input === "string") {
		if (input.length > 131072) fail("cookie_input_too_large");
		const text = (input.charCodeAt(0) === 65279 ? input.slice(1) : input).trim();
		if (!text) fail("cookie_input_empty");
		if (text.includes("\0")) fail("invalid_cookie_value");
		if (text.startsWith("[") || text.startsWith("{")) {
			let decoded;
			try {
				decoded = JSON.parse(text);
			} catch {
				return fail("invalid_cookie_json");
			}
			raw = rawFromJson(decoded);
			format = "json";
		} else if (text.includes("	") || /^# (Netscape )?HTTP Cookie File/im.test(text)) {
			raw = rawFromNetscape(text);
			format = "netscape";
		} else {
			raw = rawFromHeader(text);
			format = "header";
		}
	} else if (Array.isArray(input)) {
		if (input.length > 5e3) fail("too_many_cookies");
		raw = rawFromJson(input);
		format = "json";
	} else return fail("cookie_input_empty");
	if (raw.length === 0) fail("cookie_input_empty");
	if (raw.length > 5e3) fail("too_many_cookies");
	const skipped = {
		short_value: 0,
		expired: 0,
		other_site: 0
	};
	const cookies = [];
	for (const r of raw) {
		const leadingDot = typeof r.domain === "string" && r.domain.trim().startsWith(".");
		const domain = checkDomain(r.domain);
		const hostOnly = domain === "" ? true : r.hostOnly ?? !leadingDot;
		if (site && domain) {
			if (!(domain === site || domain.endsWith(`.${site}`) || !hostOnly && site.endsWith(`.${domain}`))) {
				skipped.other_site += 1;
				continue;
			}
		}
		const cookie = {
			name: checkName(r.name),
			value: checkValue(r.value),
			domain,
			path: checkPath(r.path),
			secure: r.secure,
			httpOnly: r.httpOnly,
			hostOnly,
			expires: checkExpiry(r.expires)
		};
		if (cookie.expires !== null && cookie.expires <= nowSec) {
			skipped.expired += 1;
			continue;
		}
		if (cookie.value.length < 8) {
			skipped.short_value += 1;
			continue;
		}
		if (cookies.some((c) => sameIdentity(c, cookie, site))) fail("duplicate_cookie");
		cookies.push(cookie);
		if (cookies.length > 200) fail("too_many_cookies");
	}
	if (cookies.length === 0) fail("no_usable_cookie");
	const jar = {
		v: 1,
		cookies
	};
	if (serializeJar(jar).length > 32768) fail("cookie_jar_too_large");
	return {
		jar,
		format,
		skipped
	};
}
function canonicalCookie(c) {
	return {
		name: c.name,
		value: c.value,
		domain: c.domain,
		path: c.path,
		secure: c.secure,
		httpOnly: c.httpOnly,
		hostOnly: c.hostOnly,
		expires: c.expires
	};
}
/** The canonical stored form: compact JSON, fixed key order, cookies in jar order. */
function serializeJar(jar) {
	return JSON.stringify({
		v: 1,
		cookies: jar.cookies.map(canonicalCookie)
	});
}
/** Strictly re-validate a stored jar. Throws CookieInputError("invalid_cookie_jar"). */
function parseStoredJar(text) {
	try {
		const o = JSON.parse(text);
		if (!o || o.v !== 1 || !Array.isArray(o.cookies) || o.cookies.length > 200) throw new Error("shape");
		return {
			v: 1,
			cookies: o.cookies.map((raw) => {
				const c = raw;
				if (!c || typeof c !== "object") throw new Error("shape");
				const expires = c.expires === null ? null : c.expires;
				if (expires !== null && !(typeof expires === "number" && Number.isInteger(expires) && expires > 0)) throw new Error("shape");
				if ([
					c.secure,
					c.httpOnly,
					c.hostOnly
				].some((b) => typeof b !== "boolean")) throw new Error("shape");
				const domain = checkDomain(c.domain);
				if (domain !== c.domain || domain === "" && c.hostOnly !== true) throw new Error("shape");
				const value = checkValue(c.value);
				if (value.length < 8) throw new Error("shape");
				const path = checkPath(c.path);
				if (path !== c.path) throw new Error("shape");
				return {
					name: checkName(c.name),
					value,
					domain,
					path,
					secure: c.secure,
					httpOnly: c.httpOnly,
					hostOnly: c.hostOnly,
					expires
				};
			})
		};
	} catch {
		throw new CookieInputError("invalid_cookie_jar");
	}
}
function cookieApplies(c, ctx, pathname) {
	if (c.expires !== null && c.expires * 1e3 <= ctx.now) return false;
	const domain = c.domain || ctx.site || "";
	if (!domain) return false;
	if (c.hostOnly ? ctx.host !== domain : !domainMatches(ctx.host, domain) || isPublicSuffix(domain)) return false;
	return pathMatches(pathname, c.path);
}
/**
* RFC 6265 §5.4: the Cookie header for one https request, or null when no
* cookie matches. Host-only cookies need the exact host; domain cookies match
* the domain and its subdomains (never a public suffix); the path must
* path-match; expired cookies are skipped; `Secure` is always satisfied (the
* broker only makes https requests); longer paths first, then jar order.
*/
function cookieHeaderFor(jar, ctx) {
	const pathname = requestPathname(ctx.path);
	const host = ctx.host.toLowerCase();
	const picked = jar.cookies.map((c, i) => ({
		c,
		i
	})).filter(({ c }) => cookieApplies(c, {
		...ctx,
		host
	}, pathname)).sort((a, b) => b.c.path.length - a.c.path.length || a.i - b.i);
	if (picked.length === 0) return null;
	return picked.map(({ c }) => `${c.name}=${c.value}`).join("; ");
}
/** RFC 6265 §5.2 (attribute parsing). Returns null for anything malformed: a response is never trusted. */
function parseSetCookie(header, nowSec) {
	if (typeof header !== "string" || header.length > MAX_SET_COOKIE_CHARS || [
		"\r",
		"\n",
		"\0"
	].some((ch) => header.includes(ch))) return null;
	const parts = header.split(";");
	const pair = parts[0];
	const eq = pair.indexOf("=");
	if (eq <= 0) return null;
	const name = pair.slice(0, eq).trim();
	const value = pair.slice(eq + 1).trim();
	if (!name || name.length > 128 || !TOKEN_RE.test(name)) return null;
	if (value.length > 4096 || !VALUE_RE.test(value)) return null;
	const out = {
		name,
		value,
		domainAttr: null,
		pathAttr: null,
		secure: false,
		httpOnly: false,
		expires: null
	};
	let maxAge = null;
	let expiresAttr = null;
	for (const part of parts.slice(1)) {
		const i = part.indexOf("=");
		const key = (i < 0 ? part : part.slice(0, i)).trim().toLowerCase();
		const val = i < 0 ? "" : part.slice(i + 1).trim();
		if (key === "secure") out.secure = true;
		else if (key === "httponly") out.httpOnly = true;
		else if (key === "domain") {
			const d = val.toLowerCase().replace(/^\./, "").replace(/\.$/, "");
			if (d) out.domainAttr = d;
		} else if (key === "path") out.pathAttr = val.startsWith("/") ? val : null;
		else if (key === "max-age") {
			if (/^-?\d{1,15}$/.test(val)) maxAge = Number(val);
		} else if (key === "expires") {
			const t = Date.parse(val);
			if (Number.isFinite(t)) expiresAttr = Math.floor(t / 1e3);
		}
	}
	if (maxAge !== null) out.expires = maxAge <= 0 ? -Infinity : nowSec + maxAge;
	else if (expiresAttr !== null) out.expires = expiresAttr <= nowSec ? -Infinity : expiresAttr;
	return out;
}
/**
* RFC 6265 §5.3: apply a response's Set-Cookie headers to the jar. Returns a
* NEW jar and whether anything changed. Rules:
*   - Domain attribute: honoured only when the request host domain-matches it
*     and it is not a public suffix (a suffix equal to the host itself becomes
*     host-only); otherwise the cookie is ignored — a response cannot set a
*     cookie for another site or for a superdomain it does not belong to.
*   - No Domain attribute: host-only for the request host.
*   - Path attribute, or the request's default-path.
*   - Max-Age <= 0 or a past Expires deletes the stored cookie.
*   - `__Secure-` needs Secure; `__Host-` needs Secure, no Domain and Path=/.
*   - A value shorter than 8 characters cannot be stored (see the file header):
*     the stored cookie of that identity, now stale, is removed.
* Date parsing uses Date.parse, not the RFC's own cookie-date algorithm.
*/
function mergeSetCookie(jar, setCookieHeaders, ctx) {
	const site = ctx.site ?? "";
	const host = ctx.host.toLowerCase();
	const nowSec = Math.floor(ctx.now / 1e3);
	const cookies = jar.cookies.map(canonicalCookie);
	let changed = false;
	for (const header of setCookieHeaders) {
		const sc = parseSetCookie(header, nowSec);
		if (!sc) continue;
		let domain = host;
		let hostOnly = true;
		if (sc.domainAttr !== null) {
			if (!HOST_RE.test(sc.domainAttr) || isIpLike(sc.domainAttr)) continue;
			if (isPublicSuffix(sc.domainAttr)) {
				if (sc.domainAttr !== host) continue;
			} else if (!domainMatches(host, sc.domainAttr)) continue;
			else hostOnly = false;
			domain = sc.domainAttr;
		}
		if (!HOST_RE.test(domain)) continue;
		const path = sc.pathAttr !== null && sc.pathAttr.length <= 1024 && PATH_RE.test(sc.pathAttr) ? sc.pathAttr : defaultPath(ctx.path);
		if (sc.name.startsWith("__Secure-") && !sc.secure) continue;
		if (sc.name.startsWith("__Host-") && (!sc.secure || sc.domainAttr !== null || path !== "/")) continue;
		const next = {
			name: sc.name,
			value: sc.value,
			domain,
			path,
			secure: sc.secure,
			httpOnly: sc.httpOnly,
			hostOnly,
			expires: sc.expires === -Infinity ? null : sc.expires
		};
		const at = cookies.findIndex((c) => sameIdentity(c, next, site));
		if (sc.expires === -Infinity || sc.value.length < 8) {
			if (at >= 0) {
				cookies.splice(at, 1);
				changed = true;
			}
			continue;
		}
		if (at >= 0) {
			const old = cookies[at];
			if (old.domain === "" && next.hostOnly && next.domain === site) next.domain = "";
			if (JSON.stringify(old) !== JSON.stringify(next)) {
				cookies[at] = next;
				changed = true;
			}
		} else if (cookies.length < 200) {
			cookies.push(next);
			changed = true;
		}
	}
	return {
		jar: {
			v: 1,
			cookies
		},
		changed
	};
}
function describeJar(jar, site = "") {
	const names = [...new Set(jar.cookies.map((c) => c.name))].sort();
	const domains = [...new Set(jar.cookies.map((c) => (c.hostOnly ? "" : ".") + (c.domain || site || "(entry site)")))].sort();
	const expiries = jar.cookies.map((c) => c.expires).filter((e) => e !== null);
	return {
		count: jar.cookies.length,
		names: names.slice(0, 50),
		domains: domains.slice(0, 20),
		truncated: names.length > 50 || domains.length > 20,
		expires_at: expiries.length ? (/* @__PURE__ */ new Date(Math.min(...expiries) * 1e3)).toISOString() : null,
		session_cookies: jar.cookies.length - expiries.length
	};
}
/**
* Every form of the jar's values that must be armed for redaction before a
* request: raw, URL-encoded, URL-decoded (a framework may echo the decoded
* value), base64 and base64url. Only forms of 8+ characters (redaction's floor).
*/
function jarRedactionForms(jar) {
	const out = /* @__PURE__ */ new Set();
	for (const { value } of jar.cookies) {
		out.add(value);
		out.add(encodeURIComponent(value));
		out.add(new URLSearchParams({ v: value }).toString().slice(2));
		try {
			out.add(decodeURIComponent(value));
		} catch {}
		const bytes = Buffer.from(value, "utf8");
		out.add(bytes.toString("base64"));
		out.add(bytes.toString("base64url"));
	}
	return [...out].filter((v) => v.trim().length >= 8);
}
/**
* Vault v2 credential entries + credential cards.
*
* Invariant: agents may USE credentials, agents may NEVER READ credentials.
*
*   Entries   Metadata rows (`vault_entries`): site, account, purpose, kind,
*             default flag, status, fingerprint (first 8 hex of sha256) and
*             length. The secret VALUE lives only in the canonical vault
*             backend under a per-entry key (`echo_vault_entry_<id>` / "entry")
*             and is never written to SQL, a log line, an error or a return
*             value. Many entries per site; identity is (site, account, kind).
*
*   useEntry  The one read path: the secret is handed to a callback that runs
*             inside this module, the callback's result is scrubbed, the use is
*             written to the ledger, and only metadata comes back.
*
*   Cards     An agent that needs a credential it does not have calls
*             requestCard(). The operator gets a Telegram message with a
*             single-use link (256-bit token, stored hashed, 30 minutes) to a
*             page where they type the secret (card-pages.ts → submitCard()).
*             The agent only ever sees {card_id, status, expires_at} and, once
*             completed, the entry's metadata.
*
* deleteEntry is the reversible SOFT delete (status → deleted; the secret is
* untouched). The irreversible step is rotation.ts → purgeEntry: it destroys the
* stored secret (backend delete where one exists, otherwise an overwrite with
* random bytes — the canonical vault has no delete, see store.ts) and then
* hard-deletes the row, its cards and its grants.
*
* Rotation state (migrations/0007): rotation_mode, rotate_interval_days,
* last_rotated_at, rotate_by, rotation_count, last_rotation_error and the
* non-secret provider_token_id. A completed card re-entry counts as a manual
* rotation; auto-rotation lives in rotation.ts.
*/
var ENTRY_KINDS = [
	"password",
	"api_key",
	"oauth_token",
	"operator_secret",
	"cookie"
];
/** Sanitized error: `code` is stable; the message never carries a secret or upstream text. */
var EntryError = class extends Error {
	code;
	constructor(code, message) {
		super(message);
		this.name = "EntryError";
		this.code = code;
	}
};
var CardError = class extends Error {
	code;
	constructor(code, message) {
		super(message);
		this.name = "CardError";
		this.code = code;
	}
};
var CARD_TTL_MS = 18e5;
var MAX_SECRET_LENGTH = 4096;
/** `cookie` entries only: the canonical jar JSON may be this long (cookie-jar.ts MAX_COOKIE_JAR_CHARS). */
var MAX_COOKIE_SECRET_LENGTH = MAX_COOKIE_JAR_CHARS;
var TOKEN_BYTES = 32;
var TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
var ENTRY_ID_PATTERN = /^ve_[0-9a-f]{32}$/;
var CARD_ID_PATTERN = /^vc_[0-9a-f]{32}$/;
var SITE_PATTERN = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
var ACCOUNT_PATTERN = /^[\x21-\x7e]{1,254}$/;
var PURPOSE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._:@/+-]{0,63}$/;
var PROVIDER_TOKEN_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
var MAX_ROTATE_INTERVAL_DAYS = 3650;
var DAY_MS = 864e5;
var DEFAULT_PURPOSE = "general";
var BACKEND_USERNAME = "entry";
var BYPASS_REASON = "echo-credential-broker vault v2 entry: the secret is typed by the operator on a single-use card page or used server-side inside useEntry for one audited action; it is never returned across an MCP/HTTP boundary.";
function invalid(field, message) {
	return new EntryError(`invalid_${field}`, message);
}
function looksLikeSecret(value) {
	return containsSecretPrefix(value) || redactString(value) !== value;
}
/** "https://www.GitHub.com:443/login" → "github.com". Throws `invalid_site`. */
function normalizeSite(input) {
	if (typeof input !== "string") throw invalid("site", "Site must be a domain such as github.com");
	let s = input.trim().toLowerCase();
	s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
	s = s.split(/[/?#]/)[0] ?? "";
	s = s.slice(s.lastIndexOf("@") + 1);
	s = s.replace(/:\d{1,5}$/, "").replace(/\.$/, "").replace(/^www\./, "");
	if (!SITE_PATTERN.test(s)) throw invalid("site", "Site must be a domain such as github.com");
	return s;
}
function normalizeAccount(input) {
	const a = typeof input === "string" ? input.trim() : "";
	if (!ACCOUNT_PATTERN.test(a)) throw invalid("account", "Account must be 1-254 printable ASCII characters without spaces");
	if (looksLikeSecret(a)) throw invalid("account", "Account looks like a secret; enter the username or email instead");
	return a;
}
function normalizePurpose(input) {
	const p = typeof input === "string" ? input.trim().replace(/\s+/g, " ") : "";
	if (!p) return DEFAULT_PURPOSE;
	if (!PURPOSE_PATTERN.test(p)) throw invalid("purpose", "Purpose must be a short tag (letters, digits, space and . _ : @ / + -; max 64)");
	if (looksLikeSecret(p)) throw invalid("purpose", "Purpose looks like a secret; enter a short tag instead");
	return p;
}
function normalizeKind(input) {
	if (typeof input !== "string" || !ENTRY_KINDS.includes(input)) throw invalid("kind", `Kind must be one of: ${ENTRY_KINDS.join(", ")}`);
	return input;
}
function entryLabel(site, account, purpose) {
	return `${site} — ${account} — ${purpose}`;
}
function entryRef(id) {
	return `vault://entry/${id}`;
}
function entryResource(site, account) {
	return `entry:${site}/${account}`;
}
function secretFingerprint(secret) {
	return createHash("sha256").update(secret, "utf8").digest("hex").slice(0, 8);
}
function sha256Hex(value) {
	return createHash("sha256").update(value, "utf8").digest("hex");
}
function backendService(id) {
	return `echo_vault_entry_${id}`;
}
function toIso(v) {
	return v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString();
}
function toIsoOrNull(v) {
	return v == null ? null : toIso(v);
}
function publicEntry(row) {
	const out = {
		id: row.id,
		ref: entryRef(row.id),
		site: row.site,
		account: row.account,
		purpose: row.purpose,
		label: row.label,
		kind: row.kind,
		is_default: row.is_default,
		status: row.status,
		fingerprint: row.fingerprint,
		secret_length: row.secret_length,
		created_at: row.created_at,
		updated_at: row.updated_at,
		last_used_at: row.last_used_at,
		last_verified_at: row.last_verified_at,
		rotation_mode: row.rotation_mode,
		rotate_interval_days: row.rotate_interval_days,
		last_rotated_at: row.last_rotated_at,
		rotate_by: row.rotate_by,
		rotation_count: row.rotation_count,
		last_rotation_error: row.last_rotation_error,
		provider_token_id: row.provider_token_id
	};
	if (row.reentry_reason) out.reentry_reason = row.reentry_reason;
	if (row.kind === "cookie" && row.cookie_jar) out.cookie_jar = cloneSummary(row.cookie_jar);
	return out;
}
function cloneSummary(s) {
	return {
		...s,
		names: [...s.names],
		domains: [...s.domains]
	};
}
/** Decode the `cookie_meta` column. Anything that is not the expected shape is dropped, never thrown. */
function summaryFromColumn(raw) {
	if (raw == null || raw === "") return void 0;
	try {
		const o = typeof raw === "string" ? JSON.parse(raw) : raw;
		const strings = (v) => Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
		return {
			count: Number(o.count) || 0,
			names: strings(o.names),
			domains: strings(o.domains),
			truncated: o.truncated === true,
			expires_at: typeof o.expires_at === "string" ? o.expires_at : null,
			session_cookies: Number(o.session_cookies) || 0
		};
	} catch {
		return;
	}
}
/** `fromIso` + N days, or null when there is no interval. */
function rotateByFrom(fromIso, intervalDays) {
	return intervalDays === null ? null : new Date(Date.parse(fromIso) + intervalDays * DAY_MS).toISOString();
}
async function defaultSqlProvider() {
	const { getSql } = await import("./db-YAhc1k3o.mjs");
	return getSql();
}
function violates(err, constraint) {
	const e = err;
	return e?.constraint === constraint || typeof e?.message === "string" && e.message.includes(constraint);
}
var ENTRY_COLUMNS = "id, site, account, purpose, label, kind, is_default, status, fingerprint, secret_length, reentry_reason, created_at, updated_at, last_used_at, last_verified_at, rotation_mode, rotate_interval_days, last_rotated_at, rotate_by, rotation_count, last_rotation_error, provider_token_id, cookie_meta";
function rowToEntry(row) {
	const rec = {
		id: String(row.id),
		ref: entryRef(String(row.id)),
		site: String(row.site),
		account: String(row.account),
		purpose: String(row.purpose),
		label: String(row.label),
		kind: String(row.kind),
		is_default: row.is_default === true,
		status: String(row.status),
		fingerprint: String(row.fingerprint),
		secret_length: Number(row.secret_length),
		created_at: toIso(row.created_at),
		updated_at: toIso(row.updated_at),
		last_used_at: toIsoOrNull(row.last_used_at),
		last_verified_at: toIsoOrNull(row.last_verified_at),
		rotation_mode: row.rotation_mode === "auto" ? "auto" : "manual",
		rotate_interval_days: row.rotate_interval_days == null ? null : Number(row.rotate_interval_days),
		last_rotated_at: toIsoOrNull(row.last_rotated_at),
		rotate_by: toIsoOrNull(row.rotate_by),
		rotation_count: Number(row.rotation_count ?? 0),
		last_rotation_error: row.last_rotation_error == null ? null : String(row.last_rotation_error),
		provider_token_id: row.provider_token_id == null ? null : String(row.provider_token_id)
	};
	if (row.reentry_reason != null && row.reentry_reason !== "") rec.reentry_reason = String(row.reentry_reason);
	const cookie = rec.kind === "cookie" ? summaryFromColumn(row.cookie_meta) : void 0;
	if (cookie) rec.cookie_jar = cookie;
	return rec;
}
/** Postgres/PGlite store over `vault_entries` (migrations/0005_vault_entries.sql). */
var SqlEntryStore = class {
	sql;
	constructor(sqlProvider = defaultSqlProvider) {
		this.sql = sqlProvider;
	}
	async one(text, params) {
		const rows = await (await this.sql()).query(text, params);
		return rows[0] ? rowToEntry(rows[0]) : null;
	}
	async insert(row) {
		const sql = await this.sql();
		for (const allowDefault of [true, false]) try {
			const rows = await sql.query(`insert into vault_entries
             (id, site, account, purpose, label, kind, is_default, status, fingerprint, secret_length, created_at, updated_at,
              cookie_meta)
           select $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,
                  ($10::boolean and not exists (select 1 from vault_entries where site = $2::text and is_default)),
                  'active', $7::text, $8::integer, $9::timestamptz, $9::timestamptz, $11::text
           returning ${ENTRY_COLUMNS}`, [
				row.id,
				row.site,
				row.account,
				row.purpose,
				row.label,
				row.kind,
				row.fingerprint,
				row.secret_length,
				row.nowIso,
				allowDefault,
				row.kind === "cookie" && row.cookie_jar ? JSON.stringify(row.cookie_jar) : null
			]);
			if (rows[0]) return rowToEntry(rows[0]);
		} catch (err) {
			if (violates(err, "vault_entries_identity_uidx")) throw new EntryError("entry_exists", "An entry already exists for this site, account and kind");
			if (allowDefault && violates(err, "vault_entries_one_default_uidx")) continue;
			throw new EntryError("entry_store_failed", "Entry could not be stored");
		}
		throw new EntryError("entry_store_failed", "Entry could not be stored");
	}
	get(id) {
		return this.one(`select ${ENTRY_COLUMNS} from vault_entries where id = $1::text`, [id]);
	}
	async list(filter) {
		return (await (await this.sql()).query(`select ${ENTRY_COLUMNS} from vault_entries
        where ($1::text is null or site = $1::text)
          and ($2::text is null or position(lower($2::text) in lower(label)) > 0)
          and ($3::boolean or status <> 'deleted')
        order by site asc, is_default desc, lower(account) asc, kind asc`, [
			filter.site ?? null,
			filter.query ?? null,
			filter.includeDeleted === true
		])).map(rowToEntry);
	}
	findIdentity(site, account, kind) {
		return this.one(`select ${ENTRY_COLUMNS} from vault_entries
        where site = $1::text and lower(account) = lower($2::text) and kind = $3::text and status <> 'deleted'`, [
			site,
			account,
			kind
		]);
	}
	async setDefault(id) {
		if ((await (await this.sql()).query("select vault_entries_set_default($1::text) as ok", [id]))[0]?.ok !== true) return null;
		return this.get(id);
	}
	async updateMeta(id, patch, nowIso) {
		try {
			return await this.one(`update vault_entries
            set account = coalesce($2::text, account),
                purpose = coalesce($3::text, purpose),
                label = coalesce($4::text, label),
                last_verified_at = coalesce($5::timestamptz, last_verified_at),
                updated_at = $6::timestamptz
          where id = $1::text and status <> 'deleted'
          returning ${ENTRY_COLUMNS}`, [
				id,
				patch.account ?? null,
				patch.purpose ?? null,
				patch.label ?? null,
				patch.last_verified_at ?? null,
				nowIso
			]);
		} catch (err) {
			if (violates(err, "vault_entries_identity_uidx")) throw new EntryError("entry_exists", "An entry already exists for this site, account and kind");
			throw new EntryError("entry_store_failed", "Entry could not be updated");
		}
	}
	replaceSecretMeta(id, fingerprint, secretLength, nowIso, cookie) {
		return this.one(`update vault_entries
          set fingerprint = $2::text, secret_length = $3::integer, status = 'active', reentry_reason = null,
              cookie_meta = case when kind = 'cookie' then coalesce($5::text, cookie_meta) else null end,
              last_verified_at = null, updated_at = $4::timestamptz,
              last_rotated_at = $4::timestamptz, rotation_count = rotation_count + 1, last_rotation_error = null,
              rotate_by = case when rotate_interval_days is null then null
                               else $4::timestamptz + make_interval(days => rotate_interval_days) end
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`, [
			id,
			fingerprint,
			secretLength,
			nowIso,
			cookie ? JSON.stringify(cookie) : null
		]);
	}
	refreshJarMeta(id, fingerprint, secretLength, cookie, nowIso) {
		return this.one(`update vault_entries
          set fingerprint = $2::text, secret_length = $3::integer, cookie_meta = $4::text, updated_at = $5::timestamptz
        where id = $1::text and status = 'active' and kind = 'cookie'
        returning ${ENTRY_COLUMNS}`, [
			id,
			fingerprint,
			secretLength,
			JSON.stringify(cookie),
			nowIso
		]);
	}
	flag(id, reason, nowIso) {
		return this.one(`update vault_entries
          set status = 'needs_reentry', reentry_reason = $2::text, updated_at = $3::timestamptz
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`, [
			id,
			reason,
			nowIso
		]);
	}
	markDeleted(id, nowIso) {
		return this.one(`update vault_entries
          set status = 'deleted', is_default = false, deleted_at = $2::timestamptz, updated_at = $2::timestamptz
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`, [id, nowIso]);
	}
	touchUsed(id, nowIso) {
		return this.one(`update vault_entries set last_used_at = $2::timestamptz
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`, [id, nowIso]);
	}
	setRotation(id, policy, nowIso) {
		return this.one(`update vault_entries
          set rotation_mode = $2::text, rotate_interval_days = $3::integer, provider_token_id = $4::text,
              rotate_by = $5::timestamptz, updated_at = $6::timestamptz
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`, [
			id,
			policy.rotation_mode,
			policy.rotate_interval_days,
			policy.provider_token_id,
			policy.rotate_by,
			nowIso
		]);
	}
	setRotationError(id, code, nowIso) {
		return this.one(`update vault_entries set last_rotation_error = $2::text, updated_at = $3::timestamptz
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`, [
			id,
			code,
			nowIso
		]);
	}
	async listRotationDue(nowIso) {
		return (await (await this.sql()).query(`select ${ENTRY_COLUMNS} from vault_entries
        where status = 'active' and rotate_by is not null and rotate_by <= $1::timestamptz
        order by rotate_by asc, id asc`, [nowIso])).map(rowToEntry);
	}
	async hardDelete(id) {
		return (await (await this.sql()).query("delete from vault_entries where id = $1::text returning id", [id])).length === 1;
	}
};
var CARD_COLUMNS = "id, token_hash, client_id, client_name, site, account, purpose, kind, reason, entry_id, is_reentry, status, created_at, expires_at, completed_at";
function rowToCard(row) {
	const rec = {
		id: String(row.id),
		token_hash: String(row.token_hash),
		client_id: String(row.client_id),
		client_name: String(row.client_name ?? ""),
		site: String(row.site),
		account: row.account == null ? null : String(row.account),
		purpose: row.purpose == null ? null : String(row.purpose),
		kind: String(row.kind),
		reason: String(row.reason ?? ""),
		entry_id: row.entry_id == null ? null : String(row.entry_id),
		is_reentry: row.is_reentry === true,
		status: String(row.status),
		created_at: toIso(row.created_at),
		expires_at: toIso(row.expires_at)
	};
	if (row.completed_at != null) rec.completed_at = toIso(row.completed_at);
	return rec;
}
/** Postgres/PGlite store over `vault_cards` (migrations/0005_vault_entries.sql). */
var SqlCardStore = class {
	sql;
	constructor(sqlProvider = defaultSqlProvider) {
		this.sql = sqlProvider;
	}
	async insert(rec) {
		await (await this.sql()).query(`insert into vault_cards
         (id, token_hash, client_id, client_name, site, account, purpose, kind, reason, entry_id, is_reentry, status,
          created_at, expires_at)
       values ($1::text, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text, $9::text, $10::text,
               $11::boolean, 'pending', $12::timestamptz, $13::timestamptz)`, [
			rec.id,
			rec.token_hash,
			rec.client_id,
			rec.client_name,
			rec.site,
			rec.account,
			rec.purpose,
			rec.kind,
			rec.reason,
			rec.entry_id,
			rec.is_reentry,
			rec.created_at,
			rec.expires_at
		]);
	}
	async one(text, params) {
		const rows = await (await this.sql()).query(text, params);
		return rows[0] ? rowToCard(rows[0]) : null;
	}
	get(id) {
		return this.one(`select ${CARD_COLUMNS} from vault_cards where id = $1::text`, [id]);
	}
	getByTokenHash(tokenHash) {
		return this.one(`select ${CARD_COLUMNS} from vault_cards where token_hash = $1::text`, [tokenHash]);
	}
	async countOpen(clientId, nowIso) {
		const rows = await (await this.sql()).query(`select count(*)::integer as n from vault_cards
        where client_id = $1::text and status in ('pending', 'claimed') and expires_at > $2::timestamptz`, [clientId, nowIso]);
		return Number(rows[0]?.n ?? 0);
	}
	async claim(id, nowIso) {
		return (await (await this.sql()).query(`update vault_cards set status = 'claimed'
        where id = $1::text and status = 'pending' and expires_at > $2::timestamptz
        returning id`, [id, nowIso])).length === 1;
	}
	async release(id) {
		await (await this.sql()).query("update vault_cards set status = 'pending' where id = $1::text and status = 'claimed'", [id]);
	}
	async complete(id, entryId, nowIso) {
		return (await (await this.sql()).query(`update vault_cards set status = 'completed', entry_id = $2::text, completed_at = $3::timestamptz
        where id = $1::text and status = 'claimed'
        returning id`, [
			id,
			entryId,
			nowIso
		])).length === 1;
	}
	async expire(id) {
		await (await this.sql()).query("update vault_cards set status = 'expired' where id = $1::text and status in ('pending', 'claimed')", [id]);
	}
	async deleteForEntry(entryId) {
		return (await (await this.sql()).query("delete from vault_cards where entry_id = $1::text returning id", [entryId])).length;
	}
};
var defaults = {};
var defaultEntryStore = null;
var defaultCardStore = null;
var defaultBackend = null;
function ctx(deps = {}) {
	const d = {
		...defaults,
		...deps
	};
	const nowMs = (d.now ?? Date.now)();
	return {
		entries: d.entries ?? (defaultEntryStore ??= new SqlEntryStore()),
		cards: d.cards ?? (defaultCardStore ??= new SqlCardStore()),
		backend: async () => {
			if (d.backend) return d.backend;
			if (!defaultBackend) {
				const { GateVaultBackend } = await import("./backend-CFQmvqUZ.mjs").then((n) => n.r).then((n) => n.n);
				defaultBackend = new GateVaultBackend();
			}
			return defaultBackend;
		},
		ledger: d.ledger ?? appendLedger,
		fetch: d.fetch,
		notify: d.notify ?? defaultNotifier,
		env: d.env ?? process.env,
		nowMs,
		nowIso: new Date(nowMs).toISOString()
	};
}
function requireEntryId(id) {
	if (typeof id !== "string" || !ENTRY_ID_PATTERN.test(id)) throw new EntryError("entry_not_found", "No such entry");
	return id;
}
function requireClient(client) {
	if (!client || typeof client.client_id !== "string" || client.client_id.length === 0 || client.client_id.length > 200) throw new EntryError("invalid_client", "An authenticated client identity is required");
	return client;
}
async function writeLedger(c, input, mustSucceed) {
	try {
		await c.ledger(input);
	} catch {
		log.error("vault_entry_ledger_failed", {
			capability: input.capability,
			client_id: input.client_id
		});
		if (mustSucceed) throw new EntryError("ledger_unavailable", "The action could not be recorded in the ledger");
	}
}
/**
* The ONE place an entry's secret is read from the backend (useEntry, and
* rotation.ts through openEntryVault). Arms the value for redaction before
* returning it. Throws EntryError("entry_secret_missing" | "vault_unavailable").
*/
async function loadEntrySecret(c, row) {
	let secret;
	try {
		const backend = await c.backend();
		const coordinate = await backend.locate(backendService(row.id), BACKEND_USERNAME, BYPASS_REASON);
		if (!coordinate) throw new EntryError("entry_secret_missing", "The vault has no secret for this entry");
		const got = await backend.get(coordinate.service, coordinate.username, BYPASS_REASON);
		if (typeof got?.secret !== "string" || got.secret.length === 0) throw new EntryError("entry_secret_missing", "The vault has no secret for this entry");
		secret = got.secret;
	} catch (err) {
		if (err instanceof EntryError) throw err;
		throw new EntryError("vault_unavailable", "The vault could not be reached");
	}
	registerSecretForRedaction(secret);
	if (secretFingerprint(secret) !== row.fingerprint) log.warn("vault_entry_fingerprint_drift", { entry_id: row.id });
	return secret;
}
async function storeEntrySecret(c, row, secret) {
	registerSecretForRedaction(secret);
	try {
		const put = await (await c.backend()).put(backendService(row.id), BACKEND_USERNAME, secret, `echo-credential-broker vault v2 entry: ${entryLabel(row.site, row.account, row.purpose)} (${row.kind})`, BYPASS_REASON);
		if (put && put.stored === false) throw new Error("not stored");
	} catch {
		throw new EntryError("vault_unavailable", "vault write failed");
	}
}
function openEntryVault(deps = {}) {
	const c = ctx(deps);
	return {
		entries: c.entries,
		cards: c.cards,
		nowMs: c.nowMs,
		nowIso: c.nowIso,
		ledger: (input, mustSucceed) => writeLedger(c, input, mustSucceed),
		readSecret: (row) => loadEntrySecret(c, row),
		writeSecret: (row, secret) => storeEntrySecret(c, row, secret),
		destroySecret: async (row) => {
			const service = backendService(requireEntryId(row.id));
			let backend;
			try {
				backend = await c.backend();
			} catch {
				throw new EntryError("vault_unavailable", "The vault could not be reached");
			}
			if (typeof backend.delete === "function") {
				try {
					await backend.delete(service, BACKEND_USERNAME, BYPASS_REASON);
				} catch {
					throw new EntryError("vault_unavailable", "The vault could not be reached");
				}
				let still = null;
				try {
					still = await backend.locate(service, BACKEND_USERNAME, BYPASS_REASON);
				} catch {
					throw new EntryError("vault_unavailable", "The delete could not be verified");
				}
				if (still) throw new EntryError("purge_secret_not_destroyed", "The secret is still present after the delete");
				return "deleted";
			}
			const filler = randomBytes(64).toString("base64url");
			registerSecretForRedaction(filler);
			let readBack;
			try {
				const put = await backend.put(service, BACKEND_USERNAME, filler, "echo-credential-broker vault v2 entry: PURGED (random filler, not a credential)", BYPASS_REASON);
				if (put && put.stored === false) throw new Error("not stored");
				const got = await backend.get(service, BACKEND_USERNAME, BYPASS_REASON);
				readBack = typeof got?.secret === "string" ? got.secret : "";
				if (readBack) registerSecretForRedaction(readBack);
			} catch {
				throw new EntryError("vault_unavailable", "The vault could not be reached");
			}
			if (!constantTimeEqual(sha256Hex(readBack), sha256Hex(filler))) throw new EntryError("purge_secret_not_destroyed", "The overwrite could not be confirmed");
			return "overwritten";
		}
	};
}
async function listEntries(filter = {}, deps = {}) {
	const c = ctx(deps);
	const site = filter.site !== void 0 && filter.site !== "" ? normalizeSite(filter.site) : void 0;
	const query = typeof filter.query === "string" && filter.query.trim() ? filter.query.trim().slice(0, 200) : void 0;
	return (await c.entries.list({
		site,
		query
	})).map(publicEntry);
}
/** Metadata for one entry (including a deleted one), or null. */
async function getEntryMetadata(id, deps = {}) {
	if (typeof id !== "string" || !ENTRY_ID_PATTERN.test(id)) return null;
	const row = await ctx(deps).entries.get(id);
	return row ? publicEntry(row) : null;
}
/**
* Pick ONE entry. With `account`: that account's entry (add `kind` when the
* account has several kinds). Without: the site's default; if there is no
* default and exactly one candidate, that one; otherwise `ambiguous_entry`.
* Never returns a deleted entry. The result may be `needs_reentry` — check
* `status` (useEntry refuses it).
*/
async function resolveEntry(query, deps = {}) {
	const c = ctx(deps);
	const site = normalizeSite(query?.site);
	const kind = query.kind !== void 0 ? normalizeKind(query.kind) : void 0;
	const rows = (await c.entries.list({ site })).filter((r) => kind ? r.kind === kind : true);
	const accounts = () => sanitizeDisplayText([...new Set(rows.map((r) => r.account))].slice(0, 10).join(", "), 400) || "(none)";
	if (query.account !== void 0 && query.account !== "") {
		const account = normalizeAccount(query.account).toLowerCase();
		const matches = rows.filter((r) => r.account.toLowerCase() === account);
		if (matches.length === 1) return publicEntry(matches[0]);
		if (matches.length === 0) throw new EntryError("entry_not_found", `No entry for that account on ${site}. Known accounts: ${accounts()}`);
		throw new EntryError("ambiguous_entry", `That account has ${matches.length} entries on ${site} (${matches.map((r) => r.kind).join(", ")}); specify kind`);
	}
	if (rows.length === 0) throw new EntryError("entry_not_found", `No entry for ${site}`);
	const def = rows.find((r) => r.is_default);
	if (def) return publicEntry(def);
	if (rows.length === 1) return publicEntry(rows[0]);
	throw new EntryError("ambiguous_entry", `${rows.length} entries for ${site} and no default; specify account. Known accounts: ${accounts()}`);
}
/** Soft-delete exactly this entry. Other entries (and the site's other defaults) are untouched. */
async function deleteEntry(id, deps = {}) {
	const c = ctx(deps);
	const row = await c.entries.markDeleted(requireEntryId(id), c.nowIso);
	if (!row) throw new EntryError("entry_not_found", "No such entry");
	log.warn("vault_entry_deleted", {
		entry_id: row.id,
		site: row.site
	});
	return publicEntry(row);
}
/** Mark exactly this entry as needing its secret re-typed. useEntry refuses it until a card completes. */
async function flagForReentry(id, reason, deps = {}) {
	const c = ctx(deps);
	const clean = sanitizeDisplayText(reason, 300) || "unspecified";
	const row = await c.entries.flag(requireEntryId(id), clean, c.nowIso);
	if (!row) throw new EntryError("entry_not_found", "No such entry");
	log.warn("vault_entry_flagged_for_reentry", {
		entry_id: row.id,
		site: row.site
	});
	return publicEntry(row);
}
/**
* Set an entry's rotation policy. `rotate_by` is recomputed as (last rotation,
* or creation when it was never rotated) + interval; no interval → never due.
* mode "auto" needs an interval. `provider_token_id` is a NON-SECRET provider
* id: anything secret-shaped, or equal to the entry's own secret, is refused.
*/
async function setRotationPolicy(id, policy, deps = {}) {
	const c = ctx(deps);
	const current = await c.entries.get(requireEntryId(id));
	if (!current || current.status === "deleted") throw new EntryError("entry_not_found", "No such entry");
	if (policy?.mode !== "manual" && policy?.mode !== "auto") throw invalid("rotation_mode", "mode must be manual or auto");
	let interval = current.rotate_interval_days;
	if (policy.interval_days !== void 0) {
		const n = policy.interval_days;
		if (n !== null && !(Number.isInteger(n) && n >= 1 && n <= 3650)) throw invalid("interval_days", `interval_days must be a whole number from 1 to ${MAX_ROTATE_INTERVAL_DAYS}`);
		interval = n;
	}
	if (policy.mode === "auto" && interval === null) throw invalid("interval_days", "auto rotation needs interval_days");
	let tokenId = current.provider_token_id;
	if (policy.provider_token_id !== void 0) {
		const t = policy.provider_token_id === null ? null : String(policy.provider_token_id).trim();
		if (t !== null) {
			if (!PROVIDER_TOKEN_ID_PATTERN.test(t)) throw invalid("provider_token_id", "provider_token_id must be 1-128 characters of A-Z a-z 0-9 . _ : -");
			if (looksLikeSecret(t) || secretFingerprint(t) === current.fingerprint) throw invalid("provider_token_id", "provider_token_id looks like a secret; give the provider's token ID, not its value");
		}
		tokenId = t;
	}
	const row = await c.entries.setRotation(id, {
		rotation_mode: policy.mode,
		rotate_interval_days: interval,
		provider_token_id: tokenId,
		rotate_by: rotateByFrom(current.last_rotated_at ?? current.created_at, interval)
	}, c.nowIso);
	if (!row) throw new EntryError("entry_not_found", "No such entry");
	log.info("vault_entry_rotation_policy_set", {
		entry_id: row.id,
		site: row.site,
		mode: row.rotation_mode,
		interval_days: row.rotate_interval_days
	});
	return publicEntry(row);
}
/** Active entries whose rotation is due at `now` (rotate_by <= now), oldest due first. Metadata only. */
async function listRotationDue(now = Date.now(), deps = {}) {
	const ms = now instanceof Date ? now.getTime() : now;
	if (!Number.isFinite(ms)) throw invalid("now", "now must be a valid time");
	return (await ctx(deps).entries.listRotationDue(new Date(ms).toISOString())).map(publicEntry);
}
/**
* Use an entry's secret without reading it: `fn(secret, entry)` runs here, the
* secret is armed for redaction first, the use is ledgered
* (capability "vault.entry.use"), and the caller gets `{ entry, result }` where
* `result` is fn's return value scrubbed through redactValue — so it must be
* JSON-serializable (anything else comes back as `{ error: "unserializable_redacted" }`).
* fn's errors surface as EntryError("entry_use_failed") with a redacted message.
*/
async function useEntry(id, client, task, fn, opts = {}) {
	const c = ctx(opts);
	const started = Date.now();
	const who = requireClient(client);
	const taskText = sanitizeDisplayText(task, 300);
	if (!taskText) throw new EntryError("invalid_task", "A task description is required to use an entry");
	if (typeof fn !== "function") throw new EntryError("invalid_callback", "useEntry needs a callback");
	const base = {
		client_id: who.client_id,
		capability: "vault.entry.use",
		decision: opts.decision ?? "allow",
		tier: opts.tier ?? 1,
		approval_id: opts.approval_id,
		task: taskText
	};
	const refuse = async (code, message, row) => {
		await writeLedger(c, {
			...base,
			resource: row ? entryResource(row.site, row.account) : "entry:unknown",
			credential_ref: row ? entryRef(row.id) : void 0,
			result: "error",
			error: code,
			duration_ms: Date.now() - started
		}, false);
		throw new EntryError(code, message);
	};
	const row = typeof id === "string" && ENTRY_ID_PATTERN.test(id) ? await c.entries.get(id) : null;
	if (!row || row.status === "deleted") return refuse("entry_not_found", "No such entry", null);
	if (row.status !== "active") return refuse("entry_needs_reentry", "This entry needs its secret re-entered before it can be used", row);
	let secret;
	try {
		secret = await loadEntrySecret(c, row);
	} catch (err) {
		const e = err instanceof EntryError ? err : new EntryError("vault_unavailable", "The vault could not be reached");
		return refuse(e.code, e.message, row);
	}
	let result;
	try {
		result = redactValue(await fn(secret, publicEntry(row)));
	} catch (err) {
		return refuse("entry_use_failed", `The action failed: ${sanitizeDisplayText(err instanceof Error ? err.message : "callback failed", 200) || "callback failed"}`, row);
	}
	const touched = await c.entries.touchUsed(row.id, c.nowIso).catch(() => null) ?? row;
	await writeLedger(c, {
		...base,
		resource: entryResource(row.site, row.account),
		credential_ref: entryRef(row.id),
		result: "ok",
		duration_ms: Date.now() - started
	}, true);
	log.info("vault_entry_used", {
		entry_id: row.id,
		client_id: who.client_id,
		site: row.site,
		task: taskText
	});
	return {
		entry: publicEntry(touched),
		result
	};
}
/** Validated origin + path prefix for card links; throws when unset or not https (http only for localhost). */
function cardBaseUrl(env = process.env) {
	const raw = env.ECHO_VAULT_PUBLIC_URL?.trim();
	let url = null;
	try {
		url = raw ? new URL(raw) : null;
	} catch {
		url = null;
	}
	const local = url ? [
		"localhost",
		"127.0.0.1",
		"[::1]"
	].includes(url.hostname) : false;
	if (!url || url.username || url.password || !(url.protocol === "https:" || url.protocol === "http:" && local)) throw new CardError("public_url_not_configured", "ECHO_VAULT_PUBLIC_URL must be an https URL");
	return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}
/** Operator-facing prompt. Plain text; every agent-supplied field is sanitized. The URL is appended verbatim. */
function formatCardText(card, url) {
	const name = sanitizeDisplayText(card.client_name, 80);
	const clientId = sanitizeDisplayText(card.client_id, 120);
	return [
		card.is_reentry ? "ECHO Vault: re-enter a credential" : "ECHO Vault: new credential requested",
		"",
		`Client: ${name ? `${name} (${clientId})` : clientId}`,
		`Site: ${sanitizeDisplayText(card.site, 253)}`,
		`Account: ${card.account ? sanitizeDisplayText(card.account, 254) : "(you choose)"}`,
		`Kind: ${card.kind}`,
		`Purpose: ${card.purpose ? sanitizeDisplayText(card.purpose, 64) : DEFAULT_PURPOSE}`,
		`Reason: ${sanitizeDisplayText(card.reason, 300) || "(none)"}`,
		card.is_reentry ? "This REPLACES the stored secret of the existing entry." : "This creates a new entry.",
		`Expires: ${card.expires_at}`,
		"",
		"Open this single-use link to type the secret:",
		url
	].join("\n");
}
var defaultNotifier = async (input) => {
	const env = input.env ?? process.env;
	const chatId = approverTelegramId(env);
	if (!chatId) throw new CardError("approver_not_configured", "Operator is not configured");
	const { callBotApi } = await import("./telegram-B-fJEnsh.mjs").then((n) => n.r).then((n) => n.r);
	await callBotApi("sendMessage", {
		chat_id: chatId,
		text: formatCardText(input.card, input.url),
		link_preview_options: { is_disabled: true }
	}, {
		fetch: input.fetch,
		env
	});
};
/**
* Ask the operator to type a secret. Returns only {card_id, status, expires_at}:
* the token and the secret never reach the requester. When the identity already
* exists (or `entry_id` is given) the card is a re-entry bound to that entry id.
*/
async function requestCard(input, deps = {}) {
	const c = ctx(deps);
	let client;
	try {
		client = requireClient(input?.client);
	} catch {
		throw new CardError("invalid_client", "An authenticated client identity is required");
	}
	const reason = sanitizeDisplayText(input.reason, 300);
	if (!reason) throw new CardError("invalid_reason", "A reason is required so the operator knows why");
	let site = normalizeSite(input.site);
	let kind = normalizeKind(input.kind);
	let account = input.account !== void 0 && input.account !== "" ? normalizeAccount(input.account) : null;
	let purpose = input.purpose !== void 0 && input.purpose !== "" ? normalizePurpose(input.purpose) : null;
	let target = null;
	if (input.entry_id !== void 0) {
		target = typeof input.entry_id === "string" && ENTRY_ID_PATTERN.test(input.entry_id) ? await c.entries.get(input.entry_id) : null;
		if (!target || target.status === "deleted") throw new CardError("entry_not_found", "No such entry to re-enter");
		if (target.site !== site || target.kind !== kind) throw new CardError("entry_mismatch", "site/kind do not match the entry being re-entered");
	} else if (account) target = await c.entries.findIdentity(site, account, kind);
	if (target) {
		site = target.site;
		kind = target.kind;
		account = target.account;
		purpose = target.purpose;
	}
	const base = cardBaseUrl(c.env);
	if (!deps.notify && !defaults.notify && !approverTelegramId(c.env)) throw new CardError("approver_not_configured", "Operator is not configured");
	if (await c.cards.countOpen(client.client_id, c.nowIso) >= 5) throw new CardError("too_many_pending_cards", "Too many pending cards for this client; wait for one to finish");
	const token = randomBytes(TOKEN_BYTES).toString("base64url");
	registerSecretForRedaction(token);
	const card = {
		id: `vc_${randomBytes(16).toString("hex")}`,
		token_hash: sha256Hex(token),
		client_id: client.client_id,
		client_name: sanitizeDisplayText(client.name ?? "", 120),
		site,
		account,
		purpose,
		kind,
		reason,
		entry_id: target ? target.id : null,
		is_reentry: target !== null,
		status: "pending",
		created_at: c.nowIso,
		expires_at: new Date(c.nowMs + CARD_TTL_MS).toISOString()
	};
	try {
		await c.cards.insert(card);
	} catch {
		log.error("vault_card_store_failed", { card_id: card.id });
		throw new CardError("card_store_failed", "Card could not be recorded");
	}
	try {
		await c.notify({
			card: { ...card },
			url: `${base}/card/${token}`,
			fetch: c.fetch,
			env: c.env
		});
	} catch (err) {
		await c.cards.expire(card.id).catch(() => void 0);
		log.error("vault_card_notify_failed", {
			card_id: card.id,
			error: err instanceof Error && "code" in err ? String(err.code) : "notify_error"
		});
		throw new CardError("card_notification_failed", "The card could not be delivered to the operator");
	}
	await writeLedger(c, {
		client_id: card.client_id,
		capability: "vault.card.request",
		resource: entryResource(site, account ?? "*"),
		credential_ref: target ? entryRef(target.id) : void 0,
		decision: "escalate",
		tier: 2,
		result: "pending_approval"
	}, false);
	log.info("vault_card_requested", {
		card_id: card.id,
		client_id: card.client_id,
		site,
		kind,
		reentry: card.is_reentry,
		expires_at: card.expires_at
	});
	return {
		card_id: card.id,
		status: "pending",
		expires_at: card.expires_at
	};
}
function cardExpired(card, nowMs) {
	const exp = Date.parse(card.expires_at);
	return !Number.isFinite(exp) || nowMs >= exp;
}
/**
* pending | completed (entry id + metadata) | expired. Pass `client` to make a
* card visible only to the client that requested it.
*/
async function getCardStatus(cardId, deps = {}) {
	const c = ctx(deps);
	const card = typeof cardId === "string" && CARD_ID_PATTERN.test(cardId) ? await c.cards.get(cardId) : null;
	if (!card || deps.client && deps.client.client_id !== card.client_id) throw new CardError("card_not_found", "No such card");
	if (card.status === "completed" && card.entry_id) {
		const entry = await c.entries.get(card.entry_id);
		const out = {
			card_id: card.id,
			status: "completed",
			expires_at: card.expires_at,
			entry_id: card.entry_id
		};
		if (entry) out.entry = publicEntry(entry);
		return out;
	}
	const status = card.status === "expired" || cardExpired(card, c.nowMs) ? "expired" : "pending";
	return {
		card_id: card.id,
		status,
		expires_at: card.expires_at
	};
}
function cardView(card) {
	return {
		card_id: card.id,
		client_name: card.client_name,
		client_id: card.client_id,
		site: card.site,
		account: card.account,
		purpose: card.purpose,
		kind: card.kind,
		reason: card.reason,
		expires_at: card.expires_at,
		reentry: card.is_reentry
	};
}
async function findCardByToken(c, token) {
	if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) return null;
	const hash = sha256Hex(token);
	const card = await c.cards.getByTokenHash(hash);
	return card && constantTimeEqual(card.token_hash, hash) ? card : null;
}
function cardState(card, nowMs) {
	if (!card) return "invalid";
	if (card.status === "completed" || card.status === "claimed") return "used";
	if (card.status === "expired" || cardExpired(card, nowMs)) return "expired";
	return "pending";
}
/** GET side of the card page: never consumes the token. */
async function lookupCard(token, deps = {}) {
	const c = ctx(deps);
	const card = await findCardByToken(c, token);
	const state = cardState(card, c.nowMs);
	return state === "pending" && card ? {
		state,
		card: cardView(card)
	} : { state };
}
/**
* POST side of the card page. Validates the token (hash lookup + constant-time
* compare, pending, unexpired), claims it atomically (single use), writes the
* secret through the vault backend, creates the entry (or, for a re-entry,
* replaces only the secret of the same entry id), completes the card and
* ledgers "vault.entry.create" / "vault.entry.reentry". On a failure before
* completion the claim is released so the operator can retry until expiry.
* The result never contains the secret.
*/
async function submitCard(token, submission, deps = {}) {
	const c = ctx(deps);
	const card = await findCardByToken(c, token);
	const state = cardState(card, c.nowMs);
	if (state !== "pending" || !card) {
		if (card && state === "expired" && card.status !== "expired") await c.cards.expire(card.id).catch(() => void 0);
		log.warn("vault_card_submit_rejected", {
			reason: state,
			card_id: card?.id ?? "unknown"
		});
		return {
			ok: false,
			code: state === "expired" ? "expired" : state === "used" ? "already_used" : "invalid_token",
			message: "This card link is invalid, expired or already used."
		};
	}
	const view = cardView(card);
	const retry = (code, message, detail) => detail ? {
		ok: false,
		code,
		message,
		detail,
		card: view
	} : {
		ok: false,
		code,
		message,
		card: view
	};
	const cookieCard = card.kind === "cookie";
	let secret = "";
	let pasted;
	if (cookieCard) {
		pasted = submission?.cookies !== void 0 ? submission.cookies : submission?.secret;
		if (typeof pasted === "string" && pasted.trim().length >= 8) registerSecretForRedaction(pasted);
	} else {
		if (submission?.cookies !== void 0) return retry("invalid_input", "This card is not for cookies.", "card_kind_not_cookie");
		secret = typeof submission?.secret === "string" ? submission.secret.trim() : "";
		if (secret.length >= 8) registerSecretForRedaction(secret);
		if (secret.length < 8 || secret.length > 4096) return retry("invalid_input", `The secret must be 8-${MAX_SECRET_LENGTH} characters.`);
	}
	let target = null;
	let site;
	let account;
	let purpose;
	if (card.is_reentry) {
		target = card.entry_id ? await c.entries.get(card.entry_id) : null;
		if (!target || target.status === "deleted") {
			await c.cards.expire(card.id).catch(() => void 0);
			return {
				ok: false,
				code: "entry_gone",
				message: "The entry this card was for no longer exists."
			};
		}
		({site, account, purpose} = target);
	} else try {
		site = normalizeSite(submission.site || card.site);
		account = normalizeAccount(submission.account || card.account || "");
		purpose = normalizePurpose(submission.purpose || card.purpose || "");
	} catch (err) {
		return retry("invalid_input", err instanceof EntryError ? err.message : "A field is invalid.");
	}
	let cookieSummary;
	let cookieCounts;
	let secretParts = [secret];
	if (cookieCard) try {
		const parsed = parseCookieInput(pasted, {
			site,
			now: c.nowMs
		});
		for (const form of jarRedactionForms(parsed.jar)) registerSecretForRedaction(form);
		secret = serializeJar(parsed.jar);
		registerSecretForRedaction(secret);
		cookieSummary = describeJar(parsed.jar, site);
		cookieCounts = {
			stored: parsed.jar.cookies.length,
			skipped: parsed.skipped
		};
		secretParts = parsed.jar.cookies.map((k) => k.value);
	} catch (err) {
		const detail = err instanceof CookieInputError ? err.code : "invalid_cookie_input";
		log.warn("vault_card_cookie_rejected", {
			card_id: card.id,
			code: detail
		});
		return retry("invalid_input", `The cookies were not accepted (${detail}). Paste a Cookie header, a JSON cookie export or a Netscape cookies.txt.`, detail);
	}
	if (!card.is_reentry) {
		if ([
			site,
			account,
			purpose
		].some((v) => secretParts.some((part) => v.includes(part)))) return retry("invalid_input", "The secret must only be typed in the secret field.");
		if (await c.entries.findIdentity(site, account, card.kind)) return retry("entry_exists", "An entry already exists for this site, account and kind. Request a re-entry instead.");
	}
	if (!await c.cards.claim(card.id, c.nowIso)) {
		const s = cardState(await c.cards.get(card.id), c.nowMs);
		log.warn("vault_card_submit_rejected", {
			reason: s === "pending" ? "used" : s,
			card_id: card.id
		});
		return {
			ok: false,
			code: s === "expired" ? "expired" : "already_used",
			message: "This card link is invalid, expired or already used."
		};
	}
	const fingerprint = secretFingerprint(secret);
	let entry;
	try {
		const id = target ? target.id : `ve_${randomBytes(16).toString("hex")}`;
		const backend = await c.backend();
		try {
			await backend.put(backendService(id), BACKEND_USERNAME, secret, `echo-credential-broker vault v2 entry: ${entryLabel(site, account, purpose)} (${card.kind})`, BYPASS_REASON);
		} catch {
			throw new EntryError("vault_unavailable", "vault write failed");
		}
		if (target) {
			const updated = await c.entries.replaceSecretMeta(id, fingerprint, secret.length, c.nowIso, cookieSummary);
			if (!updated) throw new EntryError("entry_gone", "entry vanished");
			entry = updated;
		} else entry = await c.entries.insert({
			id,
			site,
			account,
			purpose,
			label: entryLabel(site, account, purpose),
			kind: card.kind,
			fingerprint,
			secret_length: secret.length,
			nowIso: c.nowIso,
			cookie_jar: cookieSummary
		});
	} catch (err) {
		await c.cards.release(card.id).catch(() => void 0);
		const code = err instanceof EntryError ? err.code : "store_failed";
		log.error("vault_card_submit_failed", {
			card_id: card.id,
			error: code
		});
		if (code === "vault_unavailable") return retry("vault_unavailable", "The vault could not be reached. Try again.");
		if (code === "entry_exists") return retry("entry_exists", "An entry already exists for this site, account and kind. Request a re-entry instead.");
		if (code === "entry_gone") return retry("entry_gone", "The entry this card was for no longer exists.");
		return retry("store_failed", "The entry could not be stored. Try again.");
	}
	if (!await c.cards.complete(card.id, entry.id, c.nowIso).catch(() => false)) log.error("vault_card_complete_failed", {
		card_id: card.id,
		entry_id: entry.id
	});
	await writeLedger(c, {
		client_id: card.client_id,
		capability: target ? "vault.entry.reentry" : "vault.entry.create",
		resource: entryResource(entry.site, entry.account),
		credential_ref: entryRef(entry.id),
		decision: "escalate",
		tier: 2,
		result: "ok"
	}, false);
	log.info("vault_card_completed", {
		card_id: card.id,
		entry_id: entry.id,
		client_id: card.client_id,
		site: entry.site,
		reentry: target !== null
	});
	return cookieCounts ? {
		ok: true,
		entry: publicEntry(entry),
		reentry: target !== null,
		cookies: cookieCounts
	} : {
		ok: true,
		entry: publicEntry(entry),
		reentry: target !== null
	};
}
/**
* SERVER-INTERNAL (gateway.ts entry_use): a site answered a `cookie` entry's
* request with Set-Cookie and the merged jar differs from the stored one. Write
* the new canonical jar to the vault backend and refresh the entry's
* fingerprint/length/jar metadata, so the next use sends the rotated session.
*
* Never throws and never fails the request that triggered it: the outcome is
* logged and ledgered ("vault.entry.cookie_refresh": ok, or error
* cookie_jar_persist_failed / cookie_jar_too_large). `jarJson` is a secret; it
* goes to the backend only.
*/
async function refreshCookieJar(id, client, jarJson, summary, deps = {}) {
	const c = ctx(deps);
	registerSecretForRedaction(jarJson);
	let row = null;
	let error = null;
	try {
		row = typeof id === "string" && ENTRY_ID_PATTERN.test(id) ? await c.entries.get(id) : null;
		if (!row || row.status !== "active" || row.kind !== "cookie") error = "cookie_jar_persist_failed";
		else if (jarJson.length < 8 || jarJson.length > MAX_COOKIE_SECRET_LENGTH) error = "cookie_jar_too_large";
		else {
			await storeEntrySecret(c, row, jarJson);
			if (!await c.entries.refreshJarMeta(row.id, secretFingerprint(jarJson), jarJson.length, summary, c.nowIso)) error = "cookie_jar_persist_failed";
		}
	} catch {
		error = "cookie_jar_persist_failed";
	}
	if (error) log.error("vault_entry_cookie_refresh_failed", {
		entry_id: row?.id ?? "unknown",
		error
	});
	else log.info("vault_entry_cookie_refreshed", {
		entry_id: row?.id,
		site: row?.site,
		cookies: summary.count
	});
	await writeLedger(c, {
		client_id: typeof client?.client_id === "string" ? client.client_id : "unknown",
		capability: "vault.entry.cookie_refresh",
		resource: row ? entryResource(row.site, row.account) : "entry:unknown",
		credential_ref: row ? entryRef(row.id) : void 0,
		decision: "allow",
		tier: 1,
		result: error ? "error" : "ok",
		error: error ?? void 0
	}, false);
	return error === null;
}
//#endregion
export { serializeJar as A, normalizeSite as C, requestCard as D, refreshCookieJar as E, submitCard as M, useEntry as N, resolveEntry as O, normalizePurpose as S, parseStoredJar as T, listEntries as _, MAX_SECRET_LENGTH as a, mergeSetCookie as b, describeJar as c, entryRef as d, flagForReentry as f, jarRedactionForms as g, isPublicSuffix as h, MAX_COOKIE_INPUT_CHARS as i, setRotationPolicy as j, secretFingerprint as k, domainMatches as l, getEntryMetadata as m, ENTRY_KINDS as n, cookieHeaderFor as o, getCardStatus as p, EntryError as r, deleteEntry as s, CardError as t, entryLabel as u, listRotationDue as v, openEntryVault as w, normalizeAccount as x, lookupCard as y };
