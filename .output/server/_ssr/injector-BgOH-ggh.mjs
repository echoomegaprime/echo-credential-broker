import { o as log, u as registerSecretForRedaction } from "./log-BHJOU13W.mjs";
import { a as rateLimitKey, i as getDefaultRateLimitStore, o as withRateLimitStore } from "./rate-limit-store-D2QvwAS2.mjs";
import { h as sanitizeDisplayText } from "./approvals-vHr7W1Jg.mjs";
import { t as appendLedger } from "./ledger-DtKvLmuw.mjs";
import { N as useEntry, T as parseStoredJar, g as jarRedactionForms, h as isPublicSuffix, l as domainMatches, m as getEntryMetadata } from "./cards-BG7l2-sJ.mjs";
import { createHash, randomBytes, timingSafeEqual, webcrypto } from "node:crypto";
//#region node_modules/.nitro/vite/services/ssr/assets/injector-BgOH-ggh.js
var PROVIDER_POLICIES = {
	github: {
		provider: "github",
		hosts: ["api.github.com"],
		methods: [
			"GET",
			"POST",
			"PUT",
			"PATCH",
			"DELETE"
		],
		pathPrefix: "/",
		maxRequestBytes: 262144,
		maxResponseBytes: 1048576,
		timeoutMs: 12e3
	},
	cloudflare: {
		provider: "cloudflare",
		hosts: ["api.cloudflare.com"],
		methods: [
			"GET",
			"POST",
			"PUT",
			"PATCH",
			"DELETE"
		],
		pathPrefix: "/client/v4/",
		maxRequestBytes: 262144,
		maxResponseBytes: 1048576,
		timeoutMs: 12e3
	},
	openai: {
		provider: "openai",
		hosts: ["api.openai.com"],
		methods: ["GET", "POST"],
		pathPrefix: "/v1/",
		maxRequestBytes: 262144,
		maxResponseBytes: 1048576,
		timeoutMs: 15e3
	},
	stripe: {
		provider: "stripe",
		hosts: ["api.stripe.com"],
		methods: ["GET", "POST"],
		pathPrefix: "/v1/",
		maxRequestBytes: 262144,
		maxResponseBytes: 1048576,
		timeoutMs: 12e3
	},
	xai: {
		provider: "xai",
		hosts: ["api.x.ai"],
		methods: ["GET", "POST"],
		pathPrefix: "/v1/",
		maxRequestBytes: 262144,
		maxResponseBytes: 1048576,
		timeoutMs: 15e3
	}
};
var BLOCKED_HOSTS = /* @__PURE__ */ new Set([
	"localhost",
	"localhost.localdomain",
	"metadata.google.internal",
	"metadata.google.com",
	"instance-data"
]);
var BLOCKED_SUFFIXES = [
	".internal",
	".local",
	".localhost"
];
function isBlockedHost(hostname) {
	const host = normalizeHost(hostname);
	if (!host) return true;
	if (BLOCKED_HOSTS.has(host)) return true;
	if (BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) return true;
	if (isPrivateOrLinkLocalIp(host)) return true;
	return false;
}
function normalizeHost(hostname) {
	return hostname.trim().toLowerCase().replace(/\.$/, "").replace(/^\[(.*)\]$/, "$1");
}
/**
* Loopback, private, link-local, CGNAT, multicast, reserved and unspecified
* addresses, IPv4 and IPv6 (including every way an IPv4 address can ride
* inside an IPv6 one: IPv4-mapped, IPv4-compatible, NAT64, 6to4). Only IP
* literals match: a hostname such as "fdic.gov" is not an fd00::/8 address.
*/
function isPrivateOrLinkLocalIp(input) {
	const host = normalizeHost(input);
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return isPrivateIpv4(host);
	if (/^\d+$/.test(host) || /^0x[0-9a-f]+$/.test(host)) return true;
	if (host.includes(".") && !host.includes(":")) {
		const octets = host.split(".");
		if (octets.every((o) => /^(0x[0-9a-f]+|\d+)$/.test(o)) && octets.some((o) => /^0x/.test(o) || /^0\d/.test(o))) return true;
	}
	if (!host.includes(":")) return false;
	const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(host);
	if (mapped) return isPrivateIpv4(mapped[1]);
	const groups = parseIpv6(host);
	if (!groups) return true;
	return isBlockedIpv6(groups);
}
/**
* IPv6 literal → 8 hextets, or null when the text is not one. Accepts "::"
* compression, a dotted IPv4 tail and a "%zone" suffix (ignored: the zone
* selects an interface, not an address).
*/
function parseIpv6(input) {
	const text = input.replace(/%[^%]*$/, "");
	if (!/^[0-9a-f:.]+$/.test(text) || !text.includes(":")) return null;
	const halves = text.split("::");
	if (halves.length > 2) return null;
	const parseSide = (side) => {
		if (side === "") return [];
		const out = [];
		const parts = side.split(":");
		for (let i = 0; i < parts.length; i += 1) {
			const part = parts[i];
			if (part.includes(".")) {
				if (i !== parts.length - 1) return null;
				const o = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(part);
				if (!o) return null;
				const b = o.slice(1).map(Number);
				if (b.some((n) => n > 255)) return null;
				out.push(b[0] << 8 | b[1], b[2] << 8 | b[3]);
			} else {
				if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
				out.push(parseInt(part, 16));
			}
		}
		return out;
	};
	const head = parseSide(halves[0]);
	const tail = halves.length === 2 ? parseSide(halves[1]) : [];
	if (!head || !tail) return null;
	if (halves.length === 1) return head.length === 8 ? head : null;
	if (halves[0].includes(".")) return null;
	const missing = 8 - head.length - tail.length;
	if (missing < 1) return null;
	return [
		...head,
		...new Array(missing).fill(0),
		...tail
	];
}
function embeddedIpv4(hi, lo) {
	return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}
function isBlockedIpv6(g) {
	const zero = (from, to) => g.slice(from, to).every((n) => n === 0);
	if (zero(0, 6)) return true;
	if (zero(0, 5) && g[5] === 65535) return true;
	if (zero(0, 4) && g[4] === 65535 && g[5] === 0) return true;
	if (g[0] === 100 && g[1] === 65435 && zero(2, 6)) return isPrivateIpv4(embeddedIpv4(g[6], g[7]));
	if (g[0] === 100 && g[1] === 65435 && g[2] === 1) return true;
	if (g[0] === 8194) return isPrivateIpv4(embeddedIpv4(g[1], g[2]));
	if (g[0] === 8193 && g[1] === 0) return true;
	if ((g[0] & 65472) === 65152) return true;
	if ((g[0] & 65472) === 65216) return true;
	if ((g[0] & 65024) === 64512) return true;
	if ((g[0] & 65280) === 65280) return true;
	return false;
}
/**
* One comparable spelling per address, or null when the text is not an IP
* literal: dotted quad for IPv4 and IPv4-mapped IPv6, eight lower-case
* hextets for the rest. Used to compare a socket's remote address with the
* addresses a request was pinned to.
*/
function canonicalIp(input) {
	const host = normalizeHost(input);
	const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
	if (v4) {
		const octets = v4.slice(1);
		if (octets.some((o) => Number(o) > 255 || o.length > 1 && o.startsWith("0"))) return null;
		return octets.map(Number).join(".");
	}
	const g = parseIpv6(host);
	if (!g) return null;
	if (g.slice(0, 5).every((n) => n === 0) && g[5] === 65535) return embeddedIpv4(g[6], g[7]);
	return g.map((n) => n.toString(16)).join(":");
}
function isPrivateIpv4(host) {
	if (/^0\./.test(host)) return true;
	if (/^169\.254\./.test(host)) return true;
	if (/^127\./.test(host)) return true;
	if (/^10\./.test(host)) return true;
	if (/^192\.168\./.test(host)) return true;
	if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return true;
	if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host)) return true;
	if (/^192\.0\.0\./.test(host)) return true;
	if (/^198\.1[89]\./.test(host)) return true;
	if (/^(22[4-9]|23\d)\./.test(host)) return true;
	if (/^(24\d|25[0-5])\./.test(host)) return true;
	return false;
}
function isAllowedHostForProvider(provider, hostname) {
	if (isBlockedHost(hostname)) return false;
	return PROVIDER_POLICIES[provider].hosts.includes(hostname.toLowerCase());
}
function isAllowedMethod(provider, method) {
	const upper = method.toUpperCase();
	return PROVIDER_POLICIES[provider].methods.includes(upper);
}
function normalizeResourcePath(resource) {
	const trimmed = resource.trim();
	if (!trimmed.startsWith("/")) throw Object.assign(/* @__PURE__ */ new Error("invalid_resource"), { code: "invalid_resource" });
	if (trimmed.includes("://") || trimmed.startsWith("//")) throw Object.assign(/* @__PURE__ */ new Error("absolute_url_forbidden"), { code: "absolute_url_forbidden" });
	if (trimmed.includes("\\") || trimmed.includes("\0")) throw Object.assign(/* @__PURE__ */ new Error("invalid_resource"), { code: "invalid_resource" });
	const decoded = decodeURIComponent(trimmed);
	if (decoded.includes("://") || /(?:^|\/)\.\.(?:\/|$)/.test(decoded)) throw Object.assign(/* @__PURE__ */ new Error("invalid_resource"), { code: "invalid_resource" });
	return trimmed.replace(/\/{2,}/g, "/");
}
function buildProviderUrl(provider, resource) {
	const path = normalizeResourcePath(resource);
	const host = PROVIDER_POLICIES[provider].hosts[0];
	const url = new URL(`https://${host}${path}`);
	if (url.protocol !== "https:") throw Object.assign(/* @__PURE__ */ new Error("https_required"), { code: "https_required" });
	if (!isAllowedHostForProvider(provider, url.hostname)) throw Object.assign(/* @__PURE__ */ new Error("hostname_not_allowed"), { code: "hostname_not_allowed" });
	return url;
}
function assertSafeDestination(url, provider) {
	if (url.protocol !== "https:") throw Object.assign(/* @__PURE__ */ new Error("https_required"), { code: "https_required" });
	if (isBlockedHost(url.hostname) || isPrivateOrLinkLocalIp(url.hostname)) throw Object.assign(/* @__PURE__ */ new Error("hostname_not_allowed"), { code: "hostname_not_allowed" });
	if (!isAllowedHostForProvider(provider, url.hostname)) throw Object.assign(/* @__PURE__ */ new Error("hostname_not_allowed"), { code: "hostname_not_allowed" });
}
/**
* Vault v2 browser injector channel (docs/ops/injector-contract.md,
* docs/ops/injector-channel.md).
*
* An "injector" is an enrolled browser extension instance on the owner's own
* machine. It holds a P-256 ECDH private key (non-extractable, in the browser)
* and an injector token. An agent can ask for a credential to be placed in the
* owner's browser (`entry_inject`, gateway.ts); after the owner approved that
* one request on Telegram the agent gets a single-use TICKET, and the injector
* exchanges the ticket for the credential SEALED to its public key.
*
* Invariant of this module: plaintext of a stored credential exists only
* inside this process and, as ciphertext only the injector's private key can
* open, on the wire. Nothing here returns, logs, ledgers or stores a secret, a
* cookie value, the ECDH shared secret, the derived AES key, an injector token
* or a raw ticket (the mint result, returned once to the caller, excepted).
*
*   enrollInjector   owner only (gateway admin tool). Validates the public JWK
*                    by importing it with WebCrypto, mints `ein_<43 base64url>`
*                    (256 bit), stores sha256(token) only.
*   mintTicket       `eit_<32 base64url>` (192 bit), stored as sha256, TTL
*                    120 s, bound to entry, mode, target origin, injector,
*                    approval and requesting client. No ticket without its
*                    ledger row.
*   redeemTicket     atomic single use (see the table below), then the secret
*                    is read through cards.useEntry (the one read path), the
*                    plaintext is assembled and sealed, and the redeem row is
*                    written — fail closed: no ciphertext leaves when that row
*                    cannot be written.
*   reportResult     the injector's outcome ("injected" | "failed").
*
* Redeem outcomes, in this order (first match wins):
*   store down / rate-limit store down          503 unavailable       not burned
*   over the per-injector rate limit            429 rate_limited      not burned
*   malformed or unknown ticket                 404 ticket_not_found  —
*   ticket bound to ANOTHER injector            403 ticket_wrong_injector  not burned
*   already redeemed (burned)                   409 ticket_used       —
*   expired, never redeemed                     410 ticket_expired    —
*   bound injector, live ticket                 BURNED here, atomically; then
*     entry gone / needs re-entry / kind changed / no cookie for the origin /
*     vault unreachable / sealing failed / ledger unavailable → 503 unavailable
*     (the ticket stays burned), otherwise 200 with the sealed blob.
* An unauthenticated caller (bad, revoked or foreign token) never reaches this
* function: injector-http.ts answers 401 invalid_injector first.
*
* Sealing (exactly the contract): ephemeral P-256 key pair; Z = ECDH(ephemeral
* private, injector public); K = HKDF-SHA256(Z, salt[32], info
* "echo-vault-injector-v1", 32 bytes); ct = AES-256-GCM(K, iv[12], plaintext,
* aad) with the 16-byte tag appended; aad = UTF-8 of
* `eit:${sha256hex(ticket)}|${injector_id}|${target_origin}|${mode}`.
* K is derived as a non-extractable CryptoKey, so its bytes never exist in JS.
* The Z and plaintext byte buffers are zeroed after use; JS strings (the
* secret as read from the backend, the plaintext JSON) cannot be zeroed and
* live until garbage collection.
*/
var INJECTOR_ID_PATTERN = /^inj_[0-9a-f]{16}$/;
/** What this vault mints: `ein_` + 43 base64url chars (32 random bytes). Longer is tolerated on input, per the contract's "43+". */
var INJECTOR_TOKEN_PATTERN = /^ein_[A-Za-z0-9_-]{43,128}$/;
/** `eit_` + 32 base64url chars (24 random bytes, 192 bit). */
var TICKET_PATTERN = /^eit_[A-Za-z0-9_-]{32}$/;
var TICKET_TTL_MS = 12e4;
var SEAL_ALG = "ECDH-ES+HKDF-SHA256+A256GCM";
var SEAL_INFO = "echo-vault-injector-v1";
var REDEEM_WINDOW_MS = 6e4;
var INJECT_CAPABILITY = "vault.entry.inject";
var REDEEM_CAPABILITY = "vault.entry.inject.redeem";
var RESULT_CAPABILITY = "vault.entry.inject.result";
var INJECT_MODES = ["cookies", "field"];
var HEX64 = /^[0-9a-f]{64}$/;
var ENTRY_ID = /^ve_[0-9a-f]{32}$/;
var COORD = /^[A-Za-z0-9_-]{43}$/;
var HOST = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
var DETAIL_CODE = /^[a-z0-9_]{1,64}$/;
/** JWK members a browser's exportKey may add to a public key. Anything else — "d" above all — is refused. */
var JWK_PUBLIC_MEMBERS = /* @__PURE__ */ new Set([
	"kty",
	"crv",
	"x",
	"y",
	"ext",
	"key_ops",
	"alg",
	"use",
	"kid"
]);
var subtle = webcrypto.subtle;
/** A fixed short code. The message IS the code: no caller text, no secret ever rides in it. */
var InjectorError = class extends Error {
	code;
	constructor(code) {
		super(code);
		this.name = "InjectorError";
		this.code = code;
	}
};
function sha256Hex(text) {
	return createHash("sha256").update(text, "utf8").digest("hex");
}
function checkInjector(rec) {
	if (!INJECTOR_ID_PATTERN.test(rec.id)) throw new InjectorError("injector_invalid_id");
	if (typeof rec.name !== "string" || rec.name.length < 1 || rec.name.length > 64) throw new InjectorError("injector_invalid_name");
	if (canonicalJwkText(parseCanonicalJwk(rec.public_key_jwk)) !== rec.public_key_jwk) throw new InjectorError("injector_invalid_key");
	if (!HEX64.test(rec.token_sha256)) throw new InjectorError("injector_invalid_token_hash");
	if (!Number.isInteger(rec.created_at) || rec.created_at <= 0) throw new InjectorError("injector_invalid_time");
}
function checkTicket(rec) {
	if (!HEX64.test(rec.sha256)) throw new InjectorError("ticket_invalid_hash");
	if (!ENTRY_ID.test(rec.entry_id)) throw new InjectorError("ticket_invalid_entry");
	if (!INJECT_MODES.includes(rec.mode)) throw new InjectorError("ticket_invalid_mode");
	if (!isCanonicalOrigin(rec.target_origin)) throw new InjectorError("ticket_invalid_origin");
	if (!INJECTOR_ID_PATTERN.test(rec.injector_id)) throw new InjectorError("ticket_invalid_injector");
	if (typeof rec.approval_id !== "string" || rec.approval_id.length < 1 || rec.approval_id.length > 256) throw new InjectorError("ticket_invalid_approval");
	if (typeof rec.client_id !== "string" || rec.client_id.length < 1 || rec.client_id.length > 200) throw new InjectorError("ticket_invalid_client");
	if (!Number.isInteger(rec.created_at) || rec.created_at <= 0 || !Number.isInteger(rec.expires_at) || rec.expires_at <= rec.created_at) throw new InjectorError("ticket_invalid_time");
}
async function defaultSql() {
	return (await import("./db-YAhc1k3o.mjs")).getSql();
}
function violates(err, constraint) {
	const e = err;
	return e?.constraint === constraint || typeof e?.message === "string" && e.message.includes(constraint);
}
var num = (v) => Number(v);
var numOrNull = (v) => v === null || v === void 0 ? null : Number(v);
var INJECTOR_COLUMNS = "id, name, public_key_jwk, token_sha256, created_at, revoked_at, last_used_at";
function rowToInjector(row) {
	return {
		id: String(row.id),
		name: String(row.name),
		public_key_jwk: String(row.public_key_jwk),
		token_sha256: String(row.token_sha256),
		created_at: num(row.created_at),
		revoked_at: numOrNull(row.revoked_at),
		last_used_at: numOrNull(row.last_used_at)
	};
}
var SqlInjectorStore = class {
	kind = "sql";
	getSql;
	constructor(getSql = defaultSql) {
		this.getSql = getSql;
	}
	async insert(rec) {
		checkInjector(rec);
		const sql = await this.getSql();
		try {
			await sql.query(`insert into vault_injectors (${INJECTOR_COLUMNS}) values ($1, $2, $3, $4, $5, $6, $7)`, [
				rec.id,
				rec.name,
				rec.public_key_jwk,
				rec.token_sha256,
				rec.created_at,
				rec.revoked_at,
				rec.last_used_at
			]);
		} catch (err) {
			if (violates(err, "vault_injectors_pkey") || violates(err, "vault_injectors_token_sha256_key")) throw new InjectorError("injector_exists");
			throw err;
		}
	}
	async get(id) {
		if (!INJECTOR_ID_PATTERN.test(id)) return null;
		const rows = await (await this.getSql()).query(`select ${INJECTOR_COLUMNS} from vault_injectors where id = $1`, [id]);
		return rows[0] ? rowToInjector(rows[0]) : null;
	}
	async findByTokenHash(tokenSha256) {
		if (!HEX64.test(tokenSha256)) return null;
		const rows = await (await this.getSql()).query(`select ${INJECTOR_COLUMNS} from vault_injectors where token_sha256 = $1`, [tokenSha256]);
		return rows[0] ? rowToInjector(rows[0]) : null;
	}
	async list() {
		return (await (await this.getSql()).query(`select ${INJECTOR_COLUMNS} from vault_injectors order by created_at, id`)).map(rowToInjector);
	}
	async revoke(id, at) {
		if (!INJECTOR_ID_PATTERN.test(id)) return false;
		return (await (await this.getSql()).query(`update vault_injectors set revoked_at = greatest($2::bigint, created_at) where id = $1 and revoked_at is null returning id`, [id, at])).length === 1;
	}
	async touch(id, at) {
		if (!INJECTOR_ID_PATTERN.test(id)) return;
		await (await this.getSql()).query(`update vault_injectors set last_used_at = greatest($2::bigint, created_at) where id = $1`, [id, at]);
	}
};
var TICKET_COLUMNS = "sha256, entry_id, mode, target_origin, injector_id, approval_id, client_id, created_at, expires_at, redeemed_at, result";
function rowToTicket(row) {
	return {
		sha256: String(row.sha256),
		entry_id: String(row.entry_id),
		mode: String(row.mode),
		target_origin: String(row.target_origin),
		injector_id: String(row.injector_id),
		approval_id: String(row.approval_id),
		client_id: String(row.client_id),
		created_at: num(row.created_at),
		expires_at: num(row.expires_at),
		redeemed_at: numOrNull(row.redeemed_at),
		result: row.result === null || row.result === void 0 ? null : String(row.result)
	};
}
var SqlInjectTicketStore = class {
	kind = "sql";
	getSql;
	constructor(getSql = defaultSql) {
		this.getSql = getSql;
	}
	async insert(rec) {
		checkTicket(rec);
		const sql = await this.getSql();
		try {
			await sql.query(`insert into vault_inject_tickets (${TICKET_COLUMNS}) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, [
				rec.sha256,
				rec.entry_id,
				rec.mode,
				rec.target_origin,
				rec.injector_id,
				rec.approval_id,
				rec.client_id,
				rec.created_at,
				rec.expires_at,
				rec.redeemed_at,
				rec.result
			]);
		} catch (err) {
			if (violates(err, "vault_inject_tickets_approval_id_key")) throw new InjectorError("approval_already_used");
			if (violates(err, "vault_inject_tickets_pkey")) throw new InjectorError("ticket_exists");
			throw err;
		}
	}
	async get(sha256) {
		if (!HEX64.test(sha256)) return null;
		const rows = await (await this.getSql()).query(`select ${TICKET_COLUMNS} from vault_inject_tickets where sha256 = $1`, [sha256]);
		return rows[0] ? rowToTicket(rows[0]) : null;
	}
	async redeem(sha256, injectorId, now) {
		if (!HEX64.test(sha256) || !INJECTOR_ID_PATTERN.test(injectorId)) return null;
		const rows = await (await this.getSql()).query(`update vault_inject_tickets set redeemed_at = greatest($3::bigint, created_at)
        where sha256 = $1 and injector_id = $2 and redeemed_at is null and expires_at > $3::bigint
        returning ${TICKET_COLUMNS}`, [
			sha256,
			injectorId,
			now
		]);
		return rows[0] ? rowToTicket(rows[0]) : null;
	}
	async setResult(sha256, injectorId, result) {
		if (!HEX64.test(sha256) || !INJECTOR_ID_PATTERN.test(injectorId) || result !== "injected" && result !== "failed") return false;
		return (await (await this.getSql()).query(`update vault_inject_tickets set result = $3
        where sha256 = $1 and injector_id = $2 and redeemed_at is not null and result is null returning sha256`, [
			sha256,
			injectorId,
			result
		])).length === 1;
	}
	async delete(sha256) {
		if (!HEX64.test(sha256)) return;
		await (await this.getSql()).query(`delete from vault_inject_tickets where sha256 = $1`, [sha256]);
	}
	async prune(now, keepMs = 0) {
		return (await (await this.getSql()).query(`delete from vault_inject_tickets where expires_at + $2::bigint <= $1::bigint returning sha256`, [now, keepMs])).length;
	}
};
var defaultInjectorStore = null;
var defaultTicketStore = null;
function getDefaultInjectorStore() {
	defaultInjectorStore ??= new SqlInjectorStore();
	return defaultInjectorStore;
}
function getDefaultInjectTicketStore() {
	defaultTicketStore ??= new SqlInjectTicketStore();
	return defaultTicketStore;
}
function ctx(deps = {}) {
	return {
		injectors: deps.injectors ?? getDefaultInjectorStore(),
		tickets: deps.tickets ?? getDefaultInjectTicketStore(),
		now: Math.floor((deps.now ?? Date.now)()),
		limits: deps.rateLimit ?? getDefaultRateLimitStore(),
		cards: deps.cards,
		ledger: deps.ledger ?? deps.cards?.ledger ?? appendLedger
	};
}
function canonicalJwkText(jwk) {
	return `{"crv":"P-256","kty":"EC","x":${JSON.stringify(jwk.x)},"y":${JSON.stringify(jwk.y)}}`;
}
/** Structural check only (no curve check). Throws InjectorError("invalid_public_key"). */
function parseCanonicalJwk(input) {
	let value = input;
	if (typeof value === "string") {
		if (value.length > 2048) throw new InjectorError("invalid_public_key");
		try {
			value = JSON.parse(value);
		} catch {
			throw new InjectorError("invalid_public_key");
		}
	}
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new InjectorError("invalid_public_key");
	const o = value;
	if (Object.hasOwn(o, "d")) throw new InjectorError("private_key_not_allowed");
	for (const key of Object.keys(o)) if (!JWK_PUBLIC_MEMBERS.has(key)) throw new InjectorError("invalid_public_key");
	if (o.kty !== "EC" || o.crv !== "P-256" || typeof o.x !== "string" || typeof o.y !== "string" || !COORD.test(o.x) || !COORD.test(o.y)) throw new InjectorError("invalid_public_key");
	return {
		kty: "EC",
		crv: "P-256",
		x: o.x,
		y: o.y
	};
}
async function importPublicKey(jwk) {
	try {
		return await subtle.importKey("jwk", {
			kty: jwk.kty,
			crv: jwk.crv,
			x: jwk.x,
			y: jwk.y,
			ext: true
		}, {
			name: "ECDH",
			namedCurve: "P-256"
		}, true, []);
	} catch {
		throw new InjectorError("invalid_public_key");
	}
}
/** Validate a P-256 ECDH PUBLIC JWK (object or JSON text) by importing it. Returns the canonical four-member form. */
async function validatePublicJwk(input) {
	const jwk = parseCanonicalJwk(input);
	await importPublicKey(jwk);
	return jwk;
}
/** RFC 7638 thumbprint (base64url of sha256 over the canonical members). Lets the owner compare with what the extension shows. */
function jwkThumbprint(canonicalJwk) {
	return createHash("sha256").update(canonicalJwk, "utf8").digest("base64url");
}
var iso = (ms) => ms === null ? null : new Date(ms).toISOString();
function injectorView(r) {
	return {
		injector_id: r.id,
		name: r.name,
		key_thumbprint: jwkThumbprint(r.public_key_jwk),
		status: r.revoked_at === null ? "active" : "revoked",
		created_at: iso(r.created_at),
		revoked_at: iso(r.revoked_at),
		last_used_at: iso(r.last_used_at)
	};
}
/**
* Enroll an injector. The returned `token` is shown ONCE by the caller (the
* gateway's owner-only admin tool); only its sha256 is stored. Throws
* InjectorError: invalid_name | invalid_public_key | private_key_not_allowed |
* too_many_injectors | key_already_enrolled.
*/
async function enrollInjector(input, deps = {}) {
	const c = ctx(deps);
	const name = typeof input.name === "string" ? sanitizeDisplayText(input.name, 64) : "";
	if (!name) throw new InjectorError("invalid_name");
	const canonical = canonicalJwkText(await validatePublicJwk(input.public_key_jwk));
	const active = (await c.injectors.list()).filter((r) => r.revoked_at === null);
	if (active.length >= 20) throw new InjectorError("too_many_injectors");
	if (active.some((r) => r.public_key_jwk === canonical)) throw new InjectorError("key_already_enrolled");
	const token = `ein_${randomBytes(32).toString("base64url")}`;
	const rec = {
		id: `inj_${randomBytes(8).toString("hex")}`,
		name,
		public_key_jwk: canonical,
		token_sha256: sha256Hex(token),
		created_at: c.now,
		revoked_at: null,
		last_used_at: null
	};
	await c.injectors.insert(rec);
	log.info("vault_injector_enrolled", { injector_id: rec.id });
	return {
		injector: injectorView(rec),
		token
	};
}
async function listInjectors(deps = {}) {
	return (await ctx(deps).injectors.list()).map(injectorView);
}
/** Revoke. Its token stops authenticating at once, so its outstanding tickets can never be redeemed. */
async function revokeInjector(id, deps = {}) {
	const c = ctx(deps);
	if (typeof id !== "string" || !INJECTOR_ID_PATTERN.test(id)) throw new InjectorError("injector_not_found");
	if (!await c.injectors.get(id)) throw new InjectorError("injector_not_found");
	const revoked = await c.injectors.revoke(id, c.now);
	log.warn("vault_injector_revoked", {
		injector_id: id,
		was_active: revoked
	});
	return revoked;
}
/**
* Which injector an `entry_inject` call targets. With `requested`: that one,
* if active. Without: the only active injector, if there is exactly one.
* Throws InjectorError: injector_not_found | no_injector_enrolled | injector_required.
*/
async function resolveInjector(requested, deps = {}) {
	const c = ctx(deps);
	if (requested !== void 0) {
		const r = INJECTOR_ID_PATTERN.test(requested) ? await c.injectors.get(requested) : null;
		if (!r || r.revoked_at !== null) throw new InjectorError("injector_not_found");
		return injectorView(r);
	}
	const active = (await c.injectors.list()).filter((r) => r.revoked_at === null);
	if (active.length === 0) throw new InjectorError("no_injector_enrolled");
	if (active.length > 1) throw new InjectorError("injector_required");
	return injectorView(active[0]);
}
/**
* `Authorization: Bearer ein_…` → the active injector, or null. Nothing else
* authenticates here: an OAuth (`eva_`) or workload (`ewk_`) token does not
* match the pattern, and an `ein_` token is never looked at by
* http-transport.ts. Throws only when the store is unreachable.
*/
async function authenticateInjector(headers, deps = {}) {
	const match = /^Bearer\s+(\S+)$/i.exec((headers.get("authorization") ?? "").trim());
	if (!match || !INJECTOR_TOKEN_PATTERN.test(match[1])) return null;
	const digest = sha256Hex(match[1]);
	const rec = await ctx(deps).injectors.findByTokenHash(digest);
	if (!rec || rec.revoked_at !== null) return null;
	if (!timingSafeEqual(Buffer.from(rec.token_sha256, "hex"), Buffer.from(digest, "hex"))) return null;
	return rec;
}
function isCanonicalOrigin(origin) {
	return typeof origin === "string" && origin.length <= 261 && origin.startsWith("https://") && HOST.test(origin.slice(8));
}
/**
* `target_origin` must be exactly `https://<host>` (lower case, no port, path,
* query, fragment or credentials) where host is the entry's site or a
* subdomain of it, and not a blocked/internal host. Returns the host.
* Throws InjectorError: invalid_target_origin | target_origin_not_allowed.
*/
function checkTargetOrigin(origin, site) {
	if (!isCanonicalOrigin(origin)) throw new InjectorError("invalid_target_origin");
	const host = origin.slice(8);
	if (!site || host !== site && !host.endsWith(`.${site}`)) throw new InjectorError("target_origin_not_allowed");
	if (isBlockedHost(host)) throw new InjectorError("target_origin_not_allowed");
	return host;
}
/** cookies ↔ a `cookie` entry; field ↔ a `password` entry. */
function kindForMode(mode) {
	return mode === "cookies" ? "cookie" : "password";
}
/** `entry:<site>/<account>#<injector id>` — the ledger resource of every inject row. */
function injectResource(site, account, injectorId) {
	return `entry:${site}/${account}#${injectorId}`;
}
/**
* Mint one ticket. Re-checks everything the planner checked (time passed
* while the owner decided). Throws InjectorError: approval_required |
* invalid_mode | mode_kind_mismatch | entry_not_active | invalid_target_origin |
* target_origin_not_allowed | injector_not_found | approval_already_used |
* ledger_unavailable.
*/
async function mintTicket(input, deps = {}) {
	const c = ctx(deps);
	if (typeof input.approval_id !== "string" || !input.approval_id) throw new InjectorError("approval_required");
	if (!INJECT_MODES.includes(input.mode)) throw new InjectorError("invalid_mode");
	if (input.entry.kind !== kindForMode(input.mode)) throw new InjectorError("mode_kind_mismatch");
	if (input.entry.status !== "active") throw new InjectorError("entry_not_active");
	checkTargetOrigin(input.target_origin, input.entry.site);
	const injector = INJECTOR_ID_PATTERN.test(input.injector_id) ? await c.injectors.get(input.injector_id) : null;
	if (!injector || injector.revoked_at !== null) throw new InjectorError("injector_not_found");
	const ticket = `eit_${randomBytes(24).toString("base64url")}`;
	const rec = {
		sha256: sha256Hex(ticket),
		entry_id: input.entry.id,
		mode: input.mode,
		target_origin: input.target_origin,
		injector_id: injector.id,
		approval_id: input.approval_id,
		client_id: input.client_id,
		created_at: c.now,
		expires_at: c.now + TICKET_TTL_MS,
		redeemed_at: null,
		result: null
	};
	await c.tickets.insert(rec);
	try {
		await input.record();
	} catch {
		await c.tickets.delete(rec.sha256).catch(() => log.error("vault_inject_ticket_cleanup_failed", { injector_id: injector.id }));
		throw new InjectorError("ledger_unavailable");
	}
	c.tickets.prune(c.now, 864e5).catch(() => void 0);
	log.info("vault_inject_ticket_minted", {
		entry_id: rec.entry_id,
		injector_id: rec.injector_id,
		mode: rec.mode,
		approval_id: rec.approval_id
	});
	return {
		ticket,
		expires_at: new Date(rec.expires_at).toISOString(),
		injector_id: rec.injector_id,
		entry: {
			id: input.entry.id,
			label: input.entry.label,
			kind: input.entry.kind
		},
		target_origin: rec.target_origin,
		mode: rec.mode
	};
}
/**
* The cookies of `jar` that a browser would send to `host` — domain match
* only (RFC 6265 §5.1.3), every path, unexpired. A host-only cookie needs the
* exact host; a domain cookie matches its domain and subdomains, never a
* public suffix. A cookie stored with domain "" is host-only for the entry's
* site and is emitted with that site as its domain. Nothing scoped to another
* registrable domain can match, because the cookie's domain must be `host` or
* a parent of it and `host` is the entry's site or a subdomain of it.
*/
function cookiesForOrigin(jar, host, site, nowMs) {
	const out = [];
	for (const c of jar.cookies) {
		if (c.expires !== null && c.expires * 1e3 <= nowMs) continue;
		const domain = c.domain || site;
		if (!domain) continue;
		if (c.hostOnly ? host !== domain : !domainMatches(host, domain) || isPublicSuffix(domain)) continue;
		out.push({
			name: c.name,
			value: c.value,
			domain,
			path: c.path,
			secure: c.secure,
			httpOnly: c.httpOnly,
			hostOnly: c.hostOnly,
			expires: c.expires,
			sameSite: "unspecified"
		});
	}
	return out;
}
/** The plaintext JSON for one redeem. Throws Error(<short code>) — never with content. */
function assemblePlaintext(secret, entry, ticket, nowMs) {
	if (entry.kind !== kindForMode(ticket.mode)) throw new Error("mode_kind_mismatch");
	const host = checkTargetOrigin(ticket.target_origin, entry.site);
	if (ticket.mode === "cookies") {
		let jar;
		try {
			jar = parseStoredJar(secret);
		} catch {
			throw new Error("cookie_jar_invalid");
		}
		for (const form of jarRedactionForms(jar)) registerSecretForRedaction(form);
		const cookies = cookiesForOrigin(jar, host, entry.site, nowMs);
		if (cookies.length === 0) throw new Error("no_cookie_for_origin");
		return JSON.stringify({
			v: 1,
			cookies
		});
	}
	return JSON.stringify({
		v: 1,
		username: entry.account,
		secret
	});
}
/** The AAD string of the contract. `ticketSha256` is sha256 hex of the raw ticket. */
function sealAad(ticketSha256, injectorId, targetOrigin, mode) {
	return `eit:${ticketSha256}|${injectorId}|${targetOrigin}|${mode}`;
}
var b64u = (bytes) => Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");
/**
* Seal `plaintext` to a P-256 public key. ECDH-ES (ephemeral key) → HKDF-SHA256
* (random 32-byte salt, info "echo-vault-injector-v1") → AES-256-GCM (random
* 12-byte IV, AAD). The AES key is a non-extractable CryptoKey; the shared
* secret and plaintext buffers are zeroed before returning.
*/
async function sealForInjector(plaintext, recipient, aad) {
	const recipientKey = await importPublicKey(recipient);
	const ephemeral = await subtle.generateKey({
		name: "ECDH",
		namedCurve: "P-256"
	}, true, ["deriveBits"]);
	const z = new Uint8Array(await subtle.deriveBits({
		name: "ECDH",
		public: recipientKey
	}, ephemeral.privateKey, 256));
	const pt = new TextEncoder().encode(plaintext);
	try {
		const salt = webcrypto.getRandomValues(/* @__PURE__ */ new Uint8Array(32));
		const iv = webcrypto.getRandomValues(/* @__PURE__ */ new Uint8Array(12));
		const ikm = await subtle.importKey("raw", z, "HKDF", false, ["deriveKey"]);
		const key = await subtle.deriveKey({
			name: "HKDF",
			hash: "SHA-256",
			salt,
			info: new TextEncoder().encode(SEAL_INFO)
		}, ikm, {
			name: "AES-GCM",
			length: 256
		}, false, ["encrypt"]);
		const aadBytes = new TextEncoder().encode(aad);
		const ct = new Uint8Array(await subtle.encrypt({
			name: "AES-GCM",
			iv,
			additionalData: aadBytes,
			tagLength: 128
		}, key, pt));
		const epk = await subtle.exportKey("jwk", ephemeral.publicKey);
		return {
			alg: SEAL_ALG,
			epk: {
				kty: "EC",
				crv: "P-256",
				x: String(epk.x),
				y: String(epk.y)
			},
			salt: b64u(salt),
			iv: b64u(iv),
			ct: b64u(ct),
			aad: b64u(aadBytes)
		};
	} finally {
		z.fill(0);
		pt.fill(0);
	}
}
var fail = (status, error) => ({
	ok: false,
	status,
	error
});
function injectorIdentity(injector) {
	return {
		client_id: `injector:${injector.id}`,
		name: injector.name,
		kind: "workload",
		scopes: []
	};
}
/** Take one slot of a per-injector limit. Throws when the store is unreachable (callers fail closed). */
async function takeSlot(c, namespace, injectorId, limit) {
	return (await withRateLimitStore(c.limits, "hit", (s) => s.hit(rateLimitKey(namespace, injectorId), REDEEM_WINDOW_MS, c.now, limit))).recorded;
}
async function bestEffortRow(c, row) {
	try {
		await c.ledger(row);
	} catch {
		log.error("vault_inject_ledger_failed", {
			capability: row.capability,
			result: row.result
		});
	}
}
/** The ledger resource of a ticket's rows; falls back to the entry id when the entry cannot be read. */
async function ticketResource(c, entryId, injectorId) {
	const entry = await getEntryMetadata(entryId, c.cards).catch(() => null);
	return entry ? injectResource(entry.site, entry.account, injectorId) : `entry:${entryId}#${injectorId}`;
}
/**
* Exchange a ticket for the sealed credential. `injector` comes from
* authenticateInjector. Never throws; every failure is a status and a short
* code (see the table in the module header).
*/
async function redeemTicket(injector, ticket, deps = {}) {
	const c = ctx(deps);
	const who = injectorIdentity(injector);
	const refusal = {
		client_id: who.client_id,
		capability: REDEEM_CAPABILITY,
		decision: "deny",
		tier: 2,
		result: "error"
	};
	try {
		let allowed;
		try {
			allowed = await takeSlot(c, "injector.redeem", injector.id, 30);
		} catch {
			return fail(503, "unavailable");
		}
		if (!allowed) {
			log.warn("vault_inject_redeem_rate_limited", { injector_id: injector.id });
			return fail(429, "rate_limited");
		}
		if (typeof ticket !== "string" || !TICKET_PATTERN.test(ticket)) {
			await bestEffortRow(c, {
				...refusal,
				resource: `entry:unknown#${injector.id}`,
				error: "ticket_not_found"
			});
			return fail(404, "ticket_not_found");
		}
		const digest = sha256Hex(ticket);
		let burned;
		let seen = null;
		try {
			burned = await c.tickets.redeem(digest, injector.id, c.now);
			if (!burned) seen = await c.tickets.get(digest);
		} catch {
			log.error("vault_inject_ticket_store_error", { injector_id: injector.id });
			return fail(503, "unavailable");
		}
		if (!burned) {
			const [status, code] = !seen ? [404, "ticket_not_found"] : seen.injector_id !== injector.id ? [403, "ticket_wrong_injector"] : seen.redeemed_at !== null ? [409, "ticket_used"] : [410, "ticket_expired"];
			await bestEffortRow(c, {
				...refusal,
				resource: seen ? await ticketResource(c, seen.entry_id, seen.injector_id) : `entry:unknown#${injector.id}`,
				credential_ref: seen ? `vault://entry/${seen.entry_id}` : void 0,
				approval_id: seen?.approval_id,
				error: code
			});
			log.warn("vault_inject_redeem_refused", {
				injector_id: injector.id,
				code
			});
			return fail(status, code);
		}
		const bound = burned;
		const box = {
			sealed: null,
			entry: null,
			code: null
		};
		const recipient = parseCanonicalJwk(injector.public_key_jwk);
		const aad = sealAad(digest, injector.id, bound.target_origin, bound.mode);
		try {
			await useEntry(bound.entry_id, who, `inject ${bound.mode} into ${bound.target_origin}`, async (secret, meta) => {
				try {
					box.sealed = await sealForInjector(assemblePlaintext(secret, meta, bound, c.now), recipient, aad);
				} catch (err) {
					const known = err instanceof Error && /^[a-z_]{1,40}$/.test(err.message) ? err.message : "seal_failed";
					box.code = known;
					throw new Error(known);
				}
				box.entry = {
					id: meta.id,
					label: meta.label,
					kind: meta.kind
				};
				return { sealed: true };
			}, {
				...c.cards,
				decision: "escalate",
				tier: 2,
				approval_id: bound.approval_id,
				ledger: async (row) => {
					const out = {
						...row,
						capability: REDEEM_CAPABILITY,
						resource: `${row.resource}#${injector.id}`
					};
					if (box.code) {
						out.result = "error";
						out.error = box.code;
					}
					await c.ledger(out);
				}
			});
		} catch {
			box.sealed = null;
		}
		if (!box.sealed || !box.entry) {
			log.warn("vault_inject_redeem_failed", {
				injector_id: injector.id,
				entry_id: bound.entry_id,
				code: box.code ?? "entry_or_ledger_unavailable"
			});
			return fail(503, "unavailable");
		}
		await c.injectors.touch(injector.id, c.now).catch(() => void 0);
		log.info("vault_inject_redeemed", {
			injector_id: injector.id,
			entry_id: bound.entry_id,
			mode: bound.mode,
			approval_id: bound.approval_id
		});
		return {
			ok: true,
			mode: bound.mode,
			target_origin: bound.target_origin,
			entry: box.entry,
			sealed: box.sealed
		};
	} catch {
		log.error("vault_inject_redeem_internal_error", { injector_id: injector.id });
		return fail(503, "unavailable");
	}
}
/**
* Record the injector's outcome for a ticket it redeemed. Once per ticket.
*   400 invalid_request · 404 ticket_not_found · 403 ticket_wrong_injector ·
*   409 ticket_not_redeemed | result_already_reported · 429 rate_limited · 503 unavailable
*/
async function reportResult(injector, body, deps = {}) {
	const c = ctx(deps);
	try {
		let allowed;
		try {
			allowed = await takeSlot(c, "injector.report", injector.id, 60);
		} catch {
			return fail(503, "unavailable");
		}
		if (!allowed) return fail(429, "rate_limited");
		const digest = body?.ticket_sha256;
		const result = body?.result;
		const detail = body?.detail_code;
		if (typeof digest !== "string" || !HEX64.test(digest) || result !== "injected" && result !== "failed") return fail(400, "invalid_request");
		if (detail !== void 0 && (typeof detail !== "string" || !DETAIL_CODE.test(detail))) return fail(400, "invalid_request");
		let rec;
		let set = false;
		try {
			rec = await c.tickets.get(digest);
			if (rec && rec.injector_id === injector.id && rec.redeemed_at !== null && rec.result === null) set = await c.tickets.setResult(digest, injector.id, result);
		} catch {
			return fail(503, "unavailable");
		}
		if (!rec) return fail(404, "ticket_not_found");
		if (rec.injector_id !== injector.id) return fail(403, "ticket_wrong_injector");
		if (rec.redeemed_at === null) return fail(409, "ticket_not_redeemed");
		if (!set) return fail(409, "result_already_reported");
		try {
			await c.ledger({
				client_id: `injector:${injector.id}`,
				capability: RESULT_CAPABILITY,
				resource: await ticketResource(c, rec.entry_id, injector.id),
				decision: "allow",
				tier: 2,
				result: result === "injected" ? "ok" : "error",
				approval_id: rec.approval_id,
				credential_ref: `vault://entry/${rec.entry_id}`,
				error: result === "injected" ? void 0 : detail ?? "failed",
				task: `inject ${rec.mode} into ${rec.target_origin}${result === "injected" && detail ? ` (${detail})` : ""}`
			});
		} catch {
			log.error("vault_inject_ledger_failed", {
				capability: RESULT_CAPABILITY,
				result
			});
			return fail(503, "unavailable");
		}
		log.info("vault_inject_result", {
			injector_id: injector.id,
			entry_id: rec.entry_id,
			result
		});
		return { ok: true };
	} catch {
		return fail(503, "unavailable");
	}
}
//#endregion
export { revokeInjector as S, mintTicket as _, assertSafeDestination as a, reportResult as b, canonicalIp as c, injectResource as d, isAllowedMethod as f, listInjectors as g, kindForMode as h, PROVIDER_POLICIES as i, checkTargetOrigin as l, isPrivateOrLinkLocalIp as m, INJECT_MODES as n, authenticateInjector as o, isBlockedHost as p, InjectorError as r, buildProviderUrl as s, INJECT_CAPABILITY as t, enrollInjector as u, normalizeResourcePath as v, resolveInjector as x, redeemTicket as y };
