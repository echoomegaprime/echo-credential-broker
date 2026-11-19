import { r as __exportAll } from "../_runtime.mjs";
import { c as redactString, i as containsSecretPrefix, o as log, r as __exportAll$1 } from "./log-BHJOU13W.mjs";
import { r as canonicalJson } from "./approvals-vHr7W1Jg.mjs";
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
//#region node_modules/.nitro/vite/services/ssr/assets/ledger-DtKvLmuw.js
var ledger_DtKvLmuw_exports = /* @__PURE__ */ __exportAll({
	a: () => listLedger,
	c: () => verifyLedger,
	d: () => parseVaultRef,
	i: () => ledger_exports,
	l: () => formatVaultRef,
	n: () => getLedger,
	o: () => redactLedgerText,
	r: () => ledgerHead,
	s: () => scanLedger,
	t: () => appendLedger,
	u: () => isProviderId
});
var PROVIDERS = /* @__PURE__ */ new Set([
	"github",
	"cloudflare",
	"openai",
	"stripe",
	"xai"
]);
var REF_RE = /^vault:\/\/([a-z0-9-]+)\/([a-zA-Z0-9._-]+)$/;
function isProviderId(value) {
	return PROVIDERS.has(value);
}
function parseVaultRef(input) {
	if (typeof input !== "string") return null;
	const trimmed = input.trim();
	const match = REF_RE.exec(trimmed);
	if (!match) return null;
	const provider = match[1];
	const account = match[2];
	if (!provider || !account || !isProviderId(provider)) return null;
	return {
		scheme: "vault",
		provider,
		account,
		raw: `vault://${provider}/${account}`
	};
}
function formatVaultRef(provider, account) {
	return `vault://${provider}/${account}`;
}
/**
* Vault v2 ledger — append-only, hash-chained, persisted audit of every
* capability request. Replaces the in-memory 500-record `audit.ts` for v2.
*
* Chain: entry N stores `prev_hash` = hash of entry N-1 (genesis: 64 zeros)
* and `hash` = sha256 hex of `prev_hash + canonicalJson(entry without hash)`.
* `verifyLedger()` recomputes every link, so editing, deleting or reordering
* any stored row is detected at the first affected `seq`.
*
* Concurrency: appends are serialized in-process (promise queue) AND every
* insert is a compare-and-append against the current head (`seq` primary key
* + UNIQUE `prev_hash` in SQL), so two processes racing on the same database
* can never fork the chain — the loser re-reads the head and retries.
*
* Secrets: every string field passes through `redaction.ts` (+ the extra
* patterns below) before it is hashed or stored. Unknown input keys are never
* copied. `credential_ref` is kept only if it is a well-formed `vault://` ref
* that itself contains nothing secret-shaped, or a card entry ref
* (`vault://entry/ve_<32 hex>`). `task` is the caller's own free text: it is
* redacted like `error` and capped at 300 characters.
*
* Optional `ECHO_VAULT_LEDGER_HMAC_KEY` (>= 32 chars, server-only, keep it out
* of the database): when set, each row also stores HMAC-SHA256(key, hash) and
* `verifyLedger()` requires a valid HMAC on EVERY row. Without it, an attacker
* with write access to the database alone could rewrite a row and recompute
* every later hash; with it they would also need the key. Set it before the
* first append — enabling it on a ledger that already has HMAC-less rows makes
* verification fail at seq 1 by design (no silent downgrade).
*
* Limits: a hash chain cannot detect truncation of the newest rows. Anchor
* `ledgerHead()` somewhere outside the database periodically if that matters.
*/
var ledger_exports = /* @__PURE__ */ __exportAll$1({
	GENESIS_PREV_HASH: () => GENESIS_PREV_HASH,
	LEDGER_HMAC_ENV: () => LEDGER_HMAC_ENV,
	Ledger: () => Ledger,
	SqlLedgerStore: () => SqlLedgerStore,
	appendLedger: () => appendLedger,
	computeLedgerHash: () => computeLedgerHash,
	getLedger: () => getLedger,
	ledgerHead: () => ledgerHead,
	listLedger: () => listLedger,
	redactLedgerText: () => redactLedgerText,
	sanitizeLedgerInput: () => sanitizeLedgerInput,
	scanLedger: () => scanLedger,
	verifyLedger: () => verifyLedger
});
var GENESIS_PREV_HASH = "0".repeat(64);
var LEDGER_HMAC_ENV = "ECHO_VAULT_LEDGER_HMAC_KEY";
var HMAC_DOMAIN = "echo-vault-ledger-v1:";
var MIN_HMAC_KEY_LENGTH = 32;
var DEFAULT_LIST_LIMIT = 100;
var MAX_LIST_LIMIT = 1e3;
var VERIFY_BATCH = 500;
var MAX_APPEND_ATTEMPTS = 50;
/** sha256 hex of prev_hash + canonicalJson(body). Exported for external verifiers. */
function computeLedgerHash(body) {
	return createHash("sha256").update(body.prev_hash + canonicalJson(body), "utf8").digest("hex");
}
function computeHmac(key, hash) {
	return createHmac("sha256", key).update(HMAC_DOMAIN + hash, "utf8").digest("hex");
}
function hexEqual(a, b) {
	const ab = Buffer.from(a, "utf8");
	const bb = Buffer.from(b, "utf8");
	return ab.length === bb.length && timingSafeEqual(ab, bb);
}
function bodyOf(entry) {
	const body = {
		seq: entry.seq,
		id: entry.id,
		timestamp: entry.timestamp,
		prev_hash: entry.prev_hash,
		client_id: entry.client_id,
		capability: entry.capability,
		resource: entry.resource,
		decision: entry.decision,
		tier: entry.tier,
		result: entry.result
	};
	if (entry.approval_id !== void 0) body.approval_id = entry.approval_id;
	if (entry.credential_ref !== void 0) body.credential_ref = entry.credential_ref;
	if (entry.http_status !== void 0) body.http_status = entry.http_status;
	if (entry.error !== void 0) body.error = entry.error;
	if (entry.duration_ms !== void 0) body.duration_ms = entry.duration_ms;
	if (entry.task !== void 0) body.task = entry.task;
	if (entry.credential_path !== void 0) body.credential_path = entry.credential_path;
	if (entry.fallback_reason !== void 0) body.fallback_reason = entry.fallback_reason;
	return body;
}
function publicEntry(entry) {
	return {
		...bodyOf(entry),
		hash: entry.hash
	};
}
var DECISIONS = /* @__PURE__ */ new Set([
	"allow",
	"escalate",
	"deny"
]);
var RESULTS = /* @__PURE__ */ new Set([
	"ok",
	"error",
	"denied",
	"pending_approval",
	"committing"
]);
var TIERS = /* @__PURE__ */ new Set([
	0,
	1,
	2,
	3
]);
var CREDENTIAL_PATHS = /* @__PURE__ */ new Set(["installation", "pat_fallback"]);
var MAX_TASK_LENGTH = 300;
var MAX_FALLBACK_REASON_LENGTH = 200;
/** Card entries (cards.ts): `vault://entry/ve_<32 hex>`. Opaque ID, nothing secret-shaped can fit. */
var ENTRY_REF_RE = /^vault:\/\/entry\/ve_[0-9a-f]{32}$/;
/**
* Patterns redaction.ts does not (yet) catch — proposed upstream, mirrored here
* until then. Applied BEFORE redactString():
*  - PEM private keys first: redaction.ts runs its `Authorization: …` rule
*    before its PEM rule, and that rule eats the BEGIN marker when both share
*    a line, leaving the key body unredacted. A truncated PEM (no END marker)
*    is redacted to end of string.
*  - GitHub's stateless installation-token format `ghs_<APPID>_<JWT>` (staged
*    rollout since 2026-04-27); `gh[pousr]_[A-Za-z0-9]{20,}` stops at the `_`.
*  - JWT-shaped values glued to a word character (redaction.ts requires `\b`).
*/
var EXTRA_SECRET_RULES = [
	[/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"],
	[/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$/g, "[REDACTED_PRIVATE_KEY]"],
	[/gh[pousr]_[0-9]+_[A-Za-z0-9._-]{16,}/g, "[REDACTED_GITHUB_TOKEN]"],
	[/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "[REDACTED_JWT]"]
];
/** Long base62/base64-ish runs mixing upper, lower and digits — likely a random secret. */
var HIGH_ENTROPY_RUN = /[A-Za-z0-9_+=]{32,}/g;
function stripControlChars(value) {
	let out = "";
	for (const ch of value) {
		const code = ch.codePointAt(0) ?? 0;
		out += code < 32 && ch !== "\n" && ch !== "	" || code === 127 ? " " : ch;
	}
	return out;
}
/** The ledger's own scrubber. Exported so read-side reports (digest.ts) re-apply the SAME rules instead of a copy. */
function redactLedgerText(value, opts) {
	let out = stripControlChars(value);
	for (const [re, replacement] of EXTRA_SECRET_RULES) out = out.replace(re, replacement);
	out = redactString(out);
	if (opts.entropy) out = out.replace(HIGH_ENTROPY_RUN, (run) => /[A-Z]/.test(run) && /[a-z]/.test(run) && /[0-9]/.test(run) ? "[REDACTED_HIGH_ENTROPY]" : run);
	if (containsSecretPrefix(out)) return "[REDACTED_SECRET]";
	return out;
}
function invalidInput(field) {
	return Object.assign(/* @__PURE__ */ new Error(`ledger_invalid_input:${field}`), {
		code: "ledger_invalid_input",
		field
	});
}
function text(value, field, max, opts) {
	if (typeof value !== "string") throw invalidInput(field);
	const out = redactLedgerText(value, opts).slice(0, max);
	if (!opts.allowEmpty && !out.trim()) throw invalidInput(field);
	return out;
}
function optionalText(value, field, max, entropy) {
	if (value === void 0 || value === null || value === "") return void 0;
	const out = text(value, field, max, {
		entropy,
		allowEmpty: true
	});
	return out === "" ? void 0 : out;
}
function optionalInt(value, field, min, max, round) {
	if (value === void 0 || value === null) return void 0;
	if (typeof value !== "number" || !Number.isFinite(value)) throw invalidInput(field);
	const n = round ? Math.round(value) : value;
	if (!Number.isInteger(n) || n < min || n > max) throw invalidInput(field);
	return n;
}
function cleanCredentialRef(value) {
	if (value === void 0 || value === null || value === "") return void 0;
	if (typeof value === "string" && ENTRY_REF_RE.test(value.trim())) return value.trim();
	const parsed = typeof value === "string" ? parseVaultRef(value) : null;
	if (!parsed || redactLedgerText(parsed.raw, { entropy: false }) !== parsed.raw) {
		log.warn("ledger_credential_ref_rejected", { reason: "not_a_clean_vault_ref" });
		return;
	}
	return parsed.raw;
}
/**
* Whitelist-copy and scrub an input. Throws `ledger_invalid_input:<field>` only
* for structurally wrong values (bad enum, wrong type); secret-looking content
* is redacted, never rejected, so a request is still recorded.
*/
function sanitizeLedgerInput(input) {
	if (!input || typeof input !== "object") throw invalidInput("input");
	if (typeof input.decision !== "string" || !DECISIONS.has(input.decision)) throw invalidInput("decision");
	if (typeof input.tier !== "number" || !TIERS.has(input.tier)) throw invalidInput("tier");
	if (typeof input.result !== "string" || !RESULTS.has(input.result)) throw invalidInput("result");
	const out = {
		client_id: text(input.client_id, "client_id", 256, {
			entropy: false,
			allowEmpty: false
		}),
		capability: text(input.capability, "capability", 256, {
			entropy: false,
			allowEmpty: false
		}),
		resource: text(input.resource, "resource", 1024, {
			entropy: true,
			allowEmpty: true
		}),
		decision: input.decision,
		tier: input.tier,
		result: input.result
	};
	const approvalId = optionalText(input.approval_id, "approval_id", 256, false);
	if (approvalId !== void 0) out.approval_id = approvalId;
	const credentialRef = cleanCredentialRef(input.credential_ref);
	if (credentialRef !== void 0) out.credential_ref = credentialRef;
	const httpStatus = optionalInt(input.http_status, "http_status", 100, 599, false);
	if (httpStatus !== void 0) out.http_status = httpStatus;
	const error = optionalText(input.error, "error", 2e3, true);
	if (error !== void 0) out.error = error;
	const duration = optionalInt(input.duration_ms, "duration_ms", 0, Number.MAX_SAFE_INTEGER, true);
	if (duration !== void 0) out.duration_ms = duration;
	const task = optionalText(input.task, "task", MAX_TASK_LENGTH, true);
	if (task !== void 0) out.task = task;
	if (input.credential_path !== void 0 && input.credential_path !== null) {
		if (typeof input.credential_path !== "string" || !CREDENTIAL_PATHS.has(input.credential_path)) throw invalidInput("credential_path");
		out.credential_path = input.credential_path;
	}
	const fallbackReason = optionalText(input.fallback_reason, "fallback_reason", MAX_FALLBACK_REASON_LENGTH, true);
	if (fallbackReason !== void 0) out.fallback_reason = fallbackReason;
	return out;
}
function hmacKeyBuffer(key) {
	if (key === void 0 || key === null || key === "") return null;
	if (key.length < MIN_HMAC_KEY_LENGTH) throw Object.assign(/* @__PURE__ */ new Error("ledger_hmac_key_too_short"), { code: "ledger_hmac_key_too_short" });
	return Buffer.from(key, "utf8");
}
function backoff(attempt) {
	const ms = Math.min(25, attempt) * Math.random();
	return new Promise((resolve) => setTimeout(resolve, ms));
}
var Ledger = class {
	/** Read access for ledger-anchor.ts (head/scan only; appends go through `append`). */
	store;
	hmacKey;
	now;
	newId;
	queue = Promise.resolve();
	constructor(opts) {
		this.store = opts.store;
		this.hmacKey = hmacKeyBuffer(opts.hmacKey);
		this.now = opts.now ?? Date.now;
		this.newId = opts.newId ?? randomUUID;
	}
	get hmacEnabled() {
		return this.hmacKey !== null;
	}
	append(input) {
		let clean;
		try {
			clean = sanitizeLedgerInput(input);
		} catch (error) {
			return Promise.reject(error);
		}
		const run = this.queue.then(() => this.appendClean(clean));
		this.queue = run.catch(() => void 0);
		return run;
	}
	async appendClean(clean) {
		for (let attempt = 1; attempt <= MAX_APPEND_ATTEMPTS; attempt += 1) {
			const head = await this.store.head();
			const body = {
				...clean,
				seq: head ? head.seq + 1 : 1,
				id: this.newId(),
				timestamp: new Date(this.now()).toISOString(),
				prev_hash: head ? head.hash : GENESIS_PREV_HASH
			};
			const hash = computeLedgerHash(body);
			const stored = {
				...body,
				hash
			};
			if (this.hmacKey) stored.hmac = computeHmac(this.hmacKey, hash);
			if (await this.store.insertIfHead(stored) === "inserted") return publicEntry(stored);
			await backoff(attempt);
		}
		log.error("ledger_append_contention", {
			attempts: MAX_APPEND_ATTEMPTS,
			store: this.store.kind
		});
		throw Object.assign(/* @__PURE__ */ new Error("ledger_append_contention"), { code: "ledger_append_contention" });
	}
	async verify() {
		let expectedSeq = 1;
		let expectedPrev = GENESIS_PREV_HASH;
		let afterSeq = 0;
		for (;;) {
			const batch = await this.store.scanAscending(afterSeq, VERIFY_BATCH);
			if (batch.length === 0) break;
			for (const entry of batch) {
				if (entry.seq !== expectedSeq) return {
					ok: false,
					broken_at_seq: expectedSeq,
					reason: `seq_gap: expected ${expectedSeq}, found ${entry.seq}`
				};
				if (entry.prev_hash !== expectedPrev) return {
					ok: false,
					broken_at_seq: entry.seq,
					reason: "prev_hash_mismatch"
				};
				if (computeLedgerHash(bodyOf(entry)) !== entry.hash) return {
					ok: false,
					broken_at_seq: entry.seq,
					reason: "hash_mismatch"
				};
				if (this.hmacKey) {
					if (!entry.hmac) return {
						ok: false,
						broken_at_seq: entry.seq,
						reason: "hmac_missing"
					};
					if (!hexEqual(entry.hmac, computeHmac(this.hmacKey, entry.hash))) return {
						ok: false,
						broken_at_seq: entry.seq,
						reason: "hmac_mismatch"
					};
				}
				expectedPrev = entry.hash;
				expectedSeq += 1;
				afterSeq = entry.seq;
			}
		}
		return {
			ok: true,
			count: expectedSeq - 1
		};
	}
	async list(opts = {}) {
		const requested = Number.isFinite(opts.limit) ? Math.floor(opts.limit) : DEFAULT_LIST_LIMIT;
		const limit = Math.min(Math.max(requested, 1), MAX_LIST_LIMIT);
		return (await this.store.listNewestFirst({
			limit,
			client_id: opts.client_id || void 0,
			capability: opts.capability || void 0
		})).map(publicEntry);
	}
	/** Entries with seq > afterSeq, ascending, at most `limit` (1..1000). For full-history readers such as digest.ts. */
	async scan(afterSeq, limit = VERIFY_BATCH) {
		const after = Number.isFinite(afterSeq) ? Math.max(0, Math.floor(afterSeq)) : 0;
		const requested = Number.isFinite(limit) ? Math.floor(limit) : VERIFY_BATCH;
		return (await this.store.scanAscending(after, Math.min(Math.max(requested, 1), MAX_LIST_LIMIT))).map(publicEntry);
	}
	head() {
		return this.store.head();
	}
};
var COLUMNS = "seq, id, ts, prev_hash, hash, hmac, client_id, capability, resource, decision, tier, result, approval_id, credential_ref, http_status, error, duration_ms, task, credential_path, fallback_reason";
function rowToEntry(row) {
	const entry = {
		seq: Number(row.seq),
		id: String(row.id),
		timestamp: String(row.ts),
		prev_hash: String(row.prev_hash),
		hash: String(row.hash),
		client_id: String(row.client_id),
		capability: String(row.capability),
		resource: String(row.resource),
		decision: String(row.decision),
		tier: Number(row.tier),
		result: String(row.result)
	};
	if (row.hmac != null) entry.hmac = String(row.hmac);
	if (row.approval_id != null) entry.approval_id = String(row.approval_id);
	if (row.credential_ref != null) entry.credential_ref = String(row.credential_ref);
	if (row.http_status != null) entry.http_status = Number(row.http_status);
	if (row.error != null) entry.error = String(row.error);
	if (row.duration_ms != null) entry.duration_ms = Number(row.duration_ms);
	if (row.task != null) entry.task = String(row.task);
	if (row.credential_path != null) entry.credential_path = String(row.credential_path);
	if (row.fallback_reason != null) entry.fallback_reason = String(row.fallback_reason);
	return entry;
}
async function defaultGetSql() {
	return (await import("./db-YAhc1k3o.mjs")).getSql();
}
/**
* Postgres/PGLite store over `migrations/0003_vault_ledger.sql`. Each append
* is ONE autocommit statement (the shared `Sql` surface has no transactions):
* an INSERT…SELECT guarded by "the head is exactly what I read", plus the
* PRIMARY KEY(seq) / UNIQUE(prev_hash) constraints with ON CONFLICT DO NOTHING.
* Under concurrency the loser blocks on the unique index, inserts nothing,
* gets zero rows back, and the Ledger retries from the new head.
*/
var SqlLedgerStore = class {
	kind = "sql";
	getSql;
	constructor(getSql = defaultGetSql) {
		this.getSql = getSql;
	}
	async head() {
		const row = (await (await this.getSql()).query("SELECT seq, hash FROM vault_ledger ORDER BY seq DESC LIMIT 1"))[0];
		return row ? {
			seq: Number(row.seq),
			hash: String(row.hash)
		} : null;
	}
	async insertIfHead(e) {
		return (await (await this.getSql()).query(`INSERT INTO vault_ledger (${COLUMNS})
       SELECT $1::bigint, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text, $9::text,
              $10::text, $11::smallint, $12::text, $13::text, $14::text, $15::integer, $16::text, $17::bigint,
              $18::text, $19::text, $20::text
       WHERE CASE WHEN $1::bigint = 1
                  THEN $4::text = '${GENESIS_PREV_HASH}' AND NOT EXISTS (SELECT 1 FROM vault_ledger)
                  ELSE EXISTS (SELECT 1 FROM vault_ledger WHERE seq = $1::bigint - 1 AND hash = $4::text)
                       AND NOT EXISTS (SELECT 1 FROM vault_ledger WHERE seq >= $1::bigint)
             END
       ON CONFLICT DO NOTHING
       RETURNING seq`, [
			e.seq,
			e.id,
			e.timestamp,
			e.prev_hash,
			e.hash,
			e.hmac ?? null,
			e.client_id,
			e.capability,
			e.resource,
			e.decision,
			e.tier,
			e.result,
			e.approval_id ?? null,
			e.credential_ref ?? null,
			e.http_status ?? null,
			e.error ?? null,
			e.duration_ms ?? null,
			e.task ?? null,
			e.credential_path ?? null,
			e.fallback_reason ?? null
		])).length === 1 ? "inserted" : "conflict";
	}
	async scanAscending(afterSeq, limit) {
		return (await (await this.getSql()).query(`SELECT ${COLUMNS} FROM vault_ledger WHERE seq > $1::bigint ORDER BY seq ASC LIMIT $2::integer`, [afterSeq, limit])).map(rowToEntry);
	}
	async listNewestFirst(opts) {
		return (await (await this.getSql()).query(`SELECT ${COLUMNS} FROM vault_ledger
       WHERE ($1::text IS NULL OR client_id = $1::text) AND ($2::text IS NULL OR capability = $2::text)
       ORDER BY seq DESC LIMIT $3::integer`, [
			opts.client_id ?? null,
			opts.capability ?? null,
			opts.limit
		])).map(rowToEntry);
	}
};
var defaultLedger = null;
function getDefaultLedger() {
	defaultLedger ??= new Ledger({
		store: new SqlLedgerStore(),
		hmacKey: process.env["ECHO_VAULT_LEDGER_HMAC_KEY"] ?? null
	});
	return defaultLedger;
}
/** The process-wide ledger instance (ledger-anchor.ts verifies and reads its head). */
function getLedger() {
	return getDefaultLedger();
}
async function appendLedger(input) {
	return getDefaultLedger().append(input);
}
async function verifyLedger() {
	return getDefaultLedger().verify();
}
async function listLedger(opts = {}) {
	return getDefaultLedger().list(opts);
}
/** Ascending page of the default ledger (seq > afterSeq). */
async function scanLedger(afterSeq, limit) {
	return getDefaultLedger().scan(afterSeq, limit);
}
/** Current head, for anchoring outside the database (detects tail truncation). */
async function ledgerHead() {
	return getDefaultLedger().head();
}
//#endregion
export { ledgerHead as a, parseVaultRef as c, verifyLedger as d, isProviderId as i, redactLedgerText as l, formatVaultRef as n, ledger_DtKvLmuw_exports as o, getLedger as r, listLedger as s, appendLedger as t, scanLedger as u };
