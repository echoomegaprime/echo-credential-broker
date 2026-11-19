import { c as redactString, o as log, u as registerSecretForRedaction } from "./log-BHJOU13W.mjs";
import { a as rateLimitKey, i as getDefaultRateLimitStore, o as withRateLimitStore, r as RateLimitUnavailableError, t as MAX_EVENTS_PER_KEY } from "./rate-limit-store-D2QvwAS2.mjs";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
//#region node_modules/.nitro/vite/services/ssr/assets/approvals-vHr7W1Jg.js
/** Canonical JSON: object keys sorted recursively, no whitespace. Used for digests and hashes. */
function canonicalJson(value) {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	const obj = value;
	return `{${Object.keys(obj).filter((k) => obj[k] !== void 0).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}
/**
* Integration flow (implemented in gateway.ts → dispatchTool):
*   1. identity = authenticate the transport (bearer token → OAuth client; stdio → local).
*   2. decision = evaluatePolicy(req).
*   3. deny → ledger(denied) and refuse.
*      escalate → if args carry `approval_id`, consumeApproval(id, req) must be "ok";
*                 otherwise createApproval(req, summary), ledger(pending_approval),
*                 return { ok:false, error:"approval_required", approval_id, expires_at }.
*      allow → run.
*   4. ledger(result). Return the result with no secret material.
*/
/**
* Vault v2 policy engine — decides allow / escalate / deny for one
* CapabilityRequest. Pure apart from (a) reading the optional policy file named
* by ECHO_VAULT_POLICY_FILE and (b) the shared sliding-window rate limiter
* (state lives in a RateLimitStore — rate-limit-store.ts — so it survives
* restarts and holds across server instances).
*
* `evaluatePolicy` is synchronous and performs steps 1-6 and 8. Step 7 needs
* the store, so it is the separate awaited `enforceRateLimits`;
* `evaluatePolicyWithRateLimits` runs both in order. A caller that uses
* `evaluatePolicy` alone does NOT enforce max_per_hour.
*
* Order of evaluation (first failing step wins):
*   1. request shape            → deny "invalid_request"
*   2. capability registry      → deny "unknown_capability" (reported as tier 3)
*   3. default tier 3           → deny "tier3_human_only"
*   4. per-client rules         → may only make things STRICTER:
*        tier_override raises the tier (never lowers it) or sets "deny"
*        → deny "denied_by_rule" / tier 3 → deny "tier3_human_only"
*   5. scope                    → deny "missing_scope"
*   6. rule resource allowlist  → deny "resource_not_allowed"
*   7. rule max_per_hour        → deny "rate_limited" (a slot is only consumed
*                                  when every other check passed); when the
*                                  store is unreachable → deny
*                                  "rate_limit_unavailable" at EVERY tier,
*                                  tier 0 included (fail closed)
*   8. tier 0/1 → allow, tier 2 → escalate (Telegram approval, approvals.ts)
*
* Scope mapping (documented contract for identity.ts / OAuth grants):
*   required scope = `${namespace}.${access}` where namespace is the first
*   dotted segment of the capability and access is "read" for read
*   capabilities and "write" for everything else. Examples:
*     github.repo.read      → github.read      github.pr.merge     → github.write
*     cloudflare.zone.read  → cloudflare.read  cloudflare.dns.write → cloudflare.write
*     audit.read / verify   → audit.read       vault.list/metadata  → vault.read
*     vault.entry.use.read  → vault.read       vault.entry.use.write → vault.write
*     vault.card.request    → vault.write      <provider>.api.read  → <provider>.read
*     vault.entry.transfer  → vault.write
*     deploy.production     → deploy.write     email.send           → email.write
*   Grantable scopes are oauth-server.ts SUPPORTED_SCOPES; a capability whose
*   scope is not in that list (deploy.*, email.*, payment.*) cannot be reached
*   by any client until the scope is added there.
*   No scope implies another (github.write does NOT imply github.read) and
*   there are no wildcard scopes. The scope is required for tier 2 as well, so
*   a client that was never granted write access cannot page the approver.
*
* github.contents.write is tier 1 only when params.branch (optionally prefixed
* "refs/heads/") matches `agent/*`; any other branch — including a missing
* branch, which GitHub resolves to the default branch — is tier 2.
*
* Globs (rule.capability, rule.resources, tier_override keys): `*` matches any
* run of characters (including "." "/" ":"); everything else is literal and
* matching is case-sensitive.
*/
var AGENT_BRANCH = /^agent\/[A-Za-z0-9._/-]+$/;
function contentsWriteTier(req) {
	const raw = req.params?.branch;
	if (typeof raw !== "string") return 2;
	const branch = raw.startsWith("refs/heads/") ? raw.slice(11) : raw;
	if (branch.includes("..") || branch.endsWith("/") || branch.endsWith(".lock")) return 2;
	return AGENT_BRANCH.test(branch) ? 1 : 2;
}
/** Capability ID → spec. Exact IDs; prefix families are in PREFIX_REGISTRY. */
var CAPABILITY_REGISTRY = Object.freeze({
	"github.repo.read": {
		tier: 0,
		access: "read"
	},
	"github.repo.list": {
		tier: 0,
		access: "read"
	},
	"github.contents.read": {
		tier: 0,
		access: "read"
	},
	"github.user.read": {
		tier: 0,
		access: "read"
	},
	"cloudflare.zone.read": {
		tier: 0,
		access: "read"
	},
	"openai.account.read": {
		tier: 0,
		access: "read"
	},
	"xai.account.read": {
		tier: 0,
		access: "read"
	},
	"stripe.balance.read": {
		tier: 0,
		access: "read"
	},
	"audit.read": {
		tier: 0,
		access: "read"
	},
	"audit.verify": {
		tier: 0,
		access: "read"
	},
	"vault.status": {
		tier: 0,
		access: "read"
	},
	"vault.list": {
		tier: 0,
		access: "read"
	},
	"vault.find": {
		tier: 0,
		access: "read"
	},
	"vault.metadata": {
		tier: 0,
		access: "read"
	},
	"vault.credential.health": {
		tier: 0,
		access: "read"
	},
	"vault.entry.list": {
		tier: 0,
		access: "read"
	},
	"vault.card.status": {
		tier: 0,
		access: "read"
	},
	"vault.approval.status": {
		tier: 0,
		access: "read"
	},
	"vault.entry.use.read": {
		tier: 0,
		access: "read"
	},
	"github.api.read": {
		tier: 0,
		access: "read"
	},
	"cloudflare.api.read": {
		tier: 0,
		access: "read"
	},
	"openai.api.read": {
		tier: 0,
		access: "read"
	},
	"stripe.api.read": {
		tier: 0,
		access: "read"
	},
	"xai.api.read": {
		tier: 0,
		access: "read"
	},
	"github.branch.create": {
		tier: 1,
		access: "write"
	},
	"github.contents.write": {
		tier: 1,
		access: "write",
		resolveTier: contentsWriteTier
	},
	"github.pr.create_draft": {
		tier: 1,
		access: "write"
	},
	"vault.card.request": {
		tier: 1,
		access: "write"
	},
	"github.repo.transfer": {
		tier: 2,
		access: "write"
	},
	"github.pr.merge": {
		tier: 2,
		access: "write"
	},
	"github.repo.delete": {
		tier: 2,
		access: "write"
	},
	"cloudflare.dns.write": {
		tier: 2,
		access: "write"
	},
	"deploy.production": {
		tier: 2,
		access: "write"
	},
	"email.send": {
		tier: 2,
		access: "write"
	},
	"vault.entry.use.write": {
		tier: 2,
		access: "write"
	},
	"vault.entry.inject": {
		tier: 2,
		access: "write"
	},
	"vault.entry.transfer": {
		tier: 2,
		access: "write"
	},
	"github.api.write": {
		tier: 2,
		access: "write"
	},
	"cloudflare.api.write": {
		tier: 2,
		access: "write"
	},
	"openai.api.write": {
		tier: 2,
		access: "write"
	},
	"xai.api.write": {
		tier: 2,
		access: "write"
	},
	"vault.secret.reveal": {
		tier: 3,
		access: "write"
	},
	"vault.policy.write": {
		tier: 3,
		access: "write"
	},
	"vault.client.add": {
		tier: 3,
		access: "write"
	},
	"vault.secret.rotate": {
		tier: 3,
		access: "write"
	},
	"vault.secret.delete": {
		tier: 3,
		access: "write"
	}
});
/** Prefix families: any capability starting with the key (e.g. "payment.refund"). */
var PREFIX_REGISTRY = Object.freeze([["payment.", {
	tier: 3,
	access: "write"
}], ["vault.admin.", {
	tier: 3,
	access: "write"
}]]);
var CAPABILITY_ID = /^[a-z0-9_]+(?:\.[a-z0-9_]+)+$/;
function lookupCapability(capability) {
	if (!CAPABILITY_ID.test(capability)) return void 0;
	if (Object.prototype.hasOwnProperty.call(CAPABILITY_REGISTRY, capability)) return CAPABILITY_REGISTRY[capability];
	for (const [prefix, spec] of PREFIX_REGISTRY) if (capability.startsWith(prefix)) return spec;
}
/** The scope a client must hold for `capability` (see header for the mapping). */
function requiredScope(capability) {
	const spec = lookupCapability(capability);
	if (!spec) return void 0;
	return `${capability.split(".")[0]}.${spec.access}`;
}
/** sha256 hex of canonicalJson({client_id, capability, resource, params}). */
function requestDigest(req) {
	return createHash("sha256").update(canonicalJson({
		client_id: req.client.client_id,
		capability: req.capability,
		resource: req.resource,
		params: req.params ?? {}
	})).digest("hex");
}
var globCache = /* @__PURE__ */ new Map();
function globMatch(glob, value) {
	let re = globCache.get(glob);
	if (!re) {
		const body = glob.split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*");
		re = new RegExp(`^${body}$`, "s");
		if (globCache.size > 1e3) globCache.clear();
		globCache.set(glob, re);
	}
	return re.test(value);
}
var HOUR_MS = 36e5;
/**
* Sliding window over a RateLimitStore (default: the shared SQL store). The
* limiter holds no state, so two instances over one store — two processes, or
* a process before and after a restart — see the same counts.
* Every method rejects with RateLimitUnavailableError when the store fails.
*/
var SlidingWindowRateLimiter = class {
	windowMs;
	store;
	constructor(windowMs = HOUR_MS, store) {
		this.windowMs = windowMs;
		this.store = store;
	}
	backing() {
		return this.store ?? getDefaultRateLimitStore();
	}
	/** Remaining capacity check without recording. */
	async wouldExceed(key, max, now) {
		const { count } = await withRateLimitStore(this.backing(), "count", (s) => s.count(key, this.windowMs, now));
		return count >= Math.min(max, MAX_EVENTS_PER_KEY);
	}
	/** Record unconditionally. */
	async record(key, now) {
		await withRateLimitStore(this.backing(), "hit", (s) => s.hit(key, this.windowMs, now));
	}
	/**
	* Atomically record one event only while fewer than `max` are inside the
	* window. Returns whether it was recorded (false = the limit is reached).
	*/
	async tryRecord(key, max, now) {
		return (await withRateLimitStore(this.backing(), "hit", (s) => s.hit(key, this.windowMs, now, max))).recorded;
	}
	async reset(key) {
		await withRateLimitStore(this.backing(), "reset", (s) => s.reset(key));
	}
};
var defaultLimiter = new SlidingWindowRateLimiter();
/** Store key for one (rule, client) window. Both parts are hashed (rate-limit-store.ts). */
function policyRateLimitKey(ruleId, clientId) {
	return rateLimitKey("policy", ruleId, clientId);
}
var PolicyConfigError = class extends Error {
	constructor(message) {
		super(message);
		this.name = "PolicyConfigError";
	}
};
var RULE_KEYS = /* @__PURE__ */ new Set([
	"id",
	"client_id",
	"capability",
	"resources",
	"max_per_hour",
	"tier_override"
]);
function nonEmptyString(v) {
	return typeof v === "string" && v.trim().length > 0 && v.length <= 512;
}
/** Strict validation: unknown keys are rejected so a typo can never loosen policy. */
function validatePolicyRules(input) {
	let list = input;
	if (list && typeof list === "object" && !Array.isArray(list)) {
		const obj = list;
		for (const key of Object.keys(obj)) if (key !== "version" && key !== "rules") throw new PolicyConfigError(`unknown top-level key "${key}"`);
		if (obj.version !== void 0 && obj.version !== 1) throw new PolicyConfigError("unsupported version");
		list = obj.rules;
	}
	if (!Array.isArray(list)) throw new PolicyConfigError("rules must be an array");
	return list.map((raw, i) => {
		if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new PolicyConfigError(`rule ${i}: not an object`);
		const r = raw;
		for (const key of Object.keys(r)) if (!RULE_KEYS.has(key)) throw new PolicyConfigError(`rule ${i}: unknown key "${key}"`);
		if (!nonEmptyString(r.client_id)) throw new PolicyConfigError(`rule ${i}: client_id required`);
		if (!nonEmptyString(r.capability)) throw new PolicyConfigError(`rule ${i}: capability required`);
		const rule = {
			client_id: r.client_id,
			capability: r.capability
		};
		if (r.id !== void 0) {
			if (!nonEmptyString(r.id)) throw new PolicyConfigError(`rule ${i}: id must be a non-empty string`);
			rule.id = r.id;
		}
		if (r.resources !== void 0) {
			if (!Array.isArray(r.resources) || !r.resources.every(nonEmptyString)) throw new PolicyConfigError(`rule ${i}: resources must be an array of non-empty strings`);
			rule.resources = [...r.resources];
		}
		if (r.max_per_hour !== void 0) {
			if (typeof r.max_per_hour !== "number" || !Number.isInteger(r.max_per_hour) || r.max_per_hour < 0) throw new PolicyConfigError(`rule ${i}: max_per_hour must be a non-negative integer`);
			rule.max_per_hour = r.max_per_hour;
		}
		if (r.tier_override !== void 0) {
			const to = r.tier_override;
			if (!to || typeof to !== "object" || Array.isArray(to)) throw new PolicyConfigError(`rule ${i}: tier_override must be an object`);
			const out = {};
			for (const [k, v] of Object.entries(to)) {
				if (!nonEmptyString(k)) throw new PolicyConfigError(`rule ${i}: tier_override key invalid`);
				if (v !== "deny" && v !== 0 && v !== 1 && v !== 2 && v !== 3) throw new PolicyConfigError(`rule ${i}: tier_override values must be 0-3 or "deny"`);
				out[k] = v;
			}
			rule.tier_override = out;
		}
		return rule;
	});
}
/** Built-in default: no per-client restriction beyond tiers + scopes. */
var DEFAULT_POLICY_RULES = Object.freeze([]);
var fileCache = null;
/**
* Rules from ECHO_VAULT_POLICY_FILE, or the built-in default when unset.
* Throws PolicyConfigError when the file is unreadable or malformed.
*/
function loadPolicyRules(env = process.env) {
	const path = env.ECHO_VAULT_POLICY_FILE?.trim();
	if (!path) return [...DEFAULT_POLICY_RULES];
	let st;
	try {
		st = statSync(path);
	} catch {
		throw new PolicyConfigError("policy file unreadable");
	}
	if (fileCache && fileCache.path === path && fileCache.mtimeMs === st.mtimeMs && fileCache.size === st.size) return fileCache.rules;
	let parsed;
	try {
		parsed = JSON.parse(readFileSync(path, "utf8"));
	} catch {
		throw new PolicyConfigError("policy file is not valid JSON");
	}
	const rules = validatePolicyRules(parsed);
	fileCache = {
		path,
		mtimeMs: st.mtimeMs,
		size: st.size,
		rules
	};
	return rules;
}
function deny(tier, reason, rule_id) {
	return rule_id ? {
		decision: "deny",
		tier,
		reason,
		rule_id
	} : {
		decision: "deny",
		tier,
		reason
	};
}
function isValidRequest(req) {
	return !!req && typeof req === "object" && !!req.client && typeof req.client.client_id === "string" && req.client.client_id.length > 0 && Array.isArray(req.client.scopes) && typeof req.capability === "string" && typeof req.resource === "string" && req.resource.length > 0 && req.resource.length <= 512 && !!req.params && typeof req.params === "object" && !Array.isArray(req.params);
}
function applicableRules(req, activeRules) {
	const clientId = req.client.client_id;
	return activeRules.map((rule, index) => ({
		rule,
		id: rule.id ?? `rule[${index}]`
	})).filter(({ rule }) => (rule.client_id === "*" || rule.client_id === clientId) && globMatch(rule.capability, req.capability));
}
/**
* Steps 1-6 and 8 (synchronous, no I/O beyond the policy file). It does NOT
* apply max_per_hour: pass the result to `enforceRateLimits`, or call
* `evaluatePolicyWithRateLimits`.
*/
function evaluatePolicy(req, rules) {
	if (!isValidRequest(req)) return deny(3, "invalid_request");
	const spec = lookupCapability(req.capability);
	if (!spec) return deny(3, "unknown_capability");
	if (spec.tier === 3) return deny(3, "tier3_human_only");
	let activeRules;
	if (rules) activeRules = rules;
	else try {
		activeRules = loadPolicyRules();
	} catch {
		return deny(3, "policy_unavailable");
	}
	let tier = spec.tier;
	if (spec.resolveTier) {
		const resolved = spec.resolveTier(req);
		if (resolved > tier) tier = resolved;
	}
	let tierRule;
	const applicable = applicableRules(req, activeRules);
	for (const { rule, id } of applicable) {
		if (!rule.tier_override) continue;
		for (const [glob, value] of Object.entries(rule.tier_override)) {
			if (!globMatch(glob, req.capability)) continue;
			if (value === "deny") return deny(3, "denied_by_rule", id);
			if (value > tier) {
				tier = value;
				tierRule = id;
			}
		}
	}
	if (tier === 3) return deny(3, "tier3_human_only", tierRule);
	const scope = requiredScope(req.capability);
	if (!scope || !req.client.scopes.includes(scope)) return deny(tier, "missing_scope", tierRule);
	for (const { rule, id } of applicable) if (rule.resources && !rule.resources.some((g) => globMatch(g, req.resource))) return deny(tier, "resource_not_allowed", id);
	const base = {
		tier,
		...tierRule ? { rule_id: tierRule } : {}
	};
	if (tier === 2) return {
		decision: "escalate",
		reason: "approval_required",
		...base
	};
	return {
		decision: "allow",
		reason: tier === 0 ? "tier0_read" : "tier1_in_scope",
		...base
	};
}
/**
* Step 7: apply every applicable rule's max_per_hour to a decision that passed
* the other checks (a "deny" is returned untouched and consumes nothing).
*
*   - Over the limit            → deny "rate_limited" (rule_id = the rule).
*   - Store unreachable         → deny "rate_limit_unavailable" and log it, at
*     every tier including tier 0 (see docs/ops/rate-limits.md for why).
*   - No applicable max_per_hour → the store is never touched.
*
* All limits are checked first, then one slot per rule is taken atomically
* (`tryRecord`), so concurrent requests — from this or any other process —
* can never take more than `max_per_hour` slots of a rule. If a concurrent
* request takes the last slot between the check and the take, this request is
* denied; slots it already took for EARLIER rules in the list stay consumed
* (only possible with several limited rules, and only errs stricter).
*/
async function enforceRateLimits(req, decision, rules, opts = {}) {
	if (decision.decision === "deny") return decision;
	let activeRules;
	if (rules) activeRules = rules;
	else try {
		activeRules = loadPolicyRules();
	} catch {
		return deny(3, "policy_unavailable");
	}
	const limited = applicableRules(req, activeRules).filter(({ rule }) => rule.max_per_hour !== void 0);
	if (limited.length === 0) return decision;
	const limiter = opts.limiter ?? defaultLimiter;
	const now = (opts.now ?? Date.now)();
	const clientId = req.client.client_id;
	const tier = decision.tier;
	let current = limited[0].id;
	try {
		for (const { rule, id } of limited) {
			current = id;
			if (await limiter.wouldExceed(policyRateLimitKey(id, clientId), rule.max_per_hour, now)) return deny(tier, "rate_limited", id);
		}
		for (const { rule, id } of limited) {
			current = id;
			if (!await limiter.tryRecord(policyRateLimitKey(id, clientId), rule.max_per_hour, now)) return deny(tier, "rate_limited", id);
		}
	} catch (err) {
		if (!(err instanceof RateLimitUnavailableError)) throw err;
		log.error("policy_rate_limit_unavailable", {
			client_id: clientId.slice(0, 64),
			capability: req.capability,
			tier,
			rule_id: current
		});
		return deny(tier, "rate_limit_unavailable", current);
	}
	return decision;
}
var MIN_TTL_MS = 3e4;
var MAX_TTL_MS = 36e5;
var MIN_HMAC_KEY_BYTES = 32;
var MAC_BYTES = 16;
var ID_BYTES = 18;
var ID_PATTERN = /^[A-Za-z0-9_-]{24}$/;
var MAC_PATTERN = /^[A-Za-z0-9_-]{22}$/;
/** Sanitized error: `code` is stable; the message never carries secret or upstream text. */
var ApprovalError = class extends Error {
	code;
	constructor(code, message) {
		super(message);
		this.name = "ApprovalError";
		this.code = code;
	}
};
/** Constant-time string equality (hash first so lengths do not leak). */
function constantTimeEqual(a, b) {
	const ha = createHash("sha256").update(a, "utf8").digest();
	const hb = createHash("sha256").update(b, "utf8").digest();
	return timingSafeEqual(ha, hb);
}
var UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;
/** Strip control/bidi chars, collapse whitespace, redact token-shaped text, cap length. */
function sanitizeDisplayText(input, max = 500) {
	const text = redactString(String(input ?? "")).replace(UNSAFE_CHARS, " ").replace(/\s+/g, " ").trim();
	return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
function readHmacKey(env = process.env) {
	const raw = env.ECHO_VAULT_APPROVAL_HMAC_KEY;
	if (!raw || Buffer.byteLength(raw, "utf8") < MIN_HMAC_KEY_BYTES) throw new ApprovalError("hmac_key_unavailable", "Approval signing key is not configured");
	registerSecretForRedaction(raw);
	return Buffer.from(raw, "utf8");
}
/** Approver's Telegram user ID (also the private chat ID), or null when unset/invalid. */
function approverTelegramId(env = process.env) {
	const raw = env.ECHO_VAULT_APPROVER_TELEGRAM_ID?.trim();
	return raw && /^[1-9][0-9]{0,19}$/.test(raw) ? raw : null;
}
function computeApprovalMac(key, action, id, digest) {
	return createHmac("sha256", key).update(`${action}:${id}:${digest}`, "utf8").digest().subarray(0, MAC_BYTES).toString("base64url");
}
function callbackDataFor(action, id, mac) {
	return `${action === "approve" ? "a" : "d"}:${id}:${mac}`;
}
/** Parse `a:<id>:<mac>` / `d:<id>:<mac>`; null when malformed. */
function parseCallbackData(data) {
	if (typeof data !== "string" || data.length > 64) return null;
	const m = /^([ad]):([A-Za-z0-9_-]{24}):([A-Za-z0-9_-]{22})$/.exec(data);
	if (!m) return null;
	return {
		action: m[1] === "a" ? "approve" : "deny",
		id: m[2],
		mac: m[3]
	};
}
function newApprovalId() {
	return randomBytes(ID_BYTES).toString("base64url");
}
function isExpired(rec, nowMs) {
	const exp = Date.parse(rec.expires_at);
	return !Number.isFinite(exp) || nowMs >= exp;
}
/** Status as of `nowMs`: an unexpired-in-storage pending/approved record past expiry reads as expired. */
function effectiveStatus(rec, nowMs) {
	if ((rec.status === "pending" || rec.status === "approved") && isExpired(rec, nowMs)) return "expired";
	return rec.status;
}
function toIso(v) {
	if (v instanceof Date) return v.toISOString();
	return new Date(String(v)).toISOString();
}
function rowToRecord(row) {
	const rec = {
		id: String(row.id),
		request_digest: String(row.request_digest),
		client_id: String(row.client_id),
		capability: String(row.capability),
		resource: String(row.resource),
		summary: String(row.summary),
		status: String(row.status),
		created_at: toIso(row.created_at),
		expires_at: toIso(row.expires_at)
	};
	if (row.decided_at != null) rec.decided_at = toIso(row.decided_at);
	if (row.decided_by != null) rec.decided_by = String(row.decided_by);
	return rec;
}
var COLUMNS = "id, request_digest, client_id, capability, resource, summary, status, created_at, expires_at, decided_at, decided_by";
/** Postgres/PGlite store over the `vault_approvals` table (migrations/0004_vault_approvals.sql). */
var SqlApprovalStore = class {
	sqlProvider;
	constructor(sqlProvider) {
		this.sqlProvider = sqlProvider ?? (async () => {
			const { getSql } = await import("./db-YAhc1k3o.mjs");
			return getSql();
		});
	}
	async insert(rec) {
		await (await this.sqlProvider()).query(`insert into vault_approvals
         (id, request_digest, client_id, capability, resource, summary, status, created_at, expires_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::timestamptz)`, [
			rec.id,
			rec.request_digest,
			rec.client_id,
			rec.capability,
			rec.resource,
			rec.summary,
			rec.status,
			rec.created_at,
			rec.expires_at
		]);
	}
	async get(id) {
		const rows = await (await this.sqlProvider()).query(`select ${COLUMNS} from vault_approvals where id = $1`, [id]);
		return rows[0] ? rowToRecord(rows[0]) : null;
	}
	async decide(id, status, decidedBy, nowIso) {
		const rows = await (await this.sqlProvider()).query(`update vault_approvals
          set status = $2, decided_at = $4::timestamptz, decided_by = $3
        where id = $1 and status = 'pending' and expires_at > $4::timestamptz
        returning ${COLUMNS}`, [
			id,
			status,
			decidedBy,
			nowIso
		]);
		return rows[0] ? rowToRecord(rows[0]) : null;
	}
	async consume(id, digest, nowIso) {
		return (await (await this.sqlProvider()).query(`update vault_approvals
          set status = 'consumed', consumed_at = $3::timestamptz
        where id = $1 and status = 'approved' and request_digest = $2 and expires_at > $3::timestamptz
        returning id`, [
			id,
			digest,
			nowIso
		])).length === 1;
	}
	async expire(id) {
		await (await this.sqlProvider()).query(`update vault_approvals set status = 'expired' where id = $1 and status in ('pending', 'approved')`, [id]);
	}
};
var defaultStore = null;
/** The process-wide store: SQL (Neon/Postgres or PGlite via getSql) unless replaced. */
function getDefaultApprovalStore() {
	defaultStore ??= new SqlApprovalStore();
	return defaultStore;
}
var productionLedgerSink = async (input) => {
	const { appendLedger } = await import("./ledger-DtKvLmuw.mjs").then((n) => n.o).then((n) => n.i);
	await appendLedger(input);
};
var defaultLedgerSink = productionLedgerSink;
/** Capability of the ledger row that records the owner's tap. */
var APPROVAL_DECISION_CAPABILITY = "vault.approval.decide";
var defaultNotifier = async (input) => {
	const { sendApprovalRequest } = await import("./telegram-B-fJEnsh.mjs").then((n) => n.r).then((n) => n.r);
	await sendApprovalRequest(input, {
		fetch: input.fetch,
		env: input.env
	});
};
function validateForApproval(req) {
	if (!(!!req && !!req.client && typeof req.client.client_id === "string" && req.client.client_id.length > 0 && req.client.client_id.length <= 200 && typeof req.capability === "string" && req.capability.length > 0 && req.capability.length <= 128 && typeof req.resource === "string" && req.resource.length > 0 && req.resource.length <= 512 && !!req.params && typeof req.params === "object" && !Array.isArray(req.params))) throw new ApprovalError("invalid_request", "Approval request is malformed");
}
async function createApproval(req, summary, opts = {}) {
	validateForApproval(req);
	const env = opts.env ?? process.env;
	const key = readHmacKey(env);
	if (!approverTelegramId(env)) throw new ApprovalError("approver_not_configured", "Approver is not configured");
	const store = opts.store ?? getDefaultApprovalStore();
	const nowMs = (opts.now ?? Date.now)();
	const ttl = Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, opts.ttlMs ?? 6e5));
	const record = {
		id: newApprovalId(),
		request_digest: requestDigest(req),
		client_id: req.client.client_id,
		capability: req.capability,
		resource: req.resource,
		summary: sanitizeDisplayText(summary),
		status: "pending",
		created_at: new Date(nowMs).toISOString(),
		expires_at: new Date(nowMs + ttl).toISOString()
	};
	try {
		await store.insert(record);
	} catch (err) {
		log.error("vault_approval_store_failed", {
			approval_id: record.id,
			error: err instanceof ApprovalError ? err.code : "store_error"
		});
		throw new ApprovalError("approval_store_failed", "Approval could not be recorded");
	}
	const approveData = callbackDataFor("approve", record.id, computeApprovalMac(key, "approve", record.id, record.request_digest));
	const denyData = callbackDataFor("deny", record.id, computeApprovalMac(key, "deny", record.id, record.request_digest));
	try {
		await (opts.notify ?? defaultNotifier)({
			record: { ...record },
			clientName: req.client.name,
			approveData,
			denyData,
			fetch: opts.fetch,
			env
		});
	} catch (err) {
		let expired = true;
		try {
			await store.expire(record.id);
		} catch {
			expired = false;
		}
		log.error("vault_approval_notify_failed", {
			approval_id: record.id,
			error: err instanceof Error && "code" in err ? String(err.code) : "notify_error",
			marked_expired: expired
		});
		throw new ApprovalError("approval_notification_failed", "Approval request could not be delivered to the approver");
	}
	log.info("vault_approval_created", {
		approval_id: record.id,
		client_id: record.client_id,
		capability: record.capability,
		expires_at: record.expires_at
	});
	return { ...record };
}
async function getApproval(id, opts = {}) {
	if (typeof id !== "string" || !ID_PATTERN.test(id)) return null;
	const rec = await (opts.store ?? getDefaultApprovalStore()).get(id);
	if (!rec) return null;
	return {
		...rec,
		status: effectiveStatus(rec, (opts.now ?? Date.now)())
	};
}
function mapStatus(status) {
	switch (status) {
		case "consumed": return "already_consumed";
		case "denied": return "denied";
		case "expired": return "expired";
		case "pending": return "pending";
		default: return "already_consumed";
	}
}
/**
* Whether `id` is an approved, unexpired approval of exactly this request —
* WITHOUT consuming it. For a bounded session (node import) that makes several
* calls under one owner decision and then closes it with consumeApproval.
* Same result codes as consumeApproval; "ok" means approved and still open.
*/
async function checkApproval(id, req, opts = {}) {
	if (typeof id !== "string" || !ID_PATTERN.test(id)) return "not_found";
	const store = opts.store ?? getDefaultApprovalStore();
	const nowMs = (opts.now ?? Date.now)();
	const rec = await store.get(id);
	if (!rec) return "not_found";
	if (!constantTimeEqual(rec.request_digest, requestDigest(req))) {
		log.warn("vault_approval_digest_mismatch", {
			approval_id: id,
			client_id: req?.client?.client_id
		});
		return "digest_mismatch";
	}
	const status = effectiveStatus(rec, nowMs);
	return status === "approved" ? "ok" : mapStatus(status);
}
async function consumeApproval(id, req, opts = {}) {
	if (typeof id !== "string" || !ID_PATTERN.test(id)) return "not_found";
	const store = opts.store ?? getDefaultApprovalStore();
	const nowMs = (opts.now ?? Date.now)();
	const rec = await store.get(id);
	if (!rec) return "not_found";
	const digest = requestDigest(req);
	if (!constantTimeEqual(rec.request_digest, digest)) {
		log.warn("vault_approval_digest_mismatch", {
			approval_id: id,
			client_id: req?.client?.client_id
		});
		return "digest_mismatch";
	}
	const status = effectiveStatus(rec, nowMs);
	if (status === "expired" && rec.status !== "expired") await store.expire(id).catch(() => void 0);
	if (status !== "approved") return mapStatus(status);
	if (await store.consume(id, rec.request_digest, new Date(nowMs).toISOString())) {
		log.info("vault_approval_consumed", {
			approval_id: id,
			client_id: rec.client_id
		});
		return "ok";
	}
	const after = await store.get(id);
	if (!after) return "not_found";
	const afterStatus = effectiveStatus(after, nowMs);
	return afterStatus === "approved" ? "expired" : mapStatus(afterStatus);
}
function reject(reason, id, record) {
	log.warn("vault_approval_decision_rejected", {
		reason,
		approval_id: typeof id === "string" && ID_PATTERN.test(id) ? id : "invalid"
	});
	return record ? {
		ok: false,
		reason,
		record
	} : {
		ok: false,
		reason
	};
}
/**
* Record the approver's decision. Only the configured approver, holding a MAC
* minted for this exact (action, id, digest), can move a pending, unexpired
* approval. Every other call is rejected with no state change.
*/
async function decideApproval(id, action, telegramUserId, mac, opts = {}) {
	const env = opts.env ?? process.env;
	if (action !== "approve" && action !== "deny") return reject("invalid_action", id);
	const approver = approverTelegramId(env);
	if (!approver) return reject("approver_not_configured", id);
	if (typeof telegramUserId !== "string" || !constantTimeEqual(telegramUserId, approver)) return reject("unauthorized_user", id);
	let key;
	try {
		key = readHmacKey(env);
	} catch {
		return reject("hmac_key_unavailable", id);
	}
	if (typeof id !== "string" || !ID_PATTERN.test(id)) return reject("not_found", id);
	const store = opts.store ?? getDefaultApprovalStore();
	const rec = await store.get(id);
	if (!rec) return reject("not_found", id);
	const expected = computeApprovalMac(key, action, id, rec.request_digest);
	if (typeof mac !== "string" || !MAC_PATTERN.test(mac) || !constantTimeEqual(mac, expected)) return reject("bad_mac", id);
	const nowMs = (opts.now ?? Date.now)();
	const status = effectiveStatus(rec, nowMs);
	if (status === "expired") {
		if (rec.status !== "expired") await store.expire(id).catch(() => void 0);
		return reject("expired", id, {
			...rec,
			status: "expired"
		});
	}
	if (status !== "pending") return reject("not_pending", id, rec);
	const next = action === "approve" ? "approved" : "denied";
	const sink = opts.ledger ?? defaultLedgerSink;
	const decisionRow = (result, error) => ({
		client_id: "owner:telegram",
		capability: APPROVAL_DECISION_CAPABILITY,
		resource: sanitizeDisplayText(`${rec.capability} ${rec.resource}`, 300),
		decision: action === "approve" ? "allow" : "deny",
		tier: 3,
		result,
		approval_id: id,
		error,
		task: sanitizeDisplayText(`owner ${next} the request of ${rec.client_id}`, 300)
	});
	try {
		await sink(decisionRow(action === "approve" ? "ok" : "denied"));
	} catch {
		log.error("vault_approval_decision_unledgered", { approval_id: id });
		return reject("ledger_unavailable", id, rec);
	}
	const updated = await store.decide(id, next, telegramUserId, new Date(nowMs).toISOString());
	if (!updated) {
		await sink(decisionRow("error", "not_applied")).catch(() => void 0);
		const after = await store.get(id) ?? rec;
		const s = effectiveStatus(after, nowMs);
		return reject(s === "expired" ? "expired" : "not_pending", id, {
			...after,
			status: s
		});
	}
	log.info("vault_approval_decided", {
		approval_id: id,
		status: next
	});
	return {
		ok: true,
		status: next,
		record: updated
	};
}
//#endregion
export { constantTimeEqual as a, decideApproval as c, getApproval as d, lookupCapability as f, sanitizeDisplayText as h, checkApproval as i, enforceRateLimits as l, requiredScope as m, approverTelegramId as n, consumeApproval as o, parseCallbackData as p, canonicalJson as r, createApproval as s, ApprovalError as t, evaluatePolicy as u };
