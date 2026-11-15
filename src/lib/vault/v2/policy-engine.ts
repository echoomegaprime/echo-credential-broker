// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 policy engine — decides allow / escalate / deny for one
 * CapabilityRequest. Pure apart from (a) reading the optional policy file named
 * by ECHO_VAULT_POLICY_FILE and (b) an in-process sliding-window rate limiter.
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
 *                                  when every other check passed)
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
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { canonicalJson } from "./contracts.ts";
import type { CapabilityRequest, PolicyDecision, Tier } from "./contracts.ts";

export type Access = "read" | "write";

export interface CapabilitySpec {
  /** Default tier for the capability. */
  tier: Tier;
  access: Access;
  /** Optional request-dependent tier (may only return >= `tier`). */
  resolveTier?: (req: CapabilityRequest) => Tier;
}

export interface PolicyRule {
  /** Optional stable ID reported as PolicyDecision.rule_id; defaults to "rule[<index>]". */
  id?: string;
  /** Exact client_id or "*" for every client. */
  client_id: string;
  /** Capability glob, e.g. "github.repo.*". */
  capability: string;
  /** Resource allowlist globs, e.g. ["github:echoomegaprime/*"]. Absent = no restriction; [] = nothing allowed. */
  resources?: string[];
  /** Max allowed/escalated requests per rolling hour, per (rule, client). */
  max_per_hour?: number;
  /** Capability glob → raised tier or "deny". Lowering is ignored. */
  tier_override?: Record<string, Tier | "deny">;
}

export interface EvaluateOptions {
  /** Clock in epoch ms (tests). Defaults to Date.now. */
  now?: () => number;
  /** Rate limiter (tests). Defaults to the process-wide limiter. */
  limiter?: SlidingWindowRateLimiter;
}

const AGENT_BRANCH = /^agent\/[A-Za-z0-9._/-]+$/;

function contentsWriteTier(req: CapabilityRequest): Tier {
  const raw = req.params?.branch;
  if (typeof raw !== "string") return 2;
  const branch = raw.startsWith("refs/heads/") ? raw.slice("refs/heads/".length) : raw;
  if (branch.includes("..") || branch.endsWith("/") || branch.endsWith(".lock")) return 2;
  return AGENT_BRANCH.test(branch) ? 1 : 2;
}

/** Capability ID → spec. Exact IDs; prefix families are in PREFIX_REGISTRY. */
export const CAPABILITY_REGISTRY: Readonly<Record<string, Readonly<CapabilitySpec>>> = Object.freeze({
  // Tier 0 — read only
  "github.repo.read": { tier: 0, access: "read" },
  "github.repo.list": { tier: 0, access: "read" },
  "github.contents.read": { tier: 0, access: "read" },
  "github.user.read": { tier: 0, access: "read" },
  "cloudflare.zone.read": { tier: 0, access: "read" },
  "openai.account.read": { tier: 0, access: "read" },
  "xai.account.read": { tier: 0, access: "read" },
  "stripe.balance.read": { tier: 0, access: "read" },
  "audit.read": { tier: 0, access: "read" },
  "audit.verify": { tier: 0, access: "read" },
  "vault.status": { tier: 0, access: "read" },
  "vault.list": { tier: 0, access: "read" },
  "vault.find": { tier: 0, access: "read" },
  "vault.metadata": { tier: 0, access: "read" },
  "vault.credential.health": { tier: 0, access: "read" },
  "vault.entry.list": { tier: 0, access: "read" },
  "vault.card.status": { tier: 0, access: "read" },
  "vault.approval.status": { tier: 0, access: "read" },
  // One GET/HEAD to an entry's own site with the secret injected server-side.
  // Tier 0 here; gateway.ts additionally requires the owner's one-time consent
  // per (client, entry) before the first use.
  "vault.entry.use.read": { tier: 0, access: "read" },
  // Generic injecting proxy (credential_use / provider_request), GET/HEAD only.
  "github.api.read": { tier: 0, access: "read" },
  "cloudflare.api.read": { tier: 0, access: "read" },
  "openai.api.read": { tier: 0, access: "read" },
  "stripe.api.read": { tier: 0, access: "read" },
  "xai.api.read": { tier: 0, access: "read" },
  // Tier 1 — reversible writes in scope
  "github.branch.create": { tier: 1, access: "write" },
  "github.contents.write": { tier: 1, access: "write", resolveTier: contentsWriteTier },
  "github.pr.create_draft": { tier: 1, access: "write" },
  // Only messages the operator a single-use card link; nothing is stored
  // unless the human opens it and types the secret (max 5 pending per client).
  "vault.card.request": { tier: 1, access: "write" },
  // Tier 2 — hard to undo or public: human approval
  "github.repo.transfer": { tier: 2, access: "write" },
  "github.pr.merge": { tier: 2, access: "write" },
  "github.repo.delete": { tier: 2, access: "write" },
  "cloudflare.dns.write": { tier: 2, access: "write" },
  "deploy.production": { tier: 2, access: "write" },
  "email.send": { tier: 2, access: "write" },
  // Any non-GET request to an entry's site, and any non-GET through the
  // generic proxy: the broker cannot tell what it does, so a human decides.
  // (Stripe writes are not here: they map to "payment.stripe.write", tier 3.)
  "vault.entry.use.write": { tier: 2, access: "write" },
  "github.api.write": { tier: 2, access: "write" },
  "cloudflare.api.write": { tier: 2, access: "write" },
  "openai.api.write": { tier: 2, access: "write" },
  "xai.api.write": { tier: 2, access: "write" },
  // Tier 3 — never by an agent
  "vault.secret.reveal": { tier: 3, access: "write" },
  "vault.policy.write": { tier: 3, access: "write" },
  "vault.client.add": { tier: 3, access: "write" },
  "vault.secret.rotate": { tier: 3, access: "write" },
  "vault.secret.delete": { tier: 3, access: "write" },
});

/** Prefix families: any capability starting with the key (e.g. "payment.refund"). */
export const PREFIX_REGISTRY: ReadonlyArray<readonly [string, Readonly<CapabilitySpec>]> = Object.freeze([
  ["payment.", { tier: 3, access: "write" }] as const,
  // Owner-only admin surface (manage clients, consent grants, list entries).
  // Tier 3 so the policy engine denies every client; gateway.ts allows ONLY the
  // local stdio identity (the owner's own machine). See dispatchTool.
  ["vault.admin.", { tier: 3, access: "write" }] as const,
]);

const CAPABILITY_ID = /^[a-z0-9_]+(?:\.[a-z0-9_]+)+$/;

export function lookupCapability(capability: string): Readonly<CapabilitySpec> | undefined {
  if (!CAPABILITY_ID.test(capability)) return undefined;
  if (Object.prototype.hasOwnProperty.call(CAPABILITY_REGISTRY, capability)) {
    return CAPABILITY_REGISTRY[capability];
  }
  for (const [prefix, spec] of PREFIX_REGISTRY) {
    if (capability.startsWith(prefix)) return spec;
  }
  return undefined;
}

/** The scope a client must hold for `capability` (see header for the mapping). */
export function requiredScope(capability: string): string | undefined {
  const spec = lookupCapability(capability);
  if (!spec) return undefined;
  return `${capability.split(".")[0]}.${spec.access}`;
}

/** sha256 hex of canonicalJson({client_id, capability, resource, params}). */
export function requestDigest(req: CapabilityRequest): string {
  return createHash("sha256")
    .update(
      canonicalJson({
        client_id: req.client.client_id,
        capability: req.capability,
        resource: req.resource,
        params: req.params ?? {},
      }),
    )
    .digest("hex");
}

// ---------------------------------------------------------------- globbing

const globCache = new Map<string, RegExp>();

export function globMatch(glob: string, value: string): boolean {
  let re = globCache.get(glob);
  if (!re) {
    const body = glob
      .split("*")
      .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join(".*");
    re = new RegExp(`^${body}$`, "s");
    if (globCache.size > 1000) globCache.clear();
    globCache.set(glob, re);
  }
  return re.test(value);
}

// ------------------------------------------------------------ rate limiting

const HOUR_MS = 60 * 60 * 1000;

/** In-process sliding window. Not shared across instances/processes. */
export class SlidingWindowRateLimiter {
  private readonly hits = new Map<string, number[]>();
  private readonly windowMs: number;

  constructor(windowMs: number = HOUR_MS) {
    this.windowMs = windowMs;
  }

  /** Remaining capacity check without recording. */
  wouldExceed(key: string, max: number, now: number): boolean {
    return this.prune(key, now).length >= max;
  }

  record(key: string, now: number): void {
    const list = this.prune(key, now);
    list.push(now);
    this.hits.set(key, list);
  }

  reset(): void {
    this.hits.clear();
  }

  private prune(key: string, now: number): number[] {
    const cutoff = now - this.windowMs;
    const list = (this.hits.get(key) ?? []).filter((t) => t > cutoff);
    if (list.length) this.hits.set(key, list);
    else this.hits.delete(key);
    return list;
  }
}

const defaultLimiter = new SlidingWindowRateLimiter();

/** Test hook: clear the process-wide limiter. */
export function resetRateLimits(): void {
  defaultLimiter.reset();
}

// ------------------------------------------------------------ policy file

export class PolicyConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyConfigError";
  }
}

const RULE_KEYS = new Set(["id", "client_id", "capability", "resources", "max_per_hour", "tier_override"]);

function nonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0 && v.length <= 512;
}

/** Strict validation: unknown keys are rejected so a typo can never loosen policy. */
export function validatePolicyRules(input: unknown): PolicyRule[] {
  let list: unknown = input;
  if (list && typeof list === "object" && !Array.isArray(list)) {
    const obj = list as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      if (key !== "version" && key !== "rules") throw new PolicyConfigError(`unknown top-level key "${key}"`);
    }
    if (obj.version !== undefined && obj.version !== 1) throw new PolicyConfigError("unsupported version");
    list = obj.rules;
  }
  if (!Array.isArray(list)) throw new PolicyConfigError("rules must be an array");
  return list.map((raw, i): PolicyRule => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new PolicyConfigError(`rule ${i}: not an object`);
    const r = raw as Record<string, unknown>;
    for (const key of Object.keys(r)) {
      if (!RULE_KEYS.has(key)) throw new PolicyConfigError(`rule ${i}: unknown key "${key}"`);
    }
    if (!nonEmptyString(r.client_id)) throw new PolicyConfigError(`rule ${i}: client_id required`);
    if (!nonEmptyString(r.capability)) throw new PolicyConfigError(`rule ${i}: capability required`);
    const rule: PolicyRule = { client_id: r.client_id, capability: r.capability };
    if (r.id !== undefined) {
      if (!nonEmptyString(r.id)) throw new PolicyConfigError(`rule ${i}: id must be a non-empty string`);
      rule.id = r.id;
    }
    if (r.resources !== undefined) {
      if (!Array.isArray(r.resources) || !r.resources.every(nonEmptyString)) {
        throw new PolicyConfigError(`rule ${i}: resources must be an array of non-empty strings`);
      }
      rule.resources = [...(r.resources as string[])];
    }
    if (r.max_per_hour !== undefined) {
      if (typeof r.max_per_hour !== "number" || !Number.isInteger(r.max_per_hour) || r.max_per_hour < 0) {
        throw new PolicyConfigError(`rule ${i}: max_per_hour must be a non-negative integer`);
      }
      rule.max_per_hour = r.max_per_hour;
    }
    if (r.tier_override !== undefined) {
      const to = r.tier_override;
      if (!to || typeof to !== "object" || Array.isArray(to)) {
        throw new PolicyConfigError(`rule ${i}: tier_override must be an object`);
      }
      const out: Record<string, Tier | "deny"> = {};
      for (const [k, v] of Object.entries(to as Record<string, unknown>)) {
        if (!nonEmptyString(k)) throw new PolicyConfigError(`rule ${i}: tier_override key invalid`);
        if (v !== "deny" && v !== 0 && v !== 1 && v !== 2 && v !== 3) {
          throw new PolicyConfigError(`rule ${i}: tier_override values must be 0-3 or "deny"`);
        }
        out[k] = v;
      }
      rule.tier_override = out;
    }
    return rule;
  });
}

/** Built-in default: no per-client restriction beyond tiers + scopes. */
export const DEFAULT_POLICY_RULES: readonly PolicyRule[] = Object.freeze([]);

let fileCache: { path: string; mtimeMs: number; size: number; rules: PolicyRule[] } | null = null;

/**
 * Rules from ECHO_VAULT_POLICY_FILE, or the built-in default when unset.
 * Throws PolicyConfigError when the file is unreadable or malformed.
 */
export function loadPolicyRules(env: NodeJS.ProcessEnv = process.env): PolicyRule[] {
  const path = env.ECHO_VAULT_POLICY_FILE?.trim();
  if (!path) return [...DEFAULT_POLICY_RULES];
  let st;
  try {
    st = statSync(path);
  } catch {
    throw new PolicyConfigError("policy file unreadable");
  }
  if (fileCache && fileCache.path === path && fileCache.mtimeMs === st.mtimeMs && fileCache.size === st.size) {
    return fileCache.rules;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new PolicyConfigError("policy file is not valid JSON");
  }
  const rules = validatePolicyRules(parsed);
  fileCache = { path, mtimeMs: st.mtimeMs, size: st.size, rules };
  return rules;
}

// ------------------------------------------------------------ evaluation

function deny(tier: Tier, reason: string, rule_id?: string): PolicyDecision {
  return rule_id ? { decision: "deny", tier, reason, rule_id } : { decision: "deny", tier, reason };
}

function isValidRequest(req: CapabilityRequest): boolean {
  return (
    !!req &&
    typeof req === "object" &&
    !!req.client &&
    typeof req.client.client_id === "string" &&
    req.client.client_id.length > 0 &&
    Array.isArray(req.client.scopes) &&
    typeof req.capability === "string" &&
    typeof req.resource === "string" &&
    req.resource.length > 0 &&
    req.resource.length <= 512 &&
    !!req.params &&
    typeof req.params === "object" &&
    !Array.isArray(req.params)
  );
}

export function evaluatePolicy(
  req: CapabilityRequest,
  rules?: PolicyRule[],
  opts: EvaluateOptions = {},
): PolicyDecision {
  if (!isValidRequest(req)) return deny(3, "invalid_request");

  const spec = lookupCapability(req.capability);
  if (!spec) return deny(3, "unknown_capability");
  if (spec.tier === 3) return deny(3, "tier3_human_only");

  let activeRules: PolicyRule[];
  if (rules) {
    activeRules = rules;
  } else {
    try {
      activeRules = loadPolicyRules();
    } catch {
      // Fail closed: a broken policy file denies everything.
      return deny(3, "policy_unavailable");
    }
  }

  let tier: Tier = spec.tier;
  if (spec.resolveTier) {
    const resolved = spec.resolveTier(req);
    if (resolved > tier) tier = resolved;
  }
  let tierRule: string | undefined;

  const clientId = req.client.client_id;
  const applicable = activeRules
    .map((rule, index) => ({ rule, id: rule.id ?? `rule[${index}]` }))
    .filter(
      ({ rule }) =>
        (rule.client_id === "*" || rule.client_id === clientId) && globMatch(rule.capability, req.capability),
    );

  // Tier overrides: raise-only.
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

  for (const { rule, id } of applicable) {
    if (rule.resources && !rule.resources.some((g) => globMatch(g, req.resource))) {
      return deny(tier, "resource_not_allowed", id);
    }
  }

  const limiter = opts.limiter ?? defaultLimiter;
  const now = (opts.now ?? Date.now)();
  const limited = applicable.filter(({ rule }) => rule.max_per_hour !== undefined);
  for (const { rule, id } of limited) {
    if (limiter.wouldExceed(`${id}\u0000${clientId}`, rule.max_per_hour as number, now)) {
      return deny(tier, "rate_limited", id);
    }
  }
  for (const { id } of limited) limiter.record(`${id}\u0000${clientId}`, now);

  const base = { tier, ...(tierRule ? { rule_id: tierRule } : {}) };
  if (tier === 2) return { decision: "escalate", reason: "approval_required", ...base };
  return { decision: "allow", reason: tier === 0 ? "tier0_read" : "tier1_in_scope", ...base };
}
