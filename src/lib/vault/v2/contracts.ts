/**
 * Vault v2 shared contracts. Every v2 module codes against these types.
 *
 * Design: "Agents ask for actions, not secrets." A caller is authenticated
 * (identity.ts), each request is judged by the policy engine
 * (policy-engine.ts), tier-2 requests wait for a request-bound Telegram
 * approval (approvals.ts), the action runs inside the broker with a
 * short-lived credential where possible (github-app.ts), and every request
 * lands in a hash-chained ledger (ledger.ts). No v2 module ever returns,
 * logs, or persists a secret value.
 *
 * Design doc: "ECHO Vault v2 — Agents Use Credentials, Never See Them".
 */

/** 0 read · 1 reversible write in scope · 2 hard to undo / public · 3 never by an agent. */
export type Tier = 0 | 1 | 2 | 3;

export type Decision = "allow" | "escalate" | "deny";

/** An authenticated caller. Never derived from a self-asserted header. */
export interface ClientIdentity {
  /** Stable ID: "oc_<random>" for OAuth clients, "local:<name>" for stdio, "workload:<name>" for node services. */
  client_id: string;
  /** Display name, e.g. "Claude". */
  name: string;
  kind: "oauth" | "local" | "workload";
  /** Granted scopes, e.g. ["github.read", "github.write"]. */
  scopes: string[];
}

/** One requested action. `params` must never contain a secret. */
export interface CapabilityRequest {
  client: ClientIdentity;
  /** Dotted capability ID, e.g. "github.repo.transfer". */
  capability: string;
  /** Canonical resource, e.g. "github:ECHO-OMEGA-PRIME/cleanbrees". */
  resource: string;
  params: Record<string, unknown>;
}

export interface PolicyDecision {
  decision: Decision;
  tier: Tier;
  reason: string;
  rule_id?: string;
}

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired" | "consumed";

export interface ApprovalRecord {
  id: string;
  /** sha256 hex of canonical JSON of {client_id, capability, resource, params}. */
  request_digest: string;
  client_id: string;
  capability: string;
  resource: string;
  /** Human-readable one-liner shown on the phone. No secrets. */
  summary: string;
  status: ApprovalStatus;
  created_at: string;
  expires_at: string;
  decided_at?: string;
  /** Telegram user ID of the approver, as a string. */
  decided_by?: string;
}

export type ConsumeResult =
  | "ok"
  | "not_found"
  | "pending"
  | "denied"
  | "expired"
  | "already_consumed"
  | "digest_mismatch";

export type LedgerResult = "ok" | "error" | "denied" | "pending_approval" | "committing";

export interface LedgerEntryInput {
  client_id: string;
  capability: string;
  resource: string;
  decision: Decision;
  tier: Tier;
  result: LedgerResult;
  approval_id?: string;
  /** A vault:// reference only, never a value. */
  credential_ref?: string;
  http_status?: number;
  error?: string;
  duration_ms?: number;
  /** Why the caller wanted this, in its own words. Redacted, at most 300 chars. Never a secret. */
  task?: string;
  /** How a GitHub action was authorised: a short-lived installation token or the account PAT. */
  credential_path?: "installation" | "pat_fallback";
  /** Why the PAT path was taken (only with credential_path "pat_fallback"). */
  fallback_reason?: string;
}

export interface LedgerEntry extends LedgerEntryInput {
  seq: number;
  id: string;
  timestamp: string;
  prev_hash: string;
  /** sha256 hex over prev_hash + canonical JSON of this entry without `hash`. */
  hash: string;
}

/** Canonical JSON: object keys sorted recursively, no whitespace. Used for digests and hashes. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(",")}}`;
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
