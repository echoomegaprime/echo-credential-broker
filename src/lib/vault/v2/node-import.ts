// library-first: echo.functions.search → no existing impl found (2026-11-19)
/**
 * Node import: a fleet node pushes the credentials it found on its own disks
 * straight into the vault, after the owner approves that node on Telegram.
 *
 * Why this exists: the importer (import.ts) needs the vault's database and
 * backend, which live on the vault host. Copying the vault's environment to
 * every node, or giving the vault host a shell on every node, would both widen
 * what a single compromise reaches. This channel does neither.
 *
 *   POST /api/import/begin    { node, planned, session_hash, apply, include_generic }
 *        → the owner gets one Telegram prompt naming the node, the count and a
 *          pairing code. Nothing can be submitted until they approve.
 *   POST /api/import/submit   Authorization: Bearer <session secret>
 *                             { approval_id, node, planned, apply, include_generic, items: [...] }
 *        → each item is planned and stored by the same code a local import uses.
 *   POST /api/import/finish   Authorization: Bearer <session secret>, same fields
 *        → closes the session (the approval is consumed).
 *
 * Properties:
 *   - WRITE-ONLY. No route here returns, compares aloud or confirms a secret.
 *     Responses carry labels and status codes.
 *   - The session secret is generated on the node and never leaves it except
 *     as the bearer of its own submissions; the vault stores only its sha256,
 *     inside the approved request digest. A different node, count or mode is a
 *     different digest and is refused.
 *   - One owner decision per node per run, open for at most 30 minutes, capped
 *     at the number of credentials the owner was shown. Every submitted item
 *     spends that budget before it is read, so malformed or repeated items
 *     cannot be used to make the vault hold more than the approved count.
 *   - `begin` is the one unauthenticated call. It is globally rate limited and
 *     fails closed, so it cannot be used to flood the approver.
 *   - Submitted secrets are registered for redaction before anything else
 *     touches them, and never logged.
 */
import { createHash } from "node:crypto";
import { log } from "../log.ts";
import { registerSecretForRedaction } from "../redaction.ts";
import { ApprovalError, checkApproval, consumeApproval, createApproval, sanitizeDisplayText, type ApprovalOptions } from "./approvals.ts";
import { ensureV2Configured } from "./bootstrap.ts";
import type { CardsDeps } from "./cards.ts";
import type { CapabilityRequest, ConsumeResult } from "./contracts.ts";
import { applyImport, planImport, type ImportStatus, type PlannedEntry, type ScanFinding } from "./import.ts";
import { getDefaultRateLimitStore, rateLimitKey, withRateLimitStore, type RateLimitStore } from "./rate-limit-store.ts";

export const IMPORT_CAPABILITY = "vault.entry.import";
export const IMPORT_SESSION_TTL_MS = 30 * 60 * 1000;
export const MAX_PLANNED = 2000;
export const MAX_ITEMS_PER_SUBMIT = 25;
export const MAX_SOURCES_PER_ITEM = 5;
export const MAX_IMPORT_BODY_BYTES = 256 * 1024;
export const MAX_BEGIN_BODY_BYTES = 2048;
/** Import prompts the approver may receive per hour, across all nodes. */
export const MAX_BEGINS_PER_HOUR = 8;
const HOUR_MS = 60 * 60 * 1000;

const NODE_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const BEARER_PATTERN = /^Bearer ([A-Za-z0-9_-]{43,128})$/;
const FINGERPRINT_PATTERN = /^[0-9a-f]{16}$/;
const DETECTOR_PATTERN = /^[a-z0-9_]{1,40}$/;

export interface NodeImportDeps extends CardsDeps {
  approvals?: ApprovalOptions;
  limits?: RateLimitStore;
}

const HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } as const;

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...HEADERS, ...extra } });
}

const refuse = (status: number, error: string, extra: Record<string, string> = {}): Response => json(status, { ok: false, error }, extra);

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** The six characters shown both on the node's terminal and in the owner's prompt. */
export function pairingCode(sessionHash: string): string {
  return sessionHash.slice(0, 6).toUpperCase();
}

interface SessionTerms {
  node: string;
  planned: number;
  apply: boolean;
  include_generic: boolean;
}

/** The exact request the owner approves. Any difference later is a digest mismatch. */
export function importRequest(terms: SessionTerms, sessionHash: string): CapabilityRequest {
  return {
    client: { client_id: `import:${terms.node}`, name: `Node ${terms.node}`, kind: "workload", scopes: [] },
    capability: IMPORT_CAPABILITY,
    resource: `node:${terms.node}`,
    params: { session_hash: sessionHash, planned: terms.planned, apply: terms.apply, include_generic: terms.include_generic },
  };
}

function readTerms(body: Record<string, unknown>): SessionTerms | null {
  const node = typeof body.node === "string" ? body.node.toLowerCase() : "";
  const planned = body.planned;
  if (!NODE_PATTERN.test(node)) return null;
  if (typeof planned !== "number" || !Number.isInteger(planned) || planned < 1 || planned > MAX_PLANNED) return null;
  if (typeof body.apply !== "boolean" || typeof body.include_generic !== "boolean") return null;
  return { node, planned, apply: body.apply, include_generic: body.include_generic };
}

async function readBody(request: Request, maxBytes: number): Promise<Record<string, unknown> | Response> {
  if (request.method.toUpperCase() !== "POST") return refuse(405, "method_not_allowed", { allow: "POST" });
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > maxBytes) return refuse(413, "request_too_large");
  let value: unknown;
  try {
    const buf = Buffer.from(await request.arrayBuffer());
    if (buf.byteLength > maxBytes) return refuse(413, "request_too_large");
    value = JSON.parse(buf.toString("utf8"));
  } catch {
    return refuse(400, "invalid_request");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return refuse(400, "invalid_request");
  return value as Record<string, unknown>;
}

function limitsOf(deps: NodeImportDeps): RateLimitStore {
  return deps.limits ?? getDefaultRateLimitStore();
}

function nowOf(deps: NodeImportDeps): number {
  return (deps.now ?? deps.approvals?.now ?? Date.now)();
}

/** POST /api/import/begin */
export async function handleImportBegin(request: Request, deps: NodeImportDeps = {}): Promise<Response> {
  ensureV2Configured();
  const body = await readBody(request, MAX_BEGIN_BODY_BYTES);
  if (body instanceof Response) return body;
  const terms = readTerms(body);
  const sessionHash = typeof body.session_hash === "string" ? body.session_hash : "";
  if (!terms || !HASH_PATTERN.test(sessionHash)) return refuse(400, "invalid_request");

  // The one unauthenticated call: bounded before anything reaches the approver. Fails closed.
  try {
    const hit = await withRateLimitStore(limitsOf(deps), "hit", (s) =>
      s.hit(rateLimitKey("import.begin", "global"), HOUR_MS, nowOf(deps), MAX_BEGINS_PER_HOUR),
    );
    if (!hit.recorded) return refuse(429, "too_many_import_requests", { "retry-after": "600" });
  } catch {
    return refuse(503, "unavailable");
  }

  const mode = terms.apply ? "store them" : "preview only, nothing stored";
  const summary =
    `Import up to ${terms.planned} credentials found on node ${terms.node} into the vault (${mode}). ` +
    `Pairing code ${pairingCode(sessionHash)}. Write-only: nothing is read back to the node.`;
  try {
    const record = await createApproval(importRequest(terms, sessionHash), summary, {
      ...deps.approvals,
      ttlMs: IMPORT_SESSION_TTL_MS,
      now: deps.approvals?.now ?? deps.now,
      env: deps.approvals?.env ?? deps.env,
    });
    log.info("vault_node_import_requested", { node: terms.node, planned: terms.planned, apply: terms.apply, approval_id: record.id });
    return json(200, {
      ok: true,
      approval_id: record.id,
      expires_at: record.expires_at,
      pairing_code: pairingCode(sessionHash),
    });
  } catch (err) {
    const code = err instanceof ApprovalError ? err.code : "approval_failed";
    log.warn("vault_node_import_begin_failed", { node: terms.node, error: code });
    return refuse(503, /^[a-z0-9_]{1,64}$/.test(code) ? code : "approval_failed");
  }
}

interface Session {
  terms: SessionTerms;
  approvalId: string;
  request: CapabilityRequest;
  body: Record<string, unknown>;
}

const APPROVAL_HTTP: Record<Exclude<ConsumeResult, "ok">, [number, string]> = {
  not_found: [401, "invalid_session"],
  digest_mismatch: [401, "invalid_session"],
  pending: [409, "approval_pending"],
  denied: [403, "approval_denied"],
  expired: [410, "session_expired"],
  already_consumed: [410, "session_closed"],
};

/** Body, bearer, then the session terms the bearer must hash to. No approval lookup yet. */
async function readSession(request: Request): Promise<Session | Response> {
  const body = await readBody(request, MAX_IMPORT_BODY_BYTES);
  if (body instanceof Response) return body;
  const bearer = BEARER_PATTERN.exec(request.headers.get("authorization") ?? "");
  if (!bearer) return refuse(401, "invalid_session");
  const terms = readTerms(body);
  const approvalId = typeof body.approval_id === "string" ? body.approval_id : "";
  if (!terms || !approvalId) return refuse(400, "invalid_request");
  return { terms, approvalId, request: importRequest(terms, sha256Hex(bearer[1])), body };
}

interface SubmittedItem {
  finding: ScanFinding;
  secret: string;
  sources: Array<{ path: string; line: number; detector: string }>;
}

function cleanText(value: unknown, max: number): string {
  return typeof value === "string" ? sanitizeDisplayText(value, max) : "";
}

/** One submitted item → a reference finding plus its secret. Null when malformed. */
function readItem(raw: unknown): SubmittedItem | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.secret !== "string" || r.secret.length === 0 || r.secret.length > 8192) return null;
  registerSecretForRedaction(r.secret);
  if (typeof r.fingerprint !== "string" || !FINGERPRINT_PATTERN.test(r.fingerprint)) return null;
  if (typeof r.detector !== "string" || !DETECTOR_PATTERN.test(r.detector)) return null;
  // Metadata must never carry the secret itself. Checked on the raw text, before any cleaning could mask it.
  if (JSON.stringify([r.provider, r.key_name, r.sources]).includes(JSON.stringify(r.secret).slice(1, -1))) return null;
  const provider = cleanText(r.provider, 80);
  if (!provider) return null;
  const keyName = r.key_name === null || r.key_name === undefined ? null : cleanText(r.key_name, 80) || null;
  const rawSources = Array.isArray(r.sources) ? r.sources.slice(0, MAX_SOURCES_PER_ITEM) : [];
  const sources: SubmittedItem["sources"] = [];
  for (const s of rawSources) {
    if (!s || typeof s !== "object") continue;
    const path = cleanText((s as Record<string, unknown>).path, 400);
    const line = (s as Record<string, unknown>).line;
    if (!path || typeof line !== "number" || !Number.isInteger(line) || line < 1) continue;
    sources.push({ path, line, detector: r.detector });
  }
  if (sources.length === 0) return null;
  return {
    finding: {
      path: sources[0].path,
      file: sources[0].path.split(/[\\/]/).pop(),
      line: sources[0].line,
      detector: r.detector,
      provider,
      key_name: keyName,
      length: r.secret.length,
      fingerprint: r.fingerprint,
    },
    secret: r.secret,
    sources,
  };
}

/** POST /api/import/submit */
export async function handleImportSubmit(request: Request, deps: NodeImportDeps = {}): Promise<Response> {
  ensureV2Configured();
  const session = await readSession(request);
  if (session instanceof Response) return session;
  const { terms, approvalId } = session;

  const rawItems = session.body.items;
  if (!Array.isArray(rawItems) || rawItems.length === 0 || rawItems.length > MAX_ITEMS_PER_SUBMIT) return refuse(400, "invalid_request");

  let state: ConsumeResult;
  try {
    state = await checkApproval(approvalId, session.request, { ...deps.approvals, now: deps.approvals?.now ?? deps.now });
  } catch {
    return refuse(503, "unavailable");
  }
  if (state !== "ok") return refuse(...APPROVAL_HTTP[state]);

  // The owner approved `planned` credentials for this session, not an open door.
  // The budget is taken per submitted item BEFORE the item is read, so a session
  // can never make the vault hold (or register for redaction) more secrets than
  // the approved count — malformed and repeated items spend budget too.
  const accepted: SubmittedItem[] = [];
  let malformed = 0;
  let overPlan = 0;
  const seen = new Set<string>();
  try {
    for (const raw of rawItems) {
      const hit = await withRateLimitStore(limitsOf(deps), "hit", (s) =>
        s.hit(rateLimitKey("import.entries", approvalId), HOUR_MS, nowOf(deps), terms.planned),
      );
      if (!hit.recorded) {
        overPlan++;
        continue;
      }
      const item = readItem(raw);
      if (!item || seen.has(item.finding.fingerprint as string)) {
        malformed++;
        continue;
      }
      seen.add(item.finding.fingerprint as string);
      accepted.push(item);
    }
  } catch {
    return refuse(503, "unavailable");
  }

  const bySecret = new Map(accepted.map((i) => [i.finding.fingerprint as string, i]));
  const plan = planImport(
    { node: terms.node, contains_secret_values: false, findings: accepted.map((i) => i.finding) },
    { includeGeneric: terms.include_generic },
  );
  for (const entry of plan.entries) {
    const item = bySecret.get(entry.scan_fingerprint);
    if (item) entry.sources = item.sources;
  }
  const result = await applyImport(plan, {
    ...deps,
    dryRun: !terms.apply,
    actor: `import:${terms.node}`,
    resolveSecret: async (entry: PlannedEntry) => bySecret.get(entry.scan_fingerprint)?.secret ?? null,
  });

  const skipped: Record<string, number> = {};
  for (const s of plan.skipped) skipped[s.reason] = (skipped[s.reason] ?? 0) + 1;
  log.info("vault_node_import_batch", {
    node: terms.node,
    approval_id: approvalId,
    apply: terms.apply,
    submitted: rawItems.length,
    imported: result.counts.imported,
    malformed,
    over_plan: overPlan,
  });
  return json(200, {
    ok: true,
    dry_run: result.dry_run,
    counts: result.counts satisfies Record<ImportStatus, number>,
    malformed,
    over_plan: overPlan,
    skipped,
    entries: result.outcomes.map((o) => ({ label: o.label, status: o.status })),
  });
}

/** POST /api/import/finish */
export async function handleImportFinish(request: Request, deps: NodeImportDeps = {}): Promise<Response> {
  ensureV2Configured();
  const session = await readSession(request);
  if (session instanceof Response) return session;
  let state: ConsumeResult;
  try {
    state = await consumeApproval(session.approvalId, session.request, { ...deps.approvals, now: deps.approvals?.now ?? deps.now });
  } catch {
    return refuse(503, "unavailable");
  }
  if (state !== "ok") return refuse(...APPROVAL_HTTP[state]);
  log.info("vault_node_import_closed", { node: session.terms.node, approval_id: session.approvalId });
  return json(200, { ok: true, closed: true });
}
