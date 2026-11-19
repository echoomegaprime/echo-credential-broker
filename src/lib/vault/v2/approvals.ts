// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 approvals — request-bound, single-use, human approvals over Telegram.
 *
 *   createApproval(req, summary)  stores a `pending` record bound to
 *                                 requestDigest(req) and DMs the approver an
 *                                 [Approve] [Deny] inline keyboard.
 *   decideApproval(...)           called by the Telegram webhook: MAC + approver
 *                                 identity + pending + unexpired → approved/denied.
 *   decideApprovalAsService(...)  the second decider: Lyra's consent bridge,
 *                                 authenticated by its own service token, may
 *                                 decide connection + first-use approvals only;
 *                                 decisions are recorded as
 *                                 client_id "service:lyra-consent-bridge".
 *   consumeApproval(id, req)      approved → consumed exactly once, only for the
 *                                 identical request, only before expiry.
 *
 * Callback data (Telegram limit 1-64 bytes): `a:<id>:<mac>` / `d:<id>:<mac>`
 *   id  = 18 random bytes, base64url (24 chars, 144 bits)
 *   mac = first 16 bytes of HMAC-SHA256(key, `${action}:${id}:${request_digest}`),
 *         base64url (22 chars); action is "approve" or "deny".
 *   Total 49 bytes.
 *
 * Nothing secret is stored: the table holds the digest (not params), the
 * capability, the resource and a sanitized human summary. The HMAC key lives
 * only in ECHO_VAULT_APPROVAL_HMAC_KEY and is registered for redaction.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { log } from "../log.ts";
import { redactString, registerSecretForRedaction } from "../redaction.ts";
import type { ApprovalRecord, ApprovalStatus, CapabilityRequest, ConsumeResult, LedgerEntryInput } from "./contracts.ts";
import { requestDigest } from "./policy-engine.ts";
import type { Sql } from "../../db.ts";

export type ApprovalAction = "approve" | "deny";

export const DEFAULT_APPROVAL_TTL_MS = 10 * 60 * 1000;
const MIN_TTL_MS = 30 * 1000;
const MAX_TTL_MS = 60 * 60 * 1000;
export const MAX_SUMMARY_LENGTH = 500;
const MIN_HMAC_KEY_BYTES = 32;
const MAC_BYTES = 16;
const ID_BYTES = 18;
const ID_PATTERN = /^[A-Za-z0-9_-]{24}$/;
const MAC_PATTERN = /^[A-Za-z0-9_-]{22}$/;

/** Sanitized error: `code` is stable; the message never carries secret or upstream text. */
export class ApprovalError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ApprovalError";
    this.code = code;
  }
}

// ------------------------------------------------------------------ helpers

/** Constant-time string equality (hash first so lengths do not leak). */
export function constantTimeEqual(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a, "utf8").digest();
  const hb = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(ha, hb);
}

// C0/C1 controls, plus bidi overrides/isolates and zero-width chars that could
// make the approver read something other than what is stored.
// eslint-disable-next-line no-control-regex -- stripping control characters is the point
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;

/** Strip control/bidi chars, collapse whitespace, redact token-shaped text, cap length. */
export function sanitizeDisplayText(input: unknown, max: number = MAX_SUMMARY_LENGTH): string {
  const text = redactString(String(input ?? ""))
    .replace(UNSAFE_CHARS, " ")
    .replace(/\s+/g, " ")
    .trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function readHmacKey(env: NodeJS.ProcessEnv = process.env): Buffer {
  const raw = env.ECHO_VAULT_APPROVAL_HMAC_KEY;
  if (!raw || Buffer.byteLength(raw, "utf8") < MIN_HMAC_KEY_BYTES) {
    throw new ApprovalError("hmac_key_unavailable", "Approval signing key is not configured");
  }
  registerSecretForRedaction(raw);
  return Buffer.from(raw, "utf8");
}

/** Approver's Telegram user ID (also the private chat ID), or null when unset/invalid. */
export function approverTelegramId(env: NodeJS.ProcessEnv = process.env): string | null {
  const raw = env.ECHO_VAULT_APPROVER_TELEGRAM_ID?.trim();
  return raw && /^[1-9][0-9]{0,19}$/.test(raw) ? raw : null;
}

export function computeApprovalMac(key: Buffer, action: ApprovalAction, id: string, digest: string): string {
  return createHmac("sha256", key)
    .update(`${action}:${id}:${digest}`, "utf8")
    .digest()
    .subarray(0, MAC_BYTES)
    .toString("base64url");
}

export function callbackDataFor(action: ApprovalAction, id: string, mac: string): string {
  return `${action === "approve" ? "a" : "d"}:${id}:${mac}`;
}

/** Parse `a:<id>:<mac>` / `d:<id>:<mac>`; null when malformed. */
export function parseCallbackData(data: unknown): { action: ApprovalAction; id: string; mac: string } | null {
  if (typeof data !== "string" || data.length > 64) return null;
  const m = /^([ad]):([A-Za-z0-9_-]{24}):([A-Za-z0-9_-]{22})$/.exec(data);
  if (!m) return null;
  return { action: m[1] === "a" ? "approve" : "deny", id: m[2], mac: m[3] };
}

function newApprovalId(): string {
  return randomBytes(ID_BYTES).toString("base64url");
}

function isExpired(rec: ApprovalRecord, nowMs: number): boolean {
  const exp = Date.parse(rec.expires_at);
  return !Number.isFinite(exp) || nowMs >= exp;
}

/** Status as of `nowMs`: an unexpired-in-storage pending/approved record past expiry reads as expired. */
export function effectiveStatus(rec: ApprovalRecord, nowMs: number): ApprovalStatus {
  if ((rec.status === "pending" || rec.status === "approved") && isExpired(rec, nowMs)) return "expired";
  return rec.status;
}

// ------------------------------------------------------------------ storage

export interface ApprovalStore {
  insert(rec: ApprovalRecord): Promise<void>;
  get(id: string): Promise<ApprovalRecord | null>;
  /** Atomically pending → approved|denied iff pending and expires_at > nowIso. Returns the new record or null. */
  decide(id: string, status: "approved" | "denied", decidedBy: string, nowIso: string): Promise<ApprovalRecord | null>;
  /** Atomically approved → consumed iff approved, digest equal and expires_at > nowIso. True when this call won. */
  consume(id: string, digest: string, nowIso: string): Promise<boolean>;
  /** pending|approved → expired (no-op otherwise). */
  expire(id: string): Promise<void>;
}

/** In-memory store (tests / single process). Every mutation is a synchronous check-and-set. */
export class MemoryApprovalStore implements ApprovalStore {
  private readonly rows = new Map<string, ApprovalRecord>();

  async insert(rec: ApprovalRecord): Promise<void> {
    if (this.rows.has(rec.id)) throw new ApprovalError("duplicate_id", "Approval ID collision");
    this.rows.set(rec.id, { ...rec });
  }

  async get(id: string): Promise<ApprovalRecord | null> {
    const rec = this.rows.get(id);
    return rec ? { ...rec } : null;
  }

  async decide(
    id: string,
    status: "approved" | "denied",
    decidedBy: string,
    nowIso: string,
  ): Promise<ApprovalRecord | null> {
    const rec = this.rows.get(id);
    if (!rec || rec.status !== "pending" || Date.parse(rec.expires_at) <= Date.parse(nowIso)) return null;
    rec.status = status;
    rec.decided_at = nowIso;
    rec.decided_by = decidedBy;
    return { ...rec };
  }

  async consume(id: string, digest: string, nowIso: string): Promise<boolean> {
    const rec = this.rows.get(id);
    if (!rec || rec.status !== "approved" || rec.request_digest !== digest) return false;
    if (Date.parse(rec.expires_at) <= Date.parse(nowIso)) return false;
    rec.status = "consumed";
    return true;
  }

  async expire(id: string): Promise<void> {
    const rec = this.rows.get(id);
    if (rec && (rec.status === "pending" || rec.status === "approved")) rec.status = "expired";
  }

  /** Test helper. */
  size(): number {
    return this.rows.size;
  }
}

function toIso(v: unknown): string {
  if (v instanceof Date) return v.toISOString();
  return new Date(String(v)).toISOString();
}

function rowToRecord(row: Record<string, unknown>): ApprovalRecord {
  const rec: ApprovalRecord = {
    id: String(row.id),
    request_digest: String(row.request_digest),
    client_id: String(row.client_id),
    capability: String(row.capability),
    resource: String(row.resource),
    summary: String(row.summary),
    status: String(row.status) as ApprovalStatus,
    created_at: toIso(row.created_at),
    expires_at: toIso(row.expires_at),
  };
  if (row.decided_at != null) rec.decided_at = toIso(row.decided_at);
  if (row.decided_by != null) rec.decided_by = String(row.decided_by);
  return rec;
}

const COLUMNS =
  "id, request_digest, client_id, capability, resource, summary, status, created_at, expires_at, decided_at, decided_by";

/** Postgres/PGlite store over the `vault_approvals` table (migrations/0004_vault_approvals.sql). */
export class SqlApprovalStore implements ApprovalStore {
  private readonly sqlProvider: () => Promise<Sql>;

  constructor(sqlProvider?: () => Promise<Sql>) {
    this.sqlProvider =
      sqlProvider ??
      (async () => {
        const { getSql } = await import("../../db.ts");
        return getSql();
      });
  }

  async insert(rec: ApprovalRecord): Promise<void> {
    const sql = await this.sqlProvider();
    await sql.query(
      `insert into vault_approvals
         (id, request_digest, client_id, capability, resource, summary, status, created_at, expires_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::timestamptz)`,
      [
        rec.id,
        rec.request_digest,
        rec.client_id,
        rec.capability,
        rec.resource,
        rec.summary,
        rec.status,
        rec.created_at,
        rec.expires_at,
      ],
    );
  }

  async get(id: string): Promise<ApprovalRecord | null> {
    const sql = await this.sqlProvider();
    const rows = await sql.query(`select ${COLUMNS} from vault_approvals where id = $1`, [id]);
    return rows[0] ? rowToRecord(rows[0]) : null;
  }

  async decide(
    id: string,
    status: "approved" | "denied",
    decidedBy: string,
    nowIso: string,
  ): Promise<ApprovalRecord | null> {
    const sql = await this.sqlProvider();
    const rows = await sql.query(
      `update vault_approvals
          set status = $2, decided_at = $4::timestamptz, decided_by = $3
        where id = $1 and status = 'pending' and expires_at > $4::timestamptz
        returning ${COLUMNS}`,
      [id, status, decidedBy, nowIso],
    );
    return rows[0] ? rowToRecord(rows[0]) : null;
  }

  async consume(id: string, digest: string, nowIso: string): Promise<boolean> {
    const sql = await this.sqlProvider();
    const rows = await sql.query(
      `update vault_approvals
          set status = 'consumed', consumed_at = $3::timestamptz
        where id = $1 and status = 'approved' and request_digest = $2 and expires_at > $3::timestamptz
        returning id`,
      [id, digest, nowIso],
    );
    return rows.length === 1;
  }

  async expire(id: string): Promise<void> {
    const sql = await this.sqlProvider();
    await sql.query(
      `update vault_approvals set status = 'expired' where id = $1 and status in ('pending', 'approved')`,
      [id],
    );
  }
}

let defaultStore: ApprovalStore | null = null;

/** The process-wide store: SQL (Neon/Postgres or PGlite via getSql) unless replaced. */
export function getDefaultApprovalStore(): ApprovalStore {
  defaultStore ??= new SqlApprovalStore();
  return defaultStore;
}

/** Wiring/test hook. Pass null to restore the SQL default. */
export function setDefaultApprovalStore(store: ApprovalStore | null): void {
  defaultStore = store;
}

// ------------------------------------------------------------------ service

/** Delivers the approval prompt. Default: Telegram sendMessage (telegram.ts). */
export type ApprovalNotifier = (input: {
  record: ApprovalRecord;
  clientName: string;
  approveData: string;
  denyData: string;
  fetch?: typeof fetch;
  env?: NodeJS.ProcessEnv;
}) => Promise<void>;

export interface ApprovalOptions {
  store?: ApprovalStore;
  /** Injected into the default Telegram notifier. */
  fetch?: typeof fetch;
  /** Replace the notifier entirely. */
  notify?: ApprovalNotifier;
  /** Epoch-ms clock. */
  now?: () => number;
  /** Expiry; clamped to [30s, 1h]. Default 10 minutes. */
  ttlMs?: number;
  env?: NodeJS.ProcessEnv;
  /** Ledger sink for the owner's decision. Default: the process-wide sink (the hash-chained ledger). */
  ledger?: ApprovalLedgerSink;
}

/** Appends one row to the audit ledger; throws when it cannot be written. */
export type ApprovalLedgerSink = (input: LedgerEntryInput) => Promise<unknown>;

const productionLedgerSink: ApprovalLedgerSink = async (input) => {
  const { appendLedger } = await import("./ledger.ts");
  await appendLedger(input);
};
let defaultLedgerSink: ApprovalLedgerSink = productionLedgerSink;

/** Replace the process-wide decision sink (tests); null restores the real ledger. */
export function setDefaultApprovalLedgerSink(sink: ApprovalLedgerSink | null): void {
  defaultLedgerSink = sink ?? productionLedgerSink;
}

/** Capability of the ledger row that records the owner's tap. */
export const APPROVAL_DECISION_CAPABILITY = "vault.approval.decide";

const defaultNotifier: ApprovalNotifier = async (input) => {
  const { sendApprovalRequest } = await import("./telegram.ts");
  await sendApprovalRequest(input, { fetch: input.fetch, env: input.env });
};

function validateForApproval(req: CapabilityRequest): void {
  const ok =
    !!req &&
    !!req.client &&
    typeof req.client.client_id === "string" &&
    req.client.client_id.length > 0 &&
    req.client.client_id.length <= 200 &&
    typeof req.capability === "string" &&
    req.capability.length > 0 &&
    req.capability.length <= 128 &&
    typeof req.resource === "string" &&
    req.resource.length > 0 &&
    req.resource.length <= 512 &&
    !!req.params &&
    typeof req.params === "object" &&
    !Array.isArray(req.params);
  if (!ok) throw new ApprovalError("invalid_request", "Approval request is malformed");
}

export async function createApproval(
  req: CapabilityRequest,
  summary: string,
  opts: ApprovalOptions = {},
): Promise<ApprovalRecord> {
  validateForApproval(req);
  const env = opts.env ?? process.env;
  // Fail closed before anything is stored.
  const key = readHmacKey(env);
  if (!approverTelegramId(env)) {
    throw new ApprovalError("approver_not_configured", "Approver is not configured");
  }

  const store = opts.store ?? getDefaultApprovalStore();
  const nowMs = (opts.now ?? Date.now)();
  const ttl = Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, opts.ttlMs ?? DEFAULT_APPROVAL_TTL_MS));
  const record: ApprovalRecord = {
    id: newApprovalId(),
    request_digest: requestDigest(req),
    client_id: req.client.client_id,
    capability: req.capability,
    resource: req.resource,
    summary: sanitizeDisplayText(summary),
    status: "pending",
    created_at: new Date(nowMs).toISOString(),
    expires_at: new Date(nowMs + ttl).toISOString(),
  };

  try {
    await store.insert(record);
  } catch (err) {
    log.error("vault_approval_store_failed", {
      approval_id: record.id,
      error: err instanceof ApprovalError ? err.code : "store_error",
    });
    throw new ApprovalError("approval_store_failed", "Approval could not be recorded");
  }

  const approveData = callbackDataFor(
    "approve",
    record.id,
    computeApprovalMac(key, "approve", record.id, record.request_digest),
  );
  const denyData = callbackDataFor("deny", record.id, computeApprovalMac(key, "deny", record.id, record.request_digest));

  try {
    await (opts.notify ?? defaultNotifier)({
      record: { ...record },
      clientName: req.client.name,
      approveData,
      denyData,
      fetch: opts.fetch,
      env,
    });
  } catch (err) {
    // Never leave a usable approval behind when the approver was not reached.
    let expired = true;
    try {
      await store.expire(record.id);
    } catch {
      expired = false;
    }
    log.error("vault_approval_notify_failed", {
      approval_id: record.id,
      error: err instanceof Error && "code" in err ? String((err as { code: unknown }).code) : "notify_error",
      marked_expired: expired,
    });
    throw new ApprovalError("approval_notification_failed", "Approval request could not be delivered to the approver");
  }

  log.info("vault_approval_created", {
    approval_id: record.id,
    client_id: record.client_id,
    capability: record.capability,
    expires_at: record.expires_at,
  });
  return { ...record };
}

export async function getApproval(id: string, opts: ApprovalOptions = {}): Promise<ApprovalRecord | null> {
  if (typeof id !== "string" || !ID_PATTERN.test(id)) return null;
  const rec = await (opts.store ?? getDefaultApprovalStore()).get(id);
  if (!rec) return null;
  return { ...rec, status: effectiveStatus(rec, (opts.now ?? Date.now)()) };
}

function mapStatus(status: ApprovalStatus): ConsumeResult {
  switch (status) {
    case "consumed":
      return "already_consumed";
    case "denied":
      return "denied";
    case "expired":
      return "expired";
    case "pending":
      return "pending";
    default:
      return "already_consumed";
  }
}

/**
 * Whether `id` is an approved, unexpired approval of exactly this request —
 * WITHOUT consuming it. For a bounded session (node import) that makes several
 * calls under one owner decision and then closes it with consumeApproval.
 * Same result codes as consumeApproval; "ok" means approved and still open.
 */
export async function checkApproval(
  id: string,
  req: CapabilityRequest,
  opts: ApprovalOptions = {},
): Promise<ConsumeResult> {
  if (typeof id !== "string" || !ID_PATTERN.test(id)) return "not_found";
  const store = opts.store ?? getDefaultApprovalStore();
  const nowMs = (opts.now ?? Date.now)();
  const rec = await store.get(id);
  if (!rec) return "not_found";
  if (!constantTimeEqual(rec.request_digest, requestDigest(req))) {
    log.warn("vault_approval_digest_mismatch", { approval_id: id, client_id: req?.client?.client_id });
    return "digest_mismatch";
  }
  const status = effectiveStatus(rec, nowMs);
  return status === "approved" ? "ok" : mapStatus(status);
}

export async function consumeApproval(
  id: string,
  req: CapabilityRequest,
  opts: ApprovalOptions = {},
): Promise<ConsumeResult> {
  if (typeof id !== "string" || !ID_PATTERN.test(id)) return "not_found";
  const store = opts.store ?? getDefaultApprovalStore();
  const nowMs = (opts.now ?? Date.now)();
  const rec = await store.get(id);
  if (!rec) return "not_found";

  const digest = requestDigest(req);
  if (!constantTimeEqual(rec.request_digest, digest)) {
    log.warn("vault_approval_digest_mismatch", { approval_id: id, client_id: req?.client?.client_id });
    return "digest_mismatch";
  }

  const status = effectiveStatus(rec, nowMs);
  if (status === "expired" && rec.status !== "expired") {
    await store.expire(id).catch(() => undefined);
  }
  if (status !== "approved") return mapStatus(status);

  const won = await store.consume(id, rec.request_digest, new Date(nowMs).toISOString());
  if (won) {
    log.info("vault_approval_consumed", { approval_id: id, client_id: rec.client_id });
    return "ok";
  }
  // Lost a race (or expired in between): report the state that beat us.
  const after = await store.get(id);
  if (!after) return "not_found";
  const afterStatus = effectiveStatus(after, nowMs);
  return afterStatus === "approved" ? "expired" : mapStatus(afterStatus);
}

export type DecideRejectReason =
  | "invalid_action"
  | "approver_not_configured"
  | "unauthorized_user"
  | "hmac_key_unavailable"
  | "not_found"
  | "bad_mac"
  | "expired"
  | "not_pending"
  | "ledger_unavailable";

export type DecideResult =
  | { ok: true; status: "approved" | "denied"; record: ApprovalRecord }
  | { ok: false; reason: DecideRejectReason; record?: ApprovalRecord };

function reject(reason: DecideRejectReason, id: unknown, record?: ApprovalRecord): DecideResult {
  log.warn("vault_approval_decision_rejected", {
    reason,
    approval_id: typeof id === "string" && ID_PATTERN.test(id) ? id : "invalid",
  });
  return record ? { ok: false, reason, record } : { ok: false, reason };
}

/**
 * Record the approver's decision. Only the configured approver, holding a MAC
 * minted for this exact (action, id, digest), can move a pending, unexpired
 * approval. Every other call is rejected with no state change.
 */
export async function decideApproval(
  id: string,
  action: ApprovalAction,
  telegramUserId: string,
  mac: string,
  opts: ApprovalOptions = {},
): Promise<DecideResult> {
  const env = opts.env ?? process.env;
  if (action !== "approve" && action !== "deny") return reject("invalid_action", id);

  const approver = approverTelegramId(env);
  if (!approver) return reject("approver_not_configured", id);
  if (typeof telegramUserId !== "string" || !constantTimeEqual(telegramUserId, approver)) {
    return reject("unauthorized_user", id);
  }

  let key: Buffer;
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
  if (typeof mac !== "string" || !MAC_PATTERN.test(mac) || !constantTimeEqual(mac, expected)) {
    return reject("bad_mac", id);
  }

  return applyDecision(rec, action, { decidedBy: telegramUserId, ledgerClientId: OWNER_DECIDER_CLIENT_ID, actor: "owner" }, opts);
}

/** client_id on the ledger row that records the owner's Telegram decision. */
export const OWNER_DECIDER_CLIENT_ID = "owner:telegram";

/** How a decision is attributed: whose name the record and the ledger carry. */
interface DecisionAttribution {
  /** Stored on the approval record as `decided_by`. */
  decidedBy: string;
  /** client_id of the ledger row that records the decision. */
  ledgerClientId: string;
  /** Actor phrase in the ledger task text: "<actor> approved the request of …". */
  actor: string;
}

/**
 * The shared decision core, used by every decider after it has authenticated
 * in its own way: expiry/pending checks, the decision written to the
 * hash-chained ledger BEFORE it takes effect (nothing is ever approved or
 * denied without an audit row — if the row cannot be written the decision is
 * refused and the approval stays pending), the atomic decide, and the race
 * report. Attribution comes from the caller, so a decision is always recorded
 * under its real decider.
 */
async function applyDecision(
  rec: ApprovalRecord,
  action: ApprovalAction,
  attribution: DecisionAttribution,
  opts: ApprovalOptions,
): Promise<DecideResult> {
  const id = rec.id;
  const store = opts.store ?? getDefaultApprovalStore();
  const nowMs = (opts.now ?? Date.now)();
  const status = effectiveStatus(rec, nowMs);
  if (status === "expired") {
    if (rec.status !== "expired") await store.expire(id).catch(() => undefined);
    return reject("expired", id, { ...rec, status: "expired" });
  }
  if (status !== "pending") return reject("not_pending", id, rec);

  const next = action === "approve" ? "approved" : "denied";
  const sink = opts.ledger ?? defaultLedgerSink;
  const decisionRow = (result: "ok" | "denied" | "error", error?: string): LedgerEntryInput => ({
    client_id: attribution.ledgerClientId,
    capability: APPROVAL_DECISION_CAPABILITY,
    resource: sanitizeDisplayText(`${rec.capability} ${rec.resource}`, 300),
    decision: action === "approve" ? "allow" : "deny",
    tier: 3,
    result,
    approval_id: id,
    error,
    task: sanitizeDisplayText(`${attribution.actor} ${next} the request of ${rec.client_id}`, 300),
  });
  try {
    await sink(decisionRow(action === "approve" ? "ok" : "denied"));
  } catch {
    log.error("vault_approval_decision_unledgered", { approval_id: id });
    return reject("ledger_unavailable", id, rec);
  }
  const updated = await store.decide(id, next, attribution.decidedBy, new Date(nowMs).toISOString());
  if (!updated) {
    // Lost a race (decided or expired in between): say so on the ledger too.
    await sink(decisionRow("error", "not_applied")).catch(() => undefined);
    const after = (await store.get(id)) ?? rec;
    const s = effectiveStatus(after, nowMs);
    return reject(s === "expired" ? "expired" : "not_pending", id, { ...after, status: s });
  }
  log.info("vault_approval_decided", { approval_id: id, status: next });
  return { ok: true, status: next, record: updated };
}

// ------------------------------------------------------------------ bridge decider

/** client_id recorded for every decision made by Lyra's consent bridge. */
export const BRIDGE_DECIDER_CLIENT_ID = "service:lyra-consent-bridge";

/**
 * The only approval kinds the bridge decider may decide:
 *   - "vault.client.authorize" — OAuth connection approvals (bootstrap.ts);
 *   - "vault.entry.use.read"   — first-use entry-read consent approvals
 *     (the gateway's needsConsent path is the only creator of these).
 * Every other capability stays owner-only, however the bridge authenticates.
 */
export const BRIDGE_DECIDABLE_CAPABILITIES: ReadonlySet<string> = new Set(["vault.client.authorize", "vault.entry.use.read"]);

const MIN_BRIDGE_TOKEN_LENGTH = 32;

/** The consent bridge's service token, or null when unset/too short (fail closed). */
export function bridgeDeciderToken(env: NodeJS.ProcessEnv = process.env): string | null {
  const raw = env.ECHO_VAULT_BRIDGE_DECIDER_TOKEN;
  if (!raw || raw.length < MIN_BRIDGE_TOKEN_LENGTH) return null;
  registerSecretForRedaction(raw);
  return raw;
}

export type ServiceDecideRejectReason =
  | DecideRejectReason
  | "service_not_configured"
  | "unauthorized_service"
  | "out_of_scope";

export type ServiceDecideResult =
  | { ok: true; status: "approved" | "denied"; record: ApprovalRecord }
  | { ok: false; reason: ServiceDecideRejectReason; record?: ApprovalRecord };

function serviceReject(reason: ServiceDecideRejectReason, id: unknown, record?: ApprovalRecord): ServiceDecideResult {
  log.warn("vault_bridge_decision_rejected", {
    reason,
    approval_id: typeof id === "string" && ID_PATTERN.test(id) ? id : "invalid",
  });
  return record ? { ok: false, reason, record } : { ok: false, reason };
}

/**
 * Record a decision by the second decider: Lyra's consent bridge. The bridge
 * authenticates with its own service token (ECHO_VAULT_BRIDGE_DECIDER_TOKEN)
 * — never with the owner's Telegram identity and never with a callback MAC —
 * and may decide ONLY the approval kinds in BRIDGE_DECIDABLE_CAPABILITIES.
 * The decision is ledgered under client_id "service:lyra-consent-bridge" and
 * the record's decided_by carries the same value, so bridge decisions are
 * distinguishable from the owner's ("owner:telegram") forever.
 */
export async function decideApprovalAsService(
  id: string,
  action: ApprovalAction,
  serviceToken: string,
  opts: ApprovalOptions = {},
): Promise<ServiceDecideResult> {
  const env = opts.env ?? process.env;
  if (action !== "approve" && action !== "deny") return serviceReject("invalid_action", id);

  const expected = bridgeDeciderToken(env);
  if (!expected) return serviceReject("service_not_configured", id);
  if (typeof serviceToken !== "string" || !constantTimeEqual(serviceToken, expected)) {
    return serviceReject("unauthorized_service", id);
  }

  if (typeof id !== "string" || !ID_PATTERN.test(id)) return serviceReject("not_found", id);
  const store = opts.store ?? getDefaultApprovalStore();
  const rec = await store.get(id);
  if (!rec) return serviceReject("not_found", id);
  if (!BRIDGE_DECIDABLE_CAPABILITIES.has(rec.capability)) return serviceReject("out_of_scope", id, rec);

  return applyDecision(
    rec,
    action,
    { decidedBy: BRIDGE_DECIDER_CLIENT_ID, ledgerClientId: BRIDGE_DECIDER_CLIENT_ID, actor: BRIDGE_DECIDER_CLIENT_ID },
    opts,
  );
}
