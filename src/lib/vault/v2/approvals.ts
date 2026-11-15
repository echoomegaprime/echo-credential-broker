// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 approvals — request-bound, single-use, human approvals over Telegram.
 *
 *   createApproval(req, summary)  stores a `pending` record bound to
 *                                 requestDigest(req) and DMs the approver an
 *                                 [Approve] [Deny] inline keyboard.
 *   decideApproval(...)           called by the Telegram webhook: MAC + approver
 *                                 identity + pending + unexpired → approved/denied.
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
import type { ApprovalRecord, ApprovalStatus, CapabilityRequest, ConsumeResult } from "./contracts.ts";
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
}

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
  | "not_pending";

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

  const nowMs = (opts.now ?? Date.now)();
  const status = effectiveStatus(rec, nowMs);
  if (status === "expired") {
    if (rec.status !== "expired") await store.expire(id).catch(() => undefined);
    return reject("expired", id, { ...rec, status: "expired" });
  }
  if (status !== "pending") return reject("not_pending", id, rec);

  const next = action === "approve" ? "approved" : "denied";
  const updated = await store.decide(id, next, telegramUserId, new Date(nowMs).toISOString());
  if (!updated) {
    const after = (await store.get(id)) ?? rec;
    const s = effectiveStatus(after, nowMs);
    return reject(s === "expired" ? "expired" : "not_pending", id, { ...after, status: s });
  }
  log.info("vault_approval_decided", { approval_id: id, status: next });
  return { ok: true, status: next, record: updated };
}
