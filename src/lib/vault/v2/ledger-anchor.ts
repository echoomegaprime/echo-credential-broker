// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 ledger anchoring — publish the chain head OUTSIDE the database.
 *
 * `ledger.ts` proves the chain is internally consistent. It cannot see two
 * attacks by someone with database access: deleting the newest N rows (the
 * remaining prefix is still a valid chain) and rebuilding the whole chain.
 * Both change what the head is, so a copy of the head kept where the database
 * writer cannot reach it exposes them.
 *
 * The anchor is one Telegram message to the owner's chat (the same bot and
 * chat as approvals). Its whole text is one machine-parseable line:
 *
 *   ECHO-VAULT-ANCHOR v1 seq=<n> hash=<64 hex> rows=<n> at=<ISO-8601 UTC ms> mac=<64 hex>
 *   ECHO-VAULT-ANCHOR v1 seq=<n> hash=<64 hex> rows=<n> at=<ISO-8601 UTC ms> unsigned
 *
 * `mac` = HMAC-SHA256(ECHO_VAULT_ANCHOR_KEY, everything before " mac="), hex.
 * Without the key the line ends in the literal word `unsigned`. The Telegram
 * message id is the external receipt. Only seq, the chain hash, the row count
 * and a timestamp leave the process — never a ledger row's payload, never a
 * secret. The key is server-only: keep it out of the database.
 *
 * `vault_ledger_anchors` (migrations/0008) is a local INDEX of what was sent.
 * It lives in the same database as the ledger, so it is not the proof — the
 * message is. Verify a line copied from Telegram with `verifyAgainstAnchor`.
 *
 * Verdicts:
 *   ok                     the ledger still has the anchored row with the anchored hash, and at least as many rows
 *   rewritten              the row at the anchored seq has a different hash (or is gone while later rows exist)
 *   truncated              the ledger ends before the anchored seq / has fewer rows, and the anchor is authentic
 *                          (valid mac, or it matches a local anchor record)
 *   anchor_ahead_of_ledger same shortfall, but the anchor could not be authenticated (unsigned or no key
 *                          configured, and no local record): truncation, or a line from another vault / a forgery
 *   anchor_mac_invalid     a key is configured and the line's mac is missing or wrong
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import type { Sql } from "../../db.ts";
import { log } from "../log.ts";
import { registerSecretForRedaction } from "../redaction.ts";
import { approverTelegramId } from "./approvals.ts";
import { getLedger, type Ledger, type LedgerStore } from "./ledger.ts";
import { callBotApi, TelegramApiError } from "./telegram.ts";

export const ANCHOR_KEY_ENV = "ECHO_VAULT_ANCHOR_KEY";
export const ANCHOR_CHANNEL_TELEGRAM = "telegram";
const ANCHOR_PREFIX = "ECHO-VAULT-ANCHOR v1";
const ALERT_PREFIX = "ECHO-VAULT-ANCHOR ALERT v1";
const MIN_ANCHOR_KEY_LENGTH = 32;
const MAX_LINE_LENGTH = 400;
const COUNT_BATCH = 1000;
const ANCHOR_LINE_RE =
  /^ECHO-VAULT-ANCHOR v1 seq=([1-9][0-9]{0,15}) hash=([0-9a-f]{64}) rows=([1-9][0-9]{0,15}) at=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z) (?:mac=([0-9a-f]{64})|unsigned)$/;
/** Fixed alert vocabulary: nothing derived from a ledger row is ever sent. */
const ALERT_REASONS: ReadonlySet<string> = new Set([
  "seq_gap",
  "prev_hash_mismatch",
  "hash_mismatch",
  "hmac_missing",
  "hmac_mismatch",
  "truncated",
  "rewritten",
  "anchor_ahead_of_ledger",
]);

/** The head that gets anchored. `at` is an ISO-8601 UTC timestamp with milliseconds. */
export interface Anchor {
  seq: number;
  hash: string;
  row_count: number;
  at: string;
}

/** An anchor as read back from a line or a local record. `mac` is absent for an unsigned anchor. */
export interface ParsedAnchor extends Anchor {
  mac?: string;
}

/** One row of the local index. */
export interface AnchorRecord {
  seq: number;
  hash: string;
  row_count: number;
  anchored_at: string;
  channel: string;
  external_id: string;
  mac?: string;
}

export type AnchorVerdict = "ok" | "truncated" | "rewritten" | "anchor_mac_invalid" | "anchor_ahead_of_ledger";

export interface AnchorCheck {
  verdict: AnchorVerdict;
  /** True when a key is configured and the anchor's mac verified under it. */
  mac_checked: boolean;
  /** True when the local index holds an anchor with the same seq, hash and row count. */
  known_locally: boolean;
  /** Current ledger head seq (0 when the ledger is empty). */
  head_seq: number;
}

/** Fixed-code failure; the message never carries key material or upstream text. */
export class AnchorError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "AnchorError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Line format + MAC
// ---------------------------------------------------------------------------

/** The anchor key, or null when unset. Throws `anchor_key_too_short` rather than silently signing weakly or not at all. */
export function readAnchorKey(env: NodeJS.ProcessEnv = process.env): Buffer | null {
  const raw = env[ANCHOR_KEY_ENV];
  if (raw === undefined || raw === "") return null;
  if (raw.length < MIN_ANCHOR_KEY_LENGTH) throw new AnchorError("anchor_key_too_short");
  registerSecretForRedaction(raw);
  return Buffer.from(raw, "utf8");
}

function signedPart(anchor: Anchor): string {
  return `${ANCHOR_PREFIX} seq=${anchor.seq} hash=${anchor.hash} rows=${anchor.row_count} at=${anchor.at}`;
}

/** HMAC-SHA256 hex over the line up to (not including) " mac=". */
export function computeAnchorMac(key: Buffer, anchor: Anchor): string {
  return createHmac("sha256", key).update(signedPart(anchor), "utf8").digest("hex");
}

/** The exact Telegram message text. */
export function formatAnchorLine(anchor: Anchor, key: Buffer | null): string {
  return `${signedPart(anchor)} ${key ? `mac=${computeAnchorMac(key, anchor)}` : "unsigned"}`;
}

function validIso(at: string): boolean {
  const ms = Date.parse(at);
  return Number.isFinite(ms) && new Date(ms).toISOString() === at;
}

/**
 * Strict parser: the input must be exactly one anchor line — no surrounding
 * whitespace, no extra fields, canonical numbers and timestamp. Anything else
 * returns null.
 */
export function parseAnchorLine(text: unknown): ParsedAnchor | null {
  if (typeof text !== "string" || text.length > MAX_LINE_LENGTH) return null;
  const m = ANCHOR_LINE_RE.exec(text);
  if (!m) return null;
  const seq = Number(m[1]);
  const rowCount = Number(m[3]);
  if (!Number.isSafeInteger(seq) || !Number.isSafeInteger(rowCount)) return null;
  // seq is a unique key >= 1 and the anchored row is the head, so a chain can never hold more rows than its head seq.
  if (rowCount > seq) return null;
  if (!validIso(m[4])) return null;
  const anchor: ParsedAnchor = { seq, hash: m[2], row_count: rowCount, at: m[4] };
  if (m[5] !== undefined) anchor.mac = m[5];
  return anchor;
}

function hexEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

// ---------------------------------------------------------------------------
// Reading the ledger
// ---------------------------------------------------------------------------

async function countRows(store: LedgerStore): Promise<number> {
  let count = 0;
  let afterSeq = 0;
  for (;;) {
    const batch = await store.scanAscending(afterSeq, COUNT_BATCH);
    if (batch.length === 0) return count;
    count += batch.length;
    afterSeq = batch[batch.length - 1].seq;
  }
}

async function rowHashAt(store: LedgerStore, seq: number): Promise<string | null> {
  const [row] = await store.scanAscending(seq - 1, 1);
  return row && row.seq === seq ? row.hash : null;
}

/** The current head as an anchor, or null for an empty ledger. Does NOT verify the chain — `anchorHead` does. */
export async function computeAnchor(store: LedgerStore, opts: { now?: () => number } = {}): Promise<Anchor | null> {
  const head = await store.head();
  if (!head) return null;
  return {
    seq: head.seq,
    hash: head.hash,
    row_count: await countRows(store),
    at: new Date((opts.now ?? Date.now)()).toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Local index
// ---------------------------------------------------------------------------

/** Append-only index of sent anchors. There is no update or delete. */
export interface AnchorStore {
  readonly kind: string;
  /** "exists" when (seq, channel) is already recorded; the stored row is left untouched. */
  insert(record: AnchorRecord): Promise<"inserted" | "exists">;
  /** Highest-seq anchor on a channel. */
  latest(channel: string): Promise<AnchorRecord | null>;
  find(seq: number, channel: string): Promise<AnchorRecord | null>;
}

/** In-memory index for tests and local tooling. Never the production default. */
export class MemoryAnchorStore implements AnchorStore {
  readonly kind = "memory";
  private readonly rows: AnchorRecord[] = [];

  async insert(record: AnchorRecord): Promise<"inserted" | "exists"> {
    if (this.rows.some((r) => r.seq === record.seq && r.channel === record.channel)) return "exists";
    this.rows.push({ ...record });
    return "inserted";
  }

  async latest(channel: string): Promise<AnchorRecord | null> {
    const best = this.rows.filter((r) => r.channel === channel).sort((a, b) => b.seq - a.seq)[0];
    return best ? { ...best } : null;
  }

  async find(seq: number, channel: string): Promise<AnchorRecord | null> {
    const row = this.rows.find((r) => r.seq === seq && r.channel === channel);
    return row ? { ...row } : null;
  }

  /** Number of recorded anchors (tests). */
  get size(): number {
    return this.rows.length;
  }
}

type SqlQuery = Pick<Sql, "query">;

const COLUMNS = "seq, hash, row_count, anchored_at, channel, external_id, mac";

function toIso(value: unknown): string {
  return (value instanceof Date ? value : new Date(String(value))).toISOString();
}

function rowToRecord(row: Record<string, unknown>): AnchorRecord {
  const record: AnchorRecord = {
    seq: Number(row.seq),
    hash: String(row.hash),
    row_count: Number(row.row_count),
    anchored_at: toIso(row.anchored_at),
    channel: String(row.channel),
    external_id: String(row.external_id),
  };
  if (row.mac != null) record.mac = String(row.mac);
  return record;
}

/** Postgres/PGlite index over `vault_ledger_anchors` (migrations/0008_vault_ledger_anchors.sql). */
export class SqlAnchorStore implements AnchorStore {
  readonly kind = "sql";
  private readonly getSql: () => Promise<SqlQuery>;

  constructor(getSql?: () => Promise<SqlQuery>) {
    this.getSql =
      getSql ??
      (async () => {
        const db = await import("../../db.ts");
        return db.getSql();
      });
  }

  async insert(r: AnchorRecord): Promise<"inserted" | "exists"> {
    const sql = await this.getSql();
    const rows = await sql.query(
      `INSERT INTO vault_ledger_anchors (${COLUMNS})
       VALUES ($1::bigint, $2::text, $3::bigint, $4::timestamptz, $5::text, $6::text, $7::text)
       ON CONFLICT (seq, channel) DO NOTHING
       RETURNING seq`,
      [r.seq, r.hash, r.row_count, r.anchored_at, r.channel, r.external_id, r.mac ?? null],
    );
    return rows.length === 1 ? "inserted" : "exists";
  }

  async latest(channel: string): Promise<AnchorRecord | null> {
    const sql = await this.getSql();
    const rows = await sql.query<Record<string, unknown>>(
      `SELECT ${COLUMNS} FROM vault_ledger_anchors WHERE channel = $1::text ORDER BY seq DESC LIMIT 1`,
      [channel],
    );
    return rows[0] ? rowToRecord(rows[0]) : null;
  }

  async find(seq: number, channel: string): Promise<AnchorRecord | null> {
    const sql = await this.getSql();
    const rows = await sql.query<Record<string, unknown>>(
      `SELECT ${COLUMNS} FROM vault_ledger_anchors WHERE seq = $1::bigint AND channel = $2::text`,
      [seq, channel],
    );
    return rows[0] ? rowToRecord(rows[0]) : null;
  }
}

let defaultStore: AnchorStore | null = null;

/** The process-wide index: SQL (Neon/Postgres or PGlite via getSql) unless replaced. */
export function getDefaultAnchorStore(): AnchorStore {
  defaultStore ??= new SqlAnchorStore();
  return defaultStore;
}

/** Wiring/test hook. Pass null to restore the SQL default. */
export function setDefaultAnchorStore(store: AnchorStore | null): void {
  defaultStore = store;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export interface VerifyAnchorOptions {
  env?: NodeJS.ProcessEnv;
  /** Local index, used only to tell an authentic anchor from an unverifiable one. */
  anchors?: AnchorStore;
  channel?: string;
  /** Row count already known to the caller (e.g. from `verifyLedger`), to skip a scan. */
  rowCount?: number;
  /** Skip the mac check (the caller is re-reading its own index, not an external line). */
  skipMac?: boolean;
}

/**
 * Compare an anchor with the ledger as it is now. See the module header for
 * the verdicts. Throws only for storage errors and `anchor_key_too_short`.
 */
export async function verifyAgainstAnchor(
  anchor: ParsedAnchor,
  store: LedgerStore,
  opts: VerifyAnchorOptions = {},
): Promise<AnchorCheck> {
  const head = await store.head();
  const check: AnchorCheck = { verdict: "ok", mac_checked: false, known_locally: false, head_seq: head?.seq ?? 0 };
  const done = (verdict: AnchorVerdict): AnchorCheck => ({ ...check, verdict });

  // (a) Authenticity. With a key configured an unsigned or wrongly signed anchor is never accepted (no downgrade).
  const key = opts.skipMac ? null : readAnchorKey(opts.env ?? process.env);
  if (key) {
    if (!anchor.mac || !hexEqual(anchor.mac, computeAnchorMac(key, anchor))) return done("anchor_mac_invalid");
    check.mac_checked = true;
  }
  if (opts.anchors) {
    const known = await opts.anchors.find(anchor.seq, opts.channel ?? ANCHOR_CHANNEL_TELEGRAM);
    check.known_locally = !!known && known.hash === anchor.hash && known.row_count === anchor.row_count;
  }
  const authentic = check.mac_checked || check.known_locally || opts.skipMac === true;

  // (b) The anchored row must still be there, unchanged.
  const hashAtSeq = await rowHashAt(store, anchor.seq);
  if (hashAtSeq === null) {
    if (check.head_seq < anchor.seq) return done(authentic ? "truncated" : "anchor_ahead_of_ledger");
    return done("rewritten"); // later rows exist but the anchored one is gone
  }
  if (!hexEqual(hashAtSeq, anchor.hash)) return done("rewritten");

  // (c) Nothing below the anchor may have gone missing either.
  const rowCount = opts.rowCount ?? (await countRows(store));
  if (rowCount < anchor.row_count) return done("truncated");
  return done("ok");
}

function recordToAnchor(record: AnchorRecord): ParsedAnchor {
  const anchor: ParsedAnchor = { seq: record.seq, hash: record.hash, row_count: record.row_count, at: record.anchored_at };
  if (record.mac !== undefined) anchor.mac = record.mac;
  return anchor;
}

// ---------------------------------------------------------------------------
// anchorHead
// ---------------------------------------------------------------------------

/** Everything is optional: production passes nothing. */
export interface AnchorDeps {
  /** Default: the process-wide ledger (SQL store + ECHO_VAULT_LEDGER_HMAC_KEY). */
  ledger?: Ledger;
  /** Default: the SQL index. */
  anchors?: AnchorStore;
  fetch?: typeof fetch;
  env?: NodeJS.ProcessEnv;
  now?: () => number;
}

export type AnchorOutcome =
  | { ok: true; status: "anchored"; seq: number; hash: string; row_count: number; at: string; signed: boolean; channel: string; external_id: string }
  | { ok: true; status: "unchanged"; seq: number; anchored_at: string; channel: string; external_id: string }
  | { ok: true; status: "empty" }
  | { ok: false; error: string; reason?: string; seq?: number; alert_sent?: boolean; external_id?: string };

function errorCode(err: unknown, fallback: string): string {
  if (err instanceof TelegramApiError || err instanceof AnchorError) return err.code;
  return fallback;
}

async function sendOwnerMessage(text: string, deps: AnchorDeps): Promise<string> {
  const env = deps.env ?? process.env;
  const chatId = approverTelegramId(env);
  if (!chatId) throw new TelegramApiError("sendMessage", "telegram_approver_missing");
  const result = await callBotApi<{ message_id?: unknown }>(
    "sendMessage",
    { chat_id: chatId, text, link_preview_options: { is_disabled: true } },
    { fetch: deps.fetch, env },
  );
  const id = result?.message_id;
  if (typeof id !== "number" || !Number.isSafeInteger(id) || id <= 0) {
    throw new TelegramApiError("sendMessage", "telegram_no_message_id");
  }
  return String(id);
}

/** ALERT instead of an anchor. Fixed vocabulary + a sequence number; best effort. */
async function sendAlert(reason: string, seq: number, deps: AnchorDeps): Promise<boolean> {
  const code = ALERT_REASONS.has(reason) ? reason : "chain_invalid";
  const at = new Date((deps.now ?? Date.now)()).toISOString();
  const text = [
    `${ALERT_PREFIX} reason=${code} seq=${Number.isSafeInteger(seq) && seq >= 0 ? seq : 0} at=${at}`,
    "ECHO Vault: the audit ledger failed verification. No anchor was recorded. Investigate before trusting the audit log.",
  ].join("\n");
  log.error("ledger_anchor_alert", { reason: code, seq });
  try {
    await sendOwnerMessage(text, deps);
    return true;
  } catch (err) {
    log.error("ledger_anchor_alert_failed", { code: errorCode(err, "unknown") });
    return false;
  }
}

/**
 * Verify the chain, then publish its head to the owner's Telegram chat and
 * record the receipt. Never throws.
 *
 *  - broken chain, or a ledger that no longer matches the newest recorded
 *    anchor (truncated / rewritten) → an ALERT message, no anchor, `ok:false`
 *  - head unchanged since the newest anchor → `unchanged`, nothing sent
 *  - Telegram failure → `ok:false`, nothing recorded
 */
export async function anchorHead(deps: AnchorDeps = {}): Promise<AnchorOutcome> {
  const env = deps.env ?? process.env;
  const channel = ANCHOR_CHANNEL_TELEGRAM;
  let key: Buffer | null;
  try {
    key = readAnchorKey(env);
  } catch (err) {
    return { ok: false, error: errorCode(err, "anchor_key_invalid") };
  }

  let ledger: Ledger;
  let count: number;
  try {
    ledger = deps.ledger ?? getLedger();
    const verification = await ledger.verify();
    if (!verification.ok) {
      const reason = verification.reason.split(":")[0];
      const alertSent = await sendAlert(reason, verification.broken_at_seq, deps);
      return {
        ok: false,
        error: "ledger_unverified",
        reason: ALERT_REASONS.has(reason) ? reason : "chain_invalid",
        seq: verification.broken_at_seq,
        alert_sent: alertSent,
      };
    }
    count = verification.count;
  } catch (err) {
    log.error("ledger_anchor_failed", { code: errorCode(err, "ledger_unavailable") });
    return { ok: false, error: errorCode(err, "ledger_unavailable") };
  }

  const anchors = deps.anchors ?? getDefaultAnchorStore();
  let last: AnchorRecord | null;
  let headHash: string | null;
  try {
    last = await anchors.latest(channel);
    headHash = count > 0 ? await rowHashAt(ledger.store, count) : null;
    if (last) {
      // Never bless a chain that lost or changed what was already anchored.
      const check = await verifyAgainstAnchor(recordToAnchor(last), ledger.store, { rowCount: count, skipMac: true });
      if (check.verdict !== "ok") {
        const alertSent = await sendAlert(check.verdict, last.seq, deps);
        return { ok: false, error: `ledger_${check.verdict}`, reason: check.verdict, seq: last.seq, alert_sent: alertSent };
      }
    }
  } catch (err) {
    log.error("ledger_anchor_failed", { code: errorCode(err, "anchor_store_unavailable") });
    return { ok: false, error: errorCode(err, "anchor_store_unavailable") };
  }
  if (count === 0) return { ok: true, status: "empty" };
  // A verified chain of `count` rows has its head at seq === count; a miss means it changed under us.
  if (headHash === null) return { ok: false, error: "ledger_changed_during_verify" };
  if (last && last.seq === count && last.hash === headHash) {
    return { ok: true, status: "unchanged", seq: last.seq, anchored_at: last.anchored_at, channel, external_id: last.external_id };
  }

  const anchor: Anchor = { seq: count, hash: headHash, row_count: count, at: new Date((deps.now ?? Date.now)()).toISOString() };
  let externalId: string;
  try {
    externalId = await sendOwnerMessage(formatAnchorLine(anchor, key), deps);
  } catch (err) {
    log.error("ledger_anchor_failed", { code: errorCode(err, "telegram_error") });
    return { ok: false, error: errorCode(err, "telegram_error") };
  }
  const record: AnchorRecord = {
    seq: anchor.seq,
    hash: anchor.hash,
    row_count: anchor.row_count,
    anchored_at: anchor.at,
    channel,
    external_id: externalId,
  };
  if (key) record.mac = computeAnchorMac(key, anchor);
  try {
    await anchors.insert(record);
  } catch {
    // The proof exists (the message was delivered); only the index row is missing. The next run re-anchors.
    log.error("ledger_anchor_failed", { code: "anchor_record_failed", seq: anchor.seq, external_id: externalId });
    return { ok: false, error: "anchor_record_failed", seq: anchor.seq, external_id: externalId };
  }
  log.info("ledger_anchored", { seq: anchor.seq, channel, external_id: externalId, signed: key !== null });
  return { ok: true, status: "anchored", ...anchor, signed: key !== null, channel, external_id: externalId };
}

// ---------------------------------------------------------------------------
// Gateway / runner helpers
// ---------------------------------------------------------------------------

/** Verdict for the newest recorded anchor (audit_verify), or null when nothing was anchored yet. */
export async function newestAnchorVerdict(
  deps: AnchorDeps = {},
  rowCount?: number,
): Promise<{ seq: number; anchored_at: string; verdict: AnchorVerdict } | null> {
  const last = await (deps.anchors ?? getDefaultAnchorStore()).latest(ANCHOR_CHANNEL_TELEGRAM);
  if (!last) return null;
  const store = (deps.ledger ?? getLedger()).store;
  const check = await verifyAgainstAnchor(recordToAnchor(last), store, { env: deps.env, rowCount });
  // The record came from the index itself, so a shortfall is truncation, not an unknown line.
  const verdict = check.verdict === "anchor_ahead_of_ledger" ? "truncated" : check.verdict;
  return { seq: last.seq, anchored_at: last.anchored_at, verdict };
}

export interface AnchorLineCheck extends AnchorCheck {
  anchor: { seq: number; hash: string; row_count: number; at: string; signed: boolean };
}

/** Check a line copied from Telegram. Returns null when the line is malformed. */
export async function verifyAnchorLine(line: unknown, deps: AnchorDeps = {}): Promise<AnchorLineCheck | null> {
  const anchor = parseAnchorLine(typeof line === "string" ? line.trim() : line);
  if (!anchor) return null;
  const store = (deps.ledger ?? getLedger()).store;
  const check = await verifyAgainstAnchor(anchor, store, {
    env: deps.env,
    anchors: deps.anchors ?? getDefaultAnchorStore(),
  });
  return {
    ...check,
    anchor: { seq: anchor.seq, hash: anchor.hash, row_count: anchor.row_count, at: anchor.at, signed: anchor.mac !== undefined },
  };
}
