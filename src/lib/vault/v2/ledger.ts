// library-first: echo.functions.search → no existing impl found (2026-11-14)
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
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { Sql } from "../../db.ts";
import { log } from "../log.ts";
import { containsSecretPrefix, redactString } from "../redaction.ts";
import { parseVaultRef } from "../refs.ts";
import {
  canonicalJson,
  type Decision,
  type LedgerEntry,
  type LedgerEntryInput,
  type LedgerResult,
  type Tier,
} from "./contracts.ts";

export const GENESIS_PREV_HASH = "0".repeat(64);
export const LEDGER_HMAC_ENV = "ECHO_VAULT_LEDGER_HMAC_KEY";
const HMAC_DOMAIN = "echo-vault-ledger-v1:";
const MIN_HMAC_KEY_LENGTH = 32;
const DEFAULT_LIST_LIMIT = 100;
const MAX_LIST_LIMIT = 1000;
const VERIFY_BATCH = 500;
const MAX_APPEND_ATTEMPTS = 50;

/** A row as persisted: the contract entry plus an optional HMAC over `hash`. */
export interface StoredLedgerEntry extends LedgerEntry {
  hmac?: string;
}

export type LedgerVerifyResult =
  | { ok: true; count: number }
  | { ok: false; broken_at_seq: number; reason: string };

export interface LedgerListOptions {
  limit?: number;
  client_id?: string;
  capability?: string;
}

export interface LedgerHead {
  seq: number;
  hash: string;
}

/** Storage seam. `insertIfHead` is the only write and must be an atomic compare-and-append. */
export interface LedgerStore {
  readonly kind: string;
  head(): Promise<LedgerHead | null>;
  /**
   * Insert iff the store's current head is exactly (entry.seq - 1, entry.prev_hash)
   * — or the store is empty and entry is (1, GENESIS_PREV_HASH). Returns
   * "conflict" (never throws) when another writer got there first.
   */
  insertIfHead(entry: StoredLedgerEntry): Promise<"inserted" | "conflict">;
  /** Entries with seq > afterSeq, ascending, at most `limit`. */
  scanAscending(afterSeq: number, limit: number): Promise<StoredLedgerEntry[]>;
  /** Newest first, optionally filtered. */
  listNewestFirst(opts: { limit: number; client_id?: string; capability?: string }): Promise<StoredLedgerEntry[]>;
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/** The hashed body of an entry: every contract field except `hash`. */
export type LedgerEntryBody = Omit<LedgerEntry, "hash">;

/** sha256 hex of prev_hash + canonicalJson(body). Exported for external verifiers. */
export function computeLedgerHash(body: LedgerEntryBody): string {
  return createHash("sha256").update(body.prev_hash + canonicalJson(body), "utf8").digest("hex");
}

function computeHmac(key: Buffer, hash: string): string {
  return createHmac("sha256", key).update(HMAC_DOMAIN + hash, "utf8").digest("hex");
}

function hexEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

function bodyOf(entry: StoredLedgerEntry): LedgerEntryBody {
  // Rebuild from the contract field list so a stray stored property can never
  // change (or be smuggled into) what is hashed.
  const body: LedgerEntryBody = {
    seq: entry.seq,
    id: entry.id,
    timestamp: entry.timestamp,
    prev_hash: entry.prev_hash,
    client_id: entry.client_id,
    capability: entry.capability,
    resource: entry.resource,
    decision: entry.decision,
    tier: entry.tier,
    result: entry.result,
  };
  if (entry.approval_id !== undefined) body.approval_id = entry.approval_id;
  if (entry.credential_ref !== undefined) body.credential_ref = entry.credential_ref;
  if (entry.http_status !== undefined) body.http_status = entry.http_status;
  if (entry.error !== undefined) body.error = entry.error;
  if (entry.duration_ms !== undefined) body.duration_ms = entry.duration_ms;
  if (entry.task !== undefined) body.task = entry.task;
  if (entry.credential_path !== undefined) body.credential_path = entry.credential_path;
  if (entry.fallback_reason !== undefined) body.fallback_reason = entry.fallback_reason;
  return body;
}

function publicEntry(entry: StoredLedgerEntry): LedgerEntry {
  return { ...bodyOf(entry), hash: entry.hash };
}

// ---------------------------------------------------------------------------
// Input sanitization (secrets never reach the hash or the database)
// ---------------------------------------------------------------------------

const DECISIONS: ReadonlySet<string> = new Set<Decision>(["allow", "escalate", "deny"]);
const RESULTS: ReadonlySet<string> = new Set<LedgerResult>(["ok", "error", "denied", "pending_approval", "committing"]);
const TIERS: ReadonlySet<number> = new Set<Tier>([0, 1, 2, 3]);
const CREDENTIAL_PATHS: ReadonlySet<string> = new Set(["installation", "pat_fallback"]);
const MAX_TASK_LENGTH = 300;
const MAX_FALLBACK_REASON_LENGTH = 200;
/** Card entries (cards.ts): `vault://entry/ve_<32 hex>`. Opaque ID, nothing secret-shaped can fit. */
const ENTRY_REF_RE = /^vault:\/\/entry\/ve_[0-9a-f]{32}$/;

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
const EXTRA_SECRET_RULES: ReadonlyArray<readonly [RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$/g, "[REDACTED_PRIVATE_KEY]"],
  [/gh[pousr]_[0-9]+_[A-Za-z0-9._-]{16,}/g, "[REDACTED_GITHUB_TOKEN]"],
  [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "[REDACTED_JWT]"],
];

/** Long base62/base64-ish runs mixing upper, lower and digits — likely a random secret. */
const HIGH_ENTROPY_RUN = /[A-Za-z0-9_+=]{32,}/g;

function stripControlChars(value: string): string {
  let out = "";
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    out += (code < 0x20 && ch !== "\n" && ch !== "\t") || code === 0x7f ? " " : ch;
  }
  return out;
}

/** The ledger's own scrubber. Exported so read-side reports (digest.ts) re-apply the SAME rules instead of a copy. */
export function redactLedgerText(value: string, opts: { entropy: boolean }): string {
  let out = stripControlChars(value);
  for (const [re, replacement] of EXTRA_SECRET_RULES) out = out.replace(re, replacement);
  out = redactString(out);
  if (opts.entropy) {
    out = out.replace(HIGH_ENTROPY_RUN, (run) =>
      /[A-Z]/.test(run) && /[a-z]/.test(run) && /[0-9]/.test(run) ? "[REDACTED_HIGH_ENTROPY]" : run,
    );
  }
  // Last line of defence: anything still shaped like a provider token loses the whole field.
  if (containsSecretPrefix(out)) return "[REDACTED_SECRET]";
  return out;
}

function invalidInput(field: string): Error {
  return Object.assign(new Error(`ledger_invalid_input:${field}`), { code: "ledger_invalid_input", field });
}

function text(value: unknown, field: string, max: number, opts: { entropy: boolean; allowEmpty: boolean }): string {
  if (typeof value !== "string") throw invalidInput(field);
  const out = redactLedgerText(value, opts).slice(0, max);
  if (!opts.allowEmpty && !out.trim()) throw invalidInput(field);
  return out;
}

function optionalText(value: unknown, field: string, max: number, entropy: boolean): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const out = text(value, field, max, { entropy, allowEmpty: true });
  return out === "" ? undefined : out;
}

function optionalInt(value: unknown, field: string, min: number, max: number, round: boolean): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value)) throw invalidInput(field);
  const n = round ? Math.round(value) : value;
  if (!Number.isInteger(n) || n < min || n > max) throw invalidInput(field);
  return n;
}

function cleanCredentialRef(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "string" && ENTRY_REF_RE.test(value.trim())) return value.trim();
  const parsed = typeof value === "string" ? parseVaultRef(value) : null;
  // A syntactically valid ref can still carry a token as its "account" segment.
  if (!parsed || redactLedgerText(parsed.raw, { entropy: false }) !== parsed.raw) {
    log.warn("ledger_credential_ref_rejected", { reason: "not_a_clean_vault_ref" });
    return undefined;
  }
  return parsed.raw;
}

/**
 * Whitelist-copy and scrub an input. Throws `ledger_invalid_input:<field>` only
 * for structurally wrong values (bad enum, wrong type); secret-looking content
 * is redacted, never rejected, so a request is still recorded.
 */
export function sanitizeLedgerInput(input: LedgerEntryInput): LedgerEntryInput {
  if (!input || typeof input !== "object") throw invalidInput("input");
  if (typeof input.decision !== "string" || !DECISIONS.has(input.decision)) throw invalidInput("decision");
  if (typeof input.tier !== "number" || !TIERS.has(input.tier)) throw invalidInput("tier");
  if (typeof input.result !== "string" || !RESULTS.has(input.result)) throw invalidInput("result");
  const out: LedgerEntryInput = {
    client_id: text(input.client_id, "client_id", 256, { entropy: false, allowEmpty: false }),
    capability: text(input.capability, "capability", 256, { entropy: false, allowEmpty: false }),
    resource: text(input.resource, "resource", 1024, { entropy: true, allowEmpty: true }),
    decision: input.decision,
    tier: input.tier,
    result: input.result,
  };
  const approvalId = optionalText(input.approval_id, "approval_id", 256, false);
  if (approvalId !== undefined) out.approval_id = approvalId;
  const credentialRef = cleanCredentialRef(input.credential_ref);
  if (credentialRef !== undefined) out.credential_ref = credentialRef;
  const httpStatus = optionalInt(input.http_status, "http_status", 100, 599, false);
  if (httpStatus !== undefined) out.http_status = httpStatus;
  const error = optionalText(input.error, "error", 2000, true);
  if (error !== undefined) out.error = error;
  const duration = optionalInt(input.duration_ms, "duration_ms", 0, Number.MAX_SAFE_INTEGER, true);
  if (duration !== undefined) out.duration_ms = duration;
  const task = optionalText(input.task, "task", MAX_TASK_LENGTH, true);
  if (task !== undefined) out.task = task;
  if (input.credential_path !== undefined && input.credential_path !== null) {
    if (typeof input.credential_path !== "string" || !CREDENTIAL_PATHS.has(input.credential_path)) {
      throw invalidInput("credential_path");
    }
    out.credential_path = input.credential_path;
  }
  const fallbackReason = optionalText(input.fallback_reason, "fallback_reason", MAX_FALLBACK_REASON_LENGTH, true);
  if (fallbackReason !== undefined) out.fallback_reason = fallbackReason;
  return out;
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

export interface LedgerOptions {
  store: LedgerStore;
  /** HMAC key (>= 32 chars). Omit/null to disable. */
  hmacKey?: string | null;
  now?: () => number;
  newId?: () => string;
}

function hmacKeyBuffer(key: string | null | undefined): Buffer | null {
  if (key === undefined || key === null || key === "") return null;
  if (key.length < MIN_HMAC_KEY_LENGTH) {
    throw Object.assign(new Error("ledger_hmac_key_too_short"), { code: "ledger_hmac_key_too_short" });
  }
  return Buffer.from(key, "utf8");
}

function backoff(attempt: number): Promise<void> {
  const ms = Math.min(25, attempt) * Math.random();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class Ledger {
  /** Read access for ledger-anchor.ts (head/scan only; appends go through `append`). */
  readonly store: LedgerStore;
  private readonly hmacKey: Buffer | null;
  private readonly now: () => number;
  private readonly newId: () => string;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(opts: LedgerOptions) {
    this.store = opts.store;
    this.hmacKey = hmacKeyBuffer(opts.hmacKey);
    this.now = opts.now ?? Date.now;
    this.newId = opts.newId ?? randomUUID;
  }

  get hmacEnabled(): boolean {
    return this.hmacKey !== null;
  }

  append(input: LedgerEntryInput): Promise<LedgerEntry> {
    let clean: LedgerEntryInput;
    try {
      clean = sanitizeLedgerInput(input);
    } catch (error) {
      return Promise.reject(error);
    }
    const run = this.queue.then(() => this.appendClean(clean));
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async appendClean(clean: LedgerEntryInput): Promise<LedgerEntry> {
    for (let attempt = 1; attempt <= MAX_APPEND_ATTEMPTS; attempt += 1) {
      const head = await this.store.head();
      const body: LedgerEntryBody = {
        ...clean,
        seq: head ? head.seq + 1 : 1,
        id: this.newId(),
        timestamp: new Date(this.now()).toISOString(),
        prev_hash: head ? head.hash : GENESIS_PREV_HASH,
      };
      const hash = computeLedgerHash(body);
      const stored: StoredLedgerEntry = { ...body, hash };
      if (this.hmacKey) stored.hmac = computeHmac(this.hmacKey, hash);
      if ((await this.store.insertIfHead(stored)) === "inserted") return publicEntry(stored);
      await backoff(attempt); // another writer won this seq — re-read the head and retry
    }
    log.error("ledger_append_contention", { attempts: MAX_APPEND_ATTEMPTS, store: this.store.kind });
    throw Object.assign(new Error("ledger_append_contention"), { code: "ledger_append_contention" });
  }

  async verify(): Promise<LedgerVerifyResult> {
    let expectedSeq = 1;
    let expectedPrev = GENESIS_PREV_HASH;
    let afterSeq = 0;
    for (;;) {
      const batch = await this.store.scanAscending(afterSeq, VERIFY_BATCH);
      if (batch.length === 0) break;
      for (const entry of batch) {
        if (entry.seq !== expectedSeq) {
          return { ok: false, broken_at_seq: expectedSeq, reason: `seq_gap: expected ${expectedSeq}, found ${entry.seq}` };
        }
        if (entry.prev_hash !== expectedPrev) {
          return { ok: false, broken_at_seq: entry.seq, reason: "prev_hash_mismatch" };
        }
        if (computeLedgerHash(bodyOf(entry)) !== entry.hash) {
          return { ok: false, broken_at_seq: entry.seq, reason: "hash_mismatch" };
        }
        if (this.hmacKey) {
          if (!entry.hmac) return { ok: false, broken_at_seq: entry.seq, reason: "hmac_missing" };
          if (!hexEqual(entry.hmac, computeHmac(this.hmacKey, entry.hash))) {
            return { ok: false, broken_at_seq: entry.seq, reason: "hmac_mismatch" };
          }
        }
        expectedPrev = entry.hash;
        expectedSeq += 1;
        afterSeq = entry.seq;
      }
    }
    return { ok: true, count: expectedSeq - 1 };
  }

  async list(opts: LedgerListOptions = {}): Promise<LedgerEntry[]> {
    const requested = Number.isFinite(opts.limit) ? Math.floor(opts.limit as number) : DEFAULT_LIST_LIMIT;
    const limit = Math.min(Math.max(requested, 1), MAX_LIST_LIMIT);
    const rows = await this.store.listNewestFirst({
      limit,
      client_id: opts.client_id || undefined,
      capability: opts.capability || undefined,
    });
    return rows.map(publicEntry);
  }

  /** Entries with seq > afterSeq, ascending, at most `limit` (1..1000). For full-history readers such as digest.ts. */
  async scan(afterSeq: number, limit: number = VERIFY_BATCH): Promise<LedgerEntry[]> {
    const after = Number.isFinite(afterSeq) ? Math.max(0, Math.floor(afterSeq)) : 0;
    const requested = Number.isFinite(limit) ? Math.floor(limit) : VERIFY_BATCH;
    const rows = await this.store.scanAscending(after, Math.min(Math.max(requested, 1), MAX_LIST_LIMIT));
    return rows.map(publicEntry);
  }

  head(): Promise<LedgerHead | null> {
    return this.store.head();
  }
}

// ---------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------

/** In-memory store for tests and local tooling. Never the production default. */
export class MemoryLedgerStore implements LedgerStore {
  readonly kind = "memory";
  private rows: StoredLedgerEntry[] = [];

  async head(): Promise<LedgerHead | null> {
    await Promise.resolve(); // yield like a real store so concurrent writers interleave
    const last = this.rows[this.rows.length - 1];
    return last ? { seq: last.seq, hash: last.hash } : null;
  }

  async insertIfHead(entry: StoredLedgerEntry): Promise<"inserted" | "conflict"> {
    await Promise.resolve();
    const last = this.rows[this.rows.length - 1];
    const ok = last
      ? entry.seq === last.seq + 1 && entry.prev_hash === last.hash
      : entry.seq === 1 && entry.prev_hash === GENESIS_PREV_HASH;
    if (!ok) return "conflict";
    this.rows.push({ ...entry });
    return "inserted";
  }

  async scanAscending(afterSeq: number, limit: number): Promise<StoredLedgerEntry[]> {
    return [...this.rows]
      .sort((a, b) => a.seq - b.seq)
      .filter((r) => r.seq > afterSeq)
      .slice(0, limit)
      .map((r) => ({ ...r }));
  }

  async listNewestFirst(opts: { limit: number; client_id?: string; capability?: string }): Promise<StoredLedgerEntry[]> {
    return [...this.rows]
      .sort((a, b) => b.seq - a.seq)
      .filter((r) => (opts.client_id ? r.client_id === opts.client_id : true))
      .filter((r) => (opts.capability ? r.capability === opts.capability : true))
      .slice(0, opts.limit)
      .map((r) => ({ ...r }));
  }

  /** TEST ONLY: simulate an attacker editing a stored row in place. */
  tamperForTests(seq: number, patch: Record<string, unknown>): void {
    const row = this.rows.find((r) => r.seq === seq);
    if (!row) throw new Error(`no row ${seq}`);
    Object.assign(row, patch);
  }

  /** TEST ONLY: simulate an attacker deleting a stored row. */
  deleteForTests(seq: number): void {
    this.rows = this.rows.filter((r) => r.seq !== seq);
  }
}

type SqlQuery = Pick<Sql, "query">;

const COLUMNS =
  "seq, id, ts, prev_hash, hash, hmac, client_id, capability, resource, decision, tier, result, approval_id, credential_ref, http_status, error, duration_ms, task, credential_path, fallback_reason";

function rowToEntry(row: Record<string, unknown>): StoredLedgerEntry {
  const entry: StoredLedgerEntry = {
    seq: Number(row.seq),
    id: String(row.id),
    timestamp: String(row.ts),
    prev_hash: String(row.prev_hash),
    hash: String(row.hash),
    client_id: String(row.client_id),
    capability: String(row.capability),
    resource: String(row.resource),
    decision: String(row.decision) as Decision,
    tier: Number(row.tier) as Tier,
    result: String(row.result) as LedgerResult,
  };
  if (row.hmac != null) entry.hmac = String(row.hmac);
  if (row.approval_id != null) entry.approval_id = String(row.approval_id);
  if (row.credential_ref != null) entry.credential_ref = String(row.credential_ref);
  if (row.http_status != null) entry.http_status = Number(row.http_status);
  if (row.error != null) entry.error = String(row.error);
  if (row.duration_ms != null) entry.duration_ms = Number(row.duration_ms);
  if (row.task != null) entry.task = String(row.task);
  if (row.credential_path != null) entry.credential_path = String(row.credential_path) as StoredLedgerEntry["credential_path"];
  if (row.fallback_reason != null) entry.fallback_reason = String(row.fallback_reason);
  return entry;
}

async function defaultGetSql(): Promise<SqlQuery> {
  // Lazy: db.ts opens PGLite / a pg pool on first use, which unit tests must
  // avoid. It works under Vite and under plain `node` (stdio transport), where
  // PGLite persists to ECHO_VAULT_DATA_DIR.
  const db = await import("../../db.ts");
  return db.getSql();
}

/**
 * Postgres/PGLite store over `migrations/0003_vault_ledger.sql`. Each append
 * is ONE autocommit statement (the shared `Sql` surface has no transactions):
 * an INSERT…SELECT guarded by "the head is exactly what I read", plus the
 * PRIMARY KEY(seq) / UNIQUE(prev_hash) constraints with ON CONFLICT DO NOTHING.
 * Under concurrency the loser blocks on the unique index, inserts nothing,
 * gets zero rows back, and the Ledger retries from the new head.
 */
export class SqlLedgerStore implements LedgerStore {
  readonly kind = "sql";
  private readonly getSql: () => Promise<SqlQuery>;

  constructor(getSql: () => Promise<SqlQuery> = defaultGetSql) {
    this.getSql = getSql;
  }

  async head(): Promise<LedgerHead | null> {
    const sql = await this.getSql();
    const rows = await sql.query<{ seq: unknown; hash: unknown }>(
      "SELECT seq, hash FROM vault_ledger ORDER BY seq DESC LIMIT 1",
    );
    const row = rows[0];
    return row ? { seq: Number(row.seq), hash: String(row.hash) } : null;
  }

  async insertIfHead(e: StoredLedgerEntry): Promise<"inserted" | "conflict"> {
    const sql = await this.getSql();
    const rows = await sql.query(
      `INSERT INTO vault_ledger (${COLUMNS})
       SELECT $1::bigint, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text, $9::text,
              $10::text, $11::smallint, $12::text, $13::text, $14::text, $15::integer, $16::text, $17::bigint,
              $18::text, $19::text, $20::text
       WHERE CASE WHEN $1::bigint = 1
                  THEN $4::text = '${GENESIS_PREV_HASH}' AND NOT EXISTS (SELECT 1 FROM vault_ledger)
                  ELSE EXISTS (SELECT 1 FROM vault_ledger WHERE seq = $1::bigint - 1 AND hash = $4::text)
                       AND NOT EXISTS (SELECT 1 FROM vault_ledger WHERE seq >= $1::bigint)
             END
       ON CONFLICT DO NOTHING
       RETURNING seq`,
      [
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
        e.fallback_reason ?? null,
      ],
    );
    return rows.length === 1 ? "inserted" : "conflict";
  }

  async scanAscending(afterSeq: number, limit: number): Promise<StoredLedgerEntry[]> {
    const sql = await this.getSql();
    const rows = await sql.query<Record<string, unknown>>(
      `SELECT ${COLUMNS} FROM vault_ledger WHERE seq > $1::bigint ORDER BY seq ASC LIMIT $2::integer`,
      [afterSeq, limit],
    );
    return rows.map(rowToEntry);
  }

  async listNewestFirst(opts: { limit: number; client_id?: string; capability?: string }): Promise<StoredLedgerEntry[]> {
    const sql = await this.getSql();
    const rows = await sql.query<Record<string, unknown>>(
      `SELECT ${COLUMNS} FROM vault_ledger
       WHERE ($1::text IS NULL OR client_id = $1::text) AND ($2::text IS NULL OR capability = $2::text)
       ORDER BY seq DESC LIMIT $3::integer`,
      [opts.client_id ?? null, opts.capability ?? null, opts.limit],
    );
    return rows.map(rowToEntry);
  }
}

// ---------------------------------------------------------------------------
// Module-level API (default: SQL store + env HMAC key)
// ---------------------------------------------------------------------------

let defaultLedger: Ledger | null = null;

function getDefaultLedger(): Ledger {
  defaultLedger ??= new Ledger({ store: new SqlLedgerStore(), hmacKey: process.env[LEDGER_HMAC_ENV] ?? null });
  return defaultLedger;
}

/** Replace the process-wide ledger (tests, or an integrator wiring a custom store). */
export function configureLedger(opts: LedgerOptions): Ledger {
  defaultLedger = new Ledger(opts);
  return defaultLedger;
}

/** The process-wide ledger instance (ledger-anchor.ts verifies and reads its head). */
export function getLedger(): Ledger {
  return getDefaultLedger();
}

export function resetLedgerForTests(): void {
  defaultLedger = null;
}

export async function appendLedger(input: LedgerEntryInput): Promise<LedgerEntry> {
  return getDefaultLedger().append(input);
}

export async function verifyLedger(): Promise<LedgerVerifyResult> {
  return getDefaultLedger().verify();
}

export async function listLedger(opts: LedgerListOptions = {}): Promise<LedgerEntry[]> {
  return getDefaultLedger().list(opts);
}

/** Ascending page of the default ledger (seq > afterSeq). */
export async function scanLedger(afterSeq: number, limit?: number): Promise<LedgerEntry[]> {
  return getDefaultLedger().scan(afterSeq, limit);
}

/** Current head, for anchoring outside the database (detects tail truncation). */
export async function ledgerHead(): Promise<LedgerHead | null> {
  return getDefaultLedger().head();
}
