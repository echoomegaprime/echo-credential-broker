// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 shared rate-limit state.
 *
 * The two limiters — `SlidingWindowRateLimiter` (policy-engine.ts, per rule and
 * client) and `FailureRateLimiter` (oauth-server.ts, failed token attempts) —
 * keep no state of their own. They delegate to a `RateLimitStore`, so limits
 * survive a restart and hold across every server instance that shares the
 * database.
 *
 * Model: an exact sliding window. Each key maps to the timestamps (epoch ms)
 * of its events that are still inside the window; an event at time `t` is
 * live at `now` while `t > now - windowMs`.
 *
 * Storage (`SqlRateLimitStore`, migrations/0010_vault_rate_limits.sql): one row
 * per key with a `bigint[]` of live timestamps. `hit` is a single
 * `insert … on conflict (key) do update … where <live count> < <limit>`
 * statement; the row lock taken by ON CONFLICT DO UPDATE serializes concurrent
 * hits on one key and its WHERE is evaluated against the latest committed row,
 * so a limited hit is atomic across processes: N parallel hits against limit L
 * record exactly min(N, L). Trade-offs:
 *   - Time is the CALLER's clock (`now`), not the database's, so tests can
 *     inject a clock and both stores behave identically. Instances whose clocks
 *     disagree by d ms see window edges shifted by up to d ms.
 *   - A row is rewritten on every hit, so cost grows with the limit; a key
 *     holds at most MAX_EVENTS_PER_KEY (10 000) timestamps and limits above that
 *     are clamped down to it (stricter, never looser).
 *   - `count` and the `count`/`oldestAt` returned by a refused `hit` are plain
 *     reads and may be momentarily stale under concurrency; only the
 *     record-or-refuse decision of a limited `hit` is exact.
 *
 * Keys: `<namespace>:<sha256 hex>`, built ONLY by `rateLimitKey`. The parts
 * (rule id, client id, …) are hashed, so a token, code or secret can never
 * become a key, a SQL row or a log field. Both stores refuse any other shape.
 */
import { createHash } from "node:crypto";
import type { Sql } from "../../db.ts";
import { log } from "../log.ts";

export interface RateLimitCount {
  /** Events inside the window at `now`. */
  count: number;
  /** Timestamp (epoch ms) of the oldest event inside the window, or null when there is none. */
  oldestAt: number | null;
}

export interface RateLimitHit extends RateLimitCount {
  /** Whether this call recorded an event. Always true for an unlimited hit. */
  recorded: boolean;
}

/** The minimum both limiters need. Every method may reject when the store is unreachable. */
export interface RateLimitStore {
  readonly kind: "memory" | "sql";
  /**
   * Atomically record one event at `now`.
   * With `limit`, the event is recorded only when fewer than `limit` events are
   * inside the window (`recorded: false` otherwise, nothing stored). Without
   * `limit` the event is always recorded.
   * `count` / `oldestAt` describe the window after the call.
   */
  hit(key: string, windowMs: number, now: number, limit?: number): Promise<RateLimitHit>;
  /** In-window count without recording. */
  count(key: string, windowMs: number, now: number): Promise<RateLimitCount>;
  /** Forget one key. */
  reset(key: string): Promise<void>;
  /** Delete keys whose every event has left its window at `now`. Returns how many were removed. */
  prune(now: number): Promise<number>;
}

/** Thrown by the limiters when the store cannot be reached. Callers fail closed. */
export class RateLimitUnavailableError extends Error {
  readonly code = "rate_limit_unavailable";
  readonly op: string;
  constructor(op: string) {
    super("rate_limit_unavailable");
    this.name = "RateLimitUnavailableError";
    this.op = op;
  }
}

/** Hard cap on timestamps kept per key (and so on any enforceable limit). */
export const MAX_EVENTS_PER_KEY = 10_000;
const MAX_WINDOW_MS = 31 * 24 * 60 * 60 * 1000;
const DEFAULT_PRUNE_INTERVAL_MS = 60_000;

const NAMESPACE_PATTERN = /^[a-z0-9_.-]{1,40}$/;
export const RATE_LIMIT_KEY_PATTERN = /^[a-z0-9_.-]{1,40}:[0-9a-f]{64}$/;

/**
 * The only way to build a key. `namespace` is a fixed, code-chosen label;
 * `parts` (identifiers, never meant to be secrets — but hashed regardless) are
 * reduced to a sha256, so nothing a caller supplied appears in the key.
 */
export function rateLimitKey(namespace: string, ...parts: string[]): string {
  if (!NAMESPACE_PATTERN.test(namespace)) throw new Error("invalid_rate_limit_namespace");
  const digest = createHash("sha256").update(JSON.stringify(parts)).digest("hex");
  return `${namespace}:${digest}`;
}

function checkKey(key: string): void {
  if (typeof key !== "string" || !RATE_LIMIT_KEY_PATTERN.test(key)) throw new Error("invalid_rate_limit_key");
}

function checkWindow(windowMs: number): void {
  if (!Number.isInteger(windowMs) || windowMs < 1 || windowMs > MAX_WINDOW_MS) throw new Error("invalid_rate_limit_window");
}

function checkNow(now: number): number {
  if (!Number.isFinite(now)) throw new Error("invalid_rate_limit_time");
  return Math.floor(now);
}

/** undefined = unlimited; otherwise a non-negative integer clamped to MAX_EVENTS_PER_KEY. */
function checkLimit(limit: number | undefined): number | undefined {
  if (limit === undefined) return undefined;
  if (!Number.isInteger(limit) || limit < 0) throw new Error("invalid_rate_limit_limit");
  return Math.min(limit, MAX_EVENTS_PER_KEY);
}

function summarize(live: number[]): RateLimitCount {
  return { count: live.length, oldestAt: live.length ? Math.min(...live) : null };
}

interface MemoryRow {
  hits: number[];
  expiresAt: number;
}

/** In-process store (tests / explicit single-process wiring). Same semantics as the SQL store. */
export class MemoryRateLimitStore implements RateLimitStore {
  readonly kind = "memory" as const;
  private readonly rows = new Map<string, MemoryRow>();
  private readonly maxKeys: number;
  private readonly pruneIntervalMs: number;
  private lastPrune = Number.NEGATIVE_INFINITY;

  constructor(opts: { maxKeys?: number; pruneIntervalMs?: number } = {}) {
    this.maxKeys = opts.maxKeys ?? 10_000;
    this.pruneIntervalMs = opts.pruneIntervalMs ?? DEFAULT_PRUNE_INTERVAL_MS;
  }

  private live(key: string, windowMs: number, now: number): number[] {
    const cutoff = now - windowMs;
    return (this.rows.get(key)?.hits ?? []).filter((t) => t > cutoff);
  }

  async hit(key: string, windowMs: number, nowRaw: number, limitRaw?: number): Promise<RateLimitHit> {
    checkKey(key);
    checkWindow(windowMs);
    const now = checkNow(nowRaw);
    const limit = checkLimit(limitRaw);
    if (now - this.lastPrune >= this.pruneIntervalMs) {
      this.lastPrune = now;
      await this.prune(now);
    }
    const live = this.live(key, windowMs, now);
    if (limit !== undefined && live.length >= limit) return { recorded: false, ...summarize(live) };
    live.push(now);
    live.sort((a, b) => a - b);
    const kept = live.slice(-MAX_EVENTS_PER_KEY);
    const existing = this.rows.get(key);
    if (!existing && this.rows.size >= this.maxKeys) {
      const oldest = this.rows.keys().next().value;
      if (oldest !== undefined) this.rows.delete(oldest);
    }
    this.rows.set(key, { hits: kept, expiresAt: Math.max(existing?.expiresAt ?? 0, now + windowMs) });
    return { recorded: true, ...summarize(kept) };
  }

  async count(key: string, windowMs: number, nowRaw: number): Promise<RateLimitCount> {
    checkKey(key);
    checkWindow(windowMs);
    return summarize(this.live(key, windowMs, checkNow(nowRaw)));
  }

  async reset(key: string): Promise<void> {
    checkKey(key);
    this.rows.delete(key);
  }

  async prune(nowRaw: number): Promise<number> {
    const now = checkNow(nowRaw);
    let removed = 0;
    for (const [key, row] of this.rows) {
      if (row.expiresAt <= now) {
        this.rows.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  /** Test helpers (not part of RateLimitStore). */
  clear(): void {
    this.rows.clear();
    this.lastPrune = Number.NEGATIVE_INFINITY;
  }

  keys(): string[] {
    return [...this.rows.keys()];
  }
}

type SqlQuery = Pick<Sql, "query">;

function toNum(v: unknown): number | null {
  return v == null ? null : Number(v);
}

const LIVE = "(select h from unnest(r.hits) as h where h > $2::bigint - $3::bigint)";

/** Postgres/PGLite store over `vault_rate_limits` (migrations/0010_vault_rate_limits.sql). */
export class SqlRateLimitStore implements RateLimitStore {
  readonly kind = "sql" as const;
  private readonly getSql: () => Promise<SqlQuery>;
  private readonly pruneIntervalMs: number;
  private lastPrune = Number.NEGATIVE_INFINITY;

  constructor(getSql?: () => Promise<SqlQuery>, opts: { pruneIntervalMs?: number } = {}) {
    this.getSql =
      getSql ??
      (async () => {
        const db = await import("../../db.ts");
        return db.getSql();
      });
    this.pruneIntervalMs = opts.pruneIntervalMs ?? DEFAULT_PRUNE_INTERVAL_MS;
  }

  async hit(key: string, windowMs: number, nowRaw: number, limitRaw?: number): Promise<RateLimitHit> {
    checkKey(key);
    checkWindow(windowMs);
    const now = checkNow(nowRaw);
    const limit = checkLimit(limitRaw);
    if (limit === 0) return { recorded: false, ...(await this.count(key, windowMs, now)) };
    const sql = await this.getSql();
    // One statement: insert the first event, or — under the row lock, against
    // the latest committed row — drop expired events and append this one, but
    // only while the live count is under the limit ($4 null = unlimited).
    const rows = await sql.query<Record<string, unknown>>(
      `insert into vault_rate_limits as r (key, hits, expires_at)
       values ($1, array[$2::bigint], to_timestamp(($2::bigint + $3::bigint) / 1000.0))
       on conflict (key) do update
         set hits = (select array_agg(s.h order by s.h)
                       from (select h from unnest(r.hits || $2::bigint) as h
                              where h > $2::bigint - $3::bigint
                              order by h desc
                              limit $5::integer) as s),
             expires_at = greatest(r.expires_at, excluded.expires_at)
         where $4::integer is null or (select count(*) from ${LIVE} as live) < $4::integer
       returning cardinality(r.hits) as count, (select min(h) from unnest(r.hits) as h) as oldest_at`,
      [key, now, windowMs, limit ?? null, limit ?? MAX_EVENTS_PER_KEY],
    );
    if (now - this.lastPrune >= this.pruneIntervalMs) {
      this.lastPrune = now;
      // Opportunistic and best effort: a failed prune must not fail the hit.
      await this.prune(now).catch(() => {
        log.warn("rate_limit_prune_failed", { store: this.kind });
      });
    }
    if (rows.length === 0) return { recorded: false, ...(await this.count(key, windowMs, now)) };
    return { recorded: true, count: Number(rows[0].count), oldestAt: toNum(rows[0].oldest_at) };
  }

  async count(key: string, windowMs: number, nowRaw: number): Promise<RateLimitCount> {
    checkKey(key);
    checkWindow(windowMs);
    const now = checkNow(nowRaw);
    const sql = await this.getSql();
    const rows = await sql.query<Record<string, unknown>>(
      `select count(live.h) as count, min(live.h) as oldest_at
         from vault_rate_limits as r, lateral ${LIVE} as live
        where r.key = $1`,
      [key, now, windowMs],
    );
    return { count: Number(rows[0]?.count ?? 0), oldestAt: toNum(rows[0]?.oldest_at) };
  }

  async reset(key: string): Promise<void> {
    checkKey(key);
    const sql = await this.getSql();
    await sql.query("delete from vault_rate_limits where key = $1", [key]);
  }

  async prune(nowRaw: number): Promise<number> {
    const now = checkNow(nowRaw);
    const sql = await this.getSql();
    const rows = await sql.query(
      "delete from vault_rate_limits where expires_at <= to_timestamp($1::bigint / 1000.0) returning key",
      [now],
    );
    return rows.length;
  }
}

let defaultStore: RateLimitStore | null = null;

/** SQL by default (Postgres when DATABASE_URL is set, otherwise the embedded PGLite). */
export function getDefaultRateLimitStore(): RateLimitStore {
  defaultStore ??= new SqlRateLimitStore();
  return defaultStore;
}

/** Wiring/test hook. Pass null to restore the SQL default. */
export function setDefaultRateLimitStore(store: RateLimitStore | null): void {
  defaultStore = store;
}

/**
 * Run one store operation for a limiter: any failure is logged (no key, no
 * driver message — only the operation and error class) and rethrown as
 * RateLimitUnavailableError so the caller can fail closed.
 */
export async function withRateLimitStore<T>(
  store: RateLimitStore,
  op: string,
  run: (store: RateLimitStore) => Promise<T>,
): Promise<T> {
  try {
    return await run(store);
  } catch (err) {
    log.error("rate_limit_store_error", {
      op,
      store: store.kind,
      error_class: err instanceof Error ? err.name : "unknown",
    });
    throw new RateLimitUnavailableError(op);
  }
}
