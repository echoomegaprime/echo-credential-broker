// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Shared rate-limit state (rate-limit-store.ts): one behavioural suite run
 * against the in-memory store and against the SQL store on PGlite with the real
 * migration file, plus the two limiters (policy-engine.ts, oauth-server.ts)
 * over each store: cross-instance visibility, restart survival, exact counts
 * under parallel hits, pruning, key hygiene and store-failure behaviour.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, describe, it } from "node:test";
import { FailureRateLimiter, limiterKey } from "./oauth-server.ts";
import { SlidingWindowRateLimiter, policyRateLimitKey } from "./policy-engine.ts";
import {
  MAX_EVENTS_PER_KEY,
  MemoryRateLimitStore,
  RATE_LIMIT_KEY_PATTERN,
  RateLimitUnavailableError,
  SqlRateLimitStore,
  getDefaultRateLimitStore,
  rateLimitKey,
  setDefaultRateLimitStore,
  type RateLimitStore,
} from "./rate-limit-store.ts";

const T0 = Date.UTC(2026, 10, 14, 12, 0, 0);
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const RAW_TOKEN = `evr_${"S".repeat(43)}`;
const CLIENT_ID = `oc_${"c".repeat(22)}`;

interface Fixture {
  /** A store over fresh, empty state. */
  store: RateLimitStore;
  /** Another store object over the SAME state (a second process / a restart). */
  again: () => RateLimitStore;
  /** Every key currently stored. */
  keys: () => Promise<string[]>;
}

function runSuite(name: string, make: (opts?: { pruneIntervalMs?: number }) => Promise<Fixture>): void {
  describe(`rate-limit store — ${name}`, () => {
    const K1 = rateLimitKey("test", "one");
    const K2 = rateLimitKey("test", "two");

    it("an unlimited hit always records and reports the window", async () => {
      const { store } = await make();
      assert.deepEqual(await store.hit(K1, HOUR, T0), { recorded: true, count: 1, oldestAt: T0 });
      assert.deepEqual(await store.hit(K1, HOUR, T0 + 5), { recorded: true, count: 2, oldestAt: T0 });
      assert.deepEqual(await store.count(K1, HOUR, T0 + 5), { count: 2, oldestAt: T0 });
    });

    it("a limited hit records only while under the limit and stores nothing when refused", async () => {
      const { store } = await make();
      assert.equal((await store.hit(K1, HOUR, T0, 2)).recorded, true);
      assert.equal((await store.hit(K1, HOUR, T0 + 1, 2)).recorded, true);
      assert.deepEqual(await store.hit(K1, HOUR, T0 + 2, 2), { recorded: false, count: 2, oldestAt: T0 });
      assert.deepEqual(await store.hit(K1, HOUR, T0 + 3, 2), { recorded: false, count: 2, oldestAt: T0 });
      assert.deepEqual(await store.count(K1, HOUR, T0 + 3), { count: 2, oldestAt: T0 });
    });

    it("limit 0 never records, even on an empty key", async () => {
      const { store, keys } = await make();
      assert.deepEqual(await store.hit(K1, HOUR, T0, 0), { recorded: false, count: 0, oldestAt: null });
      assert.deepEqual(await keys(), []);
    });

    it("count does not record and an unknown key is empty", async () => {
      const { store, keys } = await make();
      assert.deepEqual(await store.count(K1, HOUR, T0), { count: 0, oldestAt: null });
      assert.deepEqual(await keys(), []);
    });

    it("events leave the window exactly windowMs after they happened", async () => {
      const { store } = await make();
      await store.hit(K1, HOUR, T0);
      await store.hit(K1, HOUR, T0 + 10 * MINUTE);
      assert.equal((await store.count(K1, HOUR, T0 + HOUR - 1)).count, 2);
      assert.deepEqual(await store.count(K1, HOUR, T0 + HOUR), { count: 1, oldestAt: T0 + 10 * MINUTE });
      assert.deepEqual(await store.count(K1, HOUR, T0 + HOUR + 10 * MINUTE), { count: 0, oldestAt: null });
      // A freed slot can be taken again; the expired events are dropped from the row.
      assert.deepEqual(await store.hit(K1, HOUR, T0 + HOUR, 2), { recorded: true, count: 2, oldestAt: T0 + 10 * MINUTE });
      assert.equal((await store.hit(K1, HOUR, T0 + HOUR + 1, 2)).recorded, false);
    });

    it("keys are independent and reset forgets only its own key", async () => {
      const { store, keys } = await make();
      await store.hit(K1, HOUR, T0);
      await store.hit(K2, HOUR, T0);
      await store.hit(K2, HOUR, T0 + 1);
      assert.equal((await store.count(K1, HOUR, T0 + 1)).count, 1);
      assert.equal((await store.count(K2, HOUR, T0 + 1)).count, 2);
      await store.reset(K2);
      assert.equal((await store.count(K2, HOUR, T0 + 1)).count, 0);
      assert.equal((await store.count(K1, HOUR, T0 + 1)).count, 1);
      assert.deepEqual(await keys(), [K1]);
      await store.reset(K2); // idempotent
    });

    it("prune removes only keys whose every event has expired", async () => {
      const { store, keys } = await make();
      await store.hit(K1, MINUTE, T0); // expires at T0 + 1 min
      await store.hit(K2, HOUR, T0); // expires at T0 + 1 h
      assert.equal(await store.prune(T0 + MINUTE - 1), 0);
      assert.deepEqual((await keys()).sort(), [K1, K2].sort());
      assert.equal(await store.prune(T0 + MINUTE), 1);
      assert.deepEqual(await keys(), [K2]);
      assert.equal((await store.count(K2, HOUR, T0 + MINUTE)).count, 1);
      assert.equal(await store.prune(T0 + HOUR), 1);
      assert.deepEqual(await keys(), []);
    });

    it("a later hit keeps the key alive past the first event's expiry", async () => {
      const { store, keys } = await make();
      await store.hit(K1, MINUTE, T0);
      await store.hit(K1, MINUTE, T0 + 30_000);
      assert.equal(await store.prune(T0 + MINUTE), 0);
      assert.deepEqual(await keys(), [K1]);
      assert.equal(await store.prune(T0 + MINUTE + 30_000), 1);
    });

    it("hits prune expired keys opportunistically, so the table cannot grow without bound", async () => {
      const { store, keys } = await make({ pruneIntervalMs: 1000 });
      for (let i = 0; i < 20; i += 1) await store.hit(rateLimitKey("test", `burst-${i}`), 100, T0 + i);
      assert.equal((await keys()).length, 20);
      // Past every burst key's window and past the prune interval: one hit sweeps them.
      await store.hit(K1, HOUR, T0 + 5000);
      assert.deepEqual(await keys(), [K1]);
    });

    it("N parallel limited hits record exactly the limit", async () => {
      const { store } = await make();
      const results = await Promise.all(Array.from({ length: 50 }, (_, i) => store.hit(K1, HOUR, T0 + i, 20)));
      assert.equal(results.filter((r) => r.recorded).length, 20);
      assert.equal((await store.count(K1, HOUR, T0 + 50)).count, 20);
    });

    it("N parallel unlimited hits are all counted", async () => {
      const { store } = await make();
      await Promise.all(Array.from({ length: 40 }, (_, i) => store.hit(K1, HOUR, T0 + i)));
      assert.deepEqual(await store.count(K1, HOUR, T0 + 40), { count: 40, oldestAt: T0 });
    });

    it("a second store object over the same state sees the hits (cross-process / restart)", async () => {
      const { store, again } = await make();
      await store.hit(K1, HOUR, T0, 3);
      const other = again();
      assert.equal((await other.count(K1, HOUR, T0 + 1)).count, 1);
      await other.hit(K1, HOUR, T0 + 1, 3);
      await store.hit(K1, HOUR, T0 + 2, 3);
      assert.equal((await other.hit(K1, HOUR, T0 + 3, 3)).recorded, false);
      assert.equal((await again().count(K1, HOUR, T0 + 3)).count, 3);
    });

    it("refuses any key that is not <namespace>:<sha256> — a raw token can never be stored", async () => {
      const { store, keys } = await make();
      for (const bad of [RAW_TOKEN, `client:${RAW_TOKEN}`, "client:oc_abc", "", `policy:${"A".repeat(64)}`]) {
        await assert.rejects(store.hit(bad, HOUR, T0), /invalid_rate_limit_key/);
        await assert.rejects(store.count(bad, HOUR, T0), /invalid_rate_limit_key/);
        await assert.rejects(store.reset(bad), /invalid_rate_limit_key/);
      }
      assert.deepEqual(await keys(), []);
    });

    it("rejects nonsense windows, limits and clocks", async () => {
      const { store } = await make();
      await assert.rejects(store.hit(K1, 0, T0), /invalid_rate_limit_window/);
      await assert.rejects(store.hit(K1, 1.5, T0), /invalid_rate_limit_window/);
      await assert.rejects(store.hit(K1, HOUR, T0, -1), /invalid_rate_limit_limit/);
      await assert.rejects(store.hit(K1, HOUR, Number.NaN), /invalid_rate_limit_time/);
    });

    // ------------------------------------------------------------ limiters

    it("policy limiter: two instances over one store see each other's hits", async () => {
      const { store, again } = await make();
      const a = new SlidingWindowRateLimiter(HOUR, store);
      const b = new SlidingWindowRateLimiter(HOUR, again());
      const key = policyRateLimitKey("rl", "oc_test");
      assert.equal(await a.tryRecord(key, 2, T0), true);
      assert.equal(await b.wouldExceed(key, 2, T0 + 1), false);
      assert.equal(await b.tryRecord(key, 2, T0 + 1), true);
      assert.equal(await a.wouldExceed(key, 2, T0 + 2), true);
      assert.equal(await a.tryRecord(key, 2, T0 + 2), false);
      assert.equal(await b.tryRecord(key, 2, T0 + 2), false);
    });

    it("policy limiter: state survives constructing a new limiter over the same store", async () => {
      const { store, again } = await make();
      const key = policyRateLimitKey("rl", "oc_test");
      const before = new SlidingWindowRateLimiter(HOUR, store);
      await before.record(key, T0);
      await before.record(key, T0 + 1);
      const restarted = new SlidingWindowRateLimiter(HOUR, again());
      assert.equal(await restarted.wouldExceed(key, 2, T0 + 2), true);
      assert.equal(await restarted.wouldExceed(key, 2, T0 + HOUR + 1), false);
      await restarted.reset(key);
      assert.equal(await before.wouldExceed(key, 1, T0 + 2), false);
    });

    it("policy limiter: parallel tryRecord through two instances admits exactly max", async () => {
      const { store, again } = await make();
      const limiters = [new SlidingWindowRateLimiter(HOUR, store), new SlidingWindowRateLimiter(HOUR, again())];
      const key = policyRateLimitKey("rl", "oc_parallel");
      const admitted = await Promise.all(Array.from({ length: 30 }, (_, i) => limiters[i % 2].tryRecord(key, 7, T0 + i)));
      assert.equal(admitted.filter(Boolean).length, 7);
    });

    it("failure limiter: shared across instances, survives a restart, same Retry-After arithmetic", async () => {
      const { store, again } = await make();
      let now = T0;
      const opts = { now: () => now, maxFailures: 3, windowMs: 5 * MINUTE };
      const a = new FailureRateLimiter({ ...opts, store });
      const b = new FailureRateLimiter({ ...opts, store: again() });
      const key = limiterKey("not a client id");
      assert.equal(await a.retryAfterMs(key), 0);
      await a.recordFailure(key);
      now += 1000;
      await b.recordFailure(key);
      assert.equal(await a.retryAfterMs(key), 0);
      now += 1000;
      await a.recordFailure(key);
      // Blocked on every instance until the OLDEST failure leaves the window.
      assert.equal(await a.retryAfterMs(key), 5 * MINUTE - 2000);
      assert.equal(await b.retryAfterMs(key), 5 * MINUTE - 2000);
      const restarted = new FailureRateLimiter({ ...opts, store: again() });
      assert.equal(await restarted.retryAfterMs(key), 5 * MINUTE - 2000);
      now = T0 + 5 * MINUTE - 1;
      assert.equal(await restarted.retryAfterMs(key), 1);
      now = T0 + 5 * MINUTE;
      assert.equal(await restarted.retryAfterMs(key), 0);
      await b.recordFailure(key);
      assert.ok((await a.retryAfterMs(key)) > 0);
      await a.reset(key);
      assert.equal(await b.retryAfterMs(key), 0);
    });

    it("limiter keys are hashed: no client id, rule id or token appears in the store", async () => {
      const { store, keys } = await make();
      const failures = new FailureRateLimiter({ now: () => T0, store });
      await failures.recordFailure(limiterKey(RAW_TOKEN)); // a token pasted as client_id
      await failures.recordFailure(limiterKey(CLIENT_ID));
      await new SlidingWindowRateLimiter(HOUR, store).record(policyRateLimitKey("rule-with-secret-looking-id", "oc_client"), T0);
      const stored = await keys();
      assert.equal(stored.length, 3);
      for (const key of stored) {
        assert.match(key, RATE_LIMIT_KEY_PATTERN);
        for (const raw of [RAW_TOKEN, CLIENT_ID, "oc_client", "rule-with-secret-looking-id", "malformed"]) {
          assert.equal(key.includes(raw), false);
        }
      }
    });
  });
}

runSuite("memory", async (opts) => {
  const store = new MemoryRateLimitStore(opts);
  return { store, again: () => store, keys: async () => store.keys() };
});

// One PGlite instance for the suite; the table is emptied for each fixture.
let pglite: Promise<import("@electric-sql/pglite").PGlite> | null = null;
async function sqlFixture(opts?: { pruneIntervalMs?: number }): Promise<Fixture & { pg: import("@electric-sql/pglite").PGlite }> {
  pglite ??= (async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const pg = new PGlite();
    await pg.exec(readFileSync(new URL("../../../../migrations/0010_vault_rate_limits.sql", import.meta.url), "utf8"));
    return pg;
  })();
  const pg = await pglite;
  await pg.exec("delete from vault_rate_limits");
  const getSql = async () => ({
    query: async <T>(text: string, params?: unknown[]) => (await pg.query<T>(text, params)).rows,
  });
  // A long default interval keeps the opportunistic prune out of tests that count rows.
  const storeOpts = { pruneIntervalMs: opts?.pruneIntervalMs ?? 365 * 24 * HOUR };
  return {
    pg,
    store: new SqlRateLimitStore(getSql, storeOpts),
    again: () => new SqlRateLimitStore(getSql, storeOpts),
    keys: async () => (await pg.query<{ key: string }>("select key from vault_rate_limits order by key")).rows.map((r) => r.key),
  };
}

runSuite("sql on PGlite (migrations/0010_vault_rate_limits.sql)", sqlFixture);

describe("rate-limit store — SQL specifics (PGlite)", () => {
  const K = rateLimitKey("test", "sql");

  it("the table itself refuses a key that is not a hash, and empty or oversized rows", async () => {
    const { pg } = await sqlFixture();
    const insert = (key: string, hits: string) =>
      pg.query(`insert into vault_rate_limits (key, hits, expires_at) values ($1, ${hits}, now())`, [key]);
    await assert.rejects(insert(`client:${RAW_TOKEN}`, "array[1::bigint]"));
    await assert.rejects(insert(RAW_TOKEN, "array[1::bigint]"));
    await assert.rejects(insert(K, "'{}'::bigint[]"));
    await insert(K, "array[1::bigint]");
  });

  it("a row holds only the hashed key, live timestamps and an expiry", async () => {
    const { pg, store } = await sqlFixture();
    await store.hit(K, HOUR, T0);
    await store.hit(K, HOUR, T0 + 10 * MINUTE);
    await store.hit(K, HOUR, T0 + HOUR + 1); // T0 has left the window and is dropped
    const rows = (await pg.query<{ key: string; hits: unknown[]; expires_at: Date }>("select * from vault_rate_limits")).rows;
    assert.equal(rows.length, 1);
    assert.deepEqual(Object.keys(rows[0]).sort(), ["expires_at", "hits", "key"]);
    assert.equal(rows[0].key, K);
    assert.deepEqual(rows[0].hits.map(Number), [T0 + 10 * MINUTE, T0 + HOUR + 1]);
    assert.equal(new Date(rows[0].expires_at).getTime(), T0 + 2 * HOUR + 1);
  });

  it("an unlimited key keeps at most MAX_EVENTS_PER_KEY timestamps (newest win)", async () => {
    const { pg, store } = await sqlFixture();
    await pg.query(
      `insert into vault_rate_limits (key, hits, expires_at)
       select $1, array_agg(g order by g), now() from generate_series($2::bigint, $2::bigint + $3::bigint - 1) as g`,
      [K, T0, MAX_EVENTS_PER_KEY],
    );
    const hit = await store.hit(K, HOUR, T0 + MAX_EVENTS_PER_KEY);
    assert.deepEqual(hit, { recorded: true, count: MAX_EVENTS_PER_KEY, oldestAt: T0 + 1 });
  });

  it("a limit above MAX_EVENTS_PER_KEY is clamped down to it", async () => {
    const { pg, store } = await sqlFixture();
    await pg.query(
      `insert into vault_rate_limits (key, hits, expires_at)
       select $1, array_agg(g order by g), now() from generate_series($2::bigint, $2::bigint + $3::bigint - 1) as g`,
      [K, T0, MAX_EVENTS_PER_KEY],
    );
    assert.equal((await store.hit(K, HOUR, T0 + MAX_EVENTS_PER_KEY, MAX_EVENTS_PER_KEY * 5)).recorded, false);
  });

  it("the default store is SQL and works through db.ts with every migration applied", async () => {
    setDefaultRateLimitStore(null);
    const store = getDefaultRateLimitStore();
    assert.equal(store.kind, "sql");
    const key = rateLimitKey("test", "default-store");
    try {
      assert.equal((await store.hit(key, HOUR, T0, 1)).recorded, true);
      assert.equal((await store.hit(key, HOUR, T0 + 1, 1)).recorded, false);
      // A limiter with no explicit store uses the same default.
      assert.equal(await new SlidingWindowRateLimiter().wouldExceed(key, 1, T0 + 2), true);
      await store.reset(key);
      assert.equal((await store.count(key, HOUR, T0 + 2)).count, 0);
    } finally {
      const db = await import("../../db.ts");
      await db.closeDb();
    }
  });
});

describe("rate-limit store — failure and key helpers", () => {
  class DownStore implements RateLimitStore {
    readonly kind = "sql" as const;
    calls = 0;
    private fail(): never {
      this.calls += 1;
      throw new Error(`connect ECONNREFUSED postgres://vault:${RAW_TOKEN}@db.internal/vault`);
    }
    async hit(): Promise<never> {
      return this.fail();
    }
    async count(): Promise<never> {
      return this.fail();
    }
    async reset(): Promise<never> {
      return this.fail();
    }
    async prune(): Promise<never> {
      return this.fail();
    }
  }

  async function captureStderr(run: () => Promise<void>): Promise<string> {
    const original = process.stderr.write.bind(process.stderr);
    let out = "";
    process.stderr.write = ((chunk: string | Uint8Array) => {
      out += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
      return true;
    }) as typeof process.stderr.write;
    try {
      await run();
    } finally {
      process.stderr.write = original;
    }
    return out;
  }

  it("both limiters reject with RateLimitUnavailableError when the store is down, and the log carries no key or driver message", async () => {
    const down = new DownStore();
    const policy = new SlidingWindowRateLimiter(HOUR, down);
    const failures = new FailureRateLimiter({ now: () => T0, store: down });
    const key = limiterKey(CLIENT_ID);
    const logged = await captureStderr(async () => {
      for (const attempt of [
        () => policy.wouldExceed(key, 1, T0),
        () => policy.tryRecord(key, 1, T0),
        () => policy.record(key, T0),
        () => policy.reset(key),
        () => failures.retryAfterMs(key),
        () => failures.recordFailure(key),
        () => failures.reset(key),
      ]) {
        await assert.rejects(attempt(), (err: unknown) => {
          assert.ok(err instanceof RateLimitUnavailableError);
          assert.equal(err.code, "rate_limit_unavailable");
          assert.equal(err.message, "rate_limit_unavailable");
          return true;
        });
      }
    });
    assert.equal(down.calls, 7);
    assert.match(logged, /rate_limit_store_error/);
    assert.equal(logged.includes(RAW_TOKEN), false);
    assert.equal(logged.includes("ECONNREFUSED"), false);
    assert.equal(logged.includes(key), false);
  });

  it("a failed opportunistic prune does not fail the hit", async () => {
    const { pg } = await sqlFixture();
    let failPrune = true;
    const store = new SqlRateLimitStore(
      async () => ({
        query: async <T>(text: string, params?: unknown[]) => {
          if (failPrune && text.startsWith("delete from vault_rate_limits where expires_at")) throw new Error("boom");
          return (await pg.query<T>(text, params)).rows;
        },
      }),
      { pruneIntervalMs: 1 },
    );
    const key = rateLimitKey("test", "prune-fail");
    const logged = await captureStderr(async () => {
      assert.equal((await store.hit(key, HOUR, T0)).recorded, true);
    });
    assert.match(logged, /rate_limit_prune_failed/);
    failPrune = false;
    assert.equal((await store.hit(key, HOUR, T0 + 10)).count, 2);
  });

  it("rateLimitKey is deterministic, unambiguous and never contains its parts", () => {
    const key = rateLimitKey("oauth.token", RAW_TOKEN);
    assert.match(key, RATE_LIMIT_KEY_PATTERN);
    assert.equal(key.includes(RAW_TOKEN), false);
    assert.equal(key, rateLimitKey("oauth.token", RAW_TOKEN));
    assert.notEqual(rateLimitKey("policy", "a", "b"), rateLimitKey("policy", "ab", ""));
    assert.notEqual(rateLimitKey("policy", "a", "b"), rateLimitKey("policy", "a\u0000b"));
    assert.notEqual(rateLimitKey("policy", "x"), rateLimitKey("oauth.token", "x"));
    assert.throws(() => rateLimitKey(RAW_TOKEN, "x"), /invalid_rate_limit_namespace/);
    assert.throws(() => rateLimitKey("Has Space", "x"), /invalid_rate_limit_namespace/);
  });

  it("the memory store evicts the oldest key at maxKeys", async () => {
    const store = new MemoryRateLimitStore({ maxKeys: 2 });
    const [a, b, c] = ["a", "b", "c"].map((p) => rateLimitKey("test", p));
    await store.hit(a, HOUR, T0);
    await store.hit(b, HOUR, T0);
    await store.hit(c, HOUR, T0);
    assert.deepEqual(store.keys(), [b, c]);
  });
});

after(async () => {
  if (pglite) await (await pglite).close();
});
