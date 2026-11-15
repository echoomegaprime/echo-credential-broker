// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { registerSecretForRedaction } from "../redaction.ts";
import { canonicalJson, type LedgerEntryInput } from "./contracts.ts";
import {
  appendLedger,
  computeLedgerHash,
  configureLedger,
  GENESIS_PREV_HASH,
  Ledger,
  ledgerHead,
  listLedger,
  MemoryLedgerStore,
  resetLedgerForTests,
  SqlLedgerStore,
  verifyLedger,
} from "./ledger.ts";

const HMAC_KEY = "test-only-ledger-hmac-key-0123456789abcdef";

function input(i: number, extra: Partial<LedgerEntryInput> = {}): LedgerEntryInput {
  return {
    client_id: i % 2 === 0 ? "oc_alpha" : "local:stdio",
    capability: i % 3 === 0 ? "github.repo.transfer" : "github.repo.read",
    resource: `github:echoomegaprime/repo-${i}`,
    decision: "allow",
    tier: 0,
    result: "ok",
    credential_ref: "vault://github/echoomegaprime",
    http_status: 200,
    duration_ms: 12,
    ...extra,
  };
}

async function filled(n: number, opts: { hmacKey?: string } = {}) {
  const store = new MemoryLedgerStore();
  const ledger = new Ledger({ store, hmacKey: opts.hmacKey });
  for (let i = 1; i <= n; i += 1) await ledger.append(input(i, { approval_id: `ap_${i}`, error: i === 2 ? "boom" : undefined }));
  return { store, ledger };
}

describe("ledger hash chain", () => {
  it("links genesis → n with sha256(prev_hash + canonicalJson(entry sans hash))", async () => {
    const { ledger } = await filled(5);
    const entries = (await ledger.list({ limit: 10 })).reverse();
    assert.deepEqual(entries.map((e) => e.seq), [1, 2, 3, 4, 5]);
    assert.equal(entries[0].prev_hash, GENESIS_PREV_HASH);
    assert.equal(GENESIS_PREV_HASH, "0".repeat(64));
    for (let i = 0; i < entries.length; i += 1) {
      const { hash, ...body } = entries[i];
      const expected = createHash("sha256").update(body.prev_hash + canonicalJson(body)).digest("hex");
      assert.equal(hash, expected, `hash of seq ${entries[i].seq}`);
      assert.equal(computeLedgerHash(body), hash);
      if (i > 0) assert.equal(entries[i].prev_hash, entries[i - 1].hash);
    }
    assert.deepEqual(await ledger.verify(), { ok: true, count: 5 });
  });

  it("verifies an empty ledger", async () => {
    const ledger = new Ledger({ store: new MemoryLedgerStore() });
    assert.deepEqual(await ledger.verify(), { ok: true, count: 0 });
    assert.equal(await ledger.head(), null);
  });

  const TAMPERS: Array<[string, unknown]> = [
    ["client_id", "oc_mallory"],
    ["capability", "github.repo.read"],
    ["resource", "github:echoomegaprime/other"],
    ["decision", "deny"],
    ["tier", 3],
    ["result", "error"],
    ["approval_id", "ap_forged"],
    ["credential_ref", "vault://github/bobmcwilliams4"],
    ["http_status", 500],
    ["error", "rewritten"],
    ["duration_ms", 999],
    ["timestamp", "2020-01-01T00:00:00.000Z"],
    ["id", "00000000-0000-0000-0000-000000000000"],
    ["prev_hash", "f".repeat(64)],
    ["hash", "e".repeat(64)],
  ];
  for (const [field, value] of TAMPERS) {
    it(`detects tampering with ${field} at the right seq`, async () => {
      const { store, ledger } = await filled(5);
      store.tamperForTests(3, { [field]: value });
      const result = await ledger.verify();
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.broken_at_seq, 3, result.reason);
    });
  }

  it("detects an optional field being removed or added", async () => {
    const { store, ledger } = await filled(5);
    store.tamperForTests(4, { approval_id: undefined });
    const r1 = await ledger.verify();
    assert.equal(!r1.ok && r1.broken_at_seq, 4);
    const second = await filled(5);
    second.store.tamperForTests(1, { error: "added later" });
    const r2 = await second.ledger.verify();
    assert.equal(!r2.ok && r2.broken_at_seq, 1);
  });

  it("detects a deleted row and a renumbered row", async () => {
    const a = await filled(6);
    a.store.deleteForTests(4);
    const r1 = await a.ledger.verify();
    assert.equal(r1.ok, false);
    if (!r1.ok) {
      assert.equal(r1.broken_at_seq, 4);
      assert.match(r1.reason, /seq_gap/);
    }
    const b = await filled(6);
    b.store.tamperForTests(2, { seq: 60 });
    const r2 = await b.ledger.verify();
    assert.equal(!r2.ok && r2.broken_at_seq, 2);
  });

  it("does not let a stray stored property change what is hashed", async () => {
    const { store, ledger } = await filled(3);
    store.tamperForTests(2, { injected: "ignored" });
    assert.deepEqual(await ledger.verify(), { ok: true, count: 3 });
    const listed = await ledger.list();
    assert.equal(listed.some((e) => "injected" in e), false);
  });
});

describe("ledger concurrency", () => {
  it("keeps one valid chain under 50 concurrent appends", async () => {
    const ledger = new Ledger({ store: new MemoryLedgerStore() });
    const results = await Promise.all(Array.from({ length: 50 }, (_, i) => ledger.append(input(i))));
    assert.deepEqual(
      results.map((r) => r.seq).sort((a, b) => a - b),
      Array.from({ length: 50 }, (_, i) => i + 1),
    );
    assert.deepEqual(await ledger.verify(), { ok: true, count: 50 });
  });

  it("two independent writers (no shared queue) on one store never fork the chain", async () => {
    const store = new MemoryLedgerStore();
    const a = new Ledger({ store });
    const b = new Ledger({ store });
    await Promise.all(
      Array.from({ length: 50 }, (_, i) => (i % 2 === 0 ? a : b).append(input(i, { client_id: i % 2 ? "b" : "a" }))),
    );
    assert.deepEqual(await a.verify(), { ok: true, count: 50 });
    const all = await a.list({ limit: 100 });
    assert.equal(new Set(all.map((e) => e.prev_hash)).size, 50, "each predecessor used exactly once");
  });
});

describe("ledger secret hygiene", () => {
  const PAT = "github_pat_TESTONLY_LEDGER_ABCDEF0123456789XYZW";
  const GHP = "ghp_TESTONLYLEDGER0000000000000000abcd";
  const GHS_NEW = "ghs_1234567_eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjM0NTY3In0.c2lnbmF0dXJlLXRlc3Qtb25seQ";
  const JWT = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjM0NTYifQ.dGVzdC1zaWduYXR1cmUtb25seQ";
  const RANDOM = "Zq8xT3mN7pL2vR9kW4sB6yH1jD5fG0cA";
  const KNOWN = "plain-known-secret-value-registered";
  const PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEtestonly\n-----END RSA PRIVATE KEY-----";

  it("redacts or strips secrets in every string field before hashing/storing", async () => {
    registerSecretForRedaction(KNOWN);
    const store = new MemoryLedgerStore();
    const ledger = new Ledger({ store });
    const entry = await ledger.append({
      client_id: `oc_x ${GHP}`,
      capability: `github.repo.read ${PAT}`,
      resource: `github:echoomegaprime/x?token=${RANDOM}`,
      decision: "deny",
      tier: 1,
      result: "error",
      approval_id: `ap ${JWT}`,
      credential_ref: PAT, // not a vault:// ref → dropped
      error: `failed Authorization: Bearer ${GHS_NEW} ${KNOWN} ${PEM} ${GHS_NEW}`,
      // @ts-expect-error — unknown keys must never be copied
      token: PAT,
    });
    const stored = JSON.stringify(await store.scanAscending(0, 10));
    const returned = JSON.stringify(entry);
    for (const secret of [PAT, GHP, GHS_NEW, JWT, RANDOM, KNOWN, "MIIEtestonly", "1234567_eyJ"]) {
      assert.equal(stored.includes(secret), false, "stored row leaked a secret");
      assert.equal(returned.includes(secret), false, "returned entry leaked a secret");
    }
    assert.equal(entry.credential_ref, undefined);
    assert.equal("token" in entry, false);
    assert.match(entry.error ?? "", /REDACTED/);
    assert.deepEqual(await ledger.verify(), { ok: true, count: 1 });
  });

  it("redacts a PEM key that shares a line with an Authorization header, and a truncated PEM", async () => {
    const ledger = new Ledger({ store: new MemoryLedgerStore() });
    const a = await ledger.append(input(1, { error: `Authorization: x ${PEM}` }));
    const b = await ledger.append(input(2, { error: `oops -----BEGIN PRIVATE KEY-----\nMIIEtestonly-truncated` }));
    assert.equal(JSON.stringify([a, b]).includes("MIIEtestonly"), false);
  });

  it("accepts vault://entry/ve_<32 hex> and nothing else under vault://entry/", async () => {
    const { ledger } = await filled(0);
    const good = `vault://entry/ve_${"ab".repeat(16)}`;
    assert.equal((await ledger.append(input(1, { credential_ref: good }))).credential_ref, good);
    for (const bad of ["vault://entry/ve_short", `vault://entry/${GHP}`, `vault://entry/ve_${"AB".repeat(16)}`, `${good}/extra`]) {
      assert.equal((await ledger.append(input(2, { credential_ref: bad }))).credential_ref, undefined, bad);
    }
  });

  it("redacts and caps task; rejects an unknown credential_path", async () => {
    const { store, ledger } = await filled(0);
    const entry = await ledger.append(input(1, { task: `deploy with ${GHP} ${"x".repeat(400)}` }));
    assert.ok(entry.task);
    assert.equal(entry.task?.includes(GHP), false);
    assert.ok((entry.task?.length ?? 0) <= 300);
    assert.equal(JSON.stringify(await store.scanAscending(0, 10)).includes(GHP), false);
    assert.equal((await ledger.append(input(2, { task: "" }))).task, undefined);
    await assert.rejects(
      ledger.append(input(3, { credential_path: "magic" as never })),
      /ledger_invalid_input:credential_path/,
    );
    const tampered = await ledger.append(input(4, { task: "original task", credential_path: "installation" }));
    store.tamperForTests(tampered.seq, { task: "rewritten task" });
    const r = await ledger.verify();
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.broken_at_seq, tampered.seq);
  });

  it("drops a vault:// ref whose account segment is a token", async () => {
    const ledger = new Ledger({ store: new MemoryLedgerStore() });
    const entry = await ledger.append(input(1, { credential_ref: `vault://github/${GHP}` }));
    assert.equal(entry.credential_ref, undefined);
    const ok = await ledger.append(input(2, { credential_ref: "vault://github/ECHO-OMEGA-PRIME" }));
    assert.equal(ok.credential_ref, "vault://github/ECHO-OMEGA-PRIME");
  });

  it("strips control characters (no log/line injection)", async () => {
    const ledger = new Ledger({ store: new MemoryLedgerStore() });
    const entry = await ledger.append(input(1, { error: "a\u0000b\u001b[31mc\r\nd" }));
    assert.equal(entry.error, "a b [31mc \nd");
  });

  it("rejects structurally invalid input", async () => {
    const ledger = new Ledger({ store: new MemoryLedgerStore() });
    const bad: Array<Partial<LedgerEntryInput> & Record<string, unknown>> = [
      { decision: "maybe" as never },
      { tier: 4 as never },
      { result: "great" as never },
      { client_id: "" },
      { http_status: 42 },
      { duration_ms: -1 },
    ];
    for (const patch of bad) {
      await assert.rejects(ledger.append({ ...input(1), ...patch } as LedgerEntryInput), /ledger_invalid_input/);
    }
    assert.deepEqual(await ledger.verify(), { ok: true, count: 0 });
  });
});

describe("ledger listing", () => {
  it("lists newest first with client/capability filters and a limit", async () => {
    const { ledger } = await filled(9);
    const all = await ledger.list();
    assert.deepEqual(all.map((e) => e.seq), [9, 8, 7, 6, 5, 4, 3, 2, 1]);
    const alpha = await ledger.list({ client_id: "oc_alpha" });
    assert.ok(alpha.length > 0 && alpha.every((e) => e.client_id === "oc_alpha"));
    const transfers = await ledger.list({ capability: "github.repo.transfer", limit: 2 });
    assert.deepEqual(transfers.map((e) => e.seq), [9, 6]);
    assert.equal((await ledger.list({ limit: 0 })).length, 1);
  });
});

describe("ledger HMAC (ECHO_VAULT_LEDGER_HMAC_KEY)", () => {
  it("refuses a short key", () => {
    assert.throws(() => new Ledger({ store: new MemoryLedgerStore(), hmacKey: "short" }), /ledger_hmac_key_too_short/);
  });

  it("catches a DB-only attacker who rewrites a row and recomputes the chain", async () => {
    const forge = async (store: MemoryLedgerStore) => {
      // Attacker edits seq 2 and recomputes every hash from there on, without the key.
      const rows = await store.scanAscending(0, 100);
      let prev = rows[0].hash;
      for (const row of rows.slice(1)) {
        const { hash: _h, hmac: _m, ...body } = row;
        if (row.seq === 2) body.resource = "github:evil/rewritten";
        body.prev_hash = prev;
        const hash = computeLedgerHash(body);
        store.tamperForTests(row.seq, { ...body, hash });
        prev = hash;
      }
    };
    const plain = await filled(4);
    await forge(plain.store);
    assert.deepEqual(await plain.ledger.verify(), { ok: true, count: 4 }, "without HMAC a full rewrite verifies");

    const keyed = await filled(4, { hmacKey: HMAC_KEY });
    assert.deepEqual(await keyed.ledger.verify(), { ok: true, count: 4 });
    await forge(keyed.store);
    const r = await keyed.ledger.verify();
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.broken_at_seq, 2);
      assert.equal(r.reason, "hmac_mismatch");
    }
  });

  it("requires an HMAC on every row once the key is set", async () => {
    const { store } = await filled(2);
    const keyed = new Ledger({ store, hmacKey: HMAC_KEY });
    const r = await keyed.verify();
    assert.equal(!r.ok && r.reason, "hmac_missing");
    assert.equal(!r.ok && r.broken_at_seq, 1);
  });

  it("stores HMAC-SHA256(key, domain + hash)", async () => {
    const { store } = await filled(1, { hmacKey: HMAC_KEY });
    const [row] = await store.scanAscending(0, 1);
    const expected = createHmac("sha256", HMAC_KEY).update(`echo-vault-ledger-v1:${row.hash}`).digest("hex");
    assert.equal(row.hmac, expected);
  });
});

describe("SQL ledger store (PGLite + migrations/0003_vault_ledger.sql)", () => {
  async function pglite() {
    const pg = new PGlite();
    await pg.waitReady;
    await pg.exec(readFileSync(new URL("../../../../migrations/0003_vault_ledger.sql", import.meta.url), "utf8"));
    const sql = {
      query: async <T,>(text: string, params: unknown[] = []) => (await pg.query<T>(text, params)).rows,
    };
    return { pg, getSql: async () => sql };
  }

  it("appends, verifies, lists, and keeps one chain across two writers", async () => {
    const { pg, getSql } = await pglite();
    const a = new Ledger({ store: new SqlLedgerStore(getSql), hmacKey: HMAC_KEY });
    const b = new Ledger({ store: new SqlLedgerStore(getSql), hmacKey: HMAC_KEY });
    await Promise.all(Array.from({ length: 30 }, (_, i) => (i % 2 ? a : b).append(input(i, { error: i === 7 ? "x" : undefined }))));
    assert.deepEqual(await a.verify(), { ok: true, count: 30 });
    const newest = await a.list({ limit: 3 });
    assert.deepEqual(newest.map((e) => e.seq), [30, 29, 28]);
    const filtered = await b.list({ capability: "github.repo.transfer", client_id: "oc_alpha" });
    assert.ok(filtered.every((e) => e.capability === "github.repo.transfer" && e.client_id === "oc_alpha"));
    assert.equal((await a.head())?.seq, 30);

    // Append-only at the database layer.
    await assert.rejects(pg.query("UPDATE vault_ledger SET result = 'ok' WHERE seq = 5"), /append-only/);
    await assert.rejects(pg.query("DELETE FROM vault_ledger WHERE seq = 5"), /append-only/);
    await assert.rejects(pg.query("TRUNCATE vault_ledger"), /append-only/);
    // A fork attempt (second child of seq 4) is refused by UNIQUE(prev_hash).
    const [row5] = await new SqlLedgerStore(getSql).scanAscending(4, 1);
    const fork = await new SqlLedgerStore(getSql).insertIfHead({ ...row5, seq: 31, id: "fork", hash: "a".repeat(64) });
    assert.equal(fork, "conflict");

    // A privileged attacker who disables the trigger is still caught at the right seq.
    await pg.exec("ALTER TABLE vault_ledger DISABLE TRIGGER vault_ledger_no_update_delete");
    await pg.query("UPDATE vault_ledger SET resource = 'github:evil/x' WHERE seq = 12");
    const r = await a.verify();
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.broken_at_seq, 12);
    await pg.close();
  });

  it("persists task, credential_path, fallback_reason and an entry ref, all covered by the hash", async () => {
    const { pg, getSql } = await pglite();
    const store = new SqlLedgerStore(getSql);
    const ledger = new Ledger({ store });
    const entryRef = `vault://entry/ve_${"0123456789abcdef".repeat(2)}`;
    const written = await ledger.append(
      input(1, {
        capability: "vault.entry.use.read",
        credential_ref: entryRef,
        task: "sync the docs repo",
        credential_path: "pat_fallback",
        fallback_reason: "transfer_requires_user_token",
      }),
    );
    assert.equal(written.credential_ref, entryRef);
    const [row] = await ledger.list({ limit: 1 });
    assert.equal(row.task, "sync the docs repo");
    assert.equal(row.credential_path, "pat_fallback");
    assert.equal(row.fallback_reason, "transfer_requires_user_token");
    assert.equal(row.credential_ref, entryRef);
    const { hash, ...body } = row;
    assert.equal(computeLedgerHash(body), hash);
    assert.deepEqual(await ledger.verify(), { ok: true, count: 1 });
    await pg.close();
  });

  it("module API appendLedger / verifyLedger / listLedger / ledgerHead", async () => {
    const { pg, getSql } = await pglite();
    configureLedger({ store: new SqlLedgerStore(getSql) });
    try {
      const first = await appendLedger(input(1));
      assert.equal(first.seq, 1);
      await appendLedger(input(2, { decision: "escalate", tier: 2, result: "pending_approval", approval_id: "ap_1" }));
      assert.deepEqual(await verifyLedger(), { ok: true, count: 2 });
      const listed = await listLedger({ limit: 5 });
      assert.equal(listed[0].result, "pending_approval");
      assert.equal(listed[0].http_status, 200);
      assert.equal(listed[1].approval_id, undefined);
      assert.equal((await ledgerHead())?.hash, listed[0].hash);
    } finally {
      resetLedgerForTests();
      await pg.close();
    }
  });
});
