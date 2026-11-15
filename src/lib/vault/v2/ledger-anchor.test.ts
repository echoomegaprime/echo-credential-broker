// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import type { LedgerEntryInput } from "./contracts.ts";
import { computeLedgerHash, Ledger, MemoryLedgerStore, SqlLedgerStore } from "./ledger.ts";
import {
  anchorHead,
  computeAnchor,
  computeAnchorMac,
  formatAnchorLine,
  MemoryAnchorStore,
  newestAnchorVerdict,
  parseAnchorLine,
  SqlAnchorStore,
  verifyAgainstAnchor,
  verifyAnchorLine,
  type AnchorDeps,
} from "./ledger-anchor.ts";

const APPROVER_ID = 424242;
const BOT_TOKEN = "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789";
const ANCHOR_KEY = "test-only-anchor-key-0123456789abcdefghij";
const BASE_ENV: NodeJS.ProcessEnv = { TELEGRAM_BOT_TOKEN: BOT_TOKEN, ECHO_VAULT_APPROVER_TELEGRAM_ID: String(APPROVER_ID) };
const SIGNED_ENV: NodeJS.ProcessEnv = { ...BASE_ENV, ECHO_VAULT_ANCHOR_KEY: ANCHOR_KEY };
const T0 = Date.parse("2026-11-14T10:00:00.000Z");
const LINE_RE = /^ECHO-VAULT-ANCHOR v1 seq=\d+ hash=[0-9a-f]{64} rows=\d+ at=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z (mac=[0-9a-f]{64}|unsigned)$/;

function input(i: number, extra: Partial<LedgerEntryInput> = {}): LedgerEntryInput {
  return {
    client_id: `oc_client_${i}`,
    capability: "github.repo.read",
    resource: `github:echoomegaprime/private-repo-${i}`,
    decision: "allow",
    tier: 0,
    result: "ok",
    credential_ref: "vault://github/echoomegaprime",
    task: `sync payroll export ${i}`,
    error: i === 2 ? "upstream said boom" : undefined,
    ...extra,
  };
}

interface Sent {
  method: string;
  payload: Record<string, unknown>;
}

function world(n: number, env: NodeJS.ProcessEnv = SIGNED_ENV, opts: { failTelegram?: boolean } = {}) {
  const sent: Sent[] = [];
  const state = { fail: opts.failTelegram === true, now: T0 };
  const telegramFetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    assert.ok(String(url).startsWith(`https://api.telegram.org/bot${BOT_TOKEN}/`));
    if (state.fail) return new Response(JSON.stringify({ ok: false, error_code: 502, description: "Bad Gateway" }), { status: 502 });
    sent.push({ method: String(url).split("/").pop() ?? "", payload: JSON.parse(String(init?.body ?? "{}")) });
    return new Response(JSON.stringify({ ok: true, result: { message_id: 7000 + sent.length } }), { status: 200 });
  }) as typeof fetch;
  const store = new MemoryLedgerStore();
  const ledger = new Ledger({ store });
  const anchors = new MemoryAnchorStore();
  const deps: AnchorDeps = { ledger, anchors, fetch: telegramFetch, env, now: () => state.now };
  const fill = async (count: number, from = 1) => {
    for (let i = from; i < from + count; i += 1) await ledger.append(input(i));
  };
  const texts = () => sent.map((s) => String(s.payload.text));
  return { sent, texts, state, store, ledger, anchors, deps, fill, ready: fill(n) };
}

describe("anchor line format", () => {
  it("formats, signs and parses a round trip; the mac is HMAC-SHA256 over the line before ' mac='", () => {
    const anchor = { seq: 12, hash: "ab".repeat(32), row_count: 12, at: "2026-11-14T10:00:00.000Z" };
    const key = Buffer.from(ANCHOR_KEY, "utf8");
    const line = formatAnchorLine(anchor, key);
    const body = `ECHO-VAULT-ANCHOR v1 seq=12 hash=${"ab".repeat(32)} rows=12 at=2026-11-14T10:00:00.000Z`;
    const mac = createHmac("sha256", ANCHOR_KEY).update(body, "utf8").digest("hex");
    assert.equal(line, `${body} mac=${mac}`);
    assert.equal(computeAnchorMac(key, anchor), mac);
    assert.deepEqual(parseAnchorLine(line), { ...anchor, mac });
    const unsigned = formatAnchorLine(anchor, null);
    assert.equal(unsigned, `${body} unsigned`);
    assert.deepEqual(parseAnchorLine(unsigned), anchor);
  });

  it("rejects every malformed line", () => {
    const good = `ECHO-VAULT-ANCHOR v1 seq=3 hash=${"0f".repeat(32)} rows=3 at=2026-11-14T10:00:00.000Z mac=${"a1".repeat(32)}`;
    assert.ok(parseAnchorLine(good));
    const bad: unknown[] = [
      undefined,
      null,
      42,
      "",
      ` ${good}`,
      `${good}\n`,
      `${good} extra=1`,
      good.replace("v1", "v2"),
      good.replace("seq=3", "seq=03"),
      good.replace("seq=3", "seq=0"),
      good.replace("seq=3", "seq=-3"),
      good.replace("seq=3", "seq=99999999999999999"),
      good.replace("rows=3", "rows=4"), // more rows than the head seq
      good.replace("rows=3", "rows=0"),
      good.replace("0f".repeat(32), "0F".repeat(32)),
      good.replace("0f".repeat(32), "0f".repeat(31)),
      good.replace("at=2026-11-14T10:00:00.000Z", "at=2026-11-14T10:00:00Z"),
      good.replace("at=2026-11-14T10:00:00.000Z", "at=2026-13-45T10:00:00.000Z"),
      good.replace("at=2026-11-14T10:00:00.000Z", "at=2026-02-30T10:00:00.000Z"),
      good.replace(` mac=${"a1".repeat(32)}`, ""),
      good.replace(` mac=${"a1".repeat(32)}`, " mac="),
      good.replace(` mac=${"a1".repeat(32)}`, ` mac=${"a1".repeat(32)} unsigned`),
      good.replace("seq=3 hash", "seq=3  hash"),
      good.replace("rows=3 ", ""),
      good.replace(/ /g, "\t"),
      `x${good}`,
      "x".repeat(5000),
    ];
    for (const line of bad) assert.equal(parseAnchorLine(line), null, JSON.stringify(line));
  });
});

describe("anchorHead", () => {
  it("sends one signed line to the owner chat, records the receipt, and skips an unchanged head", async () => {
    const w = world(5);
    await w.ready;
    const first = await anchorHead(w.deps);
    assert.equal(first.ok && first.status, "anchored");
    assert.equal(w.sent.length, 1);
    assert.equal(w.sent[0].method, "sendMessage");
    assert.equal(w.sent[0].payload.chat_id, String(APPROVER_ID));
    assert.equal(w.sent[0].payload.parse_mode, undefined);
    const text = w.texts()[0];
    assert.match(text, LINE_RE);
    const parsed = parseAnchorLine(text);
    const head = await w.ledger.head();
    assert.deepEqual(
      { seq: parsed?.seq, hash: parsed?.hash, rows: parsed?.row_count, at: parsed?.at },
      { seq: 5, hash: head?.hash, rows: 5, at: "2026-11-14T10:00:00.000Z" },
    );
    assert.equal(parsed?.mac, computeAnchorMac(Buffer.from(ANCHOR_KEY), parsed!));
    assert.deepEqual(await computeAnchor(w.store, { now: () => T0 }), { seq: 5, hash: head?.hash, row_count: 5, at: "2026-11-14T10:00:00.000Z" });

    const record = await w.anchors.latest("telegram");
    assert.deepEqual(record, { seq: 5, hash: head?.hash, row_count: 5, anchored_at: parsed?.at, channel: "telegram", external_id: "7001", mac: parsed?.mac });
    if (first.ok && first.status === "anchored") assert.equal(first.external_id, "7001");

    // Head has not moved: no second message, no second record.
    w.state.now += 3_600_000;
    const second = await anchorHead(w.deps);
    assert.deepEqual(second, { ok: true, status: "unchanged", seq: 5, anchored_at: parsed?.at, channel: "telegram", external_id: "7001" });
    assert.equal(w.sent.length, 1);
    assert.equal(w.anchors.size, 1);

    // Head moved: a new anchor.
    await w.fill(2, 6);
    const third = await anchorHead(w.deps);
    assert.equal(third.ok && third.status === "anchored" && third.seq, 7);
    assert.equal(w.sent.length, 2);
    assert.equal(w.anchors.size, 2);
    assert.equal((await verifyAnchorLine(w.texts()[1], w.deps))?.verdict, "ok");
    assert.equal((await verifyAnchorLine(text, w.deps))?.verdict, "ok", "an older anchor still verifies after the chain grows");
  });

  it("without a key the line says 'unsigned' and carries no mac", async () => {
    const w = world(3, BASE_ENV);
    await w.ready;
    const out = await anchorHead(w.deps);
    assert.equal(out.ok && out.status === "anchored" && out.signed, false);
    assert.match(w.texts()[0], / unsigned$/);
    assert.doesNotMatch(w.texts()[0], /mac=/);
    assert.equal((await w.anchors.latest("telegram"))?.mac, undefined);
    assert.equal((await verifyAnchorLine(w.texts()[0], w.deps))?.verdict, "ok");
  });

  it("the message contains nothing from a ledger row beyond seq, hash and count", async () => {
    const w = world(4);
    await w.ready;
    await anchorHead(w.deps);
    w.store.tamperForTests(2, { resource: "github:evil/x" }); // break the chain → alert
    await anchorHead(w.deps);
    assert.equal(w.sent.length, 2);
    const rows = await w.store.scanAscending(0, 100);
    for (const text of w.texts()) {
      for (const row of rows) {
        for (const field of [row.client_id, row.capability, row.resource, row.id, row.credential_ref, row.task, row.error, row.timestamp, row.prev_hash]) {
          if (field) assert.ok(!text.includes(field), `message leaked a ledger field: ${field}`);
        }
      }
      assert.ok(!/oc_client|github|payroll|vault:\/\/|boom/.test(text));
      assert.ok(!text.includes(ANCHOR_KEY) && !text.includes(BOT_TOKEN));
    }
    assert.deepEqual(Object.keys(w.sent[0].payload).sort(), ["chat_id", "link_preview_options", "text"]);
  });

  it("an empty ledger sends nothing", async () => {
    const w = world(0);
    await w.ready;
    assert.deepEqual(await anchorHead(w.deps), { ok: true, status: "empty" });
    assert.equal(w.sent.length, 0);
    assert.equal(await computeAnchor(w.store), null);
  });

  it("a broken chain sends an ALERT, records no anchor and returns an error", async () => {
    const w = world(6);
    await w.ready;
    w.store.tamperForTests(3, { resource: "github:evil/x" });
    const out = await anchorHead(w.deps);
    assert.deepEqual(out, { ok: false, error: "ledger_unverified", reason: "hash_mismatch", seq: 3, alert_sent: true });
    assert.equal(w.sent.length, 1);
    assert.match(w.texts()[0], /^ECHO-VAULT-ANCHOR ALERT v1 reason=hash_mismatch seq=3 at=2026-11-14T10:00:00\.000Z\n/);
    assert.equal(parseAnchorLine(w.texts()[0]), null, "an alert can never be mistaken for an anchor");
    assert.equal(parseAnchorLine(w.texts()[0].split("\n")[0]), null);
    assert.equal(w.anchors.size, 0);
  });

  it("a Telegram failure is an error with no local record, and the next run anchors", async () => {
    const w = world(3, SIGNED_ENV, { failTelegram: true });
    await w.ready;
    assert.deepEqual(await anchorHead(w.deps), { ok: false, error: "telegram_http_502" });
    assert.equal(w.anchors.size, 0);
    assert.equal(await newestAnchorVerdict(w.deps), null);
    w.state.fail = false;
    assert.equal((await anchorHead(w.deps)).ok, true);
    assert.equal(w.anchors.size, 1);
  });

  it("fails closed on missing Telegram config and on a short key; nothing is sent or recorded", async () => {
    for (const [env, error] of [
      [{ ECHO_VAULT_APPROVER_TELEGRAM_ID: String(APPROVER_ID) }, "telegram_bot_token_missing"],
      [{ TELEGRAM_BOT_TOKEN: BOT_TOKEN }, "telegram_approver_missing"],
      [{ ...BASE_ENV, ECHO_VAULT_ANCHOR_KEY: "too-short" }, "anchor_key_too_short"],
    ] as Array<[NodeJS.ProcessEnv, string]>) {
      const w = world(2, env);
      await w.ready;
      assert.deepEqual(await anchorHead(w.deps), { ok: false, error });
      assert.equal(w.sent.length, 0);
      assert.equal(w.anchors.size, 0);
    }
  });

  it("refuses to anchor over a truncated or rewritten ledger (alert, no new record)", async () => {
    const t = world(6);
    await t.ready;
    await anchorHead(t.deps);
    t.store.deleteForTests(6);
    t.store.deleteForTests(5);
    assert.deepEqual(await t.ledger.verify(), { ok: true, count: 4 }, "the chain alone cannot see truncation");
    const truncated = await anchorHead(t.deps);
    assert.deepEqual(truncated, { ok: false, error: "ledger_truncated", reason: "truncated", seq: 6, alert_sent: true });
    assert.match(t.texts()[1], /^ECHO-VAULT-ANCHOR ALERT v1 reason=truncated seq=6 /);
    assert.equal(t.anchors.size, 1);

    // Rewrite the head row and recompute its hash: the chain verifies, the anchor does not.
    const r = world(4);
    await r.ready;
    await anchorHead(r.deps);
    const [row] = await r.store.scanAscending(3, 1);
    const { hash: _hash, hmac: _hmac, ...body } = { ...row, resource: "github:innocent/repo" };
    r.store.tamperForTests(4, { resource: body.resource, hash: computeLedgerHash(body) });
    assert.deepEqual(await r.ledger.verify(), { ok: true, count: 4 });
    const rewritten = await anchorHead(r.deps);
    assert.deepEqual(rewritten, { ok: false, error: "ledger_rewritten", reason: "rewritten", seq: 4, alert_sent: true });
    assert.equal(r.anchors.size, 1);
  });
});

describe("verifyAgainstAnchor", () => {
  it("ok for an untouched ledger; truncated after the last rows are deleted", async () => {
    const w = world(8);
    await w.ready;
    await anchorHead(w.deps);
    const anchor = parseAnchorLine(w.texts()[0])!;
    assert.deepEqual(await verifyAgainstAnchor(anchor, w.store, { env: SIGNED_ENV }), { verdict: "ok", mac_checked: true, known_locally: false, head_seq: 8 });
    await w.fill(3, 9);
    assert.equal((await verifyAgainstAnchor(anchor, w.store, { env: SIGNED_ENV })).verdict, "ok");

    for (const seq of [11, 10, 9, 8, 7]) w.store.deleteForTests(seq);
    assert.deepEqual(await w.ledger.verify(), { ok: true, count: 6 });
    assert.deepEqual(await verifyAgainstAnchor(anchor, w.store, { env: SIGNED_ENV }), { verdict: "truncated", mac_checked: true, known_locally: false, head_seq: 6 });
    assert.equal((await newestAnchorVerdict(w.deps))?.verdict, "truncated");
    // Deleting everything is truncation too.
    for (const seq of [6, 5, 4, 3, 2, 1]) w.store.deleteForTests(seq);
    assert.equal((await verifyAgainstAnchor(anchor, w.store, { env: SIGNED_ENV })).verdict, "truncated");
  });

  it("truncated when authenticated by the local record; anchor_ahead_of_ledger when nothing authenticates it", async () => {
    const w = world(5, BASE_ENV);
    await w.ready;
    await anchorHead(w.deps);
    const anchor = parseAnchorLine(w.texts()[0])!;
    w.store.deleteForTests(5);
    assert.deepEqual(await verifyAgainstAnchor(anchor, w.store, { env: BASE_ENV, anchors: w.anchors }), {
      verdict: "truncated",
      mac_checked: false,
      known_locally: true,
      head_seq: 4,
    });
    assert.equal((await verifyAgainstAnchor(anchor, w.store, { env: BASE_ENV })).verdict, "anchor_ahead_of_ledger");
    assert.equal((await verifyAgainstAnchor(anchor, w.store, { env: BASE_ENV, anchors: new MemoryAnchorStore() })).verdict, "anchor_ahead_of_ledger");
    // An unsigned line for a seq the ledger never reached.
    const foreign = parseAnchorLine(`ECHO-VAULT-ANCHOR v1 seq=900 hash=${"c".repeat(64)} rows=900 at=2026-11-14T10:00:00.000Z unsigned`)!;
    assert.equal((await verifyAnchorLine(formatAnchorLine(foreign, null), w.deps))?.verdict, "anchor_ahead_of_ledger");
  });

  it("rewritten when an anchored row is altered, removed from the middle, or the whole chain is rebuilt", async () => {
    const w = world(6);
    await w.ready;
    await anchorHead(w.deps);
    const anchor = parseAnchorLine(w.texts()[0])!;

    // Rebuild: a different chain of the same (and of greater) length, internally valid.
    const rebuilt = new MemoryLedgerStore();
    const other = new Ledger({ store: rebuilt });
    for (let i = 1; i <= 9; i += 1) await other.append(input(i, { resource: `github:clean/history-${i}` }));
    assert.deepEqual(await other.verify(), { ok: true, count: 9 });
    assert.equal((await verifyAgainstAnchor(anchor, rebuilt, { env: SIGNED_ENV })).verdict, "rewritten");

    // Alter the anchored row in place (hash recomputed so the row itself looks valid).
    const [row] = await w.store.scanAscending(5, 1);
    const { hash: _hash, hmac: _hmac, ...body } = { ...row, client_id: "oc_someone_else" };
    w.store.tamperForTests(6, { client_id: body.client_id, hash: computeLedgerHash(body) });
    assert.equal((await verifyAgainstAnchor(anchor, w.store, { env: SIGNED_ENV })).verdict, "rewritten");
    assert.equal((await newestAnchorVerdict(w.deps))?.verdict, "rewritten");

    // Anchored row gone while later rows exist.
    const g = world(6);
    await g.ready;
    await anchorHead(g.deps);
    const mid = parseAnchorLine(g.texts()[0])!;
    await g.fill(2, 7);
    g.store.deleteForTests(6);
    assert.equal((await verifyAgainstAnchor(mid, g.store, { env: SIGNED_ENV })).verdict, "rewritten");
    // A row below the anchor gone: fewer rows than were anchored.
    const b = world(6);
    await b.ready;
    await anchorHead(b.deps);
    b.store.deleteForTests(2);
    assert.equal((await verifyAgainstAnchor(parseAnchorLine(b.texts()[0])!, b.store, { env: SIGNED_ENV })).verdict, "truncated");
  });

  it("anchor_mac_invalid for a tampered line, a wrong key, or an unsigned line when a key is configured", async () => {
    const w = world(5);
    await w.ready;
    await anchorHead(w.deps);
    const line = w.texts()[0];
    assert.equal((await verifyAnchorLine(line, w.deps))?.verdict, "ok");
    // Attacker truncates to 3 rows and edits the line to match the new head.
    w.store.deleteForTests(5);
    w.store.deleteForTests(4);
    const head = await w.ledger.head();
    const forged = line.replace(/seq=5 hash=[0-9a-f]{64} rows=5/, `seq=3 hash=${head?.hash} rows=3`);
    assert.ok(parseAnchorLine(forged), "the forged line is well-formed");
    assert.equal((await verifyAnchorLine(forged, w.deps))?.verdict, "anchor_mac_invalid");
    assert.equal((await verifyAnchorLine(line.replace(/at=2026-11-14T10/, "at=2026-11-14T11"), w.deps))?.verdict, "anchor_mac_invalid");
    assert.equal((await verifyAnchorLine(line.replace(/mac=[0-9a-f]{64}$/, "unsigned"), w.deps))?.verdict, "anchor_mac_invalid");
    const otherKey = { ...w.deps, env: { ...BASE_ENV, ECHO_VAULT_ANCHOR_KEY: "another-test-only-anchor-key-0123456789" } };
    assert.equal((await verifyAnchorLine(line, otherKey))?.verdict, "anchor_mac_invalid");
    // The genuine line still tells the truth.
    assert.equal((await verifyAnchorLine(line, w.deps))?.verdict, "truncated");
    assert.equal(await verifyAnchorLine("not an anchor", w.deps), null);
    assert.equal((await verifyAnchorLine(`  ${line}\n`, w.deps))?.verdict, "truncated", "surrounding whitespace from a paste is tolerated by the helper");
  });
});

describe("SQL anchor store (PGlite + migrations/0008_vault_ledger_anchors.sql)", () => {
  async function pglite() {
    const pg = new PGlite();
    await pg.waitReady;
    for (const file of ["0003_vault_ledger.sql", "0008_vault_ledger_anchors.sql"]) {
      await pg.exec(readFileSync(new URL(`../../../../migrations/${file}`, import.meta.url), "utf8"));
    }
    const sql = { query: async <T,>(text: string, params: unknown[] = []) => (await pg.query<T>(text, params)).rows };
    return { pg, getSql: async () => sql };
  }

  it("records anchors, is append-only, and survives a re-run of the migration", async () => {
    const { pg, getSql } = await pglite();
    const sent: string[] = [];
    const telegramFetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      sent.push(String(JSON.parse(String(init?.body)).text));
      return new Response(JSON.stringify({ ok: true, result: { message_id: 100 + sent.length } }), { status: 200 });
    }) as typeof fetch;
    const ledger = new Ledger({ store: new SqlLedgerStore(getSql) });
    const anchors = new SqlAnchorStore(getSql);
    const deps: AnchorDeps = { ledger, anchors, fetch: telegramFetch, env: SIGNED_ENV, now: () => T0 };
    for (let i = 1; i <= 4; i += 1) await ledger.append(input(i));

    const first = await anchorHead(deps);
    assert.equal(first.ok && first.status, "anchored");
    assert.equal((await anchorHead(deps)).ok && sent.length, 1);
    const parsed = parseAnchorLine(sent[0])!;
    assert.deepEqual(await anchors.latest("telegram"), {
      seq: 4,
      hash: parsed.hash,
      row_count: 4,
      anchored_at: "2026-11-14T10:00:00.000Z",
      channel: "telegram",
      external_id: "101",
      mac: parsed.mac,
    });
    assert.deepEqual(await anchors.find(4, "telegram"), await anchors.latest("telegram"));
    assert.equal(await anchors.find(4, "other"), null);
    assert.equal(await anchors.insert({ ...(await anchors.latest("telegram"))!, hash: "f".repeat(64) }), "exists");
    assert.equal((await anchors.latest("telegram"))?.hash, parsed.hash, "an existing anchor is never overwritten");
    assert.deepEqual(await newestAnchorVerdict(deps), { seq: 4, anchored_at: "2026-11-14T10:00:00.000Z", verdict: "ok" });

    await assert.rejects(pg.query("UPDATE vault_ledger_anchors SET hash = repeat('0', 64) WHERE seq = 4"), /append-only/);
    await assert.rejects(pg.query("DELETE FROM vault_ledger_anchors WHERE seq = 4"), /append-only/);
    await assert.rejects(pg.query("TRUNCATE vault_ledger_anchors"), /append-only/);
    await assert.rejects(
      pg.query("INSERT INTO vault_ledger_anchors (seq, hash, row_count, anchored_at, channel, external_id) VALUES (9, 'nothex', 9, now(), 'telegram', '1')"),
    );
    // Idempotent migration: re-running keeps the rows and the triggers.
    await pg.exec(readFileSync(new URL("../../../../migrations/0008_vault_ledger_anchors.sql", import.meta.url), "utf8"));
    await assert.rejects(pg.query("DELETE FROM vault_ledger_anchors"), /append-only/);

    // Tail truncation by a privileged writer who disables the ledger trigger.
    await pg.exec("ALTER TABLE vault_ledger DISABLE TRIGGER vault_ledger_no_update_delete");
    await pg.query("DELETE FROM vault_ledger WHERE seq >= 3");
    assert.deepEqual(await ledger.verify(), { ok: true, count: 2 });
    assert.equal((await newestAnchorVerdict(deps))?.verdict, "truncated");
    assert.equal((await verifyAnchorLine(sent[0], deps))?.verdict, "truncated");
    const out = await anchorHead(deps);
    assert.equal(out.ok === false && out.error, "ledger_truncated");
    await pg.close();
  });
});
