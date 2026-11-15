// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Digest tests. Memory ledger with an injected clock, in-memory stores, a fake
 * Telegram fetch, and PGlite for the state-table migration. No network.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, describe, it } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import type { CardsDeps, EntryMetadata, EntryStore } from "./cards.ts";
import type { LedgerEntry, LedgerEntryInput } from "./contracts.ts";
import {
  buildDigest,
  denialBurstThreshold,
  DIGEST_MAX_TEXT,
  DIGEST_TRUNCATED_TAIL,
  formatDigest,
  MemoryDigestStateStore,
  resolveDigestWindow,
  sendDailyDigest,
  sendDigest,
  SqlDigestStateStore,
  type Digest,
  type DigestDeps,
  type DigestLedgerSource,
} from "./digest.ts";
import { MemoryEntryGrantStore } from "./entry-grants.ts";
import { GENESIS_PREV_HASH, Ledger, MemoryLedgerStore } from "./ledger.ts";

const TOKEN = "246813579:AAG_TESTONLY_digest_bot_token_never_leak_2468";
const APPROVER = "777000222";
const ENV: NodeJS.ProcessEnv = { TELEGRAM_BOT_TOKEN: TOKEN, ECHO_VAULT_APPROVER_TELEGRAM_ID: APPROVER };

const DAY = "2026-11-13";
const WINDOW = { from: `${DAY}T00:00:00.000Z`, to: "2026-11-14T00:00:00.000Z" };
/** "Now" for the runner: five minutes into the next UTC day. */
const NOW = Date.parse("2026-11-14T00:05:00.000Z");

const ENTRY_A = `ve_${"a".repeat(32)}`;
const ENTRY_B = `ve_${"b".repeat(32)}`;
const ENTRY_C = `ve_${"c".repeat(32)}`;
const AP = (n: number) => `ap${n}${"A".repeat(21)}`;

// vault logger lines go to stderr; keep them out of the report and scan them for secrets at the end.
const captured: string[] = [];
let restoreStderr: (() => void) | null = null;
before(() => {
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: unknown) => {
    captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  restoreStderr = () => {
    process.stderr.write = orig as typeof process.stderr.write;
  };
});
after(() => {
  restoreStderr?.();
  assert.equal(captured.join("\n").includes(TOKEN), false, "the bot token reached a log line");
});

function fakeTelegram(mode: "ok" | "api_error" | "throw" = "ok") {
  const calls: Array<{ method: string; body: Record<string, unknown> }> = [];
  const state = { mode };
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    assert.ok(url.startsWith("https://api.telegram.org/bot"), "digest fetch used for a non-telegram URL");
    calls.push({ method: url.split("/").pop() ?? "", body: JSON.parse(String(init?.body ?? "{}")) });
    if (state.mode === "throw") throw new TypeError(`request to ${url} failed`);
    if (state.mode === "api_error") {
      return new Response(JSON.stringify({ ok: false, error_code: 429, description: `flood on ${url}` }), { status: 429 });
    }
    return new Response(JSON.stringify({ ok: true, result: { message_id: 9000 + calls.length } }), { status: 200 });
  }) as typeof fetch;
  return { calls, fetch: fetchImpl, state };
}

function entry(id: string, label: string, status: EntryMetadata["status"], updatedAt: string): EntryMetadata {
  return {
    id,
    ref: `vault://entry/${id}`,
    site: "example.com",
    account: "acct",
    purpose: "",
    label,
    kind: "api_key",
    is_default: false,
    status,
    fingerprint: "00000000",
    secret_length: 20,
    created_at: "2026-11-01T00:00:00.000Z",
    updated_at: updatedAt,
    last_used_at: null,
    last_verified_at: null,
    reentry_reason: status === "needs_reentry" ? "example.com answered 401 to GET" : undefined,
  };
}

function cardsWith(entries: EntryMetadata[] | Error): CardsDeps {
  const store = {
    list: async () => {
      if (entries instanceof Error) throw entries;
      return entries;
    },
  } as unknown as EntryStore;
  return { entries: store };
}

/** A realistic mixed day. Returns the ledger plus everything a digest needs. */
async function seedDay() {
  let clock = 0;
  const ledger = new Ledger({ store: new MemoryLedgerStore(), now: () => clock });
  const add = async (iso: string, input: Partial<LedgerEntryInput> & { client_id: string }): Promise<LedgerEntry> => {
    clock = Date.parse(iso);
    return ledger.append({
      capability: "github.repo.read",
      resource: "github:echoomegaprime/echo-credential-broker",
      decision: "allow",
      tier: 0,
      result: "ok",
      ...input,
    });
  };
  const at = (hms: string) => `${DAY}T${hms}Z`;
  const use = (id: string): Partial<LedgerEntryInput> => ({
    capability: "vault.entry.use",
    resource: "entry:example.com/acct",
    credential_ref: `vault://entry/${id}`,
    task: "read the billing page",
  });
  const transfer: Partial<LedgerEntryInput> = {
    capability: "github.repo.transfer",
    resource: "github:echoomegaprime/cleanbrees",
    decision: "escalate",
    tier: 2,
  };

  // --- before the window: these clients are known
  await add("2026-11-12T10:00:00.000Z", { client_id: "oc_agent" });
  await add("2026-11-12T11:00:00.000Z", { client_id: "oc_noisy" });
  await add("2026-11-12T12:00:00.000Z", { client_id: "oc_quiet" });
  await add("2026-11-12T23:59:59.999Z", { client_id: "oc_agent" }); // last ms before `from`: excluded

  // --- the day
  await add(at("00:00:00.000"), { client_id: "oc_agent" }); // exactly `from`: included
  await add(at("01:00:00.000"), { client_id: "oc_agent", ...use(ENTRY_A) });
  await add(at("01:01:00.000"), { client_id: "oc_agent", ...use(ENTRY_A) });
  await add(at("01:02:00.000"), { client_id: "oc_agent", ...use(ENTRY_B) });
  // approved mutation that completed
  await add(at("02:00:00.000"), { client_id: "oc_agent", ...transfer, result: "pending_approval", approval_id: AP(1) });
  await add(at("02:01:00.000"), { client_id: "oc_agent", ...transfer, result: "committing", approval_id: AP(1) });
  await add(at("02:01:01.000"), {
    client_id: "oc_agent",
    ...transfer,
    result: "ok",
    approval_id: AP(1),
    task: "move the cleanbrees repository into the organization as part of the consolidation",
  });
  // approved mutation that never reported an outcome
  const del: Partial<LedgerEntryInput> = { ...transfer, capability: "github.repo.delete", resource: "github:echoomegaprime/old-site" };
  await add(at("03:00:00.000"), { client_id: "oc_agent", ...del, result: "pending_approval", approval_id: AP(2) });
  await add(at("03:01:00.000"), { client_id: "oc_agent", ...del, result: "committing", approval_id: AP(2) });
  // approval the owner refused
  await add(at("04:00:00.000"), { client_id: "oc_agent", ...transfer, result: "pending_approval", approval_id: AP(3) });
  await add(at("04:05:00.000"), { client_id: "oc_agent", ...transfer, result: "denied", approval_id: AP(3), error: "approval_denied" });
  await add(at("05:00:00.000"), { client_id: "oc_agent", result: "error", error: "http_502", http_status: 502 });
  // approved entry write (self-ledgered by cards.useEntry: no committing row)
  await add(at("06:00:00.000"), {
    client_id: "oc_agent",
    capability: "vault.entry.use.write",
    resource: "entry:example.com/acct",
    decision: "escalate",
    tier: 2,
    result: "pending_approval",
    approval_id: AP(4),
  });
  await add(at("06:01:00.000"), { client_id: "oc_agent", ...use(ENTRY_A), decision: "escalate", tier: 2, approval_id: AP(4), task: "update the webhook URL" });
  await add(at("07:00:00.000"), { client_id: "oc_agent", ...use(ENTRY_A), result: "error", error: "ledger_unavailable" });
  for (let i = 0; i < 10; i += 1) {
    await add(at(`08:00:${String(i).padStart(2, "0")}.000`), { client_id: "oc_noisy", decision: "deny", result: "denied", error: "missing_scope" });
  }
  for (let i = 0; i < 9; i += 1) {
    await add(at(`09:00:${String(i).padStart(2, "0")}.000`), {
      client_id: "oc_quiet",
      capability: "vault.secret.rotate",
      resource: "vault:*",
      decision: "deny",
      tier: 3,
      result: "denied",
      error: "tier3_human_only",
    });
  }
  await add(at("10:00:00.000"), { client_id: "oc_newbie" });
  await add(at("23:59:59.999"), { client_id: "oc_agent" }); // last ms of the window: included

  // --- after the window
  await add("2026-11-14T00:00:00.000Z", { client_id: "oc_late" }); // exactly `to`: excluded

  const grants = new MemoryEntryGrantStore();
  const grant = (client: string, id: string, grantedAt: string, expiresAt: string, uses: number | null) =>
    grants.add({
      client_id: client,
      entry_id: id,
      host: "example.com",
      path_prefix: "/v1",
      approval_id: AP(9),
      granted_at: grantedAt,
      expires_at: expiresAt,
      max_uses: uses,
      uses_remaining: uses,
    });
  await grant("oc_agent", ENTRY_A, at("01:00:00.000"), "2026-11-14T01:00:00.000Z", 500); // created in window, active
  await grant("oc_agent", ENTRY_B, "2026-11-12T01:00:00.000Z", "2026-11-20T00:00:00.000Z", null); // older, active
  await grant("oc_noisy", ENTRY_A, at("02:00:00.000"), "2026-11-13T12:00:00.000Z", 500); // created in window, expired
  await grant("oc_quiet", ENTRY_A, "2026-11-12T02:00:00.000Z", "2026-11-20T00:00:00.000Z", 0); // spent

  const cards = cardsWith([
    entry(ENTRY_A, "example.com — acct — billing", "needs_reentry", at("07:30:00.000")),
    entry(ENTRY_B, "other.com — bob — api", "needs_reentry", "2026-11-12T07:30:00.000Z"), // flagged before the window
    entry(ENTRY_C, "third.com — carol — api", "active", at("08:00:00.000")),
  ]);
  const telegram = fakeTelegram();
  const deps: DigestDeps = { ledger, cards, grants, env: ENV, now: () => NOW, fetch: telegram.fetch, state: new MemoryDigestStateStore() };
  return { ledger, deps, telegram, add, at, grants };
}

describe("resolveDigestWindow", () => {
  it("defaults to the previous full UTC day, whatever the time of day", () => {
    for (const now of ["2026-11-14T00:00:00.000Z", "2026-11-14T00:05:00.000Z", "2026-11-14T23:59:59.999Z"]) {
      assert.deepEqual(resolveDigestWindow({}, Date.parse(now)), WINDOW);
    }
    assert.deepEqual(resolveDigestWindow({}, Date.parse("2026-11-15T00:00:00.000Z")), {
      from: "2026-11-14T00:00:00.000Z",
      to: "2026-11-15T00:00:00.000Z",
    });
  });

  it("takes explicit bounds, normalizes offsets to UTC, and fills a missing bound with 24 h", () => {
    assert.deepEqual(resolveDigestWindow({ from: DAY, to: "2026-11-14" }), WINDOW);
    assert.deepEqual(resolveDigestWindow({ from: DAY }), WINDOW);
    assert.deepEqual(resolveDigestWindow({ to: "2026-11-14" }), WINDOW);
    // 18:00 at UTC-06:00 is midnight UTC the next day.
    assert.deepEqual(resolveDigestWindow({ from: "2026-11-12T18:00:00-06:00", to: "2026-11-13T18:00:00-06:00" }), WINDOW);
    assert.deepEqual(resolveDigestWindow({ from: "2026-11-13T06:00Z", to: "2026-11-13T07:30:00.5Z" }), {
      from: "2026-11-13T06:00:00.000Z",
      to: "2026-11-13T07:30:00.500Z",
    });
  });

  it("rejects zone-less times, garbage, empty and oversized windows", () => {
    const bad: Array<{ from?: string; to?: string }> = [
      { from: "2026-11-13T00:00:00" }, // local time would shift the window
      { from: "yesterday" },
      { from: "2026-13-45" },
      { from: "2026-11-14", to: "2026-11-13" },
      { from: "2026-11-13", to: "2026-11-13" },
      { from: "2024-01-01", to: "2026-11-13" },
    ];
    for (const input of bad) {
      assert.throws(() => resolveDigestWindow(input), (e: unknown) => (e as { code?: string }).code === "invalid_window", JSON.stringify(input));
    }
  });
});

describe("buildDigest on a realistic mixed day", () => {
  it("gets every count right", async () => {
    const { deps } = await seedDay();
    const d = await buildDigest(WINDOW, deps);

    assert.deepEqual(d.window, WINDOW);
    assert.equal(d.total_actions, 36);
    assert.deepEqual(d.by_result, { ok: 8, error: 2, denied: 20, pending_approval: 4, committing: 2 });
    assert.deepEqual(d.clients, [
      { client_id: "oc_agent", actions: 16, denied: 1, errors: 2, entries_used: 2 },
      { client_id: "oc_noisy", actions: 10, denied: 10, errors: 0, entries_used: 0 },
      { client_id: "oc_quiet", actions: 9, denied: 9, errors: 0, entries_used: 0 },
      { client_id: "oc_newbie", actions: 1, denied: 0, errors: 0, entries_used: 0 },
    ]);
    assert.equal(d.clients_omitted, 0);
    assert.deepEqual(d.approvals, { requested: 4, granted: 3, denied: 1, expired: 0 });

    assert.equal(d.tier2_mutations.count, 2);
    assert.deepEqual(
      d.tier2_mutations.items.map((m) => [m.capability, m.resource]),
      [
        ["github.repo.transfer", "github:echoomegaprime/cleanbrees"],
        ["vault.entry.use", "entry:example.com/acct"],
      ],
    );
    // The task is a short clipped label, never the full free text.
    const label = d.tier2_mutations.items[0].label ?? "";
    assert.ok(label.length <= 48 && label.endsWith("…") && label.startsWith("move the cleanbrees"), label);

    assert.deepEqual(d.top_denied_reasons, [
      { reason: "missing_scope", count: 10 },
      { reason: "tier3_human_only", count: 9 },
      { reason: "approval_denied", count: 1 },
    ]);
    assert.deepEqual(d.needs_reentry, [{ label: "example.com — acct — billing", flagged_at: `${DAY}T07:30:00.000Z` }]);
    assert.deepEqual(d.grants, { created: 2, active: 2 });
    assert.deepEqual(d.chain, { ok: true, count: 41 });
    assert.deepEqual(d.unavailable, []);
    assert.deepEqual(d.extra, []);
  });

  it("fires each anomaly exactly once, for the right subject", async () => {
    const { deps } = await seedDay();
    const a = (await buildDigest(WINDOW, deps)).anomalies;
    assert.deepEqual(a.new_clients, [{ client_id: "oc_newbie", first_seen: `${DAY}T10:00:00.000Z` }]);
    assert.deepEqual(a.denial_bursts, [{ client_id: "oc_noisy", denied: 10, threshold: 10 }]);
    assert.equal(a.orphan_committing.length, 1);
    assert.equal(a.orphan_committing[0].capability, "github.repo.delete");
    assert.equal(a.orphan_committing[0].resource, "github:echoomegaprime/old-site");
    assert.equal(a.orphan_committing[0].approval_ref, AP(2).slice(0, 8));
    assert.equal(a.ledger_unavailable.count, 1);
    assert.equal(a.ledger_unavailable.items[0].client_id, "oc_agent");
    assert.equal((await buildDigest(WINDOW, deps)).anomaly_count, 4);
  });

  it("denial burst threshold: >= N fires, N-1 does not, and N comes from the environment", async () => {
    const { deps } = await seedDay();
    const bursts = async (value: string | undefined) =>
      (await buildDigest(WINDOW, { ...deps, env: { ...ENV, ECHO_VAULT_DIGEST_DENIAL_BURST: value } })).anomalies.denial_bursts.map((b) => b.client_id);
    assert.deepEqual(await bursts(undefined), ["oc_noisy"]); // default 10: 10 fires, 9 does not
    assert.deepEqual(await bursts("9"), ["oc_noisy", "oc_quiet"]);
    assert.deepEqual(await bursts("11"), []);
    assert.deepEqual(await bursts("1"), ["oc_agent", "oc_noisy", "oc_quiet"]); // oc_agent has exactly one denial
    for (const junk of ["0", "-3", "abc", "2.5", ""]) assert.deepEqual(await bursts(junk), ["oc_noisy"], `junk ${junk} falls back to 10`);
    assert.equal(denialBurstThreshold({}), 10);
    assert.equal(denialBurstThreshold({ ECHO_VAULT_DIGEST_DENIAL_BURST: " 25 " }), 25);
  });

  it("an outcome row for the same approval clears the orphan, even when it lands after the window", async () => {
    const { deps, add } = await seedDay();
    await add("2026-11-14T00:00:30.000Z", {
      client_id: "oc_agent",
      capability: "github.repo.delete",
      resource: "github:echoomegaprime/old-site",
      decision: "escalate",
      tier: 2,
      result: "error",
      error: "http_500",
      approval_id: AP(2),
    });
    const d = await buildDigest(WINDOW, deps);
    assert.deepEqual(d.anomalies.orphan_committing, []);
    assert.equal(d.total_actions, 36, "the late outcome row is not counted in the window");
  });

  it("a committing row that is only seconds old is not reported as orphaned yet", async () => {
    const { deps } = await seedDay();
    const early = Date.parse(`${DAY}T03:01:30.000Z`); // 30 s after the committing row
    const window = { from: WINDOW.from, to: `${DAY}T03:02:00.000Z` };
    assert.deepEqual((await buildDigest(window, { ...deps, now: () => early })).anomalies.orphan_committing, []);
    const later = Date.parse(`${DAY}T03:04:00.000Z`);
    assert.equal((await buildDigest(window, { ...deps, now: () => later })).anomalies.orphan_committing.length, 1);
  });

  it("a client is new only on its first-ever appearance", async () => {
    const { deps } = await seedDay();
    // The day after: oc_late appears for the first time; oc_newbie is now known.
    const next = await buildDigest({ from: "2026-11-14T00:00:00.000Z", to: "2026-11-15T00:00:00.000Z" }, deps);
    assert.deepEqual(next.anomalies.new_clients.map((c) => c.client_id), ["oc_late"]);
    assert.equal(next.total_actions, 1);
  });

  it("windows are half-open and UTC: [from, to)", async () => {
    const { deps } = await seedDay();
    const count = async (from: string, to: string) => (await buildDigest({ from, to }, deps)).total_actions;
    assert.equal(await count(`${DAY}T00:00:00.000Z`, `${DAY}T00:00:00.001Z`), 1, "a row exactly at from is included");
    assert.equal(await count("2026-11-12T23:59:59.999Z", `${DAY}T00:00:00.000Z`), 1, "a row exactly at to is excluded");
    assert.equal(await count(`${DAY}T23:59:59.999Z`, "2026-11-14T00:00:00.000Z"), 1, "the last ms belongs to the day");
    assert.equal(await count("2026-11-14T00:00:00.000Z", "2026-11-14T00:00:00.001Z"), 1, "midnight belongs to the next day");
    // The same instants written with an offset select the same rows.
    assert.equal(await count("2026-11-12T19:00:00-05:00", "2026-11-13T19:00:00-05:00"), 36);
    // Adjacent windows partition the ledger: nothing is counted twice or dropped.
    const before = await count("2026-11-12T00:00:00.000Z", WINDOW.from);
    const afterDay = await count(WINDOW.to, "2026-11-15T00:00:00.000Z");
    assert.equal(before + 36 + afterDay, 41);
  });

  it("reports a broken chain as the verdict and as an anomaly", async () => {
    const store = new MemoryLedgerStore();
    let clock = Date.parse(`${DAY}T01:00:00.000Z`);
    const ledger = new Ledger({ store, now: () => clock });
    for (let i = 0; i < 3; i += 1) {
      clock += 1000;
      await ledger.append({ client_id: "oc_agent", capability: "github.repo.read", resource: "github:a/b", decision: "allow", tier: 0, result: "ok" });
    }
    store.tamperForTests(2, { resource: "github:a/EDITED" });
    const d = await buildDigest(WINDOW, { ledger, cards: cardsWith([]), grants: new MemoryEntryGrantStore(), now: () => NOW, env: ENV });
    assert.deepEqual(d.chain, { ok: false, broken_at_seq: 2, reason: "hash_mismatch" });
    const text = formatDigest(d);
    assert.match(text, /Ledger chain: BROKEN at seq 2 \(hash_mismatch\)/);
    assert.match(text, /! LEDGER CHAIN BROKEN at seq 2/);
    assert.ok(text.indexOf("LEDGER CHAIN BROKEN") < text.indexOf("TOTALS"), "the broken chain leads");
  });

  it("degrades (never invents zeros silently) when verification or a metadata source is down", async () => {
    const { deps, ledger } = await seedDay();
    const source: DigestLedgerSource = {
      scan: (afterSeq, limit) => ledger.scan(afterSeq, limit),
      verify: async () => {
        throw new Error("db down");
      },
    };
    const failingGrants = { list: async () => Promise.reject(new Error("db down")) } as unknown as MemoryEntryGrantStore;
    const d = await buildDigest(WINDOW, { ...deps, ledger: source, cards: cardsWith(new Error("db down")), grants: failingGrants });
    assert.deepEqual(d.chain, { ok: false, reason: "verify_unavailable" });
    assert.deepEqual(d.unavailable, ["entries", "grants"]);
    assert.equal(d.total_actions, 36);
    const text = formatDigest(d);
    assert.match(text, /Ledger chain: NOT VERIFIED/);
    assert.match(text, /Not included \(source unavailable\): entries, grants/);
  });

  it("pages through a ledger larger than one scan batch", async () => {
    let clock = Date.parse(`${DAY}T00:00:00.000Z`);
    const ledger = new Ledger({ store: new MemoryLedgerStore(), now: () => clock });
    for (let i = 0; i < 1203; i += 1) {
      clock += 1000;
      await ledger.append({ client_id: `oc_${i % 3}`, capability: "github.repo.read", resource: "github:a/b", decision: "allow", tier: 0, result: "ok" });
    }
    const d = await buildDigest(WINDOW, { ledger, cards: cardsWith([]), grants: new MemoryEntryGrantStore(), now: () => NOW, env: ENV });
    assert.equal(d.total_actions, 1203);
    assert.deepEqual(d.clients.map((c) => c.actions), [401, 401, 401]);
  });
});

describe("formatDigest", () => {
  it("puts the chain verdict and anomalies first, then totals and clients", async () => {
    const { deps } = await seedDay();
    const text = formatDigest(await buildDigest(WINDOW, deps));
    const lines = text.split("\n");
    assert.equal(lines[0], "ECHO Vault daily digest");
    assert.equal(lines[1], `Window: ${DAY} (UTC day)`);
    assert.equal(lines[2], "Ledger chain: OK (41 rows verified)");
    const order = ["ANOMALIES (4)", "TOTALS", "CLIENTS (4)", "TIER-2 MUTATIONS (2)", "TOP DENIED REASONS", "NEEDS RE-ENTRY (1)", "CONSENT GRANTS"].map((h) => {
      const i = lines.indexOf(h);
      assert.ok(i > 0, `missing section ${h}`);
      return i;
    });
    assert.deepEqual([...order].sort((x, y) => x - y), order);
    assert.ok(lines.includes("Actions: 36 (ok 8, error 2, denied 20, pending approval 4, committing 2)"));
    assert.ok(lines.includes("Approvals: requested 4, granted 3, denied 1, expired 0"));
    assert.ok(lines.includes("oc_agent: 16 actions, 1 denied, 2 errors, 2 entries"));
    assert.ok(lines.includes("oc_newbie: 1 action, 0 denied, 0 errors, 0 entries"));
    assert.ok(lines.includes("! New client: oc_newbie (first seen 11-13 10:00)"));
    assert.ok(lines.includes("! Denial burst: oc_noisy, 10 denials (threshold 10)"));
    assert.ok(lines.some((l) => l.startsWith("! Authorized mutation never reported: github.repo.delete on github:echoomegaprime/old-site by oc_agent")));
    assert.ok(lines.some((l) => l.startsWith("! Ledger unavailable: 1 event, first at seq")));
    assert.ok(lines.includes("Created 2, active now 2"));
    assert.ok(text.length < DIGEST_MAX_TEXT);
    // No credential ref, entry id or full approval id ever appears.
    assert.equal(/vault:\/\//.test(text), false);
    assert.equal(text.includes(ENTRY_A), false);
    assert.equal(text.includes(AP(2)), false);
  });

  it("a quiet day is short and still reports the chain verdict", async () => {
    const ledger = new Ledger({ store: new MemoryLedgerStore(), now: () => Date.parse("2026-11-10T00:00:00.000Z") });
    await ledger.append({ client_id: "oc_agent", capability: "github.repo.read", resource: "github:a/b", decision: "allow", tier: 0, result: "ok" });
    const d = await buildDigest(WINDOW, { ledger, cards: cardsWith([]), grants: new MemoryEntryGrantStore(), now: () => NOW, env: ENV });
    assert.equal(d.total_actions, 0);
    assert.equal(d.anomaly_count, 0);
    assert.equal(
      formatDigest(d),
      ["ECHO Vault daily digest", `Window: ${DAY} (UTC day)`, "Ledger chain: OK (1 rows verified)", "No activity in this window."].join("\n"),
    );
    // An empty ledger too.
    const empty = await buildDigest(WINDOW, { ledger: new Ledger({ store: new MemoryLedgerStore() }), cards: cardsWith([]), grants: new MemoryEntryGrantStore(), env: ENV });
    assert.match(formatDigest(empty), /Ledger chain: OK \(0 rows verified\)\nNo activity in this window\.$/);
  });

  it("is hard-capped at 4096 characters with a clear truncated tail, keeping the most important part", async () => {
    const { deps } = await seedDay();
    const filler = Array.from({ length: 10 }, (_, s) => async () => ({
      title: `Filler ${s}`,
      lines: Array.from({ length: 20 }, (_, i) => `section ${s} line ${i} ${"lorem ipsum ".repeat(15)}`),
    }));
    const text = formatDigest(await buildDigest(WINDOW, { ...deps, extraSections: filler }));
    assert.ok(text.length <= DIGEST_MAX_TEXT, `length ${text.length}`);
    assert.ok(text.length > DIGEST_MAX_TEXT - 300, "the budget is used, not wasted");
    assert.ok(text.endsWith(`\n${DIGEST_TRUNCATED_TAIL}`));
    assert.ok(text.startsWith("ECHO Vault daily digest\n"));
    for (const must of ["ANOMALIES (4)", "TOTALS", "CLIENTS (4)", "! New client: oc_newbie"]) assert.ok(text.includes(must), must);
    // Cut on a line boundary: the line before the tail is a complete line of the full text.
    const kept = text.slice(0, -`\n${DIGEST_TRUNCATED_TAIL}`.length).split("\n").pop() as string;
    assert.match(kept, /^(section \d+ line \d+ (lorem ipsum ?)+|FILLER \d+|)$/);
  });

  it("a short digest is not marked truncated; exactly 4096 fits, 4097 does not", async () => {
    const { deps } = await seedDay();
    const base = await buildDigest(WINDOW, deps);
    assert.equal(formatDigest(base).includes(DIGEST_TRUNCATED_TAIL), false);
    const baseLen = formatDigest({ ...base, extra: [{ title: "PAD", lines: ["x"] }] }).length;
    // "x".repeat(n) keeps one line growing; each line is clipped at 200, so pad with several lines.
    const pad = (n: number): Digest => {
      const lines: string[] = [];
      let left = n;
      while (left > 0) {
        const take = Math.min(left, 150);
        lines.push("x".repeat(take));
        left -= take + 1; // + newline
      }
      return { ...base, extra: [{ title: "PAD", lines }] };
    };
    const exact = formatDigest(pad(DIGEST_MAX_TEXT - baseLen + 1));
    assert.equal(exact.length, DIGEST_MAX_TEXT);
    assert.equal(exact.includes(DIGEST_TRUNCATED_TAIL), false);
    const over = formatDigest(pad(DIGEST_MAX_TEXT - baseLen + 2));
    assert.ok(over.length <= DIGEST_MAX_TEXT);
    assert.ok(over.endsWith(DIGEST_TRUNCATED_TAIL));
  });

  it("strips control and bidi characters, including from a hand-built digest", async () => {
    const { deps } = await seedDay();
    const base = await buildDigest(WINDOW, deps);
    const nasty = "evil\u0000\u0007\u001b[31m\u202eclient\r\nFAKE: Ledger chain: OK\u200b";
    const text = formatDigest({
      ...base,
      clients: [{ client_id: nasty, actions: 1, denied: 0, errors: 0, entries_used: 0 }],
      extra: [{ title: `t\u0000itle\nINJECTED`, lines: [nasty] }],
    });
    // eslint-disable-next-line no-control-regex -- asserting their absence is the point
    assert.equal(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e]/.test(text), false);
    assert.equal(text.split("\n").some((l) => l.startsWith("FAKE:") || l === "INJECTED"), false, "a field cannot start a line of its own");
  });
});

describe("secrets never reach the digest", () => {
  const GH = `ghp_${"TESTONLYdigest0000000000000000000001".slice(0, 36)}`;
  const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJURVNUT05MWSJ9.c2lnbmF0dXJlLVRFU1RPTkxZLTAwMDA";
  const OPENAI = "sk-TESTONLYdigest000000000000000000000002";
  const RANDOM = "Zx9Kq2Lm8Vb4Nc7Xw1Rt6Yp3Hs5Jd0FgAeUiOo12";
  const SECRETS = [GH, JWT, OPENAI, RANDOM, TOKEN];

  /** Rows as a compromised or buggy store might return them: NOT scrubbed by Ledger.append. */
  function rawSource(): DigestLedgerSource {
    const row = (seq: number, patch: Partial<LedgerEntry>): LedgerEntry => ({
      seq,
      id: `id-${seq}`,
      timestamp: `${DAY}T0${seq}:00:00.000Z`,
      prev_hash: GENESIS_PREV_HASH,
      hash: GENESIS_PREV_HASH,
      client_id: "oc_agent",
      capability: "github.repo.read",
      resource: "github:a/b",
      decision: "allow",
      tier: 0,
      result: "ok",
      ...patch,
    });
    const rows = [
      row(1, { result: "denied", decision: "deny", error: `bad token ${GH} supplied` }),
      row(2, { result: "error", error: `upstream said Authorization: Bearer ${JWT}` }),
      row(3, { tier: 2, decision: "escalate", approval_id: AP(5), task: `use ${OPENAI} to deploy`, resource: `github:a/b?token=${RANDOM}` }),
      row(4, { result: "committing", tier: 2, decision: "escalate", approval_id: AP(6), resource: `repo ${GH}`, task: GH }),
      row(5, { client_id: `oc_${GH}`, capability: `cap.${OPENAI}`, error: `ledger_unavailable ${JWT}`, result: "error" }),
    ];
    return {
      scan: async (afterSeq) => rows.filter((r) => r.seq > afterSeq),
      verify: async () => ({ ok: false, broken_at_seq: 1, reason: `hash_mismatch ${GH}` }),
    };
  }

  it("a planted secret-shaped token in task / error / resource / client fields appears nowhere", async () => {
    const telegram = fakeTelegram();
    const deps: DigestDeps = {
      ledger: rawSource(),
      cards: cardsWith([entry(ENTRY_A, `site — ${GH} — ${OPENAI}`, "needs_reentry", `${DAY}T05:00:00.000Z`)]),
      grants: new MemoryEntryGrantStore(),
      env: ENV,
      now: () => NOW,
      fetch: telegram.fetch,
      state: new MemoryDigestStateStore(),
      extraSections: [async () => ({ title: `Rotation ${GH}`, lines: [`key ${OPENAI} is due`, `jwt ${JWT}`] })],
    };
    const digest = await buildDigest(WINDOW, deps);
    const text = formatDigest(digest);
    const sent = await sendDailyDigest(deps);
    assert.equal(sent.sent, true);
    const blobs = { structured: JSON.stringify(digest), text, telegram: JSON.stringify(telegram.calls), result: JSON.stringify(sent) };
    for (const [where, blob] of Object.entries(blobs)) {
      for (const secret of SECRETS) {
        assert.equal(blob.includes(secret), false, `${where} contains a planted secret`);
        assert.equal(blob.includes(secret.slice(4, 24)), false, `${where} contains part of a planted secret`);
      }
    }
    // The rows were still counted and reported — redacted, not dropped.
    assert.equal(digest.total_actions, 5);
    assert.equal(digest.anomalies.orphan_committing.length, 1);
    assert.equal(digest.anomalies.ledger_unavailable.count, 1);
    assert.match(text, /REDACTED/);
    assert.equal(text.includes("to deploy"), true, "the non-secret part of a task label survives");
  });

  it("the structured digest carries no credential ref, entry id, request body or full task", async () => {
    const { deps } = await seedDay();
    const blob = JSON.stringify(await buildDigest(WINDOW, deps));
    assert.equal(blob.includes("vault://"), false);
    assert.equal(blob.includes(ENTRY_A), false);
    assert.equal(blob.includes("as part of the consolidation"), false, "long task text is clipped");
    assert.equal(blob.includes("answered 401"), false, "the re-entry reason is not copied");
    for (const n of [1, 2, 3, 4]) assert.equal(blob.includes(AP(n)), false, "full approval ids are not repeated");
  });
});

describe("extraSections", () => {
  it("render after the built-in sections, in order, sanitized and bounded", async () => {
    const { deps } = await seedDay();
    const seen: unknown[] = [];
    const d = await buildDigest(WINDOW, {
      ...deps,
      extraSections: [
        async (window, passed) => {
          seen.push(window, passed.env === ENV);
          return { title: "Rotation due", lines: ["github PAT: 12 days", "  spaced\tout  ", ""] };
        },
        async () => {
          throw new Error(`boom ${TOKEN}`);
        },
        async () => ({ title: "Ledger anchor", lines: Array.from({ length: 30 }, (_, i) => `anchor ${i}`) }),
      ],
    });
    assert.deepEqual(seen, [WINDOW, true]);
    assert.deepEqual(d.extra[0], { title: "Rotation due", lines: ["github PAT: 12 days", "spaced out"] });
    assert.deepEqual(d.extra[1], { title: "Section unavailable", lines: ["This section could not be built."] });
    assert.equal(d.extra[2].lines.length, 20);
    const text = formatDigest(d);
    const grantsAt = text.indexOf("CONSENT GRANTS");
    const rotationAt = text.indexOf("ROTATION DUE\ngithub PAT: 12 days\nspaced out");
    const anchorAt = text.indexOf("LEDGER ANCHOR\nanchor 0");
    assert.ok(grantsAt > 0 && rotationAt > grantsAt && anchorAt > rotationAt, text);
    assert.equal(text.includes(TOKEN), false);
  });

  it("also render on a quiet day", async () => {
    const d = await buildDigest(WINDOW, {
      ledger: new Ledger({ store: new MemoryLedgerStore() }),
      cards: cardsWith([]),
      grants: new MemoryEntryGrantStore(),
      env: ENV,
      extraSections: [async () => ({ title: "Rotation due", lines: ["nothing due"] })],
    });
    assert.match(formatDigest(d), /No activity in this window\.\n\nROTATION DUE\nnothing due$/);
  });
});

describe("sendDailyDigest", () => {
  it("sends the previous UTC day once; the second call is already_sent with no second message", async () => {
    const { deps, telegram } = await seedDay();
    const first = await sendDailyDigest(deps);
    assert.deepEqual(first, { sent: true, message_id: 9001, window: WINDOW, recorded: true });
    assert.equal(telegram.calls.length, 1);
    assert.equal(telegram.calls[0].method, "sendMessage");
    assert.equal(telegram.calls[0].body.chat_id, APPROVER);
    assert.deepEqual(telegram.calls[0].body.link_preview_options, { is_disabled: true });
    assert.equal("parse_mode" in telegram.calls[0].body, false, "plain text only");
    assert.equal(telegram.calls[0].body.text, formatDigest(await buildDigest(WINDOW, deps)));

    const second = await sendDailyDigest(deps);
    assert.deepEqual(second, { sent: false, reason: "already_sent", window: WINDOW });
    // Later the same day, and with the window spelled differently: still the same window.
    assert.equal((await sendDailyDigest({ ...deps, now: () => NOW + 12 * 3_600_000 })).sent, false);
    assert.deepEqual(await sendDailyDigest(deps, { from: DAY }), { sent: false, reason: "already_sent", window: WINDOW });
    assert.equal(telegram.calls.length, 1, "no second message");
    assert.deepEqual((await deps.state?.lastSent())?.message_id, 9001);

    // The next day is a new window.
    const tomorrow = await sendDailyDigest({ ...deps, now: () => NOW + 86_400_000 });
    assert.equal(tomorrow.sent, true);
    assert.equal(telegram.calls.length, 2);
  });

  it("an explicit window overrides the default and is tracked separately", async () => {
    const { deps, telegram } = await seedDay();
    const window = { from: `${DAY}T00:00:00.000Z`, to: `${DAY}T12:00:00.000Z` };
    const res = await sendDailyDigest(deps, window);
    assert.deepEqual(res, { sent: true, message_id: 9001, window, recorded: true });
    assert.match(String(telegram.calls[0].body.text), /Window: 2026-11-13T00:00:00\.000Z to 2026-11-13T12:00:00\.000Z \(UTC\)/);
    assert.equal((await sendDailyDigest(deps, window)).sent, false);
    assert.equal((await sendDailyDigest(deps)).sent, true, "the full day was not sent yet");
    assert.deepEqual(await sendDailyDigest(deps, { from: "garbage" }), {
      sent: false,
      reason: "invalid_window",
      detail: "from: use YYYY-MM-DD (UTC) or an ISO time with Z or an offset",
    });
  });

  it("a Telegram failure leaves the window unsent, and the retry sends it", async () => {
    for (const mode of ["api_error", "throw"] as const) {
      const { deps, telegram } = await seedDay();
      telegram.state.mode = mode;
      const failed = await sendDailyDigest(deps);
      assert.deepEqual(failed, {
        sent: false,
        reason: "telegram_failed",
        window: WINDOW,
        detail: mode === "throw" ? "telegram_network_error" : "telegram_http_429",
      });
      assert.equal(await deps.state?.lastSent(), null, "nothing is recorded as sent");
      assert.equal(JSON.stringify(failed).includes("api.telegram.org"), false);

      telegram.state.mode = "ok";
      const retry = await sendDailyDigest(deps);
      assert.equal(retry.sent, true, "the window was not marked sent by the failure");
      assert.equal(telegram.calls.length, 2);
      assert.equal((await sendDailyDigest(deps)).sent, false);
    }
  });

  it("missing Telegram configuration fails without marking the window", async () => {
    const { deps, telegram } = await seedDay();
    const noApprover = await sendDailyDigest({ ...deps, env: { TELEGRAM_BOT_TOKEN: TOKEN } });
    assert.deepEqual(noApprover, { sent: false, reason: "telegram_failed", window: WINDOW, detail: "telegram_approver_missing" });
    const noToken = await sendDailyDigest({ ...deps, env: { ECHO_VAULT_APPROVER_TELEGRAM_ID: APPROVER } });
    assert.deepEqual(noToken, { sent: false, reason: "telegram_failed", window: WINDOW, detail: "telegram_bot_token_missing" });
    assert.equal(telegram.calls.length, 0);
    assert.equal((await sendDailyDigest(deps)).sent, true);
  });

  it("a ledger that cannot be read sends nothing and releases the claim", async () => {
    const { deps, telegram, ledger } = await seedDay();
    const broken: DigestLedgerSource = { scan: async () => Promise.reject(new Error("db down")), verify: () => ledger.verify() };
    assert.deepEqual(await sendDailyDigest({ ...deps, ledger: broken }), { sent: false, reason: "build_failed", window: WINDOW });
    assert.equal(telegram.calls.length, 0);
    assert.equal((await sendDailyDigest(deps)).sent, true);
  });

  it("refuses to send when the state store is unavailable (a duplicate could not be ruled out)", async () => {
    const { deps, telegram } = await seedDay();
    const state = new MemoryDigestStateStore();
    state.claim = async () => Promise.reject(new Error("db down"));
    assert.deepEqual(await sendDailyDigest({ ...deps, state }), { sent: false, reason: "state_unavailable", window: WINDOW });
    assert.equal(telegram.calls.length, 0);
  });

  it("two concurrent runners send one message", async () => {
    const { deps, telegram } = await seedDay();
    const results = await Promise.all([sendDailyDigest(deps), sendDailyDigest(deps), sendDailyDigest(deps)]);
    assert.equal(results.filter((r) => r.sent).length, 1);
    assert.deepEqual(
      results.filter((r) => !r.sent).map((r) => (r.sent ? "" : r.reason)),
      ["in_progress", "in_progress"],
    );
    assert.equal(telegram.calls.length, 1);
  });

  it("a claim left by a crashed runner blocks for 10 minutes, then is taken over", async () => {
    const { deps, telegram } = await seedDay();
    const state = new MemoryDigestStateStore();
    assert.equal(await state.claim(WINDOW, NOW, NOW - 600_000), "claimed"); // the runner then died
    assert.deepEqual(await sendDailyDigest({ ...deps, state, now: () => NOW + 9 * 60_000 }), { sent: false, reason: "in_progress", window: WINDOW });
    assert.equal(telegram.calls.length, 0);
    assert.equal((await sendDailyDigest({ ...deps, state, now: () => NOW + 11 * 60_000 })).sent, true);
    assert.equal(telegram.calls.length, 1);
  });

  it("if recording the send fails after Telegram accepted it, the window is not re-sent right away", async () => {
    const { deps, telegram } = await seedDay();
    const state = new MemoryDigestStateStore();
    const realMark = state.markSent.bind(state);
    state.markSent = async () => Promise.reject(new Error("db down"));
    assert.deepEqual(await sendDailyDigest({ ...deps, state }), { sent: true, message_id: 9001, window: WINDOW, recorded: false });
    state.markSent = realMark;
    assert.deepEqual(await sendDailyDigest({ ...deps, state }), { sent: false, reason: "in_progress", window: WINDOW });
    assert.equal(telegram.calls.length, 1);
  });

  it("sendDigest sends a prebuilt digest under the same once-per-window rule", async () => {
    const { deps, telegram } = await seedDay();
    const digest = await buildDigest(WINDOW, deps);
    assert.equal((await sendDigest(digest, deps)).sent, true);
    assert.deepEqual(await sendDailyDigest(deps), { sent: false, reason: "already_sent", window: WINDOW });
    assert.equal(telegram.calls.length, 1);
  });
});

describe("SqlDigestStateStore over PGlite with migrations/0009_vault_digest_state.sql", () => {
  async function pglite() {
    const pg = new PGlite();
    await pg.waitReady;
    const file = readFileSync(new URL("../../../../migrations/0009_vault_digest_state.sql", import.meta.url), "utf8");
    await pg.exec(file);
    await pg.exec(file); // idempotent: the migration can be applied twice
    const sql = { query: async <T,>(text: string, params: unknown[] = []) => (await pg.query<T>(text, params)).rows };
    return { pg, store: new SqlDigestStateStore(async () => sql) };
  }

  it("claims once, records the send, and never hands the window out again", async () => {
    const { pg, store } = await pglite();
    assert.equal(await store.lastSent(), null);
    assert.equal(await store.claim(WINDOW, NOW, NOW - 600_000), "claimed");
    assert.equal(await store.claim(WINDOW, NOW + 1000, NOW + 1000 - 600_000), "in_progress");
    await store.markSent(WINDOW, 4242, NOW + 2000);
    assert.equal(await store.claim(WINDOW, NOW + 3000, NOW + 3000 - 600_000), "already_sent");
    assert.equal(await store.claim(WINDOW, NOW + 86_400_000, NOW + 86_400_000 - 600_000), "already_sent", "a sent window never goes stale");
    await store.release(WINDOW); // must not remove a sent row
    assert.deepEqual(await store.lastSent(), {
      from: WINDOW.from,
      to: WINDOW.to,
      status: "sent",
      claimed_at: new Date(NOW).toISOString(),
      sent_at: new Date(NOW + 2000).toISOString(),
      message_id: 4242,
    });
    await pg.close();
  });

  it("release frees an unsent claim; a stale claim is taken over; lastSent is the newest window", async () => {
    const { pg, store } = await pglite();
    const next = { from: WINDOW.to, to: "2026-11-15T00:00:00.000Z" };
    assert.equal(await store.claim(WINDOW, NOW, NOW - 600_000), "claimed");
    await store.release(WINDOW);
    assert.equal(await store.claim(WINDOW, NOW, NOW - 600_000), "claimed");
    // 11 minutes later the unsent claim is stale.
    const later = NOW + 11 * 60_000;
    assert.equal(await store.claim(WINDOW, later, later - 600_000), "claimed");
    assert.equal(await store.claim(WINDOW, later + 1, later + 1 - 600_000), "in_progress");
    await store.markSent(WINDOW, 1, later);
    assert.equal(await store.claim(next, later, later - 600_000), "claimed");
    await store.markSent(next, 2, later);
    assert.equal((await store.lastSent())?.message_id, 2);
    await assert.rejects(store.markSent({ from: "2026-11-01T00:00:00.000Z", to: "2026-11-02T00:00:00.000Z" }, 3, later), /digest_state_missing_claim/);
    await pg.close();
  });

  it("concurrent claims of one window: exactly one wins", async () => {
    const { pg, store } = await pglite();
    const results = await Promise.all(Array.from({ length: 8 }, () => store.claim(WINDOW, NOW, NOW - 600_000)));
    assert.equal(results.filter((r) => r === "claimed").length, 1);
    assert.equal(results.filter((r) => r === "in_progress").length, 7);
    await pg.close();
  });

  it("the table refuses malformed windows and inconsistent rows", async () => {
    const { pg } = await pglite();
    const insert = (from: string, to: string, status: string, sentAt: string | null) =>
      pg.query("insert into vault_digest_state (window_from, window_to, status, claimed_at, sent_at) values ($1, $2, $3, now(), $4)", [from, to, status, sentAt]);
    await assert.rejects(insert("2026-11-13", WINDOW.to, "sending", null));
    await assert.rejects(insert(WINDOW.to, WINDOW.from, "sending", null));
    await assert.rejects(insert(WINDOW.from, WINDOW.to, "done", null));
    await assert.rejects(insert(WINDOW.from, WINDOW.to, "sent", null));
    await assert.rejects(insert(WINDOW.from, WINDOW.to, "sending", "2026-11-14T00:00:00Z"));
    await insert(WINDOW.from, WINDOW.to, "sending", null);
    await assert.rejects(insert(WINDOW.from, WINDOW.to, "sending", null), "one row per window");
    await pg.close();
  });

  it("end to end on the SQL store: second run is already_sent", async () => {
    const { pg, store } = await pglite();
    const { deps, telegram } = await seedDay();
    assert.equal((await sendDailyDigest({ ...deps, state: store })).sent, true);
    assert.deepEqual(await sendDailyDigest({ ...deps, state: store }), { sent: false, reason: "already_sent", window: WINDOW });
    assert.equal(telegram.calls.length, 1);
    await pg.close();
  });
});
