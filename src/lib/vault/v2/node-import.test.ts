// library-first: echo.functions.search → no existing impl found (2026-11-19)
/**
 * Node import channel. In memory throughout: approvals, rate limits, entry
 * stores, the vault backend. Telegram is a recording notifier. Fake secrets are
 * assembled at runtime so no token-shaped literal sits in the repo.
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import { FakeVaultBackend } from "../backend.ts";
import { MemoryApprovalStore, type ApprovalNotifier } from "./approvals.ts";
import { MemoryCardStore, MemoryEntryStore } from "./cards.ts";
import type { LedgerEntryInput } from "./contracts.ts";
import {
  handleImportBegin,
  handleImportFinish,
  handleImportSubmit,
  MAX_BEGINS_PER_HOUR,
  MAX_ITEMS_PER_SUBMIT,
  pairingCode,
  type NodeImportDeps,
} from "./node-import.ts";
import { MemoryRateLimitStore } from "./rate-limit-store.ts";

const SECRETS = {
  google: "AIza" + "Sy" + "B1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R",
  github: "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3lM6",
  github2: "ghp_" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9Oo8",
};
const ENV: NodeJS.ProcessEnv = {
  ECHO_VAULT_APPROVAL_HMAC_KEY: "test-only-approval-hmac-key-0123456789abcdef",
  ECHO_VAULT_APPROVER_TELEGRAM_ID: "424242",
  ECHO_VAULT_PUBLIC_URL: "https://vault.example.test/",
};

function world() {
  const approvals = new MemoryApprovalStore();
  const prompts: string[] = [];
  const notify: ApprovalNotifier = async ({ record }) => {
    prompts.push(record.summary);
  };
  const clock = { t: Date.parse("2026-11-19T05:00:00.000Z") };
  const ledger: LedgerEntryInput[] = [];
  const entries = new MemoryEntryStore();
  const deps: NodeImportDeps = {
    entries,
    cards: new MemoryCardStore(),
    backend: new FakeVaultBackend(),
    ledger: async (input) => {
      ledger.push(JSON.parse(JSON.stringify(input)));
    },
    env: ENV,
    now: () => clock.t,
    limits: new MemoryRateLimitStore(),
    approvals: { store: approvals, notify, env: ENV, ledger: async () => undefined },
  };
  const approve = async (id: string) => assert.ok(await approvals.decide(id, "approved", "424242", new Date(clock.t).toISOString()));
  const deny = async (id: string) => assert.ok(await approvals.decide(id, "denied", "424242", new Date(clock.t).toISOString()));
  return { deps, approvals, prompts, clock, ledger, entries, approve, deny };
}

const post = (path: string, body: unknown, bearer?: string) =>
  new Request(`https://vault.example.test/api/import/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
    body: JSON.stringify(body),
  });

const newSession = () => {
  const secret = randomBytes(32).toString("base64url");
  return { secret, hash: createHash("sha256").update(secret, "utf8").digest("hex") };
};

const item = (secret: string, fp: string, over: Record<string, unknown> = {}) => ({
  fingerprint: fp,
  detector: "github_token",
  provider: "github.com",
  key_name: "GITHUB_TOKEN",
  secret,
  sources: [{ path: "/home/x/.env", line: 3 }],
  ...over,
});

const TERMS = { node: "temper", planned: 2, apply: true, include_generic: false };

async function begin(w: ReturnType<typeof world>, terms = TERMS) {
  const s = newSession();
  const res = await handleImportBegin(post("begin", { ...terms, session_hash: s.hash }), w.deps);
  const body = (await res.json()) as { ok: boolean; approval_id: string; pairing_code: string };
  return { ...s, res, body };
}

const noSecrets = (value: unknown) => {
  const text = JSON.stringify(value);
  for (const s of Object.values(SECRETS)) assert.ok(!text.includes(s), "a secret value leaked");
};

describe("node import: begin", () => {
  it("asks the owner once, naming the node, the count, the mode and the pairing code", async () => {
    const w = world();
    const s = await begin(w);
    assert.equal(s.res.status, 200);
    assert.equal(s.body.pairing_code, pairingCode(s.hash));
    assert.equal(w.prompts.length, 1);
    assert.match(w.prompts[0], /up to 2 credentials found on node temper/);
    assert.match(w.prompts[0], /store them/);
    assert.ok(w.prompts[0].includes(s.body.pairing_code));
    assert.ok(!JSON.stringify(s.body).includes(s.secret));
  });

  it("rejects malformed terms without prompting the owner", async () => {
    const w = world();
    const good = { ...TERMS, session_hash: "f".repeat(64) };
    for (const bad of [
      { ...good, node: "Bad Node!" },
      { ...good, planned: 0 },
      { ...good, planned: 999999 },
      { ...good, apply: "yes" },
      { ...good, include_generic: undefined },
      { ...good, session_hash: "nothex" },
    ]) {
      assert.equal((await handleImportBegin(post("begin", bad), w.deps)).status, 400);
    }
    assert.equal(w.prompts.length, 0);
    assert.equal((await handleImportBegin(new Request("https://vault.example.test/api/import/begin"), w.deps)).status, 405);
  });

  it("is rate limited so it cannot flood the approver", async () => {
    const w = world();
    for (let i = 0; i < MAX_BEGINS_PER_HOUR; i++) assert.equal((await begin(w)).res.status, 200);
    const over = await begin(w);
    assert.equal(over.res.status, 429);
    assert.equal(w.prompts.length, MAX_BEGINS_PER_HOUR);
  });
});

describe("node import: submit", () => {
  it("stores nothing until the owner approves", async () => {
    const w = world();
    const s = await begin(w);
    const res = await handleImportSubmit(post("submit", { ...TERMS, approval_id: s.body.approval_id, items: [item(SECRETS.github, "a".repeat(16))] }, s.secret), w.deps);
    assert.equal(res.status, 409);
    assert.equal(((await res.json()) as { error: string }).error, "approval_pending");
    assert.equal((await w.entries.list({})).length, 0);
  });

  it("after approval, stores the submitted credentials and answers with labels only", async () => {
    const w = world();
    const s = await begin(w);
    await w.approve(s.body.approval_id);
    const res = await handleImportSubmit(
      post(
        "submit",
        {
          ...TERMS,
          approval_id: s.body.approval_id,
          items: [
            item(SECRETS.github, "a".repeat(16)),
            item(SECRETS.google, "b".repeat(16), { detector: "google_api_key", provider: "google.com", key_name: "YOUTUBE_API_KEY" }),
          ],
        },
        s.secret,
      ),
      w.deps,
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as { counts: Record<string, number>; entries: Array<{ label: string; status: string }> };
    noSecrets(body);
    noSecrets(w.ledger);
    assert.equal(body.counts.imported, 2);
    assert.deepEqual(body.entries.map((e) => e.status), ["imported", "imported"]);
    const stored = await w.entries.list({});
    assert.deepEqual(stored.map((e) => `${e.site}/${e.account}`).sort(), ["github.com/github_token", "google.com/youtube_api_key"]);
    assert.ok(stored.every((e) => e.purpose === "import temper/.env"));
    assert.ok(w.ledger.every((r) => r.client_id === "import:temper" && r.capability === "vault.entry.import"));
  });

  it("a preview session stores nothing", async () => {
    const w = world();
    const terms = { ...TERMS, apply: false };
    const s = await begin(w, terms);
    assert.match(w.prompts[0], /preview only/);
    await w.approve(s.body.approval_id);
    const res = await handleImportSubmit(post("submit", { ...terms, approval_id: s.body.approval_id, items: [item(SECRETS.github, "a".repeat(16))] }, s.secret), w.deps);
    const body = (await res.json()) as { dry_run: boolean; counts: Record<string, number> };
    assert.equal(body.dry_run, true);
    assert.equal(body.counts.would_import, 1);
    assert.equal((await w.entries.list({})).length, 0);
  });

  it("refuses another bearer, another node, a bigger count or a changed mode", async () => {
    const w = world();
    const s = await begin(w);
    await w.approve(s.body.approval_id);
    const items = [item(SECRETS.github, "a".repeat(16))];
    const base = { ...TERMS, approval_id: s.body.approval_id, items };
    const attempts: Array<[Record<string, unknown>, string | undefined]> = [
      [base, newSession().secret],
      [base, undefined],
      [{ ...base, node: "quench" }, s.secret],
      [{ ...base, planned: 500 }, s.secret],
      [{ ...base, include_generic: true }, s.secret],
      [{ ...base, approval_id: "ap_does_not_exist" }, s.secret],
    ];
    for (const [body, bearer] of attempts) {
      const res = await handleImportSubmit(post("submit", body, bearer), w.deps);
      assert.equal(res.status, 401, JSON.stringify(Object.keys(body)));
    }
    assert.equal((await w.entries.list({})).length, 0);
  });

  it("a denied or expired session cannot submit", async () => {
    const w = world();
    const denied = await begin(w);
    await w.deny(denied.body.approval_id);
    const items = [item(SECRETS.github, "a".repeat(16))];
    assert.equal((await handleImportSubmit(post("submit", { ...TERMS, approval_id: denied.body.approval_id, items }, denied.secret), w.deps)).status, 403);

    const late = await begin(w);
    await w.approve(late.body.approval_id);
    w.clock.t += 31 * 60 * 1000;
    assert.equal((await handleImportSubmit(post("submit", { ...TERMS, approval_id: late.body.approval_id, items }, late.secret), w.deps)).status, 410);
    assert.equal((await w.entries.list({})).length, 0);
  });

  it("never accepts more credentials than the owner was shown", async () => {
    const w = world();
    const terms = { ...TERMS, planned: 1 };
    const s = await begin(w, terms);
    await w.approve(s.body.approval_id);
    const res = await handleImportSubmit(
      post("submit", { ...terms, approval_id: s.body.approval_id, items: [item(SECRETS.github, "a".repeat(16)), item(SECRETS.github2, "c".repeat(16), { key_name: "OTHER" })] }, s.secret),
      w.deps,
    );
    const body = (await res.json()) as { counts: Record<string, number>; over_plan: number };
    assert.equal(body.counts.imported, 1);
    assert.equal(body.over_plan, 1);
    assert.equal((await w.entries.list({})).length, 1);
  });

  it("malformed items spend the approved budget, so a session cannot push unbounded secrets", async () => {
    const w = world();
    const terms = { ...TERMS, planned: 2 };
    const s = await begin(w, terms);
    await w.approve(s.body.approval_id);
    const junk = [item(SECRETS.github, "not-a-fingerprint"), item(SECRETS.github2, "also-bad")];
    const first = await handleImportSubmit(post("submit", { ...terms, approval_id: s.body.approval_id, items: junk }, s.secret), w.deps);
    assert.equal(((await first.json()) as { malformed: number }).malformed, 2);
    const second = await handleImportSubmit(post("submit", { ...terms, approval_id: s.body.approval_id, items: [item(SECRETS.google, "b".repeat(16), { detector: "google_api_key", provider: "google.com" })] }, s.secret), w.deps);
    const body = (await second.json()) as { over_plan: number; counts: Record<string, number> };
    assert.equal(body.over_plan, 1);
    assert.equal(body.counts.imported, 0);
    assert.equal((await w.entries.list({})).length, 0);
  });

  it("drops malformed items and oversize batches without storing them", async () => {
    const w = world();
    const TERMS = { node: "temper", planned: 40, apply: true, include_generic: false };
    const s = await begin(w, TERMS);
    await w.approve(s.body.approval_id);
    const bad = [
      item(SECRETS.github, "not-a-fingerprint"),
      item(SECRETS.github, "d".repeat(16), { sources: [] }),
      item(SECRETS.github, "e".repeat(16), { key_name: SECRETS.github }),
      { fingerprint: "f".repeat(16) },
    ];
    const res = await handleImportSubmit(post("submit", { ...TERMS, approval_id: s.body.approval_id, items: bad }, s.secret), w.deps);
    const body = (await res.json()) as { malformed: number; counts: Record<string, number> };
    noSecrets(body);
    assert.equal(body.malformed, 4);
    assert.equal(body.counts.imported, 0);
    const many = Array.from({ length: MAX_ITEMS_PER_SUBMIT + 1 }, (_, i) => item(SECRETS.github, i.toString(16).padStart(16, "0")));
    assert.equal((await handleImportSubmit(post("submit", { ...TERMS, approval_id: s.body.approval_id, items: many }, s.secret), w.deps)).status, 400);
    assert.equal((await w.entries.list({})).length, 0);
  });
});

describe("node import: finish", () => {
  it("closes the session; nothing more can be submitted", async () => {
    const w = world();
    const s = await begin(w);
    await w.approve(s.body.approval_id);
    const base = { ...TERMS, approval_id: s.body.approval_id };
    assert.equal((await handleImportFinish(post("finish", base, newSession().secret), w.deps)).status, 401);
    const done = await handleImportFinish(post("finish", base, s.secret), w.deps);
    assert.equal(done.status, 200);
    const after = await handleImportSubmit(post("submit", { ...base, items: [item(SECRETS.github, "a".repeat(16))] }, s.secret), w.deps);
    assert.equal(after.status, 410);
    assert.equal(((await after.json()) as { error: string }).error, "session_closed");
    assert.equal((await w.entries.list({})).length, 0);
  });
});
