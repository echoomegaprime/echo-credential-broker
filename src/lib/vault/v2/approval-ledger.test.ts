// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  APPROVAL_DECISION_CAPABILITY,
  MemoryApprovalStore,
  callbackDataFor,
  computeApprovalMac,
  createApproval,
  decideApproval,
  getApproval,
  setDefaultApprovalLedgerSink,
  type ApprovalOptions,
} from "./approvals.ts";
import type { CapabilityRequest, LedgerEntryInput } from "./contracts.ts";

const HMAC_KEY = "hmac-TESTONLY-approval-key-0123456789abcdefghij";
const APPROVER = "424242";
const ENV: NodeJS.ProcessEnv = {
  TELEGRAM_BOT_TOKEN: "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789",
  ECHO_VAULT_APPROVAL_HMAC_KEY: HMAC_KEY,
  ECHO_VAULT_APPROVER_TELEGRAM_ID: APPROVER,
};
const REQUEST: CapabilityRequest = {
  client: { client_id: "oc_agent", name: "agent", kind: "oauth", scopes: ["vault.write"] },
  capability: "github.repo.transfer",
  resource: "github:echoomegaprime/demo",
  params: { new_owner: "echoomegaprime" },
};

describe("the owner's approval decision is on the ledger before it takes effect", () => {
  let rows: LedgerEntryInput[];
  let opts: ApprovalOptions;
  const mac = (action: "approve" | "deny", id: string, digest: string) =>
    computeApprovalMac(Buffer.from(HMAC_KEY, "utf8"), action, id, digest);

  beforeEach(() => {
    rows = [];
    opts = {
      store: new MemoryApprovalStore(),
      env: ENV,
      now: () => Date.parse("2026-11-14T12:00:00Z"),
      notify: async () => undefined,
      ledger: async (input) => {
        rows.push(input);
      },
    };
  });
  afterEach(() => setDefaultApprovalLedgerSink(null));

  it("approve writes one allow/ok row carrying the approval id, then the approval is approved", async () => {
    const rec = await createApproval(REQUEST, "transfer demo", opts);
    const d = await decideApproval(rec.id, "approve", APPROVER, mac("approve", rec.id, rec.request_digest), opts);
    assert.equal(d.ok, true);
    assert.equal(rows.length, 1);
    assert.deepEqual(
      { ...rows[0], task: undefined },
      {
        client_id: "owner:telegram",
        capability: APPROVAL_DECISION_CAPABILITY,
        resource: "github.repo.transfer github:echoomegaprime/demo",
        decision: "allow",
        tier: 3,
        result: "ok",
        approval_id: rec.id,
        error: undefined,
        task: undefined,
      },
    );
    assert.match(String(rows[0].task), /oc_agent/);
    assert.ok(!JSON.stringify(rows).includes(APPROVER), "the approver's Telegram id is not written to the ledger");
    assert.ok(callbackDataFor("approve", rec.id, "x".repeat(22)).length > 0);
  });

  it("deny writes a deny/denied row", async () => {
    const rec = await createApproval(REQUEST, "transfer demo", opts);
    const d = await decideApproval(rec.id, "deny", APPROVER, mac("deny", rec.id, rec.request_digest), opts);
    assert.equal(d.ok && d.status, "denied");
    assert.deepEqual(rows.map((r) => [r.decision, r.result]), [["deny", "denied"]]);
  });

  it("a ledger that cannot be written refuses the tap and leaves the approval pending", async () => {
    const rec = await createApproval(REQUEST, "transfer demo", opts);
    const failing: ApprovalOptions = { ...opts, ledger: async () => { throw new Error("db down"); } };
    const d = await decideApproval(rec.id, "approve", APPROVER, mac("approve", rec.id, rec.request_digest), failing);
    assert.equal(d.ok, false);
    assert.equal(!d.ok && d.reason, "ledger_unavailable");
    assert.equal((await getApproval(rec.id, opts))?.status, "pending");
    // The owner can tap again once the ledger is back.
    const again = await decideApproval(rec.id, "approve", APPROVER, mac("approve", rec.id, rec.request_digest), opts);
    assert.equal(again.ok, true);
  });

  it("a rejected tap (wrong user, bad MAC) writes nothing", async () => {
    const rec = await createApproval(REQUEST, "transfer demo", opts);
    const good = mac("approve", rec.id, rec.request_digest);
    assert.equal((await decideApproval(rec.id, "approve", "999", good, opts)).ok, false);
    assert.equal((await decideApproval(rec.id, "approve", APPROVER, "A".repeat(good.length), opts)).ok, false);
    assert.equal(rows.length, 0);
  });

  it("a second tap after the decision is not_pending and adds no decision row", async () => {
    const rec = await createApproval(REQUEST, "transfer demo", opts);
    const m = mac("approve", rec.id, rec.request_digest);
    await decideApproval(rec.id, "approve", APPROVER, m, opts);
    const again = await decideApproval(rec.id, "approve", APPROVER, m, opts);
    assert.equal(!again.ok && again.reason, "not_pending");
    assert.equal(rows.length, 1);
  });

  it("the process-wide sink is used when no sink is passed", async () => {
    const seen: LedgerEntryInput[] = [];
    setDefaultApprovalLedgerSink(async (input) => {
      seen.push(input);
    });
    const { ledger: _unused, ...withoutSink } = opts;
    void _unused;
    const rec = await createApproval(REQUEST, "transfer demo", withoutSink);
    await decideApproval(rec.id, "approve", APPROVER, mac("approve", rec.id, rec.request_digest), withoutSink);
    assert.equal(seen.length, 1);
    assert.equal(rows.length, 0);
  });
});
