// library-first: echo.functions.search → no existing impl found (2026-11-15)
/**
 * The second decider: Lyra's consent bridge decides connection and first-use
 * approvals over a loopback-only, service-token endpoint, and every decision
 * is recorded under client_id "service:lyra-consent-bridge" — never as the
 * owner. The owner's Telegram path (MAC + approver id → "owner:telegram")
 * must be completely unaffected.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  APPROVAL_DECISION_CAPABILITY,
  BRIDGE_DECIDER_CLIENT_ID,
  MemoryApprovalStore,
  computeApprovalMac,
  createApproval,
  decideApproval,
  decideApprovalAsService,
  getApproval,
  type ApprovalOptions,
} from "./approvals.ts";
import { handleBridgeDecide } from "./bridge-decider.ts";
import type { CapabilityRequest, LedgerEntryInput } from "./contracts.ts";

const HMAC_KEY = "hmac-TESTONLY-approval-key-0123456789abcdefghij";
const APPROVER = "424242";
const BRIDGE_TOKEN = "bridge-TESTONLY-decider-token-0123456789abcdef";
const WRONG_TOKEN = "bridge-TESTONLY-wrong-token-0123456789abcdef00";

const ENV: NodeJS.ProcessEnv = {
  ECHO_VAULT_APPROVAL_HMAC_KEY: HMAC_KEY,
  ECHO_VAULT_APPROVER_TELEGRAM_ID: APPROVER,
  ECHO_VAULT_BRIDGE_DECIDER_TOKEN: BRIDGE_TOKEN,
};

const CONNECTION_REQ: CapabilityRequest = {
  client: { client_id: "dcr_bridge_test", name: "Bridge Test Client", kind: "oauth", scopes: [] },
  capability: "vault.client.authorize",
  resource: "oauth:claude.ai",
  params: { requested_scopes: ["vault.read"], is_new_client: true },
};

const FIRST_USE_REQ: CapabilityRequest = {
  client: { client_id: "oc_claude", name: "Claude", kind: "oauth", scopes: ["vault.read"] },
  capability: "vault.entry.use.read",
  resource: "entry:example.com/alice",
  params: { method: "GET", host: "example.com", path: "/" },
};

/** A tier-2 escalation approval: decidable ONLY by the owner. */
const ESCALATION_REQ: CapabilityRequest = {
  client: { client_id: "oc_claude", name: "Claude", kind: "oauth", scopes: ["github.write"] },
  capability: "github.pr.merge",
  resource: "github:echoomegaprime/demo",
  params: { pr: 12, merge_method: "squash" },
};

const T0 = Date.parse("2026-11-15T12:00:00Z");

function harness(env: NodeJS.ProcessEnv = ENV) {
  const store = new MemoryApprovalStore();
  const rows: LedgerEntryInput[] = [];
  const clock = { t: T0 };
  const opts: ApprovalOptions = {
    store,
    env,
    now: () => clock.t,
    notify: async () => undefined,
    ledger: async (input) => {
      rows.push(input);
    },
  };
  return { store, rows, clock, opts };
}

const LOOPBACK_URL = "http://127.0.0.1:8355/api/internal/approvals/decide";

function decideRequest(
  body: unknown,
  o: {
    token?: string | null;
    url?: string;
    headers?: Record<string, string>;
    method?: string;
  } = {},
): Request {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...(o.headers ?? {}),
  };
  if (o.token !== null) headers.authorization = `Bearer ${o.token ?? BRIDGE_TOKEN}`;
  return new Request(o.url ?? LOOPBACK_URL, {
    method: o.method ?? "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

const ownerMac = (action: "approve" | "deny", id: string, digest: string) =>
  computeApprovalMac(Buffer.from(HMAC_KEY, "utf8"), action, id, digest);

describe("bridge decider (service path)", () => {
  it("approves a connection approval and ledgers it under the bridge identity, not the owner", async () => {
    const { rows, opts } = harness();
    const rec = await createApproval(CONNECTION_REQ, "New connection from claude.ai", opts);

    const res = await handleBridgeDecide(
      decideRequest({ approval_id: rec.id, action: "approve" }),
      opts,
    );
    assert.equal(res.status, 200);
    const resText = await res.text();
    assert.ok(!resText.includes(BRIDGE_TOKEN), "token never echoed");
    const body = JSON.parse(resText) as Record<string, unknown>;
    assert.equal(body.ok, true);
    assert.equal(body.status, "approved");
    assert.equal(body.decided_by, BRIDGE_DECIDER_CLIENT_ID);

    const after = await getApproval(rec.id, opts);
    assert.equal(after?.status, "approved");
    assert.equal(after?.decided_by, BRIDGE_DECIDER_CLIENT_ID);
    assert.notEqual(after?.decided_by, APPROVER, "never recorded as the owner");

    assert.equal(rows.length, 1);
    assert.equal(rows[0].client_id, "service:lyra-consent-bridge");
    assert.equal(rows[0].capability, APPROVAL_DECISION_CAPABILITY);
    assert.equal(rows[0].decision, "allow");
    assert.equal(rows[0].result, "ok");
    assert.equal(rows[0].approval_id, rec.id);
    assert.ok(
      !JSON.stringify(rows).includes(APPROVER),
      "the owner's Telegram id is not in the bridge ledger row",
    );
  });

  it("denies a first-use approval, recorded as the bridge", async () => {
    const { rows, opts } = harness();
    const rec = await createApproval(FIRST_USE_REQ, "FIRST USE of an entry", opts);

    const d = await decideApprovalAsService(rec.id, "deny", BRIDGE_TOKEN, opts);
    assert.equal(d.ok, true);
    assert.equal(d.ok && d.status, "denied");
    const after = await getApproval(rec.id, opts);
    assert.equal(after?.status, "denied");
    assert.equal(after?.decided_by, BRIDGE_DECIDER_CLIENT_ID);
    assert.deepEqual(
      rows.map((r) => [r.client_id, r.decision, r.result]),
      [["service:lyra-consent-bridge", "deny", "denied"]],
    );
  });

  it("missing service token → 401, nothing decided, no ledger row", async () => {
    const { rows, opts } = harness();
    const rec = await createApproval(CONNECTION_REQ, "New connection", opts);

    const res = await handleBridgeDecide(
      decideRequest({ approval_id: rec.id, action: "approve" }, { token: null }),
      opts,
    );
    assert.equal(res.status, 401);
    assert.equal((await getApproval(rec.id, opts))?.status, "pending");
    assert.equal(rows.length, 0);

    const d = await decideApprovalAsService(rec.id, "approve", "", opts);
    assert.equal(d.ok, false);
    assert.equal(!d.ok && d.reason, "unauthorized_service");
  });

  it("wrong service token → 401, nothing decided", async () => {
    const { rows, opts } = harness();
    const rec = await createApproval(CONNECTION_REQ, "New connection", opts);

    const res = await handleBridgeDecide(
      decideRequest({ approval_id: rec.id, action: "approve" }, { token: WRONG_TOKEN }),
      opts,
    );
    assert.equal(res.status, 401);
    assert.equal((await getApproval(rec.id, opts))?.status, "pending");
    assert.equal(rows.length, 0);
  });

  it("token not configured on the server → 401 (fail closed)", async () => {
    const unconfigured: NodeJS.ProcessEnv = { ...ENV };
    delete unconfigured.ECHO_VAULT_BRIDGE_DECIDER_TOKEN;
    const { rows, opts } = harness(unconfigured);
    const rec = await createApproval(CONNECTION_REQ, "New connection", opts);

    const d = await decideApprovalAsService(rec.id, "approve", BRIDGE_TOKEN, opts);
    assert.equal(d.ok, false);
    assert.equal(!d.ok && d.reason, "service_not_configured");

    const res = await handleBridgeDecide(
      decideRequest({ approval_id: rec.id, action: "approve" }),
      opts,
    );
    assert.equal(res.status, 401);
    assert.equal((await getApproval(rec.id, opts))?.status, "pending");
    assert.equal(rows.length, 0);
  });

  it("out-of-scope approval type → 403, still pending, and the owner can still decide it", async () => {
    const { rows, opts } = harness();
    const rec = await createApproval(ESCALATION_REQ, "merge PR 12", opts);

    const res = await handleBridgeDecide(
      decideRequest({ approval_id: rec.id, action: "approve" }),
      opts,
    );
    assert.equal(res.status, 403);
    assert.equal(((await res.json()) as Record<string, unknown>).error, "out_of_scope");
    assert.equal((await getApproval(rec.id, opts))?.status, "pending");
    assert.equal(rows.length, 0, "a refused bridge attempt writes no decision row");

    // The refusal did not burn the approval: the owner's Telegram tap still works.
    const d = await decideApproval(
      rec.id,
      "approve",
      APPROVER,
      ownerMac("approve", rec.id, rec.request_digest),
      opts,
    );
    assert.equal(d.ok, true);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].client_id, "owner:telegram");
    assert.equal((await getApproval(rec.id, opts))?.decided_by, APPROVER);
  });

  it("the owner Telegram path is unaffected: MAC + approver id still decide, as owner:telegram", async () => {
    const { rows, opts } = harness();
    const rec = await createApproval(CONNECTION_REQ, "New connection", opts);

    const d = await decideApproval(
      rec.id,
      "deny",
      APPROVER,
      ownerMac("deny", rec.id, rec.request_digest),
      opts,
    );
    assert.equal(d.ok, true);
    assert.equal((await getApproval(rec.id, opts))?.decided_by, APPROVER);
    assert.deepEqual(
      rows.map((r) => [r.client_id, r.decision, r.result]),
      [["owner:telegram", "deny", "denied"]],
    );
  });
});

describe("bridge decider (HTTP surface)", () => {
  it("non-loopback host → 403 even with the right token", async () => {
    const { rows, opts } = harness();
    const rec = await createApproval(CONNECTION_REQ, "New connection", opts);

    const res = await handleBridgeDecide(
      decideRequest(
        { approval_id: rec.id, action: "approve" },
        { url: "https://credbroker.echo-op.com/api/internal/approvals/decide" },
      ),
      opts,
    );
    assert.equal(res.status, 403);
    assert.equal(((await res.json()) as Record<string, unknown>).error, "not_loopback");
    assert.equal((await getApproval(rec.id, opts))?.status, "pending");
    assert.equal(rows.length, 0);
  });

  it("a proxied request (forwarding headers) → 403 even on a loopback host", async () => {
    const { opts } = harness();
    const rec = await createApproval(CONNECTION_REQ, "New connection", opts);

    const res = await handleBridgeDecide(
      decideRequest(
        { approval_id: rec.id, action: "approve" },
        { headers: { "cf-connecting-ip": "203.0.113.9" } },
      ),
      opts,
    );
    assert.equal(res.status, 403);
    assert.equal((await getApproval(rec.id, opts))?.status, "pending");
  });

  it("GET → 405, malformed JSON → 400, unknown id → 404", async () => {
    const { opts } = harness();
    const get = await handleBridgeDecide(
      new Request(LOOPBACK_URL, {
        method: "GET",
        headers: { authorization: `Bearer ${BRIDGE_TOKEN}` },
      }),
      opts,
    );
    assert.equal(get.status, 405);

    const bad = await handleBridgeDecide(decideRequest("{not json"), opts);
    assert.equal(bad.status, 400);

    const missing = await handleBridgeDecide(
      decideRequest({ approval_id: "A".repeat(24), action: "approve" }),
      opts,
    );
    assert.equal(missing.status, 404);
  });

  it("an already-decided approval → 409, and an expired one → 410", async () => {
    const { clock, opts } = harness();
    const rec = await createApproval(CONNECTION_REQ, "New connection", opts);
    const first = await handleBridgeDecide(
      decideRequest({ approval_id: rec.id, action: "approve" }),
      opts,
    );
    assert.equal(first.status, 200);
    const again = await handleBridgeDecide(
      decideRequest({ approval_id: rec.id, action: "deny" }),
      opts,
    );
    assert.equal(again.status, 409);

    const short = await createApproval(CONNECTION_REQ, "New connection", {
      ...opts,
      ttlMs: 30_000,
    });
    clock.t += 31_000;
    const expired = await handleBridgeDecide(
      decideRequest({ approval_id: short.id, action: "approve" }),
      opts,
    );
    assert.equal(expired.status, 410);
    assert.equal((await getApproval(short.id, opts))?.status, "expired");
  });
});
