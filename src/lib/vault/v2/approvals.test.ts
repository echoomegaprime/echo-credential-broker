// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, afterEach, beforeEach, describe, it } from "node:test";
import type { CapabilityRequest } from "./contracts.ts";
import {
  ApprovalError,
  callbackDataFor,
  computeApprovalMac,
  consumeApproval,
  createApproval,
  decideApproval,
  getApproval,
  MemoryApprovalStore,
  parseCallbackData,
  SqlApprovalStore,
} from "./approvals.ts";
import type { ApprovalOptions, ApprovalStore } from "./approvals.ts";
import type { Sql } from "../../db.ts";

const TOKEN = "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789";
const HMAC_KEY = "hmac-TESTONLY-approval-key-0123456789abcdefghij";
const WEBHOOK_SECRET = "whsec_TESTONLY_0123456789abcdef";
const APPROVER = "424242";
const SECRETS = [TOKEN, HMAC_KEY, WEBHOOK_SECRET];

const ENV: NodeJS.ProcessEnv = {
  TELEGRAM_BOT_TOKEN: TOKEN,
  ECHO_VAULT_APPROVAL_HMAC_KEY: HMAC_KEY,
  ECHO_VAULT_APPROVER_TELEGRAM_ID: APPROVER,
  ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET: WEBHOOK_SECRET,
};

interface TgCall {
  url: string;
  method: string;
  body: Record<string, any>;
}

function fakeTelegram(mode: "ok" | "throw" | "api_error" = "ok") {
  const calls: TgCall[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = JSON.parse(String(init?.body ?? "{}"));
    calls.push({ url, method: url.split("/").pop() ?? "", body });
    if (mode === "throw") throw new TypeError(`fetch failed for ${url} (connect ECONNREFUSED)`);
    if (mode === "api_error") {
      return new Response(JSON.stringify({ ok: false, error_code: 401, description: `Unauthorized: ${url}` }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    }
    const result = url.endsWith("/sendMessage") ? { message_id: 77, chat: { id: Number(APPROVER) } } : true;
    return new Response(JSON.stringify({ ok: true, result }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { calls, fetch: fetchImpl };
}

/** Capture everything written to stderr / console while the test runs. */
function captureOutput() {
  const chunks: string[] = [];
  const origErr = process.stderr.write;
  const origLog = console.log;
  const origError = console.error;
  const origWarn = console.warn;
  process.stderr.write = ((chunk: unknown) => {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  const sink = (...args: unknown[]) => {
    chunks.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
  };
  console.log = sink;
  console.error = sink;
  console.warn = sink;
  return {
    text: () => chunks.join("\n"),
    restore: () => {
      process.stderr.write = origErr;
      console.log = origLog;
      console.error = origError;
      console.warn = origWarn;
    },
  };
}

function assertNoSecrets(label: string, text: string): void {
  for (const s of SECRETS) assert.equal(text.includes(s), false, `${label} leaked a secret`);
  // The token's secret half alone must not appear either.
  assert.equal(text.includes(TOKEN.split(":")[1]), false, `${label} leaked the token suffix`);
}

function makeReq(params: Record<string, unknown> = { pr: 12, merge_method: "squash" }): CapabilityRequest {
  return {
    client: { client_id: "oc_claude", name: "Claude", kind: "oauth", scopes: ["github.write"] },
    capability: "github.pr.merge",
    resource: "github:ECHO-OMEGA-PRIME/cleanbrees",
    params,
  };
}

function callbackFrom(calls: TgCall[], action: "approve" | "deny") {
  const send = calls.find((c) => c.method === "sendMessage");
  assert.ok(send, "sendMessage was called");
  const buttons = send.body.reply_markup.inline_keyboard[0] as Array<{ text: string; callback_data: string }>;
  const btn = buttons.find((b) => b.text === (action === "approve" ? "Approve" : "Deny"));
  assert.ok(btn);
  const parsed = parseCallbackData(btn.callback_data);
  assert.ok(parsed);
  return parsed;
}

function runSuite(name: string, makeStore: () => Promise<ApprovalStore>) {
  describe(`approvals (${name})`, () => {
    let store: ApprovalStore;
    let tg: ReturnType<typeof fakeTelegram>;
    let clock: number;
    let out: ReturnType<typeof captureOutput>;
    let opts: ApprovalOptions;
    const thrown: string[] = [];

    beforeEach(async () => {
      store = await makeStore();
      tg = fakeTelegram();
      clock = Date.parse("2026-11-14T12:00:00.000Z");
      opts = { store, fetch: tg.fetch, env: ENV, now: () => clock };
      out = captureOutput();
    });

    afterEach(() => {
      out.restore();
      assertNoSecrets("log output", out.text());
      assertNoSecrets("thrown errors", thrown.join("\n"));
    });

    it("happy path: create → approve by the approver → consume once", async () => {
      const req = makeReq();
      const rec = await createApproval(req, "Merge PR #12 into main", opts);
      assert.equal(rec.status, "pending");
      assert.match(rec.id, /^[A-Za-z0-9_-]{24}$/);
      assert.equal(rec.expires_at, new Date(clock + 10 * 60 * 1000).toISOString());
      assertNoSecrets("record", JSON.stringify(rec));

      const send = tg.calls.find((c) => c.method === "sendMessage");
      assert.ok(send);
      assert.equal(send.body.chat_id, APPROVER);
      assert.equal(send.body.parse_mode, undefined);
      for (const b of send.body.reply_markup.inline_keyboard[0]) {
        assert.ok(Buffer.byteLength(b.callback_data, "utf8") <= 64);
      }
      assertNoSecrets("telegram payload", JSON.stringify(send.body));

      const cb = callbackFrom(tg.calls, "approve");
      assert.equal(cb.id, rec.id);
      clock += 60_000;
      const decided = await decideApproval(cb.id, cb.action, APPROVER, cb.mac, opts);
      assert.equal(decided.ok, true);
      assert.equal(decided.ok && decided.status, "approved");
      const stored = await getApproval(rec.id, opts);
      assert.equal(stored?.status, "approved");
      assert.equal(stored?.decided_by, APPROVER);
      assert.equal(stored?.decided_at, new Date(clock).toISOString());

      assert.equal(await consumeApproval(rec.id, makeReq(), opts), "ok");
      assert.equal((await getApproval(rec.id, opts))?.status, "consumed");
      // The capture really sees the structured log lines the leak scan checks.
      for (const event of ["vault_approval_created", "vault_approval_decided", "vault_approval_consumed"]) {
        assert.ok(out.text().includes(event), event);
      }
    });

    it("replay → already_consumed", async () => {
      const rec = await createApproval(makeReq(), "merge", opts);
      const cb = callbackFrom(tg.calls, "approve");
      assert.equal((await decideApproval(cb.id, cb.action, APPROVER, cb.mac, opts)).ok, true);
      assert.equal(await consumeApproval(rec.id, makeReq(), opts), "ok");
      assert.equal(await consumeApproval(rec.id, makeReq(), opts), "already_consumed");
    });

    it("changed params (or client) → digest_mismatch, approval stays usable for the real request", async () => {
      const rec = await createApproval(makeReq(), "merge", opts);
      const cb = callbackFrom(tg.calls, "approve");
      await decideApproval(cb.id, cb.action, APPROVER, cb.mac, opts);
      assert.equal(await consumeApproval(rec.id, makeReq({ pr: 13, merge_method: "squash" }), opts), "digest_mismatch");
      const otherClient = { ...makeReq(), client: { ...makeReq().client, client_id: "oc_evil" } };
      assert.equal(await consumeApproval(rec.id, otherClient, opts), "digest_mismatch");
      assert.equal(await consumeApproval(rec.id, { ...makeReq(), resource: "github:x/y" }, opts), "digest_mismatch");
      // Key order does not matter.
      assert.equal(await consumeApproval(rec.id, makeReq({ merge_method: "squash", pr: 12 }), opts), "ok");
    });

    it("expired → expired (consume and late decision)", async () => {
      const rec = await createApproval(makeReq(), "merge", opts);
      const cb = callbackFrom(tg.calls, "approve");
      await decideApproval(cb.id, cb.action, APPROVER, cb.mac, opts);
      clock += 10 * 60 * 1000;
      assert.equal(await consumeApproval(rec.id, makeReq(), opts), "expired");
      assert.equal((await getApproval(rec.id, opts))?.status, "expired");

      tg.calls.length = 0;
      const rec2 = await createApproval(makeReq(), "merge", opts);
      const cb2 = callbackFrom(tg.calls, "approve");
      clock += 11 * 60 * 1000;
      const late = await decideApproval(cb2.id, cb2.action, APPROVER, cb2.mac, opts);
      assert.equal(late.ok, false);
      assert.equal(!late.ok && late.reason, "expired");
      assert.equal(await consumeApproval(rec2.id, makeReq(), opts), "expired");
    });

    it("ttl is configurable", async () => {
      const rec = await createApproval(makeReq(), "merge", { ...opts, ttlMs: 2 * 60 * 1000 });
      assert.equal(rec.expires_at, new Date(clock + 2 * 60 * 1000).toISOString());
    });

    it("pending and denied are not consumable", async () => {
      const rec = await createApproval(makeReq(), "merge", opts);
      assert.equal(await consumeApproval(rec.id, makeReq(), opts), "pending");
      const cb = callbackFrom(tg.calls, "deny");
      const d = await decideApproval(cb.id, cb.action, APPROVER, cb.mac, opts);
      assert.equal(d.ok && d.status, "denied");
      assert.equal(await consumeApproval(rec.id, makeReq(), opts), "denied");
      // Cannot flip a decision afterwards.
      const ap = callbackFrom(tg.calls, "approve");
      const again = await decideApproval(ap.id, ap.action, APPROVER, ap.mac, opts);
      assert.equal(!again.ok && again.reason, "not_pending");
      assert.equal((await getApproval(rec.id, opts))?.status, "denied");
    });

    it("wrong Telegram user → rejected, no state change", async () => {
      const rec = await createApproval(makeReq(), "merge", opts);
      const cb = callbackFrom(tg.calls, "approve");
      for (const user of ["999999", "", "4242420", " 424242", "424242 "]) {
        const r = await decideApproval(cb.id, cb.action, user, cb.mac, opts);
        assert.equal(!r.ok && r.reason, "unauthorized_user", JSON.stringify(user));
      }
      assert.equal((await getApproval(rec.id, opts))?.status, "pending");
    });

    it("bad MAC → rejected, no state change", async () => {
      const rec = await createApproval(makeReq(), "merge", opts);
      const approve = callbackFrom(tg.calls, "approve");
      const deny = callbackFrom(tg.calls, "deny");
      const flipped = approve.mac.startsWith("A") ? `B${approve.mac.slice(1)}` : `A${approve.mac.slice(1)}`;
      const forgedKey = computeApprovalMac(Buffer.alloc(32, 1), "approve", rec.id, rec.request_digest);
      for (const [action, mac] of [
        ["approve", flipped],
        ["approve", deny.mac], // deny MAC cannot approve
        ["deny", approve.mac], // approve MAC cannot deny
        ["approve", forgedKey],
        ["approve", ""],
        ["approve", "x".repeat(22)],
      ] as const) {
        const r = await decideApproval(rec.id, action, APPROVER, mac, opts);
        assert.equal(!r.ok && r.reason, "bad_mac", `${action}/${mac}`);
      }
      // A MAC for another approval does not transfer.
      tg.calls.length = 0;
      const rec2 = await createApproval(makeReq({ pr: 99 }), "other", opts);
      const cb2 = callbackFrom(tg.calls, "approve");
      const cross = await decideApproval(rec.id, "approve", APPROVER, cb2.mac, opts);
      assert.equal(!cross.ok && cross.reason, "bad_mac");
      assert.equal((await getApproval(rec.id, opts))?.status, "pending");
      assert.equal((await getApproval(rec2.id, opts))?.status, "pending");
    });

    it("unknown or malformed IDs", async () => {
      assert.equal(await consumeApproval("nope", makeReq(), opts), "not_found");
      assert.equal(await consumeApproval("A".repeat(24), makeReq(), opts), "not_found");
      assert.equal(await getApproval("../../etc", opts), null);
      const r = await decideApproval("A".repeat(24), "approve", APPROVER, "A".repeat(22), opts);
      assert.equal(!r.ok && r.reason, "not_found");
    });

    it("concurrent consumes: exactly one wins", async () => {
      const rec = await createApproval(makeReq(), "merge", opts);
      const cb = callbackFrom(tg.calls, "approve");
      await decideApproval(cb.id, cb.action, APPROVER, cb.mac, opts);
      const results = await Promise.all(Array.from({ length: 25 }, () => consumeApproval(rec.id, makeReq(), opts)));
      assert.equal(results.filter((r) => r === "ok").length, 1);
      assert.equal(results.filter((r) => r === "already_consumed").length, 24);
    });

    it("concurrent decisions: exactly one wins", async () => {
      const rec = await createApproval(makeReq(), "merge", opts);
      const ap = callbackFrom(tg.calls, "approve");
      const dn = callbackFrom(tg.calls, "deny");
      const results = await Promise.all([
        decideApproval(ap.id, ap.action, APPROVER, ap.mac, opts),
        decideApproval(dn.id, dn.action, APPROVER, dn.mac, opts),
        decideApproval(ap.id, ap.action, APPROVER, ap.mac, opts),
      ]);
      assert.equal(results.filter((r) => r.ok).length, 1);
      const final = await getApproval(rec.id, opts);
      assert.ok(final?.status === "approved" || final?.status === "denied");
    });

    for (const mode of ["throw", "api_error"] as const) {
      it(`Telegram send failure (${mode}) leaves no usable approval and leaks nothing`, async () => {
        const bad = fakeTelegram(mode);
        const failOpts = { ...opts, fetch: bad.fetch };
        let err: unknown;
        try {
          await createApproval(makeReq(), "merge", failOpts);
        } catch (e) {
          err = e;
        }
        assert.ok(err instanceof ApprovalError);
        assert.equal(err.code, "approval_notification_failed");
        thrown.push(String(err.message), String(err.stack), JSON.stringify(err));
        // The bot token really was used (in the URL) ...
        assert.ok(bad.calls[0].url.includes(TOKEN));
        // ... but the approval it would have authorized is dead.
        const cb = callbackFrom(bad.calls, "approve");
        const rec = await getApproval(cb.id, failOpts);
        assert.equal(rec?.status, "expired");
        const d = await decideApproval(cb.id, cb.action, APPROVER, cb.mac, failOpts);
        assert.equal(d.ok, false);
        assert.equal(await consumeApproval(cb.id, makeReq(), failOpts), "expired");
        assert.ok(out.text().includes("vault_approval_notify_failed"));
        assert.ok(out.text().includes('"marked_expired":true'));
      });
    }

    it("fails closed without a valid HMAC key or approver, storing nothing", async () => {
      for (const env of [
        { ...ENV, ECHO_VAULT_APPROVAL_HMAC_KEY: undefined },
        { ...ENV, ECHO_VAULT_APPROVAL_HMAC_KEY: "short-key-31-bytes-xxxxxxxxxxxx" },
      ]) {
        await assert.rejects(createApproval(makeReq(), "merge", { ...opts, env }), (e: unknown) => {
          thrown.push(String((e as Error).message));
          return e instanceof ApprovalError && e.code === "hmac_key_unavailable";
        });
      }
      await assert.rejects(
        createApproval(makeReq(), "merge", { ...opts, env: { ...ENV, ECHO_VAULT_APPROVER_TELEGRAM_ID: "" } }),
        (e: unknown) => e instanceof ApprovalError && e.code === "approver_not_configured",
      );
      assert.equal(tg.calls.length, 0);

      // Decisions also fail closed.
      const rec = await createApproval(makeReq(), "merge", opts);
      const cb = callbackFrom(tg.calls, "approve");
      const noApprover = await decideApproval(cb.id, cb.action, APPROVER, cb.mac, {
        ...opts,
        env: { ...ENV, ECHO_VAULT_APPROVER_TELEGRAM_ID: undefined },
      });
      assert.equal(!noApprover.ok && noApprover.reason, "approver_not_configured");
      const noKey = await decideApproval(cb.id, cb.action, APPROVER, cb.mac, {
        ...opts,
        env: { ...ENV, ECHO_VAULT_APPROVAL_HMAC_KEY: undefined },
      });
      assert.equal(!noKey.ok && noKey.reason, "hmac_key_unavailable");
      assert.equal((await getApproval(rec.id, opts))?.status, "pending");
    });

    it("summary is sanitized: control/bidi chars stripped, tokens redacted, length capped", async () => {
      const rec = await createApproval(
        makeReq(),
        `Merge\u0000 PR\n#12\u202e evil ghp_${"A".repeat(36)} ${"x".repeat(2000)}`,
        opts,
      );
      // eslint-disable-next-line no-control-regex -- asserting control characters were stripped
      assert.equal(/[\u0000-\u001f\u202e]/.test(rec.summary), false);
      assert.equal(rec.summary.includes("ghp_"), false);
      assert.ok(rec.summary.length <= 500);
      assert.ok(rec.summary.startsWith("Merge PR #12 evil"));
      assert.equal((await getApproval(rec.id, opts))?.summary, rec.summary);
    });

    it("rejects malformed requests before storing", async () => {
      await assert.rejects(
        createApproval({ ...makeReq(), resource: "" }, "x", opts),
        (e: unknown) => e instanceof ApprovalError && e.code === "invalid_request",
      );
      assert.equal(tg.calls.length, 0);
    });
  });
}

describe("callback data", () => {
  it("round-trips and fits Telegram's 64-byte limit", () => {
    const id = "A".repeat(24);
    const mac = computeApprovalMac(Buffer.from(HMAC_KEY), "approve", id, "0".repeat(64));
    const data = callbackDataFor("approve", id, mac);
    assert.ok(Buffer.byteLength(data) <= 64);
    assert.deepEqual(parseCallbackData(data), { action: "approve", id, mac });
    assert.equal(parseCallbackData(`x:${id}:${mac}`), null);
    assert.equal(parseCallbackData(`a:${id}:${mac}:extra`), null);
    assert.equal(parseCallbackData(42), null);
  });
});

runSuite("memory store", async () => new MemoryApprovalStore());

// The SQL store against a real (embedded) Postgres with the real migration.
// One PGlite instance for the suite; the table is emptied before each test.
let pglite: Promise<import("@electric-sql/pglite").PGlite> | null = null;
runSuite("sql store on PGlite", async () => {
  pglite ??= (async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const pg = new PGlite();
    await pg.exec(readFileSync(new URL("../../../../migrations/0004_vault_approvals.sql", import.meta.url), "utf8"));
    return pg;
  })();
  const pg = await pglite;
  await pg.exec("delete from vault_approvals");
  const sql = {
    query: async (text: string, params: unknown[] = []) => (await pg.query(text, params)).rows,
  } as unknown as Sql;
  return new SqlApprovalStore(async () => sql);
});
after(async () => {
  if (pglite) await (await pglite).close();
});
