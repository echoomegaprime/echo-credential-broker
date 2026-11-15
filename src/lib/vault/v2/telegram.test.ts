// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";
import type { CapabilityRequest } from "./contracts.ts";
import { createApproval, getApproval, MemoryApprovalStore, parseCallbackData } from "./approvals.ts";
import type { ApprovalOptions } from "./approvals.ts";
import {
  answerCallbackQuery,
  callBotApi,
  formatApprovalText,
  handleTelegramWebhook,
  sendApprovalRequest,
  setTelegramWebhook,
  TelegramApiError,
} from "./telegram.ts";

const TOKEN = "987654321:AAF_TESTONLY_telegram_token_never_leak_9876";
const HMAC_KEY = "hmac-TESTONLY-telegram-suite-key-0123456789abcdef";
const WEBHOOK_SECRET = "whsec_TESTONLY_telegram_suite_0123";
const APPROVER = "555000111";
const SECRETS = [TOKEN, TOKEN.split(":")[1], HMAC_KEY, WEBHOOK_SECRET];

const ENV: NodeJS.ProcessEnv = {
  TELEGRAM_BOT_TOKEN: TOKEN,
  ECHO_VAULT_APPROVAL_HMAC_KEY: HMAC_KEY,
  ECHO_VAULT_APPROVER_TELEGRAM_ID: APPROVER,
  ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET: WEBHOOK_SECRET,
};

interface TgCall {
  url: string;
  method: string;
  init: RequestInit;
  body: Record<string, any>;
}

function fakeTelegram(mode: "ok" | "throw" | "api_error" | "garbage" = "ok") {
  const calls: TgCall[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, method: url.split("/").pop() ?? "", init: init ?? {}, body: JSON.parse(String(init?.body ?? "{}")) });
    if (mode === "throw") throw new TypeError(`request to ${url} failed, reason: getaddrinfo ENOTFOUND`);
    if (mode === "api_error") {
      return new Response(
        JSON.stringify({ ok: false, error_code: 400, description: `Bad Request: token ${TOKEN} at ${url}` }),
        { status: 400, headers: { "content-type": "application/json" } },
      );
    }
    if (mode === "garbage") return new Response(`<html>${url}</html>`, { status: 502 });
    const result = url.endsWith("/sendMessage") ? { message_id: 31337, chat: { id: Number(APPROVER) } } : true;
    return new Response(JSON.stringify({ ok: true, result }), { status: 200 });
  }) as typeof fetch;
  return { calls, fetch: fetchImpl };
}

function captureOutput() {
  const chunks: string[] = [];
  const origErr = process.stderr.write;
  const orig = { log: console.log, error: console.error, warn: console.warn };
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
      Object.assign(console, orig);
    },
  };
}

function assertNoSecrets(label: string, text: string): void {
  for (const s of SECRETS) assert.equal(text.includes(s), false, `${label} leaked a secret`);
}

function makeReq(): CapabilityRequest {
  return {
    client: { client_id: "oc_claude", name: "Claude", kind: "oauth", scopes: ["github.write"] },
    capability: "github.repo.transfer",
    resource: "github:ECHO-OMEGA-PRIME/cleanbrees",
    params: { new_owner: "echoomegaprime" },
  };
}

function webhookRequest(body: unknown, secret: string | null = WEBHOOK_SECRET): Request {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (secret !== null) headers["X-Telegram-Bot-Api-Secret-Token"] = secret;
  return new Request("https://vault.example/api/telegram/webhook", {
    method: "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function callbackUpdate(data: string, fromId: number, messageId = 31337) {
  return {
    update_id: 1000,
    callback_query: {
      id: "cbq-1",
      from: { id: fromId, is_bot: false, first_name: "Bobby" },
      chat_instance: "ci",
      message: { message_id: messageId, date: 1, chat: { id: Number(APPROVER), type: "private" }, text: "..." },
      data,
    },
  };
}

describe("telegram webhook", () => {
  let store: MemoryApprovalStore;
  let tg: ReturnType<typeof fakeTelegram>;
  let clock: number;
  let opts: ApprovalOptions;
  let out: ReturnType<typeof captureOutput>;
  const responses: string[] = [];

  beforeEach(() => {
    store = new MemoryApprovalStore();
    tg = fakeTelegram();
    clock = Date.parse("2026-11-14T15:00:00.000Z");
    opts = { store, fetch: tg.fetch, env: ENV, now: () => clock };
    out = captureOutput();
  });

  afterEach(() => {
    out.restore();
    assertNoSecrets("log output", out.text());
    assertNoSecrets("http responses", responses.join("\n"));
  });

  async function send(req: Request, o: ApprovalOptions = opts): Promise<Response> {
    const res = await handleTelegramWebhook(req, o);
    const text = await res.clone().text();
    responses.push(text, JSON.stringify([...res.headers]));
    return res;
  }

  async function pendingApproval() {
    const rec = await createApproval(makeReq(), "Transfer cleanbrees to echoomegaprime", opts);
    const buttons = tg.calls.find((c) => c.method === "sendMessage")!.body.reply_markup.inline_keyboard[0];
    tg.calls.length = 0;
    return { rec, approve: buttons[0].callback_data as string, deny: buttons[1].callback_data as string };
  }

  it("rejects a missing or wrong secret with 401 and no side effects", async () => {
    const { rec, approve } = await pendingApproval();
    for (const secret of [null, "", "wrong", `${WEBHOOK_SECRET}x`, WEBHOOK_SECRET.slice(0, -1)]) {
      const res = await send(webhookRequest(callbackUpdate(approve, Number(APPROVER)), secret));
      assert.equal(res.status, 401, String(secret));
    }
    assert.equal(tg.calls.length, 0);
    assert.equal((await getApproval(rec.id, opts))?.status, "pending");
  });

  it("fails closed (401) when the webhook secret is unset or too weak", async () => {
    const { approve } = await pendingApproval();
    for (const value of [undefined, "", "short", "has spaces in it 1234"]) {
      const env = { ...ENV, ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET: value };
      const res = await send(webhookRequest(callbackUpdate(approve, Number(APPROVER)), value ?? ""), { ...opts, env });
      assert.equal(res.status, 401, String(value));
    }
    assert.equal(tg.calls.length, 0);
  });

  it("approve by the approver: 200, answers the query, edits the message", async () => {
    const { rec, approve } = await pendingApproval();
    clock += 30_000;
    const res = await send(webhookRequest(callbackUpdate(approve, Number(APPROVER))));
    assert.equal(res.status, 200);
    const stored = await getApproval(rec.id, opts);
    assert.equal(stored?.status, "approved");
    assert.equal(stored?.decided_by, APPROVER);

    const answer = tg.calls.find((c) => c.method === "answerCallbackQuery");
    assert.deepEqual(answer?.body, { callback_query_id: "cbq-1", text: "Approved" });
    const edit = tg.calls.find((c) => c.method === "editMessageText");
    assert.equal(edit?.body.chat_id, Number(APPROVER));
    assert.equal(edit?.body.message_id, 31337);
    assert.ok(String(edit?.body.text).includes(`Approved by you at ${new Date(clock).toISOString()}`));
    assert.equal(edit?.body.reply_markup, undefined, "keyboard is not re-sent");
    assert.equal(edit?.body.parse_mode, undefined);
  });

  it("deny by the approver", async () => {
    const { rec, deny } = await pendingApproval();
    const res = await send(webhookRequest(callbackUpdate(deny, Number(APPROVER))));
    assert.equal(res.status, 200);
    assert.equal((await getApproval(rec.id, opts))?.status, "denied");
    assert.equal(tg.calls.find((c) => c.method === "answerCallbackQuery")?.body.text, "Denied");
    assert.ok(String(tg.calls.find((c) => c.method === "editMessageText")?.body.text).includes("Denied"));
  });

  it("someone else pressing the button: 200, rejected, no state change, no edit", async () => {
    const { rec, approve } = await pendingApproval();
    const res = await send(webhookRequest(callbackUpdate(approve, 123456)));
    assert.equal(res.status, 200);
    assert.equal((await getApproval(rec.id, opts))?.status, "pending");
    assert.equal(tg.calls.find((c) => c.method === "answerCallbackQuery")?.body.text, "Not permitted");
    assert.equal(tg.calls.some((c) => c.method === "editMessageText"), false);
    assert.ok(out.text().includes("unauthorized_user"));
  });

  it("tampered callback data: 200, rejected, no state change", async () => {
    const { rec, approve, deny } = await pendingApproval();
    const parsedDeny = parseCallbackData(deny)!;
    const swapped = `a:${parsedDeny.id}:${parsedDeny.mac}`; // deny MAC on an approve action
    for (const data of [swapped, approve.slice(0, -1) + (approve.endsWith("A") ? "B" : "A"), "a:short:mac", "", "x".repeat(65)]) {
      const res = await send(webhookRequest(callbackUpdate(data, Number(APPROVER))));
      assert.equal(res.status, 200);
    }
    assert.equal((await getApproval(rec.id, opts))?.status, "pending");
    assert.equal(tg.calls.some((c) => c.method === "editMessageText"), false);
  });

  it("expired approval: edits the message to Expired", async () => {
    const { rec, approve } = await pendingApproval();
    clock += 10 * 60 * 1000 + 1;
    const res = await send(webhookRequest(callbackUpdate(approve, Number(APPROVER))));
    assert.equal(res.status, 200);
    assert.equal((await getApproval(rec.id, opts))?.status, "expired");
    assert.equal(tg.calls.find((c) => c.method === "answerCallbackQuery")?.body.text, "Expired");
    assert.ok(String(tg.calls.find((c) => c.method === "editMessageText")?.body.text).endsWith("Expired"));
  });

  it("second press: Already decided, decision unchanged", async () => {
    const { rec, approve, deny } = await pendingApproval();
    await send(webhookRequest(callbackUpdate(approve, Number(APPROVER))));
    tg.calls.length = 0;
    const res = await send(webhookRequest(callbackUpdate(deny, Number(APPROVER))));
    assert.equal(res.status, 200);
    assert.equal((await getApproval(rec.id, opts))?.status, "approved");
    assert.equal(tg.calls.find((c) => c.method === "answerCallbackQuery")?.body.text, "Already decided");
  });

  it("non-callback updates, bad JSON and oversized bodies are acknowledged and ignored", async () => {
    for (const body of [{ update_id: 1, message: { text: "hi" } }, "{not json", {}, "x".repeat(300 * 1024)]) {
      const res = await send(webhookRequest(body));
      assert.equal(res.status, 200);
    }
    assert.equal(tg.calls.length, 0);
  });

  it("Telegram API failures while answering still return 200 and leak nothing", async () => {
    const { rec, approve } = await pendingApproval();
    for (const mode of ["throw", "api_error", "garbage"] as const) {
      const bad = fakeTelegram(mode);
      const res = await send(webhookRequest(callbackUpdate(approve, Number(APPROVER))), { ...opts, fetch: bad.fetch });
      assert.equal(res.status, 200);
      assert.ok(bad.calls.length >= 1);
    }
    assert.equal((await getApproval(rec.id, opts))?.status, "approved");
    assert.ok(out.text().includes("telegram_answer_failed"));
  });

  it("works through the default env (process.env) path", async () => {
    const saved = { ...process.env };
    Object.assign(process.env, ENV);
    try {
      const { rec, approve } = await pendingApproval();
      const res = await send(webhookRequest(callbackUpdate(approve, Number(APPROVER))), {
        store,
        fetch: tg.fetch,
        now: () => clock,
      });
      assert.equal(res.status, 200);
      assert.equal((await getApproval(rec.id, opts))?.status, "approved");
    } finally {
      for (const k of Object.keys(ENV)) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
    }
  });
});

describe("telegram client", () => {
  let out: ReturnType<typeof captureOutput>;
  const thrown: string[] = [];
  beforeEach(() => {
    out = captureOutput();
  });
  afterEach(() => {
    out.restore();
    assertNoSecrets("log output", out.text());
    assertNoSecrets("thrown errors", thrown.join("\n"));
  });

  async function expectTelegramError(p: Promise<unknown>, code: string) {
    let err: unknown;
    try {
      await p;
    } catch (e) {
      err = e;
    }
    assert.ok(err instanceof TelegramApiError, "throws TelegramApiError");
    assert.equal(err.code, code);
    thrown.push(err.message, String(err.stack), JSON.stringify(err), String(err));
  }

  it("POSTs JSON to /bot<token>/<method>", async () => {
    const tg = fakeTelegram();
    await answerCallbackQuery("q1", "x".repeat(500), { fetch: tg.fetch, env: ENV });
    assert.equal(tg.calls[0].url, `https://api.telegram.org/bot${TOKEN}/answerCallbackQuery`);
    assert.equal(tg.calls[0].init.method, "POST");
    assert.equal(new Headers(tg.calls[0].init.headers).get("content-type"), "application/json");
    assert.equal(tg.calls[0].body.text.length, 200, "answer text clipped to 200 chars");
  });

  it("sendMessage payload: plain text, inline keyboard, callback data ≤ 64 bytes", async () => {
    const tg = fakeTelegram();
    const record = {
      id: "B".repeat(24),
      request_digest: "f".repeat(64),
      client_id: "oc_claude",
      capability: "github.repo.transfer",
      resource: "github:o/r",
      summary: "Transfer repo",
      status: "pending" as const,
      created_at: "2026-11-14T15:00:00.000Z",
      expires_at: "2026-11-14T15:10:00.000Z",
    };
    const res = await sendApprovalRequest(
      { record, clientName: "Claude\u202e", approveData: `a:${"B".repeat(24)}:${"m".repeat(22)}`, denyData: `d:${"B".repeat(24)}:${"m".repeat(22)}` },
      { fetch: tg.fetch, env: ENV },
    );
    assert.equal(res.message_id, 31337);
    const body = tg.calls[0].body;
    assert.equal(body.chat_id, APPROVER);
    assert.equal(body.parse_mode, undefined);
    assert.deepEqual(body.link_preview_options, { is_disabled: true });
    assert.deepEqual(
      body.reply_markup.inline_keyboard[0].map((b: { text: string }) => b.text),
      ["Approve", "Deny"],
    );
    assert.ok(body.text.length <= 4096);
    assert.ok(body.text.includes("github.repo.transfer"));
    assert.equal(body.text.includes("\u202e"), false);
    await expectTelegramError(
      sendApprovalRequest(
        { record, clientName: "x", approveData: "a".repeat(65), denyData: "d" },
        { fetch: tg.fetch, env: ENV },
      ),
      "telegram_callback_data_too_long",
    );
  });

  it("network errors that embed the URL never surface the token", async () => {
    await expectTelegramError(
      callBotApi("sendMessage", { chat_id: APPROVER, text: "x" }, { fetch: fakeTelegram("throw").fetch, env: ENV }),
      "telegram_network_error",
    );
  });

  it("API errors whose description echoes the token never surface it", async () => {
    await expectTelegramError(
      callBotApi("sendMessage", {}, { fetch: fakeTelegram("api_error").fetch, env: ENV }),
      "telegram_http_400",
    );
    await expectTelegramError(
      callBotApi("sendMessage", {}, { fetch: fakeTelegram("garbage").fetch, env: ENV }),
      "telegram_http_502",
    );
  });

  it("missing or malformed bot token fails closed without calling fetch", async () => {
    const tg = fakeTelegram();
    for (const value of [undefined, "", "not-a-token", "123:short", `${TOKEN}/../x`]) {
      await expectTelegramError(
        callBotApi("getMe", {}, { fetch: tg.fetch, env: { ...ENV, TELEGRAM_BOT_TOKEN: value } }),
        "telegram_bot_token_missing",
      );
    }
    assert.equal(tg.calls.length, 0);
  });

  it("setTelegramWebhook sends the secret_token and limits updates to callback queries", async () => {
    const tg = fakeTelegram();
    await setTelegramWebhook("https://vault.example/api/telegram/webhook", { fetch: tg.fetch, env: ENV });
    assert.equal(tg.calls[0].method, "setWebhook");
    assert.equal(tg.calls[0].body.secret_token, WEBHOOK_SECRET);
    assert.deepEqual(tg.calls[0].body.allowed_updates, ["callback_query"]);
    await expectTelegramError(
      setTelegramWebhook("https://vault.example/x", { fetch: fakeTelegram("api_error").fetch, env: ENV }),
      "telegram_http_400",
    );
    await expectTelegramError(
      setTelegramWebhook("http://insecure.example/x", { fetch: tg.fetch, env: ENV }),
      "telegram_webhook_url_not_https",
    );
  });

  it("formatApprovalText strips control characters and stays within 4096 chars", () => {
    const text = formatApprovalText(
      {
        id: "C".repeat(24),
        request_digest: "a".repeat(64),
        client_id: "oc_x",
        capability: "email.send",
        resource: `mail:${"z".repeat(5000)}`,
        summary: "line1\nline2\u0007",
        status: "pending",
        created_at: "2026-11-14T15:00:00.000Z",
        expires_at: "2026-11-14T15:10:00.000Z",
      },
      "Agent\u0000Name",
    );
    assert.ok(text.length <= 4096);
    // eslint-disable-next-line no-control-regex -- asserting control characters were stripped
    assert.equal(/[\u0000\u0007]/.test(text), false);
    assert.ok(text.includes("Summary: line1 line2"));
  });
});
