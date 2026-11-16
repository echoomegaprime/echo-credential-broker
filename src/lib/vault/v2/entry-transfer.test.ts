// library-first: echo.functions.search → no existing impl found (2026-11-16)
/**
 * entry_transfer tests. Everything is in-memory or faked, with the same fakes
 * the entry_use tests use (gateway.test.ts): stores, the vault backend,
 * Telegram and the destination's own site. No network, no real vault, and
 * every "secret" below is an obviously fake test value.
 *
 * The invariant under test: neither the source nor the destination secret ever
 * reaches a tool result, a ledger row, an approval prompt or a log line.
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { FakeVaultBackend } from "../backend.ts";
import { MemoryApprovalStore } from "./approvals.ts";
import { handleCardRequest } from "./card-pages.ts";
import { MemoryCardStore, MemoryEntryStore, type CardsDeps } from "./cards.ts";
import type { ClientIdentity, LedgerEntryInput } from "./contracts.ts";
import { MemoryEntryGrantStore } from "./entry-grants.ts";
import {
  buildTransferBody,
  locatePlaceholder,
  parseTransferAuth,
  TRANSFER_CAPABILITY,
  TRANSFER_PLACEHOLDER,
  TransferInputError,
  transferRedactionForms,
} from "./entry-transfer.ts";
import { dispatchTool, listTools, type GatewayDeps, type GatewayResult } from "./gateway.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";
import type { PinnedFetch } from "./pinned-fetch.ts";
import { lookupCapability, requiredScope } from "./policy-engine.ts";
import { MemoryRateLimitStore, setDefaultRateLimitStore } from "./rate-limit-store.ts";
import { handleTelegramWebhook } from "./telegram.ts";

// Rate-limit state defaults to the shared SQL store; this file keeps it in memory.
setDefaultRateLimitStore(new MemoryRateLimitStore());

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ORIGIN = "https://vault.example.test";
const APPROVER_ID = 424242;
const WEBHOOK_SECRET = "test-webhook-secret-0123456789";
const ENV: NodeJS.ProcessEnv = {
  TELEGRAM_BOT_TOKEN: "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789",
  ECHO_VAULT_APPROVER_TELEGRAM_ID: String(APPROVER_ID),
  ECHO_VAULT_PUBLIC_URL: ORIGIN,
  ECHO_VAULT_APPROVAL_HMAC_KEY: "test-only-approval-hmac-key-0123456789abcdef",
  ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET: WEBHOOK_SECRET,
};
const PUBLIC_IP = "140.82.112.5";

// Fake values. The source one contains characters that change under URL encoding and JSON
// escaping, and neither looks like a provider token, so only the registered-value redaction
// (not a pattern rule) can be what removes them.
const SOURCE_SECRET = "TESTONLY-fake-source+cred/ential=A1b2 c3";
const DEST_SECRET = "TESTONLY-fake-destination-cred-Z9y8x7";
const OTHER_SOURCE_SECRET = "TESTONLY-fake-second-source-Q5w6e7r8";
const PASSWORD_SECRET = "TESTONLY-fake-password-P4s5w6d7";
const OPERATOR_SECRET = "TESTONLY-fake-operator-O1p2e3r4";
const COOKIE_VALUE = "TESTONLYfakecookievalue0011223344";
const ALL_SECRETS = [SOURCE_SECRET, DEST_SECRET, OTHER_SOURCE_SECRET, PASSWORD_SECRET, OPERATOR_SECRET, COOKIE_VALUE];

const SRC_SITE = "source-svc.example";
const DST_SITE = "dest-svc.example";
const DST_HOST = `api.${DST_SITE}`;
const TASK = "Store the source key as a secret in the destination workspace";

// Process output (logs) is captured for the whole file and scanned for secrets at the end.
const captured: string[] = [];
const restores: Array<() => void> = [];
const everyResult: unknown[] = [];
const everyLedgerRow: unknown[] = [];
const everyPrompt: unknown[] = [];

before(() => {
  for (const stream of [process.stdout, process.stderr]) {
    const orig = stream.write.bind(stream);
    const isErr = stream === process.stderr;
    stream.write = ((chunk: unknown, enc?: unknown, cb?: unknown) => {
      captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("latin1"));
      // Keep the vault logger's stderr lines out of the report; stdout carries the test runner's stream.
      return isErr ? true : orig(chunk as never, enc as never, cb as never);
    }) as typeof stream.write;
    restores.push(() => {
      stream.write = orig as typeof stream.write;
    });
  }
});

/** Every spelling of a secret this file looks for: raw, URL-encoded, base64 (padded or not), base64url, JSON-escaped. */
function spellings(secret: string): string[] {
  const b64 = Buffer.from(secret).toString("base64");
  return [...new Set([secret, encodeURIComponent(secret), b64, b64.replace(/=+$/, ""), Buffer.from(secret).toString("base64url"), JSON.stringify(secret).slice(1, -1)])];
}

function scan(label: string, value: unknown): void {
  const blob = typeof value === "string" ? value : JSON.stringify(value);
  for (const secret of ALL_SECRETS) {
    for (const form of spellings(secret)) assert.equal(blob.includes(form), false, `${label} contains a secret (or an encoding of one)`);
  }
}

after(() => {
  for (const restore of restores) restore();
  scan("captured process output", captured.join("\n"));
  scan("every tool result", everyResult);
  scan("every ledger row", everyLedgerRow);
  scan("every Telegram prompt", everyPrompt);
});

interface SiteCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
}

function makeWorld() {
  const telegram: Array<{ method: string; payload: Record<string, unknown> }> = [];
  const telegramFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    assert.ok(url.startsWith("https://api.telegram.org/bot"), "telegram fetch used for a non-telegram URL");
    const payload = JSON.parse(String(init?.body ?? "{}"));
    telegram.push({ method: url.split("/").pop() ?? "", payload });
    everyPrompt.push(payload);
    return new Response(JSON.stringify({ ok: true, result: { message_id: telegram.length } }), { status: 200 });
  }) as typeof fetch;

  // The destination's own site. By default it stores what it is sent and answers with an id.
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "set-cookie": "session=abc" } });
  const site = {
    calls: [] as SiteCall[],
    respond: ((): Response => json(200, { id: "sec_0001", stored: true })) as (call: SiteCall) => Response,
    json,
  };
  const siteFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, key) => {
      headers[key] = value;
    });
    const call: SiteCall = { url: new URL(String(input)).href, method: init?.method ?? "GET", headers, body: typeof init?.body === "string" ? init.body : null };
    site.calls.push(call);
    return site.respond(call);
  }) as typeof fetch;

  const backend = new FakeVaultBackend();
  const ledgerStore = new MemoryLedgerStore();
  const ledger = new Ledger({ store: ledgerStore });
  const approvalStore = new MemoryApprovalStore();
  // The entry store, with every call counted (the missing-scope test asserts it is never touched).
  let entryStoreCalls = 0;
  const entries = new Proxy(new MemoryEntryStore(), {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => {
        entryStoreCalls += 1;
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  /** When set, a ledger write the predicate matches fails, as an unreachable ledger would. */
  let ledgerDown: ((row: LedgerEntryInput) => boolean) | null = null;
  const ledgerSink = async (input: LedgerEntryInput) => {
    if (ledgerDown?.(input)) throw Object.assign(new Error("ledger unreachable"), { code: "ledger_unavailable" });
    return ledger.append(input);
  };
  const cards: CardsDeps = { entries, cards: new MemoryCardStore(), backend, ledger: ledgerSink, fetch: telegramFetch, env: ENV };
  const deps: GatewayDeps = {
    ledger: ledgerSink,
    listLedger: (opts) => ledger.list(opts),
    verifyLedger: () => ledger.verify(),
    ledgerHead: () => ledger.head(),
    approvals: { store: approvalStore, fetch: telegramFetch, env: ENV },
    rules: [],
    cards,
    grants: new MemoryEntryGrantStore(),
    fetch: siteFetch,
    resolveHost: async () => [PUBLIC_IP],
  };

  const callWith = async (identity: ClientIdentity, name: string, args: unknown, withDeps: GatewayDeps): Promise<GatewayResult> => {
    const result = await dispatchTool(identity, name, args, withDeps);
    everyResult.push(result);
    return result;
  };
  const call = (identity: ClientIdentity, name: string, args: unknown = {}) => callWith(identity, name, args, deps);

  /** The owner taps a button on their phone: replay the callback_data of that approval's prompt through the real webhook handler. */
  const tap = async (approvalId: string, action: "Approve" | "Deny" = "Approve"): Promise<void> => {
    type Keyboard = { inline_keyboard?: Array<Array<{ text: string; callback_data: string }>> };
    const prompt = [...telegram].reverse().find((c) => (c.payload.reply_markup as Keyboard | undefined)?.inline_keyboard?.[0]?.some((b) => b.callback_data.includes(approvalId)));
    assert.ok(prompt, "no Telegram prompt for that approval");
    const data = (prompt.payload.reply_markup as Required<Keyboard>).inline_keyboard[0].find((b) => b.text === action)?.callback_data;
    const res = await handleTelegramWebhook(
      new Request(`${ORIGIN}/api/telegram/webhook`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-telegram-bot-api-secret-token": WEBHOOK_SECRET },
        body: JSON.stringify({ callback_query: { id: "cq1", from: { id: APPROVER_ID }, data, message: { message_id: 1, chat: { id: APPROVER_ID } } } }),
      }),
      { store: approvalStore, fetch: telegramFetch, env: ENV },
    );
    assert.equal(res.status, 200);
  };

  /** Create an entry through the card flow (the agent asks, the owner types the secret) and return its id. */
  const seed = async (opts: { site: string; account: string; kind: string; secret: string }): Promise<string> => {
    const seeder = client("oc_seeder", ["vault.read", "vault.write"]);
    expectOk(await call(seeder, "entry_request_card", { site: opts.site, account: opts.account, kind: opts.kind, reason: "seed an entry for the test" }));
    const text = [...telegram].reverse().find((c) => typeof c.payload.text === "string" && /\/card\//.test(c.payload.text as string));
    const token = /\/card\/([A-Za-z0-9_-]{43})/.exec(String(text?.payload.text))?.[1];
    assert.ok(token, "no card link was sent to the owner");
    const res = await handleCardRequest(
      new Request(`${ORIGIN}/card/${token}`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", origin: "null", "sec-fetch-site": "same-origin" },
        body: new URLSearchParams({ secret: opts.secret }).toString(),
      }),
      token,
      cards,
    );
    assert.equal(res.status, 200, "the card accepted the test value");
    const listed = expectOk(await call(seeder, "entry_list", { site: opts.site })).entries as Array<Record<string, unknown>>;
    const id = listed.find((e) => e.account === opts.account && e.kind === opts.kind)?.id;
    assert.ok(typeof id === "string", "seeded entry has an id");
    return id;
  };

  const entryOf = async (site: string, account: string): Promise<Record<string, unknown>> => {
    const listed = expectOk(await call(client("oc_seeder", ["vault.read", "vault.write"]), "entry_list", { site })).entries as Array<Record<string, unknown>>;
    const found = listed.find((e) => e.account === account);
    assert.ok(found, `entry ${site}/${account} exists`);
    return found;
  };

  const rows = async () => {
    const all = await ledgerStore.scanAscending(0, 10_000);
    everyLedgerRow.push(all);
    return all;
  };
  const transferRows = async () => (await rows()).filter((r) => r.capability === TRANSFER_CAPABILITY);
  /** Approval prompts sent so far (messages with Approve / Deny buttons). */
  const prompts = () => telegram.filter((c) => c.payload.reply_markup !== undefined).map((c) => String(c.payload.text));

  return {
    deps,
    call,
    callWith,
    tap,
    seed,
    entryOf,
    site,
    telegram,
    prompts,
    ledger,
    rows,
    transferRows,
    entryStoreCalls: () => entryStoreCalls,
    setLedgerDown: (predicate: ((row: LedgerEntryInput) => boolean) | null) => {
      ledgerDown = predicate;
    },
  };
}

type World = ReturnType<typeof makeWorld>;

function client(id: string, scopes: string[]): ClientIdentity {
  return { client_id: id, name: id, kind: "oauth", scopes };
}

function expectFail(result: GatewayResult, error: string): Extract<GatewayResult, { ok: false }> {
  assert.equal(result.ok, false, JSON.stringify(result));
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.error, error, JSON.stringify(result));
  return result;
}

function expectOk(result: GatewayResult): Record<string, unknown> {
  assert.equal(result.ok, true, JSON.stringify(result));
  if (!result.ok) throw new Error("unreachable");
  return result.data as Record<string, unknown>;
}

const AGENT = client("oc_transfer_agent", ["vault.read", "vault.write"]);

/** A world with one source entry and one destination entry, as in the motivating case. */
async function pairWorld(): Promise<World & { fromId: string; toId: string }> {
  const w = makeWorld();
  const fromId = await w.seed({ site: SRC_SITE, account: "owner", kind: "api_key", secret: SOURCE_SECRET });
  const toId = await w.seed({ site: DST_SITE, account: "workspace", kind: "api_key", secret: DEST_SECRET });
  return { ...w, fromId, toId };
}

function transferArgs(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    from_site: SRC_SITE,
    from_account: "owner",
    to_site: DST_SITE,
    to_account: "workspace",
    method: "POST",
    host: DST_HOST,
    url_path: "/v1/workspace/secrets",
    body: { type: "new", name: "SOURCE_API_KEY", value: TRANSFER_PLACEHOLDER },
    task: TASK,
    ...over,
  };
}

/** Ask, have the owner approve that exact request, and run it. */
async function approveAndRun(w: World, who: ClientIdentity, args: Record<string, unknown>, deps?: GatewayDeps): Promise<GatewayResult> {
  const ask = expectFail(await w.callWith(who, "entry_transfer", args, deps ?? w.deps), "approval_required");
  await w.tap(String(ask.approval_id));
  return w.callWith(who, "entry_transfer", { ...args, approval_id: ask.approval_id }, deps ?? w.deps);
}

// ---------------------------------------------------------------------------
// The pure parts (entry-transfer.ts)
// ---------------------------------------------------------------------------

describe("entry-transfer.ts: placeholder, auth header and body helpers", () => {
  it("locates the one placeholder and names its field as a dotted / indexed path", () => {
    assert.equal(locatePlaceholder({ type: "new", value: TRANSFER_PLACEHOLDER }).path, "value");
    assert.equal(locatePlaceholder({ config: { keys: [{ secret: TRANSFER_PLACEHOLDER }] } }).path, "config.keys[0].secret");
    assert.equal(locatePlaceholder({ list: ["a", ["b", TRANSFER_PLACEHOLDER]] }).path, "list[1][1]");
    // A key that could be mistaken for a nested path is quoted, never shown as dots.
    assert.equal(locatePlaceholder({ "a.b": { "odd key": TRANSFER_PLACEHOLDER } }).path, '["a.b"]["odd key"]');
    // Control and bidi characters in a key never reach the owner's phone; a long key is clipped.
    const hostile = locatePlaceholder({ ["x\u202e\u0007y"]: { ["k".repeat(200)]: TRANSFER_PLACEHOLDER } }).path;
    assert.equal([...hostile].some((ch) => ch.charCodeAt(0) < 0x20 || (ch >= "\u202a" && ch <= "\u202e")), false);
    assert.ok(hostile.length < 80, hostile);
  });

  it("refuses zero, two, embedded, key and non-object uses, and never echoes body content in the message", () => {
    const MARK = "DO-NOT-ECHO-this-body-content";
    const bad: unknown[] = [
      { note: MARK },
      { a: TRANSFER_PLACEHOLDER, b: TRANSFER_PLACEHOLDER, note: MARK },
      { a: [TRANSFER_PLACEHOLDER, { deep: TRANSFER_PLACEHOLDER }], note: MARK },
      { a: `Bearer ${TRANSFER_PLACEHOLDER}`, note: MARK },
      { a: ` ${TRANSFER_PLACEHOLDER}`, note: MARK },
      { [TRANSFER_PLACEHOLDER]: "x", note: MARK },
      { [`k-${TRANSFER_PLACEHOLDER}`]: TRANSFER_PLACEHOLDER, note: MARK },
      [TRANSFER_PLACEHOLDER],
      TRANSFER_PLACEHOLDER,
      `{"value":"${TRANSFER_PLACEHOLDER}"}`,
      null,
      42,
    ];
    for (const body of bad) {
      assert.throws(
        () => locatePlaceholder(body),
        (err: unknown) => err instanceof TransferInputError && !err.message.includes(MARK),
        JSON.stringify(body),
      );
    }
    let deep: unknown = TRANSFER_PLACEHOLDER;
    for (let i = 0; i < 100; i += 1) deep = { d: deep };
    assert.throws(() => locatePlaceholder(deep), TransferInputError);
  });

  it("to_auth: default, or one lower-cased header name that cannot route, frame or already authenticate the request", () => {
    assert.deepEqual(parseTransferAuth(undefined), { scheme: "default" });
    assert.deepEqual(parseTransferAuth({ scheme: "default" }), { scheme: "default" });
    assert.deepEqual(parseTransferAuth({ scheme: "header", name: "Xi-Api-Key" }), { scheme: "header", name: "xi-api-key" });
    assert.deepEqual(parseTransferAuth({ scheme: "header", name: "x".repeat(40) }), { scheme: "header", name: "x".repeat(40) });
    const forbidden = [
      "host", "cookie", "set-cookie", "content-length", "content-type", "transfer-encoding", "connection", "authorization",
      "proxy-authorization", "te", "upgrade", "via", "forwarded", "x-forwarded-for", "X-Forwarded-Host", "sec-fetch-site", "Sec-WebSocket-Key",
      "Authorization", "COOKIE", "", "1abc", "-abc", "bad name", "x_api_key", "x-api-key:", "x-api-key\r\nhost", "x".repeat(41), "clé",
    ];
    for (const name of forbidden) assert.throws(() => parseTransferAuth({ scheme: "header", name }), TransferInputError, name);
    for (const shape of ["header", [], { scheme: "bearer" }, { scheme: "header" }, { scheme: "header", name: 7 }, { scheme: "header", name: "x-key", extra: 1 }, { scheme: "default", name: "x-key" }, { name: "x-key" }]) {
      assert.throws(() => parseTransferAuth(shape), TransferInputError, JSON.stringify(shape));
    }
  });

  it("builds the body by replacing only the placeholder value, with JSON escaping done by JSON.stringify", () => {
    const awkward = 'q"uote\\back\nline\u2028é😀';
    const template = JSON.stringify({ name: "K", nested: [{ value: TRANSFER_PLACEHOLDER }], n: 1, t: true, z: null });
    const sent = buildTransferBody(template, awkward);
    assert.deepEqual(JSON.parse(sent), { name: "K", nested: [{ value: awkward }], n: 1, t: true, z: null });
    assert.equal(sent.includes(TRANSFER_PLACEHOLDER), false);
    // A secret that is itself JSON cannot add fields: it stays one string.
    const injected = JSON.parse(buildTransferBody(template, '","admin":true,"x":"'));
    assert.deepEqual(Object.keys(injected).sort(), ["n", "name", "nested", "t", "z"]);
  });

  it("lists the encodings of the transferred secret that are armed for redaction", () => {
    const forms = transferRedactionForms(SOURCE_SECRET);
    for (const form of spellings(SOURCE_SECRET).filter((f) => f !== SOURCE_SECRET)) assert.ok(forms.includes(form), "an encoding is missing");
    assert.equal(forms.includes(SOURCE_SECRET), false, "the raw value is armed by cards.ts, not listed here");
    assert.ok(transferRedactionForms('a"b\\c-0123456789').includes('a\\"b\\\\c-0123456789'), "JSON-escaped form");
  });
});

// ---------------------------------------------------------------------------
// The tool, through dispatchTool
// ---------------------------------------------------------------------------

describe("entry_transfer: registration", () => {
  it("is a listed tool under vault.entry.transfer: tier 2, scope vault.write", () => {
    const tool = listTools().find((t) => t.name === "entry_transfer");
    assert.ok(tool, "entry_transfer is in tools/list");
    assert.match(tool.description, /Neither secret is ever returned/);
    assert.match(tool.description, /vault\.write/);
    assert.match(tool.description, /EVERY call/);
    assert.deepEqual((tool.inputSchema.required as string[]).sort(), ["body", "from_site", "method", "task", "to_site", "url_path"]);
    assert.deepEqual(lookupCapability(TRANSFER_CAPABILITY), { tier: 2, access: "write" });
    assert.equal(requiredScope(TRANSFER_CAPABILITY), "vault.write");
  });
});

describe("entry_transfer: the transfer itself", () => {
  it("1. default auth: the destination gets its own credential as the Authorization header and the source secret in the marked field; nothing secret comes back or is recorded", async () => {
    const w = await pairWorld();
    const args = transferArgs();

    const ask = expectFail(await w.call(AGENT, "entry_transfer", args), "approval_required");
    assert.equal(ask.tier, 2);
    assert.equal(w.site.calls.length, 0, "nothing leaves before the owner approves");
    await w.tap(String(ask.approval_id));
    const data = expectOk(await w.call(AGENT, "entry_transfer", { ...args, approval_id: ask.approval_id }));

    // What the destination received.
    assert.equal(w.site.calls.length, 1);
    const sent = w.site.calls[0];
    assert.equal(sent.url, `https://${DST_HOST}/v1/workspace/secrets`);
    assert.equal(sent.method, "POST");
    assert.equal(sent.headers.authorization, `Bearer ${DEST_SECRET}`);
    assert.equal(sent.headers["content-type"], "application/json");
    assert.deepEqual(JSON.parse(String(sent.body)), { type: "new", name: "SOURCE_API_KEY", value: SOURCE_SECRET });
    assert.equal(String(sent.body).includes(TRANSFER_PLACEHOLDER), false);

    // What the agent got: status, body and entry metadata. No header, no secret.
    assert.deepEqual(Object.keys(data).sort(), ["body", "from", "status", "to"]);
    assert.equal(data.status, 200);
    assert.deepEqual(data.body, { id: "sec_0001", stored: true });
    assert.deepEqual([(data.from as Record<string, unknown>).id, (data.to as Record<string, unknown>).id], [w.fromId, w.toId]);
    for (const view of [data.from, data.to] as Array<Record<string, unknown>>) {
      assert.equal("fingerprint" in view, false);
      assert.equal("secret_length" in view, false);
    }
    scan("transfer result", data);

    // Each entry's use is recorded and its last-used time moves.
    assert.ok((await w.entryOf(SRC_SITE, "owner")).last_used_at, "source last_used_at");
    assert.ok((await w.entryOf(DST_SITE, "workspace")).last_used_at, "destination last_used_at");
    const rows = await w.transferRows();
    assert.deepEqual(
      rows.map((r) => [r.result, r.decision, r.tier, r.credential_ref ?? null, r.http_status ?? null]),
      [
        ["pending_approval", "escalate", 2, null, null],
        ["committing", "escalate", 2, null, null],
        ["ok", "escalate", 2, `vault://entry/${w.toId}`, 200],
        ["ok", "escalate", 2, `vault://entry/${w.fromId}`, 200],
      ],
    );
    for (const row of rows.slice(1)) assert.equal(row.approval_id, ask.approval_id);
    for (const row of rows) assert.equal(row.task, TASK);
    const [destinationRow, sourceRow] = rows.slice(2);
    assert.match(destinationRow.resource, /\[destination\]/);
    assert.match(sourceRow.resource, /\[source\]/);
    for (const row of [destinationRow, sourceRow]) {
      // Both entries by id, the request line and the field; no body.
      for (const part of [w.fromId, w.toId, `entry:${SRC_SITE}/owner`, `entry:${DST_SITE}/workspace`, `POST https://${DST_HOST}/v1/workspace/secrets`, "field value"]) {
        assert.ok(row.resource.includes(part), `ledger row names ${part}`);
      }
      assert.equal(row.resource.includes("SOURCE_API_KEY"), false, "no body content in the ledger");
    }
    scan("ledger rows", await w.rows());
    assert.equal((await w.ledger.verify()).ok, true);
    assert.ok(captured.join("\n").includes("vault_entry_used"), "the log capture is live");
    scan("logs so far", captured.join("\n"));
  });

  it("2. to_auth header: the destination credential arrives in that header and NO Authorization header is sent", async () => {
    const w = await pairWorld();
    // Any letter case is accepted; the header goes out (and is approved) lower-cased.
    const data = expectOk(await approveAndRun(w, AGENT, transferArgs({ to_auth: { scheme: "header", name: "Xi-Api-Key" } })));
    assert.equal(data.status, 200);
    assert.equal(w.site.calls.length, 1);
    const sent = w.site.calls[0];
    assert.equal(sent.headers["xi-api-key"], DEST_SECRET);
    assert.equal("authorization" in sent.headers, false, "no Authorization header with a header scheme");
    assert.equal("cookie" in sent.headers, false);
    assert.equal(JSON.parse(String(sent.body)).value, SOURCE_SECRET);
    assert.equal(Object.values(sent.headers).filter((v) => v.includes(DEST_SECRET)).length, 1, "the destination credential is sent exactly once");
    assert.equal(Object.values(sent.headers).some((v) => v.includes(SOURCE_SECRET)), false, "the source secret is never a header");
    scan("header-scheme result", data);
    scan("ledger rows", await w.rows());
  });

  it("2b. a password destination authenticates with HTTP Basic, exactly as entry_use does", async () => {
    const w = await pairWorld();
    await w.seed({ site: "basic-dest.example", account: "svc-user", kind: "password", secret: PASSWORD_SECRET });
    const data = expectOk(await approveAndRun(w, AGENT, transferArgs({ to_site: "basic-dest.example", to_account: "svc-user", host: "basic-dest.example" })));
    assert.equal(data.status, 200);
    assert.equal(w.site.calls[0].headers.authorization, `Basic ${Buffer.from(`svc-user:${PASSWORD_SECRET}`).toString("base64")}`);
    assert.equal(JSON.parse(String(w.site.calls[0].body)).value, SOURCE_SECRET);
    scan("password-destination result", data);
  });

  it("3. a destination that echoes what it was sent (verbatim, URL-encoded, base64, inside other text, as text/plain) gets it redacted on the way back", async () => {
    const w = await pairWorld();
    const b64 = Buffer.from(SOURCE_SECRET).toString("base64");
    w.site.respond = (call) => {
      const value = String(JSON.parse(String(call.body)).value);
      const credential = call.headers["xi-api-key"] ?? call.headers.authorization ?? "";
      return w.site.json(201, {
        echo: value,
        echo_in_text: `stored ${value} for you`,
        echo_url: encodeURIComponent(value),
        echo_form: `value=${encodeURIComponent(value)}&ok=1`,
        echo_b64: b64,
        echo_b64_unpadded: b64.replace(/=+$/, ""),
        echo_b64url: Buffer.from(value).toString("base64url"),
        echo_raw_body: call.body,
        nested: [{ deep: { again: value } }],
        you_authenticated_with: credential,
        [value]: "as a key",
      });
    };
    const data = expectOk(await approveAndRun(w, AGENT, transferArgs({ to_auth: { scheme: "header", name: "xi-api-key" } })));
    assert.equal(data.status, 201);
    assert.equal(JSON.parse(String(w.site.calls[0].body)).value, SOURCE_SECRET, "the site really was sent the secret");
    scan("echoed JSON result", data);
    const body = data.body as Record<string, unknown>;
    assert.match(String(body.echo), /REDACTED/);
    assert.match(String(body.echo_in_text), /^stored \[REDACTED_SECRET\] for you$/);
    assert.match(String(body.you_authenticated_with), /REDACTED/);

    // The same echo as plain text (no JSON leaves to redact one by one).
    w.site.respond = (call) => {
      const value = String(JSON.parse(String(call.body)).value);
      return new Response(`saved: ${value} | ${encodeURIComponent(value)} | ${b64} | ${call.body} | ${call.headers.authorization}`, { status: 200, headers: { "content-type": "text/plain" } });
    };
    const text = expectOk(await approveAndRun(w, AGENT, transferArgs({ task: "second transfer, plain-text answer" })));
    assert.equal(typeof text.body, "string");
    assert.match(String(text.body), /REDACTED/);
    scan("echoed text result", text);
    scan("ledger rows", await w.rows());
  });

  it("3b. a response's headers never come back: no Location, no content type, no Set-Cookie", async () => {
    const w = await pairWorld();
    w.site.respond = () =>
      new Response(JSON.stringify({ moved: true }), {
        status: 307,
        headers: { "content-type": "application/json", location: "https://elsewhere.example/steal", "set-cookie": "sid=abcdef0123456789", "x-request-id": "r-1" },
      });
    const data = expectOk(await approveAndRun(w, AGENT, transferArgs()));
    assert.deepEqual(Object.keys(data).sort(), ["body", "from", "status", "to"]);
    assert.equal(data.status, 307);
    assert.equal(w.site.calls.length, 1, "a redirect is reported, never followed: the body is not replayed to another host");
    const blob = JSON.stringify(data);
    for (const leak of ["elsewhere.example", "sid=abcdef", "r-1"]) assert.equal(blob.includes(leak), false, leak);
  });

  it("goes through the DNS-pinned transport with entry_use's limits (production branch: no injected fetch)", async () => {
    const w = await pairWorld();
    const sent: Array<{ url: string; addresses: string[]; header: string | null; auth: string | null; body: unknown; timeoutMs?: number; maxResponseBytes?: number; testOnly: boolean }> = [];
    const pinned: PinnedFetch = async (url, init, options) => {
      const headers = new Headers(init.headers);
      sent.push({
        url: String(url),
        addresses: [...options.addresses],
        header: headers.get("xi-api-key"),
        auth: headers.get("authorization"),
        body: init.body,
        timeoutMs: options.timeoutMs,
        maxResponseBytes: options.maxResponseBytes,
        testOnly: options.testOnly !== undefined,
      });
      options.onConnect?.(options.addresses[0]);
      return new Response(JSON.stringify({ ok: true, echo: JSON.parse(String(init.body)).value }), { status: 200, headers: { "content-type": "application/json" } });
    };
    const realFetch = globalThis.fetch;
    let globalFetchCalls = 0;
    globalThis.fetch = (async () => {
      globalFetchCalls += 1;
      throw new Error("global fetch must not be used by entry_transfer");
    }) as typeof fetch;
    try {
      const resolved: string[] = [];
      const deps: GatewayDeps = {
        ...w.deps,
        fetch: undefined,
        pinnedFetch: pinned,
        resolveHost: async (host) => {
          resolved.push(host);
          return [PUBLIC_IP];
        },
      };
      const data = expectOk(await approveAndRun(w, AGENT, transferArgs({ to_auth: { scheme: "header", name: "xi-api-key" } }), deps));
      assert.deepEqual(resolved, [DST_HOST], "resolved once, only after approval");
      assert.equal(sent.length, 1);
      assert.equal(sent[0].url, `https://${DST_HOST}/v1/workspace/secrets`);
      assert.deepEqual(sent[0].addresses, [PUBLIC_IP], "pinned to the validated address");
      assert.deepEqual([sent[0].header, sent[0].auth], [DEST_SECRET, null]);
      assert.equal(JSON.parse(String(sent[0].body)).value, SOURCE_SECRET);
      assert.deepEqual([sent[0].timeoutMs, sent[0].maxResponseBytes, sent[0].testOnly], [12_000, 1024 * 1024, false]);
      assert.equal(globalFetchCalls, 0);
      scan("pinned transfer result", data);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});

describe("entry_transfer: what is refused before anything is sent", () => {
  /** Refused at once: the given error, no request, no approval prompt. */
  async function refused(w: World, args: Record<string, unknown>, error: string, who: ClientIdentity = AGENT): Promise<Extract<GatewayResult, { ok: false }>> {
    const promptsBefore = w.prompts().length;
    const sentBefore = w.site.calls.length;
    const result = expectFail(await w.call(who, "entry_transfer", args), error);
    assert.equal(w.site.calls.length, sentBefore, `nothing is sent (${error})`);
    assert.equal(w.prompts().length, promptsBefore, `no approval is created (${error})`);
    assert.equal("approval_id" in result, false);
    return result;
  }

  it("4. placeholder rules: zero, two, embedded in a longer string, in a key, body not an object, body a string, body missing", async () => {
    const w = await pairWorld();
    const MARK = "DO-NOT-ECHO-other-body-content";
    const bodies: unknown[] = [
      { type: "new", name: MARK },
      { value: TRANSFER_PLACEHOLDER, again: TRANSFER_PLACEHOLDER, name: MARK },
      { value: TRANSFER_PLACEHOLDER, list: [{ again: TRANSFER_PLACEHOLDER }], name: MARK },
      { value: `Bearer ${TRANSFER_PLACEHOLDER}`, name: MARK },
      { value: `${TRANSFER_PLACEHOLDER}\n`, name: MARK },
      { [TRANSFER_PLACEHOLDER]: "value", name: MARK },
      { [`x${TRANSFER_PLACEHOLDER}`]: TRANSFER_PLACEHOLDER, name: MARK },
      [{ value: TRANSFER_PLACEHOLDER }],
      `{"value":"${TRANSFER_PLACEHOLDER}"}`,
      TRANSFER_PLACEHOLDER,
      7,
      true,
    ];
    for (const body of bodies) {
      const result = await refused(w, transferArgs({ body }), "invalid_arguments");
      assert.equal(JSON.stringify(result).includes(MARK), false, "the refusal does not echo other body content");
    }
    const noBody = transferArgs();
    delete noBody.body;
    await refused(w, noBody, "invalid_arguments");
    await refused(w, transferArgs({ body: null }), "invalid_arguments");
    // content_type and other entry_use-only arguments do not exist here.
    await refused(w, transferArgs({ content_type: "text/plain" }), "invalid_arguments");
    await refused(w, transferArgs({ body: { value: TRANSFER_PLACEHOLDER, pad: "x".repeat(256 * 1024) } }), "request_too_large");
    assert.equal((await w.transferRows()).length, 0, "an argument refusal is not a transfer row");
    scan("refusals", await w.rows());
  });

  it("5. method, host and path rules: POST/PUT/PATCH only; exactly the destination site or api.<site>; blocked and private hosts", async () => {
    const w = await pairWorld();
    for (const method of ["GET", "HEAD", "DELETE", "OPTIONS", "get", "delete"]) await refused(w, transferArgs({ method }), "invalid_arguments");
    for (const host of ["evil.example", SRC_SITE, `api.${SRC_SITE}`, `${DST_HOST}.evil.example`, `app.${DST_SITE}`, `api.${DST_SITE}:8443`, "127.0.0.1", "localhost"]) {
      await refused(w, transferArgs({ host }), "hostname_not_allowed");
    }
    for (const url_path of ["https://evil.example/x", "//evil.example/x", "/../../etc/passwd", "v1/secrets"]) await refused(w, transferArgs({ url_path }), "invalid_arguments");
    await refused(w, transferArgs({ task: "" }), "invalid_arguments");

    // A destination entry whose own site is not reachable through the broker.
    await w.seed({ site: "vault.internal", account: "svc", kind: "api_key", secret: OTHER_SOURCE_SECRET });
    await refused(w, transferArgs({ to_site: "vault.internal", to_account: "svc", host: "vault.internal" }), "hostname_not_allowed");

    // PUT and PATCH are allowed; the default host is the destination site itself.
    for (const method of ["PUT", "patch"]) {
      const args = transferArgs({ method, task: `transfer with ${method}` });
      delete args.host;
      expectOk(await approveAndRun(w, AGENT, args));
      const last = w.site.calls[w.site.calls.length - 1];
      assert.deepEqual([last.method, last.url], [method.toUpperCase(), `https://${DST_SITE}/v1/workspace/secrets`]);
    }

    // The destination's name resolves to a private address: approved, but nothing is connected or sent.
    const before = w.site.calls.length;
    const privateDns: GatewayDeps = { ...w.deps, resolveHost: async () => [PUBLIC_IP, "10.0.0.5"] };
    const rebound = expectFail(await approveAndRun(w, AGENT, transferArgs({ task: "private address" }), privateDns), "entry_use_failed");
    assert.match(String(rebound.detail), /hostname_not_allowed/);
    assert.deepEqual([rebound.request_sent, rebound.failed_entry], [false, "destination"]);
    assert.equal(w.site.calls.length, before, "no request for a private address");
    const lastTwo = (await w.transferRows()).slice(-2);
    assert.deepEqual(lastTwo.map((r) => r.result), ["error", "error"], "neither entry gets an ok row");
    scan("host refusals", await w.rows());
  });

  it("6. kind rules: only api_key / oauth_token are transferable; no cookie or operator_secret destination; a header only for api_key / oauth_token; forbidden header names", async () => {
    const w = await pairWorld();
    await w.seed({ site: "kinds.example", account: "pw", kind: "password", secret: PASSWORD_SECRET });
    await w.seed({ site: "kinds.example", account: "op", kind: "operator_secret", secret: OPERATOR_SECRET });
    await w.seed({ site: "kinds.example", account: "ck", kind: "cookie", secret: `sid=${COOKIE_VALUE}` });
    await w.seed({ site: "kinds.example", account: "tok", kind: "oauth_token", secret: OTHER_SOURCE_SECRET });

    // Source: by the entry's actual kind, and by an explicit from_kind.
    for (const account of ["pw", "op", "ck"]) {
      await refused(w, transferArgs({ from_site: "kinds.example", from_account: account }), "entry_kind_not_transferable");
    }
    for (const from_kind of ["password", "operator_secret", "cookie"]) await refused(w, transferArgs({ from_kind }), "entry_kind_not_transferable");
    await refused(w, transferArgs({ from_kind: "ssh_key" }), "invalid_arguments");

    // Destination.
    const toKinds = (account: string, over: Record<string, unknown> = {}) => transferArgs({ to_site: "kinds.example", to_account: account, host: "kinds.example", ...over });
    for (const account of ["op", "ck"]) await refused(w, toKinds(account), "entry_kind_not_usable");
    for (const to_kind of ["operator_secret", "cookie"]) await refused(w, transferArgs({ to_kind }), "entry_kind_not_usable");
    await refused(w, toKinds("pw", { to_auth: { scheme: "header", name: "x-api-key" } }), "invalid_arguments");

    // Header names.
    for (const name of ["authorization", "Authorization", "cookie", "host", "x-forwarded-for", "sec-fetch-site", "proxy-authorization", "content-type", "content-length", "bad name", "x_api_key", "9lives", "x-key\r\nhost", "", "x".repeat(41)]) {
      await refused(w, transferArgs({ to_auth: { scheme: "header", name } }), "invalid_arguments");
    }
    for (const to_auth of ["xi-api-key", { scheme: "bearer" }, { scheme: "header" }, { scheme: "header", name: "x-key", value: "v" }, ["header"]]) {
      await refused(w, transferArgs({ to_auth }), "invalid_arguments");
    }

    // An oauth_token is transferable, to an oauth_token destination with a header.
    const data = expectOk(await approveAndRun(w, AGENT, transferArgs({ from_site: "kinds.example", from_account: "tok", from_kind: "oauth_token", to_auth: { scheme: "header", name: "x-api-key" } })));
    assert.equal(data.status, 200);
    assert.equal(JSON.parse(String(w.site.calls[0].body)).value, OTHER_SOURCE_SECRET);
    scan("kind refusals", await w.rows());
  });

  it("7. the source and the destination must be different entries", async () => {
    const w = await pairWorld();
    await refused(w, transferArgs({ from_site: DST_SITE, from_account: "workspace" }), "invalid_arguments");
    await refused(w, transferArgs({ to_site: SRC_SITE, to_account: "owner", host: SRC_SITE }), "invalid_arguments");
    // Two different accounts of one site are two entries: allowed.
    await w.seed({ site: DST_SITE, account: "second", kind: "api_key", secret: OTHER_SOURCE_SECRET });
    expectOk(await approveAndRun(w, AGENT, transferArgs({ from_site: DST_SITE, from_account: "second" })));
    assert.equal(JSON.parse(String(w.site.calls[0].body)).value, OTHER_SOURCE_SECRET);
    assert.equal(w.site.calls[0].headers.authorization, `Bearer ${DEST_SECRET}`);
  });

  it("an unknown entry on either side is reported, without a prompt", async () => {
    const w = await pairWorld();
    assert.match(String((await refused(w, transferArgs({ from_site: "nowhere.example" }), "entry_not_found")).detail), /^from_site: /);
    assert.match(String((await refused(w, transferArgs({ to_account: "nobody" }), "entry_not_found")).detail), /^to_site: /);
  });

  it("8. without vault.write: missing_scope, the same shape entry_use returns, and neither entry is resolved or confirmed", async () => {
    const w = await pairWorld();
    const reader = client("oc_reader_only", ["vault.read", "audit.read"]);
    const storeCallsBefore = w.entryStoreCalls();
    const real = await refused(w, transferArgs(), "missing_scope", reader);
    const unknownEntries = await refused(w, transferArgs({ from_site: "does-not-exist.example", to_site: "nor-does-this.example", host: "nor-does-this.example" }), "missing_scope", reader);
    const badKinds = await refused(w, transferArgs({ from_account: "no-such-account", to_account: "no-such-account" }), "missing_scope", reader);
    assert.equal(w.entryStoreCalls(), storeCallsBefore, "the entry store was not consulted at all");
    assert.deepEqual(real, unknownEntries, "existing and missing entries are indistinguishable");
    assert.deepEqual(real, badKinds);
    const entryUse = expectFail(
      await w.call(reader, "entry_use", { site: DST_SITE, account: "workspace", method: "POST", host: DST_HOST, url_path: "/v1/workspace/secrets", body: {}, task: TASK }),
      "missing_scope",
    );
    assert.deepEqual(real, entryUse, "the same shape entry_use returns");
    const denied = (await w.transferRows()).filter((r) => r.client_id === reader.client_id);
    assert.equal(denied.length, 3);
    for (const row of denied) assert.deepEqual([row.result, row.decision, row.error, row.credential_ref], ["denied", "deny", "missing_scope", undefined]);
    // No scope at all behaves the same.
    await refused(w, transferArgs(), "missing_scope", client("oc_no_scopes", []));
  });
});

describe("entry_transfer: approval", () => {
  it("9. every call needs its own approval, and an approval is bound to the exact request", async () => {
    const w = await pairWorld();
    await w.seed({ site: SRC_SITE, account: "other", kind: "api_key", secret: OTHER_SOURCE_SECRET });
    const args = transferArgs({ to_auth: { scheme: "header", name: "xi-api-key" } });

    const first = expectFail(await w.call(AGENT, "entry_transfer", args), "approval_required");
    // Not approved yet → still pending, nothing sent.
    expectFail(await w.call(AGENT, "entry_transfer", { ...args, approval_id: first.approval_id }), "approval_pending");
    await w.tap(String(first.approval_id));

    // The approval does not cover any other request.
    const different: Array<[string, Record<string, unknown>]> = [
      ["another body value", { body: { type: "new", name: "OTHER_NAME", value: TRANSFER_PLACEHOLDER } }],
      ["another placeholder field", { body: { type: "new", value: "SOURCE_API_KEY", name: TRANSFER_PLACEHOLDER } }],
      ["a nested placeholder field", { body: { type: "new", name: "SOURCE_API_KEY", config: { value: TRANSFER_PLACEHOLDER } } }],
      ["another header name", { to_auth: { scheme: "header", name: "x-api-key" } }],
      ["the default auth instead of the header", { to_auth: undefined }],
      ["another source entry", { from_account: "other" }],
      ["another host", { host: DST_SITE }],
      ["another path", { url_path: "/v1/workspace/secrets/other" }],
      ["another method", { method: "PUT" }],
      ["another task", { task: "something else entirely" }],
    ];
    for (const [what, over] of different) {
      expectFail(await w.call(AGENT, "entry_transfer", { ...args, ...over, approval_id: first.approval_id }), "approval_digest_mismatch");
      assert.equal(w.site.calls.length, 0, `nothing is sent for ${what}`);
    }
    // Another client cannot use it either.
    expectFail(await w.call(client("oc_other_agent", ["vault.read", "vault.write"]), "entry_transfer", { ...args, approval_id: first.approval_id }), "approval_digest_mismatch");
    assert.equal(w.site.calls.length, 0);

    // The exact request runs once.
    expectOk(await w.call(AGENT, "entry_transfer", { ...args, approval_id: first.approval_id }));
    assert.equal(w.site.calls.length, 1);
    expectFail(await w.call(AGENT, "entry_transfer", { ...args, approval_id: first.approval_id }), "approval_already_consumed");

    // A second, identical call is asked about again: there is no standing grant.
    const second = expectFail(await w.call(AGENT, "entry_transfer", args), "approval_required");
    assert.notEqual(second.approval_id, first.approval_id);
    assert.equal(w.site.calls.length, 1);
    // …and a denial is final.
    await w.tap(String(second.approval_id), "Deny");
    expectFail(await w.call(AGENT, "entry_transfer", { ...args, approval_id: second.approval_id }), "approval_denied");
    assert.equal(w.site.calls.length, 1);
    // entry_use reads of the destination are not unlocked by a transfer approval either.
    expectFail(await w.call(AGENT, "entry_use", { site: DST_SITE, account: "workspace", method: "GET", host: DST_HOST, url_path: "/v1/workspace/secrets", task: "list" }), "approval_required");
    scan("approval rows", await w.rows());
  });

  it("11. the owner's prompt says TRANSFER, names both entries, the host, the field and the header, and carries no secret", async () => {
    const w = await pairWorld();
    const nested = { type: "new", config: { keys: [{ name: "SOURCE_API_KEY", secret: TRANSFER_PLACEHOLDER }] } };
    expectFail(await w.call(AGENT, "entry_transfer", transferArgs({ body: nested, to_auth: { scheme: "header", name: "xi-api-key" } })), "approval_required");
    const withHeader = w.prompts().at(-1) as string;
    const fromLabel = String((await w.entryOf(SRC_SITE, "owner")).label);
    const toLabel = String((await w.entryOf(DST_SITE, "workspace")).label);
    for (const part of [
      `TRANSFER the secret of "${fromLabel}" into POST https://${DST_HOST}/v1/workspace/secrets, JSON field config.keys[0].secret, authenticated as "${toLabel}", sent in header xi-api-key.`,
      `${DST_SITE} will receive and may store this secret.`,
      `Task: ${TASK}`,
      TRANSFER_CAPABILITY,
    ]) {
      assert.ok(withHeader.includes(part), `the prompt contains: ${part}`);
    }
    scan("prompt with header", withHeader);

    expectFail(await w.call(AGENT, "entry_transfer", transferArgs()), "approval_required");
    const plain = w.prompts().at(-1) as string;
    assert.ok(plain.includes(`JSON field value, authenticated as "${toLabel}". ${DST_SITE} will receive and may store this secret. Task: ${TASK}`), plain);
    assert.equal(plain.includes("sent in header"), false);
    assert.equal(plain.includes("SOURCE_API_KEY"), false, "body content other than the field path is not shown");
    scan("prompt without header", plain);

    // A long task cannot push the warning off the prompt; hostile key text is neutralised.
    const hostileKey = "x\u202e\u0007evil";
    expectFail(await w.call(AGENT, "entry_transfer", transferArgs({ body: { [hostileKey]: TRANSFER_PLACEHOLDER }, task: "t".repeat(300) })), "approval_required");
    const long = w.prompts().at(-1) as string;
    assert.ok(long.includes(`${DST_SITE} will receive and may store this secret. Task: ttt`));
    assert.equal(long.includes("\u0007") || long.includes("\u202e"), false);
  });
});

describe("entry_transfer: the destination's answer and failures", () => {
  it("10. a 401 flags only the destination entry; a 403 is site_forbidden and flags neither", async () => {
    const w = await pairWorld();
    const status = async () => [(await w.entryOf(SRC_SITE, "owner")).status, (await w.entryOf(DST_SITE, "workspace")).status];

    w.site.respond = (call) => w.site.json(403, { message: "not allowed for this key", you_sent: JSON.parse(String(call.body)).value });
    const forbidden = expectFail(await approveAndRun(w, AGENT, transferArgs({ task: "forbidden transfer" })), "site_forbidden");
    assert.deepEqual([forbidden.status, forbidden.entry_id, forbidden.entry_flagged_for_reentry], [403, w.toId, undefined]);
    assert.match(JSON.stringify(forbidden.body), /REDACTED/);
    scan("403 result", forbidden);
    assert.deepEqual(await status(), ["active", "active"]);

    w.site.respond = (call) => w.site.json(401, { message: "Bad credentials", you_sent: call.headers.authorization, body_was: call.body });
    const rejected = expectFail(await approveAndRun(w, AGENT, transferArgs({ task: "rejected transfer" })), "site_rejected_credential");
    assert.deepEqual([rejected.status, rejected.entry_id, rejected.entry_flagged_for_reentry], [401, w.toId, true]);
    assert.equal("body" in rejected, false);
    scan("401 result", rejected);
    assert.deepEqual(await status(), ["active", "needs_reentry"], "the source entry is never flagged by the destination's answer");

    const rows = await w.transferRows();
    const outcome = rows.filter((r) => r.http_status !== undefined).map((r) => [r.result, r.error, r.http_status, r.credential_ref]);
    assert.deepEqual(outcome, [
      ["error", "site_forbidden", 403, `vault://entry/${w.toId}`],
      ["error", "site_forbidden", 403, `vault://entry/${w.fromId}`],
      ["error", "site_rejected_credential", 401, `vault://entry/${w.toId}`],
      ["error", "site_rejected_credential", 401, `vault://entry/${w.fromId}`],
    ]);

    // While the destination is flagged, nothing is sent and the source gets no success row.
    const sentBefore = w.site.calls.length;
    const blocked = expectFail(await approveAndRun(w, AGENT, transferArgs({ task: "while flagged" })), "entry_needs_reentry");
    assert.deepEqual([blocked.failed_entry, blocked.entry_id, blocked.request_sent], ["destination", w.toId, false]);
    assert.equal(w.site.calls.length, sentBefore);
    const lastTwo = (await w.transferRows()).slice(-2);
    assert.deepEqual(
      lastTwo.map((r) => [r.result, r.error, r.credential_ref]),
      [
        ["error", "entry_needs_reentry", `vault://entry/${w.toId}`],
        ["error", "transfer_failed: entry_needs_reentry", `vault://entry/${w.fromId}`],
      ],
    );
    assert.equal((await w.ledger.verify()).ok, true);
    scan("401/403 rows", await w.rows());
  });

  it("other statuses come back as they are, redacted (as entry_use does)", async () => {
    const w = await pairWorld();
    w.site.respond = (call) => w.site.json(422, { error: "name already exists", received: JSON.parse(String(call.body)) });
    const data = expectOk(await approveAndRun(w, AGENT, transferArgs()));
    assert.equal(data.status, 422);
    assert.match(JSON.stringify(data.body), /REDACTED/);
    scan("422 result", data);
    assert.deepEqual((await w.transferRows()).slice(-2).map((r) => [r.result, r.http_status]), [["ok", 422], ["ok", 422]]);
  });

  it("a source entry that cannot be used stops the transfer before the destination entry is opened", async () => {
    const w = await pairWorld();
    // Flag the source by having its own site reject it once (through entry_use).
    w.site.respond = () => w.site.json(401, { message: "Bad credentials" });
    const use = { site: SRC_SITE, account: "owner", method: "POST", url_path: "/ping", body: {}, task: "provoke a 401 on the source" };
    const ask = expectFail(await w.call(AGENT, "entry_use", use), "approval_required");
    await w.tap(String(ask.approval_id));
    expectFail(await w.call(AGENT, "entry_use", { ...use, approval_id: ask.approval_id }), "site_rejected_credential");
    w.site.respond = () => w.site.json(200, { id: "sec_0001" });
    const sentBefore = w.site.calls.length;

    const result = expectFail(await approveAndRun(w, AGENT, transferArgs()), "entry_needs_reentry");
    assert.deepEqual([result.failed_entry, result.entry_id, result.request_sent], ["source", w.fromId, false]);
    assert.equal(w.site.calls.length, sentBefore, "nothing is sent");
    const after = (await w.transferRows()).filter((r) => r.result === "ok" || r.result === "error");
    assert.deepEqual(after.map((r) => [r.result, r.error, r.credential_ref]), [["error", "entry_needs_reentry", `vault://entry/${w.fromId}`]], "one row, for the source; the destination was never opened");
    assert.equal((await w.entryOf(DST_SITE, "workspace")).last_used_at, null);
  });

  it("a transfer that ran but could not be recorded is not reported as a success, and says the request was sent", async () => {
    const w = await pairWorld();
    // The destination's outcome row cannot be written.
    w.setLedgerDown((row) => row.capability === TRANSFER_CAPABILITY && row.result === "ok" && row.resource.includes("[destination]"));
    const lost = expectFail(await approveAndRun(w, AGENT, transferArgs()), "ledger_unavailable");
    assert.deepEqual([lost.request_sent, lost.failed_entry], [true, "destination"]);
    assert.equal(w.site.calls.length, 1);
    scan("ledger-down result", lost);
    w.setLedgerDown(null);
    const rows = await w.transferRows();
    assert.equal(rows.some((r) => r.result === "ok"), false, "no ok row for either entry");
    assert.deepEqual(rows.at(-1) && [rows.at(-1)?.result, rows.at(-1)?.error, rows.at(-1)?.http_status], ["error", "transfer_failed: ledger_unavailable", 200]);

    // The authorization cannot be recorded before acting → nothing is sent at all.
    w.setLedgerDown((row) => row.capability === TRANSFER_CAPABILITY && row.result === "committing");
    const refused = expectFail(await approveAndRun(w, AGENT, transferArgs({ task: "ledger down before acting" })), "ledger_unavailable");
    assert.equal(refused.action_performed, false);
    assert.equal(w.site.calls.length, 1, "no second request");
    w.setLedgerDown(null);
  });
});
