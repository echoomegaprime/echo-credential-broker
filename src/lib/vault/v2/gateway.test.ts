// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Gateway tests. Everything is in-memory or faked: stores, the vault backend,
 * Telegram, GitHub and the credential's own site. No network, no real vault.
 */
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { FakeVaultBackend } from "../backend.ts";
import { handleMcpRequest } from "../mcp.ts";
import { isBlockedHost, isPrivateOrLinkLocalIp } from "../policy.ts";
import { CredentialStore } from "../store.ts";
import { FORBIDDEN_TOOLS } from "../types.ts";
import { MemoryApprovalStore } from "./approvals.ts";
import { ensureV2Configured } from "./bootstrap.ts";
import { handleCardRequest } from "./card-pages.ts";
import { MemoryCardStore, MemoryEntryStore, type CardsDeps } from "./cards.ts";
import type { ClientIdentity } from "./contracts.ts";
import { MemoryDigestStateStore, type Digest } from "./digest.ts";
import { MemoryEntryGrantStore, revokeEntryGrant } from "./entry-grants.ts";
import { MemoryAnchorStore } from "./ledger-anchor.ts";
import { dispatchTool, isForbiddenToolName, listTools, TOOL_DEFINITIONS, type GatewayDeps, type GatewayResult } from "./gateway.ts";
import { handleInjectorRedeem, handleInjectorReport } from "./injector-http.ts";
import { enrollInjector, MemoryInjectorStore, MemoryInjectTicketStore, type InjectorDeps } from "./injector.ts";
import { InstallationTokenCache } from "./github-app.ts";
import { handleMcpGet, handleMcpPost, handleRestTool } from "./http-transport.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";
import { MemoryOAuthStore } from "./oauth-store.ts";
import { PinnedFetchError, type PinnedFetch } from "./pinned-fetch.ts";
import {
  configureOAuth,
  handleAuthorize,
  handleRegister,
  handleToken,
  resetOAuth,
  s256Challenge,
  type OwnerApprover,
} from "./oauth-server.ts";
import { CAPABILITY_REGISTRY, requiredScope } from "./policy-engine.ts";
import { SUPPORTED_SCOPES } from "./oauth-server.ts";
import { handleTelegramWebhook } from "./telegram.ts";
import { resetWorkloadCacheForTests } from "./workload.ts";
import { SlidingWindowRateLimiter } from "./policy-engine.ts";
import { MemoryRateLimitStore, setDefaultRateLimitStore, type RateLimitStore } from "./rate-limit-store.ts";

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
const GITHUB_PAT = "ghp_TESTONLYgatewayEcho0000000000000001";
const ACCOUNTS: Record<string, { id: number; type: string }> = {
  echoomegaprime: { id: 314902331, type: "User" },
  "ECHO-OMEGA-PRIME": { id: 264607697, type: "Organization" },
};

// Process output (logs) is captured for the whole file and scanned for secrets at the end.
const captured: string[] = [];
const restores: Array<() => void> = [];
const everyResult: unknown[] = [];
const secretsToScan = new Set<string>([GITHUB_PAT]);

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

function scan(label: string, value: unknown): void {
  const blob = typeof value === "string" ? value : JSON.stringify(value);
  for (const secret of secretsToScan) {
    assert.equal(blob.includes(secret), false, `${label} contains a raw secret`);
    assert.equal(blob.includes(Buffer.from(secret).toString("base64")), false, `${label} contains a base64 secret`);
  }
}

after(() => {
  for (const restore of restores) restore();
  scan("captured process output", captured.join("\n"));
  scan("every tool result", everyResult);
});

interface TelegramCall {
  method: string;
  payload: Record<string, unknown>;
}

function makeWorld() {
  const telegram: TelegramCall[] = [];
  const telegramFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    assert.ok(url.startsWith("https://api.telegram.org/bot"), "telegram fetch used for a non-telegram URL");
    telegram.push({ method: url.split("/").pop() ?? "", payload: JSON.parse(String(init?.body ?? "{}")) });
    return new Response(JSON.stringify({ ok: true, result: { message_id: telegram.length } }), { status: 200 });
  }) as typeof fetch;

  // The credential's own site. It answers by bearer token and (deliberately) echoes the Authorization header back.
  const site = { calls: [] as Array<{ url: string; method: string; auth: string; body: string | null }>, status: new Map<string, number>() };
  const siteFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const auth = new Headers(init?.headers).get("authorization") ?? "";
    site.calls.push({ url: url.href, method: init?.method ?? "GET", auth, body: typeof init?.body === "string" ? init.body : null });
    const forced = site.status.get(auth);
    if (forced) return new Response(JSON.stringify({ message: "Bad credentials", you_sent: auth }), { status: forced, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify({ ok: true, path: url.pathname, you_sent: auth, headers: { Authorization: auth } }), {
      status: 200,
      headers: { "content-type": "application/json", "set-cookie": "session=abc" },
    });
  }) as typeof fetch;

  const githubCalls: string[] = [];
  const githubFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    assert.equal(url.origin, "https://api.github.com");
    const method = init?.method ?? "GET";
    githubCalls.push(`${method} ${url.pathname}`);
    const bearer = (new Headers(init?.headers).get("authorization") ?? "").replace(/^Bearer /, "");
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.pathname === "/user") return bearer === GITHUB_PAT ? json(200, { login: "echoomegaprime", id: ACCOUNTS.echoomegaprime.id }) : json(401, { message: "Bad credentials" });
    const user = /^\/users\/([^/]+)$/.exec(url.pathname);
    if (user) {
      const login = decodeURIComponent(user[1]);
      return ACCOUNTS[login] ? json(200, { login, ...ACCOUNTS[login] }) : json(404, { message: "Not Found" });
    }
    const transfer = /^\/repos\/([^/]+)\/([^/]+)\/transfer$/.exec(url.pathname);
    if (transfer && method === "POST") {
      return json(202, { full_name: `${transfer[1]}/${transfer[2]}`, html_url: `https://github.com/${transfer[1]}/${transfer[2]}`, owner: { login: transfer[1], type: "User" } });
    }
    return json(404, { message: "Not Found" });
  }) as typeof fetch;

  const backend = new FakeVaultBackend();
  const store = new CredentialStore(backend);
  const ledgerStore = new MemoryLedgerStore();
  const ledger = new Ledger({ store: ledgerStore });
  const approvalStore = new MemoryApprovalStore();
  const grants = new MemoryEntryGrantStore();
  const anchors = new MemoryAnchorStore();
  const entries = new MemoryEntryStore();
  const cards: CardsDeps = {
    entries,
    cards: new MemoryCardStore(),
    backend,
    ledger: (input) => ledger.append(input),
    fetch: telegramFetch,
    env: ENV,
  };
  const deps: GatewayDeps = {
    ledger: (input) => ledger.append(input),
    listLedger: (opts) => ledger.list(opts),
    verifyLedger: () => ledger.verify(),
    ledgerHead: () => ledger.head(),
    anchor: { ledger, anchors, fetch: telegramFetch, env: ENV },
    approvals: { store: approvalStore, fetch: telegramFetch, env: ENV },
    rules: [],
    store,
    github: { store, fetch: githubFetch, env: {}, tokenCache: new InstallationTokenCache() },
    cards,
    grants,
    fetch: siteFetch,
    resolveHost: async () => ["140.82.112.5"],
  };

  const call = async (identity: ClientIdentity, name: string, args: unknown = {}): Promise<GatewayResult> => {
    const result = await dispatchTool(identity, name, args, deps);
    everyResult.push(result);
    return result;
  };

  /** The owner taps a button on their phone: replay the callback_data of the latest approval prompt through the real webhook handler. */
  const tap = async (approvalId: string, action: "Approve" | "Deny", fromId: number = APPROVER_ID): Promise<void> => {
    const prompt = [...telegram].reverse().find((c) => {
      const keyboard = (c.payload.reply_markup as { inline_keyboard?: Array<Array<{ text: string; callback_data: string }>> } | undefined)?.inline_keyboard;
      return keyboard?.[0]?.some((b) => b.callback_data.includes(approvalId));
    });
    assert.ok(prompt, "no Telegram prompt for that approval");
    const buttons = (prompt.payload.reply_markup as { inline_keyboard: Array<Array<{ text: string; callback_data: string }>> }).inline_keyboard[0];
    const data = buttons.find((b) => b.text === action)?.callback_data;
    const res = await handleTelegramWebhook(
      new Request(`${ORIGIN}/api/telegram/webhook`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-telegram-bot-api-secret-token": WEBHOOK_SECRET },
        body: JSON.stringify({ callback_query: { id: "cq1", from: { id: fromId }, data, message: { message_id: 1, chat: { id: fromId } } } }),
      }),
      { store: approvalStore, fetch: telegramFetch, env: ENV },
    );
    assert.equal(res.status, 200);
  };

  /** The owner opens the card link from Telegram and types the secret. */
  const fillLatestCard = async (fields: Record<string, string>): Promise<Response> => {
    const text = [...telegram].reverse().find((c) => typeof c.payload.text === "string" && /\/card\//.test(c.payload.text as string));
    const token = /\/card\/([A-Za-z0-9_-]{43})/.exec(String(text?.payload.text))?.[1];
    assert.ok(token, "no card link was sent to the owner");
    return handleCardRequest(
      new Request(`${ORIGIN}/card/${token}`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", origin: "null", "sec-fetch-site": "same-origin" },
        body: new URLSearchParams(fields).toString(),
      }),
      token,
      cards,
    );
  };

  const rows = () => ledgerStore.scanAscending(0, 10_000);
  return { deps, call, tap, fillLatestCard, telegram, site, githubCalls, ledger, ledgerStore, rows, grants, entries, store, approvalStore, anchors };
}

function client(id: string, scopes: string[], kind: ClientIdentity["kind"] = "oauth"): ClientIdentity {
  return { client_id: id, name: id, kind, scopes };
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

type World = ReturnType<typeof makeWorld>;

/** Create an entry through the card flow and return its id. */
async function seedEntry(
  w: World,
  who: ClientIdentity,
  opts: { site: string; account: string; kind: string; secret: string },
): Promise<string> {
  expectOk(
    await w.call(who, "entry_request_card", {
      site: opts.site,
      account: opts.account,
      kind: opts.kind,
      reason: "seed an entry for the test",
    }),
  );
  assert.equal((await w.fillLatestCard({ secret: opts.secret })).status, 200);
  const listed = expectOk(await w.call(who, "entry_list", { site: opts.site })).entries as Array<Record<string, unknown>>;
  const id = listed.find((e) => e.account === opts.account)?.id;
  assert.ok(typeof id === "string", "seeded entry has an id");
  return id as string;
}

/** Drive the first read of an entry through approval, creating the consent grant. */
async function firstRead(w: World, who: ClientIdentity, use: Record<string, unknown>): Promise<void> {
  const ask = expectFail(await w.call(who, "entry_use", use), "approval_required");
  await w.tap(String(ask.approval_id), "Approve");
  expectOk(await w.call(who, "entry_use", { ...use, approval_id: ask.approval_id }));
}

/** dispatchTool with custom deps (e.g. an injected clock or grant env). */
async function callWith(
  identity: ClientIdentity,
  name: string,
  args: unknown,
  deps: GatewayDeps,
): Promise<GatewayResult> {
  const result = await dispatchTool(identity, name, args, deps);
  everyResult.push(result);
  return result;
}

// ---------------------------------------------------------------------------
// Transport authentication
// ---------------------------------------------------------------------------

describe("HTTP transports authenticate before anything else", () => {
  const BASE = "http://localhost:8080";
  const REDIRECT = "http://127.0.0.1:33418/callback";
  const approver: OwnerApprover = {
    requestClientApproval: async () => ({ approval_id: "ap_auto" }),
    checkClientApproval: async () => "approved",
  };
  let oauthStore: MemoryOAuthStore;
  let dir: string;
  const workloadToken = `ewk_${randomBytes(32).toString("base64url")}`;
  const savedEnv = process.env.ECHO_VAULT_WORKLOAD_TOKENS_FILE;

  before(() => {
    ensureV2Configured(); // production wiring first; the test then swaps in a memory store + auto-approver
    resetOAuth();
    oauthStore = new MemoryOAuthStore();
    configureOAuth({ store: oauthStore, approver, env: { ECHO_VAULT_PUBLIC_URL: BASE } });
    dir = mkdtempSync(join(tmpdir(), "vault-workload-"));
    const file = join(dir, "workloads.json");
    writeFileSync(
      file,
      JSON.stringify([
        {
          sha256: createHash("sha256").update(workloadToken).digest("hex"),
          client_id: "workload:sdk-gate",
          name: "SDK gate",
          scopes: ["vault.read", "not.a.scope"],
        },
      ]),
    );
    process.env.ECHO_VAULT_WORKLOAD_TOKENS_FILE = file;
    resetWorkloadCacheForTests();
    secretsToScan.add(workloadToken);
  });
  after(() => {
    if (savedEnv === undefined) delete process.env.ECHO_VAULT_WORKLOAD_TOKENS_FILE;
    else process.env.ECHO_VAULT_WORKLOAD_TOKENS_FILE = savedEnv;
    resetWorkloadCacheForTests();
    resetOAuth();
    rmSync(dir, { recursive: true, force: true });
  });

  const rpc = (headers: Record<string, string>, body: unknown = { jsonrpc: "2.0", id: 1, method: "tools/list" }) =>
    new Request(`${BASE}/api/mcp`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

  async function connect(scope: string): Promise<string> {
    const reg = await handleRegister(
      new Request(`${BASE}/api/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_name: "Claude", redirect_uris: [REDIRECT] }),
      }),
    );
    const clientId = ((await reg.json()) as { client_id: string }).client_id;
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: REDIRECT,
      code_challenge: s256Challenge(verifier),
      code_challenge_method: "S256",
      scope,
      resource: `${BASE}/api/mcp`,
    });
    const page = await (await handleAuthorize(new Request(`${BASE}/api/oauth/authorize?${q}`))).text();
    const pollUrl = (/content="\d+;url=([^"]+)"/.exec(page)?.[1] ?? "").replace(/&amp;/g, "&");
    const redirect = await handleAuthorize(new Request(pollUrl));
    const code = new URL(redirect.headers.get("location") ?? "").searchParams.get("code") ?? "";
    const res = await handleToken(
      new Request(`${BASE}/api/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId }).toString(),
      }),
    );
    const token = ((await res.json()) as { access_token: string }).access_token;
    secretsToScan.add(token);
    return token;
  }

  it("no credentials → 401 with a plain Bearer challenge naming the resource metadata", async () => {
    const w = makeWorld();
    for (const res of [await handleMcpPost(rpc({}), w.deps), await handleRestTool(rpc({}, { tool: "vault_list", arguments: {} }), w.deps)]) {
      assert.equal(res.status, 401);
      const challenge = res.headers.get("www-authenticate") ?? "";
      assert.match(challenge, /^Bearer /);
      assert.match(challenge, /resource_metadata="http:\/\/localhost:8080\/\.well-known\/oauth-protected-resource"/);
      assert.equal(/error=/.test(challenge), false, "no error attribute when no token was presented");
      assert.equal(JSON.stringify(await res.json()).includes("vault_list"), false);
    }
    assert.equal((await w.rows()).length, 0, "nothing ran, nothing to ledger");
  });

  it("x-echo-agent / x-echo-caller alone → 401 (self-asserted headers are worthless)", async () => {
    const w = makeWorld();
    const spoofs: Array<Record<string, string>> = [
      { "x-echo-agent": "claude" },
      { "x-echo-caller": "echo" },
      { "x-echo-agent": "vault-console", "x-echo-caller": "acceptance-test" },
    ];
    for (const headers of spoofs) {
      const call = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vault_list", arguments: {} } };
      const mcp = await handleMcpPost(rpc(headers, call), w.deps);
      assert.equal(mcp.status, 401);
      assert.ok(mcp.headers.get("www-authenticate"));
      const rest = await handleRestTool(rpc(headers, { tool: "vault_list", arguments: {} }), w.deps);
      assert.equal(rest.status, 401);
    }
    assert.equal((await w.rows()).length, 0);
  });

  it("a presented but invalid token → 401 with error=\"invalid_token\"", async () => {
    const w = makeWorld();
    const bogus = [`Bearer eva_${randomBytes(32).toString("base64url")}`, `Bearer ewk_${randomBytes(32).toString("base64url")}`, "Bearer nonsense", "Basic Zm9vOmJhcg=="];
    for (const authorization of bogus) {
      const res = await handleMcpPost(rpc({ authorization, "x-echo-agent": "claude" }), w.deps);
      assert.equal(res.status, 401, authorization.slice(0, 12));
      assert.match(res.headers.get("www-authenticate") ?? "", /error="invalid_token"/);
    }
  });

  it("GET /api/mcp shows name + invariant to anyone, the tool list only to an authenticated client", async () => {
    const anonymous = await handleMcpGet(new Request(`${BASE}/api/mcp`, { headers: { "x-echo-agent": "claude" } }));
    assert.equal(anonymous.status, 200);
    const body = (await anonymous.json()) as Record<string, unknown>;
    assert.equal(body.name, "echo-credential-broker");
    assert.match(String(body.invariant), /NEVER READ/);
    assert.equal(body.tools, undefined);
    assert.equal(JSON.stringify(body).includes("entry_use"), false);
    const sse = await handleMcpGet(new Request(`${BASE}/api/mcp`, { headers: { accept: "text/event-stream" } }));
    assert.equal(sse.status, 405);
  });

  it("an OAuth access token authenticates; the identity and scopes come from the token, not from headers", async () => {
    const w = makeWorld();
    const token = await connect("vault.read");
    const headers = { authorization: `Bearer ${token}`, "x-echo-agent": "echo" };
    const list = await handleMcpPost(rpc(headers), w.deps);
    assert.equal(list.status, 200);
    const tools = ((await list.json()) as { result: { tools: Array<{ name: string }> } }).result.tools.map((t) => t.name);
    assert.ok(tools.includes("entry_use") && tools.includes("github_repo_transfer"));

    const ok = await handleMcpPost(rpc(headers, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "vault_list", arguments: {} } }), w.deps);
    const okBody = (await ok.json()) as { result: { isError: boolean; structuredContent: GatewayResult } };
    assert.equal(okBody.result.isError, false);

    // The token carries vault.read only: a GitHub read is refused whatever the headers say.
    const denied = await handleMcpPost(
      rpc(headers, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "github_get_user", arguments: {} } }),
      w.deps,
    );
    const deniedBody = (await denied.json()) as { result: { isError: boolean; structuredContent: { error: string } } };
    assert.equal(deniedBody.result.isError, true);
    assert.equal(deniedBody.result.structuredContent.error, "missing_scope");

    const rows = await w.rows();
    assert.equal(rows.length, 2);
    assert.match(rows[0].client_id, /^oc_/);
    assert.equal(rows[0].client_id, rows[1].client_id);

    const notification = await handleMcpPost(rpc(headers, { jsonrpc: "2.0", method: "notifications/initialized" }), w.deps);
    assert.equal(notification.status, 202);
    const authedGet = (await (await handleMcpGet(new Request(`${BASE}/api/mcp`, { headers }))).json()) as { tools?: unknown[] };
    assert.equal(authedGet.tools?.length, TOOL_DEFINITIONS.length);
  });

  it("a workload token authenticates on /api/rest/tool with only its supported scopes", async () => {
    const w = makeWorld();
    const res = await handleRestTool(rpc({ authorization: `Bearer ${workloadToken}` }, { tool: "vault_status", arguments: {} }), w.deps);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { ok: boolean; result: GatewayResult };
    assert.equal(body.ok, true);
    assert.equal(body.result.ok, true);
    const [row] = await w.rows();
    assert.equal(row.client_id, "workload:sdk-gate");
    const bad = await handleRestTool(rpc({ authorization: `Bearer ${workloadToken}` }, { tool: "audit_list", arguments: {} }), w.deps);
    assert.equal(((await bad.json()) as { result: { error: string } }).result.error, "missing_scope");
  });

  it("token types do not cross: an injector token (ein_) calls no tool, and OAuth / workload tokens cannot redeem or report", async () => {
    const w = makeWorld();
    const injectors = new MemoryInjectorStore();
    const injector: InjectorDeps = { injectors, tickets: new MemoryInjectTicketStore(), rateLimit: new MemoryRateLimitStore(), ledger: w.deps.ledger };
    const { x, y } = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
    const enrolled = await enrollInjector({ name: "browser", public_key_jwk: { kty: "EC", crv: "P-256", x, y } }, injector);
    secretsToScan.add(enrolled.token);
    const ein = `Bearer ${enrolled.token}`;
    const injectorPost = (handler: typeof handleInjectorRedeem, path: string, authorization: string, body: unknown) =>
      handler(new Request(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json", authorization }, body: JSON.stringify(body) }), injector);
    const bogusTicket = { ticket: `eit_${randomBytes(24).toString("base64url")}` };

    // The injector token is a real, active credential on its own endpoint (404: it authenticated, the ticket is unknown) …
    const own = await injectorPost(handleInjectorRedeem, "/api/injector/redeem", ein, bogusTicket);
    assert.deepEqual([own.status, await own.json()], [404, { ok: false, error: "ticket_not_found" }]);
    // … and nothing at all on the tool transports.
    const before = (await w.rows()).length;
    const mcpList = await handleMcpPost(rpc({ authorization: ein }), { ...w.deps, injector });
    assert.equal(mcpList.status, 401);
    assert.match(mcpList.headers.get("www-authenticate") ?? "", /error="invalid_token"/);
    const mcpCall = await handleMcpPost(rpc({ authorization: ein }, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "vault_status", arguments: {} } }), { ...w.deps, injector });
    assert.equal(mcpCall.status, 401);
    for (const tool of ["vault_status", "entry_inject", "admin_list_injectors", "entry_use"]) {
      const rest = await handleRestTool(rpc({ authorization: ein }, { tool, arguments: {} }), { ...w.deps, injector });
      assert.equal(rest.status, 401, tool);
      assert.equal(((await rest.json()) as { error: string }).error, "invalid_token");
    }
    const get = (await (await handleMcpGet(new Request(`${BASE}/api/mcp`, { headers: { authorization: ein } }))).json()) as { tools?: unknown; client_id?: unknown };
    assert.deepEqual([get.tools, get.client_id], [undefined, undefined], "not even the tool list");
    assert.equal((await w.rows()).length, before, "no tool ran for the injector token");

    // An OAuth access token and a workload token are valid tool credentials …
    const eva = await connect("vault.read vault.write");
    assert.match(eva, /^eva_/);
    assert.equal((await handleRestTool(rpc({ authorization: `Bearer ${eva}` }, { tool: "vault_status", arguments: {} }), w.deps)).status, 200);
    assert.equal((await handleRestTool(rpc({ authorization: `Bearer ${workloadToken}` }, { tool: "vault_status", arguments: {} }), w.deps)).status, 200);
    // … and are refused on both injector endpoints.
    for (const token of [eva, workloadToken]) {
      const redeem = await injectorPost(handleInjectorRedeem, "/api/injector/redeem", `Bearer ${token}`, bogusTicket);
      assert.deepEqual([redeem.status, await redeem.json()], [401, { ok: false, error: "invalid_injector" }], token.slice(0, 4));
      const report = await injectorPost(handleInjectorReport, "/api/injector/report", `Bearer ${token}`, { ticket_sha256: "0".repeat(64), result: "injected" });
      assert.deepEqual([report.status, await report.json()], [401, { ok: false, error: "invalid_injector" }], token.slice(0, 4));
    }
  });
});

// ---------------------------------------------------------------------------
// Policy tiers through dispatchTool
// ---------------------------------------------------------------------------

describe("dispatchTool: tiers, scopes, approvals", () => {
  it("tier 0 with the scope is allowed and ledgered", async () => {
    const w = makeWorld();
    const who = client("oc_reader", ["vault.read", "audit.read"]);
    const status = expectOk(await w.call(who, "vault_status"));
    assert.equal(status.get_secret, false);
    expectOk(await w.call(who, "vault_list"));
    const rows = await w.rows();
    assert.deepEqual(
      rows.map((r) => [r.client_id, r.capability, r.decision, r.tier, r.result]),
      [
        ["oc_reader", "vault.status", "allow", 0, "ok"],
        ["oc_reader", "vault.list", "allow", 0, "ok"],
      ],
    );
    const audit = expectOk(await w.call(who, "audit_list", { limit: 10 }));
    assert.equal((audit.records as unknown[]).length, 2);
    const verified = expectOk(await w.call(who, "audit_verify"));
    assert.equal(verified.ok, true);
    assert.equal(verified.count, 3);
  });

  it("a missing scope is denied and ledgered; no scope implies another", async () => {
    const w = makeWorld();
    const who = client("oc_gh_writer", ["github.write"]);
    expectFail(await w.call(who, "vault_list"), "missing_scope");
    expectFail(await w.call(who, "github_get_repository", { owner: "echoomegaprime", repo: "x" }), "missing_scope");
    expectFail(await w.call(who, "audit_list"), "missing_scope");
    expectFail(await w.call(client("oc_none", []), "entry_list"), "missing_scope");
    const rows = await w.rows();
    assert.equal(rows.length, 4);
    assert.ok(rows.every((r) => r.decision === "deny" && r.result === "denied" && r.error === "missing_scope"));
    assert.equal(w.githubCalls.length, 0);
  });

  it("unknown tools, bad arguments and unauthenticated identities are refused", async () => {
    const w = makeWorld();
    const who = client("oc_reader", ["vault.read"]);
    expectFail(await w.call(who, "no_such_tool"), "unknown_tool");
    expectFail(await w.call(who, "vault_list", { surprise: 1 }), "invalid_arguments");
    expectFail(await w.call(who, "vault_metadata", {}), "invalid_arguments");
    expectFail(await w.call(who, "vault_list", "not-an-object"), "invalid_arguments");
    assert.deepEqual(await dispatchTool({ client_id: "claude" } as never, "vault_list", {}, w.deps), { ok: false, error: "unauthenticated" });
    assert.deepEqual(await dispatchTool("claude" as never, "vault_list", {}, w.deps), { ok: false, error: "unauthenticated" });
    // A credential must never be sent to another provider's host.
    expectFail(await w.call(client("oc_gh", ["github.read"]), "github_get_user", { credential_ref: "vault://stripe/secret_key" }), "provider_mismatch");
  });

  it("tier 3 is denied whatever the scopes: rotate, revoke, reveal-like names, Stripe writes", async () => {
    const w = makeWorld();
    const all = client("oc_everything", [...SUPPORTED_SCOPES]);
    expectFail(await w.call(all, "credential_rotate", { credential_ref: "vault://github/echoomegaprime" }), "tier3_human_only");
    expectFail(await w.call(all, "credential_revoke", { credential_ref: "vault://github/echoomegaprime" }), "tier3_human_only");
    for (const name of [...FORBIDDEN_TOOLS, "vault_reveal", "entry_reveal_secret", "get_api_key", "show_password", "export_entries", "secret_get"]) {
      assert.equal(isForbiddenToolName(name), true, name);
      expectFail(await w.call(all, name, { approval_id: "x" }), "tool_forbidden");
    }
    for (const name of listTools().map((t) => t.name)) assert.equal(isForbiddenToolName(name), false, name);
    expectFail(
      await w.call(all, "provider_request", { credential_ref: "vault://stripe/secret_key", provider: "stripe", method: "POST", path: "/v1/refunds", body: { charge: "ch_1" } }),
      "tier3_human_only",
    );
    const rows = await w.rows();
    assert.ok(rows.every((r) => r.tier === 3 && r.decision === "deny" && r.result === "denied"));
    assert.equal(w.telegram.length, 0, "tier 3 never pages the owner");
    assert.equal(listTools().some((t) => /secret|reveal|password/i.test(t.name)), false);
  });

  it("every tool's capability is registered and reachable through a supported scope", () => {
    for (const [capability, spec] of Object.entries(CAPABILITY_REGISTRY)) {
      if (spec.tier === 3) continue;
      const scope = requiredScope(capability);
      if (!scope) assert.fail(capability);
      if (!/^(deploy|email)\./.test(capability)) assert.ok((SUPPORTED_SCOPES as readonly string[]).includes(scope), `${capability} → ${scope}`);
    }
  });

  it("generic proxy: GET is a tier-0 read; any other method escalates before the credential is touched", async () => {
    const w = makeWorld();
    const who = client("oc_cf", ["cloudflare.read", "cloudflare.write"]);
    const res = expectFail(
      await w.call(who, "provider_request", {
        credential_ref: "vault://cloudflare/global_api_key",
        provider: "cloudflare",
        method: "POST",
        path: "/client/v4/zones/abc/dns_records",
        body: { type: "A", name: "x", content: "203.0.113.9" },
      }),
      "approval_required",
    );
    assert.equal(res.tier, 2);
    const [row] = await w.rows();
    assert.deepEqual([row.capability, row.decision, row.result], ["cloudflare.api.write", "escalate", "pending_approval"]);
    // Read-only scope cannot even ask.
    expectFail(
      await w.call(client("oc_cf_ro", ["cloudflare.read"]), "credential_use", {
        credential_ref: "vault://cloudflare/global_api_key",
        provider: "cloudflare",
        operation: "DELETE",
        resource: "/client/v4/zones/abc",
      }),
      "missing_scope",
    );
  });

  it("github_repo_transfer: approval_required → approved once → replay fails → changed params fail", async () => {
    const w = makeWorld();
    await w.store.put({ provider: "github", account: "echoomegaprime", type: "pat", secret: GITHUB_PAT, source: "test" });
    const who = client("oc_claude", ["github.read", "github.write"]);
    const args = { owner: "echoomegaprime", repo: "cleanbrees", new_owner: "ECHO-OMEGA-PRIME" };

    const first = expectFail(await w.call(who, "github_repo_transfer", args), "approval_required");
    const approvalId = String(first.approval_id);
    assert.match(approvalId, /^[A-Za-z0-9_-]{24}$/);
    assert.ok(Date.parse(String(first.expires_at)) > Date.now());
    assert.equal(w.githubCalls.length, 0, "nothing touches GitHub before approval");
    const prompt = w.telegram.find((c) => c.method === "sendMessage");
    assert.match(String(prompt?.payload.text), /TRANSFER repository echoomegaprime\/cleanbrees to ECHO-OMEGA-PRIME/);
    assert.match(String(prompt?.payload.text), /github\.repo\.transfer/);

    // Not yet approved.
    expectFail(await w.call(who, "github_repo_transfer", { ...args, approval_id: approvalId }), "approval_pending");
    assert.equal(expectOk(await w.call(client("oc_claude", ["vault.read"]), "approval_status", { approval_id: approvalId })).status, "pending");
    // Someone else's approval is invisible.
    expectFail(await w.call(client("oc_other", ["vault.read"]), "approval_status", { approval_id: approvalId }), "approval_not_found");
    // A stranger tapping the button changes nothing.
    await w.tap(approvalId, "Approve", 999);
    expectFail(await w.call(who, "github_repo_transfer", { ...args, approval_id: approvalId }), "approval_pending");

    await w.tap(approvalId, "Approve");

    // Changed params: the approval does not fit (and is not burned by the attempt).
    expectFail(await w.call(who, "github_repo_transfer", { ...args, new_name: "renamed", approval_id: approvalId }), "approval_digest_mismatch");
    expectFail(await w.call(who, "github_repo_transfer", { ...args, repo: "other-repo", approval_id: approvalId }), "approval_digest_mismatch");
    // Another client cannot spend it either.
    expectFail(
      await w.call(client("oc_mallory", ["github.write"]), "github_repo_transfer", { ...args, approval_id: approvalId }),
      "approval_digest_mismatch",
    );
    assert.equal(w.githubCalls.length, 0);

    const done = expectOk(await w.call(who, "github_repo_transfer", { ...args, approval_id: approvalId }));
    assert.equal(done.accepted_for_processing, true);
    assert.deepEqual(w.githubCalls, ["GET /user", "GET /users/ECHO-OMEGA-PRIME", "POST /repos/echoomegaprime/cleanbrees/transfer"]);

    // Replay: single use.
    expectFail(await w.call(who, "github_repo_transfer", { ...args, approval_id: approvalId }), "approval_already_consumed");
    assert.equal(w.githubCalls.length, 3);

    const rows = await w.rows();
    const success = rows.find((r) => r.result === "ok" && r.capability === "github.repo.transfer");
    assert.ok(success);
    assert.equal(success.approval_id, approvalId);
    assert.equal(success.decision, "escalate");
    assert.equal(success.tier, 2);
    assert.equal(success.credential_ref, "vault://github/echoomegaprime");
    assert.equal(success.credential_path, "pat_fallback");
    assert.equal(success.fallback_reason, "transfer_requires_user_token");
    assert.equal(success.http_status, 202);
    assert.equal(rows.filter((r) => r.error === "approval_digest_mismatch").length, 3);
    assert.deepEqual(await w.ledger.verify(), { ok: true, count: rows.length });
    scan("ledger rows", rows);
    scan("telegram payloads", w.telegram);
  });

  it("a denied approval can never be used; a missing one is not found", async () => {
    const w = makeWorld();
    const who = client("oc_claude", ["github.write"]);
    const args = { owner: "echoomegaprime", repo: "cleanbrees", new_owner: "ECHO-OMEGA-PRIME" };
    const first = expectFail(await w.call(who, "github_repo_transfer", args), "approval_required");
    await w.tap(String(first.approval_id), "Deny");
    expectFail(await w.call(who, "github_repo_transfer", { ...args, approval_id: first.approval_id }), "approval_denied");
    expectFail(await w.call(who, "github_repo_transfer", { ...args, approval_id: "A".repeat(24) }), "approval_not_found");
    assert.equal(w.githubCalls.length, 0);
  });

  it("contents write: agent/* is tier 1, any other branch needs an approval", async () => {
    const w = makeWorld();
    const who = client("oc_claude", ["github.write"]);
    const base = { owner: "echoomegaprime", repo: "docs", path: "README.md", message: "update", content_base64: Buffer.from("hi").toString("base64") };
    const main = expectFail(await w.call(who, "github_create_or_update_file", { ...base, branch: "main" }), "approval_required");
    assert.equal(main.tier, 2);
    // agent/* runs without a prompt (it then fails at the fake GitHub, which is fine: it was allowed).
    const agent = await w.call(who, "github_create_or_update_file", { ...base, branch: "agent/docs-fix" });
    assert.notEqual(agent.ok === false && agent.error, "approval_required");
    const rows = await w.rows();
    assert.deepEqual(rows.map((r) => [r.decision, r.tier]), [
      ["escalate", 2],
      ["allow", 1],
    ]);
  });

  it("a failing ledger withholds the result (fail closed)", async () => {
    const w = makeWorld();
    const broken: GatewayDeps = { ...w.deps, ledger: async () => Promise.reject(new Error("db down")) };
    const res = await dispatchTool(client("oc_reader", ["vault.read"]), "vault_list", {}, broken);
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error, "ledger_unavailable");
  });

  it("MCP tools/call wraps the same gateway", async () => {
    const w = makeWorld();
    const res = (await handleMcpRequest(
      { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "get_secret", arguments: {} } },
      client("local:claude", ["vault.read"], "local"),
      w.deps,
    )) as { result: { isError: boolean; structuredContent: { error: string } } };
    assert.equal(res.result.isError, true);
    assert.equal(res.result.structuredContent.error, "tool_forbidden");
    const init = (await handleMcpRequest({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }, client("local:claude", [], "local"), w.deps)) as {
      result: { protocolVersion: string };
    };
    assert.equal(init.result.protocolVersion, "2025-06-18");
    assert.equal(await handleMcpRequest({ jsonrpc: "2.0", method: "notifications/initialized" }, client("local:claude", [], "local"), w.deps), null);
  });
});

describe("dispatchTool: max_per_hour over the shared rate-limit store", () => {
  const reader = client("oc_limited", ["vault.read", "vault.write", "github.write"]);
  const rules = [{ id: "cap", client_id: "oc_limited", capability: "*", max_per_hour: 2 }];

  class DownStore implements RateLimitStore {
    readonly kind = "sql" as const;
    private fail(): never {
      throw new Error("db down");
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

  it("the limit holds across two gateways sharing one store and across a restart", async () => {
    const shared = new MemoryRateLimitStore();
    const w = makeWorld();
    const now = () => 1_000_000;
    const instanceA: GatewayDeps = { ...w.deps, rules, policy: { limiter: new SlidingWindowRateLimiter(undefined, shared), now } };
    const instanceB: GatewayDeps = { ...w.deps, rules, policy: { limiter: new SlidingWindowRateLimiter(undefined, shared), now } };
    expectOk(await callWith(reader, "vault_list", {}, instanceA));
    expectOk(await callWith(reader, "vault_status", {}, instanceB));
    expectFail(await callWith(reader, "vault_list", {}, instanceA), "rate_limited");
    expectFail(await callWith(reader, "vault_list", {}, instanceB), "rate_limited");
    // A freshly constructed limiter (a restarted process) over the same store is still limited.
    const restarted: GatewayDeps = { ...w.deps, rules, policy: { limiter: new SlidingWindowRateLimiter(undefined, shared), now } };
    expectFail(await callWith(reader, "vault_status", {}, restarted), "rate_limited");
    // Another client is unaffected, and the window still slides.
    expectOk(await callWith(client("oc_other", ["vault.read"]), "vault_list", {}, restarted));
    const later: GatewayDeps = { ...restarted, policy: { limiter: restarted.policy?.limiter, now: () => 1_000_000 + 3_600_000 } };
    expectOk(await callWith(reader, "vault_list", {}, later));
    const rows = await w.rows();
    assert.deepEqual(
      rows.filter((r) => r.client_id === "oc_limited").map((r) => [r.decision, r.result, r.error ?? null]),
      [
        ["allow", "ok", null],
        ["allow", "ok", null],
        ["deny", "denied", "rate_limited"],
        ["deny", "denied", "rate_limited"],
        ["deny", "denied", "rate_limited"],
        ["allow", "ok", null],
      ],
    );
    for (const key of shared.keys()) assert.match(key, /^policy:[0-9a-f]{64}$/);
  });

  it("store unreachable → rate_limit_unavailable for tier 0 and tier 1; nothing runs, the denial is ledgered", async () => {
    const w = makeWorld();
    const deps: GatewayDeps = { ...w.deps, rules, policy: { limiter: new SlidingWindowRateLimiter(undefined, new DownStore()) } };
    const read = expectFail(await callWith(reader, "vault_list", {}, deps), "rate_limit_unavailable");
    assert.equal(read.tier, 0);
    const card = expectFail(
      await callWith(reader, "entry_request_card", { site: "github.com", account: "bot", kind: "api_key", reason: "store is down" }, deps),
      "rate_limit_unavailable",
    );
    assert.equal(card.tier, 1);
    assert.equal(w.telegram.length, 0, "no card link may be sent when the request was denied");
    const rows = await w.rows();
    assert.deepEqual(
      rows.map((r) => [r.capability, r.decision, r.tier, r.result, r.error]),
      [
        ["vault.list", "deny", 0, "denied", "rate_limit_unavailable"],
        ["vault.card.request", "deny", 1, "denied", "rate_limit_unavailable"],
      ],
    );
    // A client the rule does not cover never touches the store and is unaffected by the outage.
    expectOk(await callWith(client("oc_other", ["vault.read"]), "vault_list", {}, deps));
  });
});

describe("host blocking used by entry_use", () => {
  it("blocks private/loopback/link-local literals but not hostnames that merely start with fc/fd", () => {
    for (const host of ["localhost", "127.0.0.1", "10.1.2.3", "192.168.1.220", "172.16.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "[::1]", "fe80::1", "fd00::1", "fc00::1", "::ffff:10.0.0.1", "foo.internal", "printer.local"]) {
      assert.equal(isBlockedHost(host), true, host);
    }
    for (const host of ["github.com", "api.github.com", "fdic.gov", "fcbarcelona.com", "fd.io", "140.82.112.5", "2606:4700::1111"]) {
      assert.equal(isBlockedHost(host), false, host);
    }
    assert.equal(isPrivateOrLinkLocalIp("fdic.gov"), false);
  });
});

describe("entry_use: DNS pinning (resolve once, connect only to what was validated)", () => {
  const PUBLIC_IP = "140.82.112.5";
  const SECRET = "PIN-rebind-secret-7c1e55a0f3b24d19";
  const who = client("oc_pin", ["vault.read", "vault.write"]);
  const use = { site: "pin.example", account: "acct", method: "GET", host: "pin.example", url_path: "/v1/me", task: "read my profile" };

  before(() => {
    secretsToScan.add(SECRET);
  });

  /** A world whose entry_use goes down the PRODUCTION branch (no deps.fetch), with the pinned transport and the resolver observed. */
  async function pinWorld(resolve: (call: number) => string[]) {
    const w = makeWorld();
    await seedEntry(w, who, { site: "pin.example", account: "acct", kind: "api_key", secret: SECRET });
    const resolverCalls: string[] = [];
    const resolveHost = async (host: string) => {
      resolverCalls.push(host);
      return resolve(resolverCalls.length);
    };
    const sent: Array<{ url: string; addresses: string[]; auth: string; hasTestOnly: boolean; timeoutMs?: number; maxResponseBytes?: number }> = [];
    const pinned: PinnedFetch = async (url, init, options) => {
      const auth = new Headers(init.headers).get("authorization") ?? "";
      sent.push({
        url: String(url),
        addresses: [...options.addresses],
        auth,
        hasTestOnly: options.testOnly !== undefined,
        timeoutMs: options.timeoutMs,
        maxResponseBytes: options.maxResponseBytes,
      });
      options.onConnect?.(options.addresses[0]);
      // The site echoes the credential back, as hostile sites do.
      return new Response(JSON.stringify({ ok: true, you_sent: auth }), { status: 200, headers: { "content-type": "application/json" } });
    };
    // Any use of the global fetch from here on is a bug: count it, never let it out.
    const realFetch = globalThis.fetch;
    let globalFetchCalls = 0;
    globalThis.fetch = (async () => {
      globalFetchCalls += 1;
      throw new Error("global fetch must not be used by entry_use");
    }) as typeof fetch;
    const deps: GatewayDeps = { ...w.deps, fetch: undefined, resolveHost, pinnedFetch: pinned };
    return { w, deps, resolveHost, resolverCalls, sent, globalFetchCalls: () => globalFetchCalls, restore: () => void (globalThis.fetch = realFetch) };
  }

  it("a rebinding resolver (public first, 127.0.0.1 afterwards) cannot move the request: one lookup, pinned to the validated address", async () => {
    const p = await pinWorld((call) => (call === 1 ? [PUBLIC_IP] : ["127.0.0.1"]));
    try {
      const ask = expectFail(await callWith(who, "entry_use", use, p.deps), "approval_required");
      assert.equal(p.resolverCalls.length, 0, "nothing is resolved before consent");
      await p.w.tap(String(ask.approval_id), "Approve");

      const first = expectOk(await callWith(who, "entry_use", { ...use, approval_id: ask.approval_id }, p.deps));
      assert.equal(first.status, 200);
      assert.deepEqual(p.resolverCalls, ["pin.example"], "the resolver is called exactly once for the request");
      assert.equal(p.sent.length, 1);
      assert.equal(p.sent[0].url, "https://pin.example/v1/me");
      assert.deepEqual(p.sent[0].addresses, [PUBLIC_IP], "the transport is pinned to the address that was validated");
      assert.equal(p.sent[0].auth, `Bearer ${SECRET}`, "the credential went to the pinned transport");
      assert.equal(p.sent[0].hasTestOnly, false, "production never passes the test-only relaxations");
      assert.equal(p.sent[0].timeoutMs, 12_000);
      assert.equal(p.sent[0].maxResponseBytes, 1024 * 1024);
      // The echoed credential is redacted on the way out.
      assert.match(JSON.stringify(first), /REDACTED/);
      scan("pinned entry_use result", first);
      assert.ok(captured.some((line) => line.includes("vault_entry_use_connected") && line.includes(PUBLIC_IP)), "the connected address is logged");

      // What a second lookup (the one global fetch used to make) would have got:
      assert.deepEqual(await p.resolveHost("pin.example"), ["127.0.0.1"]);
      assert.equal(p.sent.length, 1, "…and it changed nothing: no transport call was ever aimed at it");

      // The next request resolves once more, sees the rebound answer and sends nothing.
      const rebound = expectFail(await callWith(who, "entry_use", { ...use, task: "second read" }, p.deps), "entry_use_failed");
      assert.match(String(rebound.detail), /hostname_not_allowed/);
      assert.equal(p.resolverCalls.length, 3, "exactly one more lookup for the second request");
      assert.equal(p.sent.length, 1, "nothing was sent to the rebound address");
      scan("rebound entry_use result", rebound);
      assert.equal(p.globalFetchCalls(), 0, "the default path never touches global fetch");
    } finally {
      p.restore();
    }
  });

  it("one private answer among public ones rejects the whole request; nothing is sent", async () => {
    for (const answer of [
      [PUBLIC_IP, "10.0.0.5"],
      ["169.254.169.254", PUBLIC_IP],
      [PUBLIC_IP, "::ffff:127.0.0.1"],
      [PUBLIC_IP, "64:ff9b::a9fe:a9fe"],
      [PUBLIC_IP, "0:0:0:0:0:0:0:1"],
      [PUBLIC_IP, "pin.example"], // a resolver must answer with addresses, not names
      [],
    ]) {
      const p = await pinWorld(() => answer);
      try {
        const ask = expectFail(await callWith(who, "entry_use", use, p.deps), "approval_required");
        await p.w.tap(String(ask.approval_id), "Approve");
        const res = expectFail(await callWith(who, "entry_use", { ...use, approval_id: ask.approval_id }, p.deps), "entry_use_failed");
        assert.match(String(res.detail), answer.length === 0 ? /dns_lookup_failed/ : /hostname_not_allowed/, JSON.stringify(answer));
        assert.equal(p.resolverCalls.length, 1);
        assert.equal(p.sent.length, 0, `nothing sent for ${JSON.stringify(answer)}`);
        assert.equal(p.globalFetchCalls(), 0);
        scan("mixed-answer entry_use result", res);
      } finally {
        p.restore();
      }
    }
  });

  it("every validated address is handed to the transport, de-duplicated, and a transport refusal surfaces without the secret", async () => {
    const p = await pinWorld(() => [PUBLIC_IP, "2606:4700::1111", PUBLIC_IP]);
    try {
      const ask = expectFail(await callWith(who, "entry_use", use, p.deps), "approval_required");
      await p.w.tap(String(ask.approval_id), "Approve");
      expectOk(await callWith(who, "entry_use", { ...use, approval_id: ask.approval_id }, p.deps));
      assert.deepEqual(p.sent[0].addresses, [PUBLIC_IP, "2606:4700::1111"]);

      // The real transport's fail-closed error (socket connected outside the pinned set).
      const refusing: GatewayDeps = { ...p.deps, pinnedFetch: async () => Promise.reject(new PinnedFetchError("hostname_not_allowed")) };
      const res = expectFail(await callWith(who, "entry_use", { ...use, task: "transport refuses" }, refusing), "entry_use_failed");
      assert.match(String(res.detail), /hostname_not_allowed/);
      scan("transport-refused entry_use result", res);
    } finally {
      p.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// The owner's acceptance test
// ---------------------------------------------------------------------------

describe("owner acceptance: two GitHub accounts, two clients, use without read", () => {
  const SECRET_ECHO = "Zx9-echoomegaprime-ALPHA-credential-73hd82kd";
  const SECRET_BMC = "Qm4-bmcii1976-BRAVO-credential-91ks02pq";
  const TASK_A = "list my repositories to pick the docs repo";
  const TASK_B = "check the bmcii1976 profile before opening an issue";
  const clientA = client("oc_client_a", ["vault.read", "vault.write", "audit.read"]);
  const clientB = client("oc_client_b", ["vault.read", "vault.write"]);

  before(() => {
    secretsToScan.add(SECRET_ECHO);
    secretsToScan.add(SECRET_BMC);
  });

  it("runs end to end through dispatchTool", async () => {
    const w = makeWorld();

    // 1. Two entries for the same site, created through the card flow (requestCard → page POST).
    const cardA = expectOk(
      await w.call(clientA, "entry_request_card", { site: "github.com", account: "echoomegaprime", kind: "api_key", purpose: "main", reason: "need the main GitHub account" }),
    );
    assert.deepEqual(Object.keys(cardA).sort(), ["card_id", "expires_at", "next", "status"]);
    assert.equal(expectOk(await w.call(clientA, "entry_card_status", { card_id: cardA.card_id })).status, "pending");
    expectFail(await w.call(clientB, "entry_card_status", { card_id: cardA.card_id }), "card_not_found");
    assert.equal((await w.fillLatestCard({ secret: SECRET_ECHO })).status, 200);

    const cardB = expectOk(
      await w.call(clientB, "entry_request_card", { site: "github.com", account: "bmcii1976", kind: "api_key", purpose: "personal", reason: "need the personal GitHub account" }),
    );
    assert.equal((await w.fillLatestCard({ secret: SECRET_BMC })).status, 200);
    const doneB = expectOk(await w.call(clientB, "entry_card_status", { card_id: cardB.card_id }));
    assert.equal(doneB.status, "completed");

    const listed = expectOk(await w.call(clientA, "entry_list", { site: "github.com" })).entries as Array<Record<string, unknown>>;
    assert.deepEqual(listed.map((e) => e.account).sort(), ["bmcii1976", "echoomegaprime"]);
    for (const entry of listed) {
      assert.equal("fingerprint" in entry, false);
      assert.equal("secret_length" in entry, false);
      assert.match(String(entry.ref), /^vault:\/\/entry\/ve_[0-9a-f]{32}$/);
    }
    const refOf = (account: string) => String(listed.find((e) => e.account === account)?.ref);
    const idOf = (account: string) => String(listed.find((e) => e.account === account)?.id);

    // 2. First use needs the owner's consent — per client, per entry.
    const useA = { site: "github.com", account: "echoomegaprime", method: "GET", host: "api.github.com", url_path: "/user/repos?per_page=5", task: TASK_A };
    const useB = { site: "github.com", account: "bmcii1976", method: "GET", host: "api.github.com", url_path: "/user", task: TASK_B };
    const askA = expectFail(await w.call(clientA, "entry_use", useA), "approval_required");
    assert.equal(w.site.calls.length, 0, "no request leaves before consent");
    const consentPrompt = String(w.telegram[w.telegram.length - 1].payload.text);
    assert.match(consentPrompt, /FIRST USE/);
    assert.match(consentPrompt, /echoomegaprime/);
    assert.match(consentPrompt, /list my repositories/);
    await w.tap(String(askA.approval_id), "Approve");
    const askB = expectFail(await w.call(clientB, "entry_use", useB), "approval_required");
    // B cannot ride on A's approval, and A's approval does not cover B's entry.
    expectFail(await w.call(clientB, "entry_use", { ...useB, approval_id: askA.approval_id }), "approval_digest_mismatch");
    await w.tap(String(askB.approval_id), "Approve");

    // 3. Client A uses one account, client B the other.
    const resA = expectOk(await w.call(clientA, "entry_use", { ...useA, approval_id: askA.approval_id }));
    const resB = expectOk(await w.call(clientB, "entry_use", { ...useB, approval_id: askB.approval_id }));
    assert.equal(resA.status, 200);
    assert.equal(resB.status, 200);
    assert.equal((resA.entry as Record<string, unknown>).account, "echoomegaprime");
    assert.equal((resB.entry as Record<string, unknown>).account, "bmcii1976");
    // The site really received each secret, each to the right place…
    assert.deepEqual(
      w.site.calls.map((c) => [c.url, c.method, c.auth]),
      [
        ["https://api.github.com/user/repos?per_page=5", "GET", `Bearer ${SECRET_ECHO}`],
        ["https://api.github.com/user", "GET", `Bearer ${SECRET_BMC}`],
      ],
    );
    // …and although the site echoed the Authorization header back, the agents did not get it.
    assert.match(JSON.stringify(resA), /REDACTED/);
    scan("entry_use result A", resA);
    scan("entry_use result B", resB);

    // 4. Later read-only uses UNDER the approved host+path run without a prompt;
    //    a sibling path, a write, and another entry each prompt again.
    const prompts = w.telegram.length;
    // Covered by the grant: same host, under the approved /user/repos prefix.
    expectOk(await w.call(clientA, "entry_use", { ...useA, url_path: "/user/repos?per_page=10", task: "second read" }));
    assert.equal(w.telegram.length, prompts, "no new Telegram prompt for a later read under the approved path");
    // A sibling path NOT under the approved prefix re-prompts (least privilege).
    const sibling = expectFail(await w.call(clientA, "entry_use", { ...useA, url_path: "/user/emails", task: "read emails" }), "approval_required");
    assert.ok(sibling.approval_id);
    const cross = expectFail(await w.call(clientA, "entry_use", { ...useB, task: "A tries B's account" }), "approval_required");
    assert.ok(cross.approval_id);
    const write = { site: "github.com", account: "echoomegaprime", method: "POST", host: "api.github.com", url_path: "/user/repos", body: { name: "new-repo" }, task: "create a repo" };
    const askWrite = expectFail(await w.call(clientA, "entry_use", write), "approval_required");
    assert.equal(askWrite.tier, 2);
    await w.tap(String(askWrite.approval_id), "Approve");
    expectFail(await w.call(clientA, "entry_use", { ...write, body: { name: "evil-repo" }, approval_id: askWrite.approval_id }), "approval_digest_mismatch");
    expectOk(await w.call(clientA, "entry_use", { ...write, approval_id: askWrite.approval_id }));
    expectFail(await w.call(clientA, "entry_use", { ...write, approval_id: askWrite.approval_id }), "approval_already_consumed");
    expectFail(await w.call(clientA, "entry_use", write), "approval_required"); // every write, every time
    expectFail(await w.call(client("oc_reader", ["vault.read"]), "entry_use", write), "missing_scope");

    // 5. Destination rules.
    expectFail(await w.call(clientA, "entry_use", { ...useA, host: "evil.example" }), "hostname_not_allowed");
    expectFail(await w.call(clientA, "entry_use", { ...useA, host: "api.github.com.evil.example" }), "hostname_not_allowed");
    expectFail(await w.call(clientA, "entry_use", { ...useA, url_path: "https://evil.example/x" }), "invalid_arguments");
    expectFail(await w.call(clientA, "entry_use", { ...useA, url_path: "/../../etc/passwd" }), "invalid_arguments");
    expectFail(await w.call(clientA, "entry_use", { ...useA, task: "" }), "invalid_arguments");
    const { task: _task, ...noTask } = useA;
    expectFail(await w.call(clientA, "entry_use", noTask), "invalid_arguments");
    const rebind = await dispatchTool(clientA, "entry_use", useA, { ...w.deps, resolveHost: async () => ["10.0.0.5"] });
    everyResult.push(rebind);
    expectFail(rebind, "entry_use_failed");
    const callsBefore = w.site.calls.length;

    // 6. Revoking consent brings the prompt back.
    assert.equal(await revokeEntryGrant(clientA.client_id, idOf("echoomegaprime"), w.grants), true);
    expectFail(await w.call(clientA, "entry_use", { ...useA, task: "after revoke" }), "approval_required");
    assert.equal(w.site.calls.length, callsBefore);

    // 7. A 401 from the site flags only that entry.
    w.site.status.set(`Bearer ${SECRET_BMC}`, 401);
    const rejected = expectFail(await w.call(clientB, "entry_use", { ...useB, task: "token was rotated upstream" }), "site_rejected_credential");
    assert.equal(rejected.status, 401);
    assert.equal(rejected.entry_flagged_for_reentry, true);
    const after401 = expectOk(await w.call(clientB, "entry_list", { site: "github.com" })).entries as Array<Record<string, unknown>>;
    assert.equal(after401.find((e) => e.account === "bmcii1976")?.status, "needs_reentry");
    assert.equal(after401.find((e) => e.account === "echoomegaprime")?.status, "active");
    expectFail(await w.call(clientB, "entry_use", { ...useB, task: "retry while flagged" }), "entry_needs_reentry");
    // Re-entry through a card restores it, same entry id.
    expectOk(await w.call(clientB, "entry_request_card", { site: "github.com", account: "bmcii1976", kind: "api_key", reason: "token rotated", entry_id: idOf("bmcii1976") }));
    w.site.status.clear();
    const SECRET_BMC_2 = "Rt7-bmcii1976-CHARLIE-credential-55pl19zx";
    secretsToScan.add(SECRET_BMC_2);
    assert.equal((await w.fillLatestCard({ secret: SECRET_BMC_2 })).status, 200);
    expectOk(await w.call(clientB, "entry_use", { ...useB, task: "after re-entry" }));
    assert.equal(w.site.calls[w.site.calls.length - 1].auth, `Bearer ${SECRET_BMC_2}`);

    // 8. The ledger shows both uses with client ids, entry refs and task text — and verifies.
    const rows = await w.rows();
    const uses = rows.filter((r) => r.capability === "vault.entry.use.read" && r.result === "ok");
    const useRowA = uses.find((r) => r.client_id === "oc_client_a" && r.task === TASK_A);
    const useRowB = uses.find((r) => r.client_id === "oc_client_b" && r.task === TASK_B);
    assert.ok(useRowA, "client A's use is in the ledger");
    assert.ok(useRowB, "client B's use is in the ledger");
    assert.equal(useRowA.credential_ref, refOf("echoomegaprime"));
    assert.equal(useRowB.credential_ref, refOf("bmcii1976"));
    assert.equal(useRowA.resource, "entry:github.com/echoomegaprime");
    assert.equal(useRowB.resource, "entry:github.com/bmcii1976");
    assert.equal(useRowA.http_status, 200);
    assert.equal(useRowA.approval_id, askA.approval_id);
    assert.equal(useRowA.decision, "escalate");
    const failed = rows.find((r) => r.error === "site_rejected_credential");
    assert.ok(failed);
    assert.deepEqual([failed.client_id, failed.http_status, failed.result, failed.credential_ref], ["oc_client_b", 401, "error", refOf("bmcii1976")]);
    const writeRow = rows.find((r) => r.capability === "vault.entry.use.write" && r.result === "ok");
    assert.ok(writeRow);
    assert.deepEqual([writeRow.tier, writeRow.decision, writeRow.approval_id, writeRow.task], [2, "escalate", askWrite.approval_id, "create a repo"]);
    assert.ok(rows.some((r) => r.capability === "vault.entry.create"));
    assert.ok(rows.some((r) => r.capability === "vault.entry.reentry"));
    // Exactly one "ok" row per request that reached the site successfully.
    assert.equal(rows.filter((r) => /^vault\.entry\.use\./.test(r.capability) && r.result === "ok").length, w.site.calls.length - 1);
    assert.deepEqual(await w.ledger.verify(), { ok: true, count: rows.length });
    const viaTool = expectOk(await w.call(clientA, "audit_verify"));
    assert.equal(viaTool.ok, true);
    const audit = expectOk(await w.call(clientA, "audit_list", { capability: "vault.entry.use.read", limit: 50 }));
    assert.ok((audit.records as unknown[]).length >= 2);

    // 9. Neither raw secret appears anywhere an agent, a log reader or the phone can see.
    scan("ledger rows", await w.rows());
    scan("telegram payloads", w.telegram);
    scan("tool results so far", everyResult);
    scan("log lines so far", captured.join("\n"));
    assert.ok(captured.join("\n").includes("vault_entry_used"), "the log capture is live");
    assert.ok(JSON.stringify(w.telegram).includes("/card/"), "the telegram capture is live");
  });
});

// ---------------------------------------------------------------------------
// Change 1: scoped + expiring consent grants (gateway integration)
// ---------------------------------------------------------------------------

describe("scoped, expiring, use-capped consent grants", () => {
  it("a granted read repeats on the same path and under it; a sibling path or host re-prompts", async () => {
    const w = makeWorld();
    const who = client("oc_scope", ["vault.read", "vault.write"]);
    const secret = "SCOPE-ALPHA-secret-0000000000";
    secretsToScan.add(secret);
    await seedEntry(w, who, { site: "example.com", account: "acct", kind: "api_key", secret });
    const use = { site: "example.com", account: "acct", method: "GET", host: "example.com", url_path: "/api/v1/items?page=1", task: "read items" };
    await firstRead(w, who, use);
    const prompts = w.telegram.length;
    // Same path (query differs) and a sub-path: no new prompt.
    expectOk(await w.call(who, "entry_use", { ...use, url_path: "/api/v1/items?page=2", task: "page 2" }));
    expectOk(await w.call(who, "entry_use", { ...use, url_path: "/api/v1/items/42", task: "one item" }));
    assert.equal(w.telegram.length, prompts, "covered reads never prompt");
    // A sibling path NOT under the prefix re-prompts.
    expectFail(await w.call(who, "entry_use", { ...use, url_path: "/api/v1/users", task: "users" }), "approval_required");
    // The api.<site> host is a different host → re-prompt.
    expectFail(await w.call(who, "entry_use", { ...use, host: "api.example.com", task: "api host" }), "approval_required");
    assert.match(String(w.telegram[w.telegram.length - 1].payload.text ?? ""), /GET\/HEAD requests to https:\/\/api\.example\.com\/api\/v1\/items\(\/\*\)/);
  });

  it("an expired grant re-prompts", async () => {
    const w = makeWorld();
    let clock = Date.UTC(2026, 5, 1, 9, 0, 0);
    const deps: GatewayDeps = { ...w.deps, now: () => clock, env: { ECHO_VAULT_GRANT_TTL_MS: "3600000" } };
    const who = client("oc_exp", ["vault.read", "vault.write"]);
    const secret = "EXPIRE-secret-00000000000000";
    secretsToScan.add(secret);
    await seedEntry(w, who, { site: "exp.com", account: "a", kind: "api_key", secret });
    const use = { site: "exp.com", account: "a", method: "GET", host: "exp.com", url_path: "/data", task: "read" };
    const ask = expectFail(await callWith(who, "entry_use", use, deps), "approval_required");
    await w.tap(String(ask.approval_id), "Approve");
    expectOk(await callWith(who, "entry_use", { ...use, approval_id: ask.approval_id }, deps));
    expectOk(await callWith(who, "entry_use", { ...use, task: "within the hour" }, deps));
    clock += 2 * 3_600_000; // past the 1h TTL
    expectFail(await callWith(who, "entry_use", { ...use, task: "after the hour" }, deps), "approval_required");
  });

  it("a use-capped grant re-prompts after N uses", async () => {
    const w = makeWorld();
    const deps: GatewayDeps = { ...w.deps, env: { ECHO_VAULT_GRANT_MAX_USES: "2" } };
    const who = client("oc_cap", ["vault.read", "vault.write"]);
    const secret = "CAP-secret-000000000000000000";
    secretsToScan.add(secret);
    await seedEntry(w, who, { site: "cap.com", account: "a", kind: "api_key", secret });
    const use = { site: "cap.com", account: "a", method: "GET", host: "cap.com", url_path: "/x", task: "read" };
    const ask = expectFail(await callWith(who, "entry_use", use, deps), "approval_required");
    await w.tap(String(ask.approval_id), "Approve");
    expectOk(await callWith(who, "entry_use", { ...use, approval_id: ask.approval_id }, deps)); // approval authorises the first use
    expectOk(await callWith(who, "entry_use", { ...use, task: "use 1" }, deps)); // 2 → 1
    expectOk(await callWith(who, "entry_use", { ...use, task: "use 2" }, deps)); // 1 → 0
    expectFail(await callWith(who, "entry_use", { ...use, task: "use 3" }, deps), "approval_required"); // spent
  });

  it("a client can hold two narrow grants for one entry at once", async () => {
    const w = makeWorld();
    const who = client("oc_two", ["vault.read", "vault.write"]);
    const secret = "TWO-secret-000000000000000000";
    secretsToScan.add(secret);
    const id = await seedEntry(w, who, { site: "two.com", account: "a", kind: "api_key", secret });
    const base = { site: "two.com", account: "a", method: "GET", host: "two.com", task: "t" };
    await firstRead(w, who, { ...base, url_path: "/alpha" });
    // /beta is a separate narrow grant: it still re-prompts the first time.
    const ask = expectFail(await w.call(who, "entry_use", { ...base, url_path: "/beta" }), "approval_required");
    await w.tap(String(ask.approval_id), "Approve");
    expectOk(await w.call(who, "entry_use", { ...base, url_path: "/beta", approval_id: ask.approval_id }));
    const prompts = w.telegram.length;
    expectOk(await w.call(who, "entry_use", { ...base, url_path: "/alpha/1", task: "alpha again" }));
    expectOk(await w.call(who, "entry_use", { ...base, url_path: "/beta/2", task: "beta again" }));
    assert.equal(w.telegram.length, prompts, "both narrow grants run without a prompt");
    const grants = await w.grants.list({ client_id: who.client_id, entry_id: id });
    assert.deepEqual(grants.map((g) => g.path_prefix).sort(), ["/alpha", "/beta"]);
  });

  it("revoking the grant forces the next read to re-prompt", async () => {
    const w = makeWorld();
    const who = client("oc_rev", ["vault.read", "vault.write"]);
    const secret = "REVOKE-secret-00000000000000";
    secretsToScan.add(secret);
    const id = await seedEntry(w, who, { site: "rev.com", account: "a", kind: "api_key", secret });
    const use = { site: "rev.com", account: "a", method: "GET", host: "rev.com", url_path: "/x", task: "t" };
    await firstRead(w, who, use);
    expectOk(await w.call(who, "entry_use", { ...use, task: "again" }));
    assert.equal(await revokeEntryGrant(who.client_id, id, w.grants), true);
    expectFail(await w.call(who, "entry_use", { ...use, task: "after revoke" }), "approval_required");
  });
});

// ---------------------------------------------------------------------------
// Change 2: pre-commit (intent) audit row for approved mutations
// ---------------------------------------------------------------------------

describe("pre-commit intent row for approved mutations", () => {
  const PAT_ARGS = { owner: "echoomegaprime", repo: "cleanbrees", new_owner: "ECHO-OMEGA-PRIME" };

  async function approvedTransfer(w: World): Promise<string> {
    await w.store.put({ provider: "github", account: "echoomegaprime", type: "pat", secret: GITHUB_PAT, source: "test" });
    const who = client("oc_claude", ["github.read", "github.write"]);
    const first = expectFail(await w.call(who, "github_repo_transfer", PAT_ARGS), "approval_required");
    await w.tap(String(first.approval_id), "Approve");
    return String(first.approval_id);
  }

  it("a normal approved mutation writes a committing row then an outcome row", async () => {
    const w = makeWorld();
    const approvalId = await approvedTransfer(w);
    const who = client("oc_claude", ["github.read", "github.write"]);
    expectOk(await w.call(who, "github_repo_transfer", { ...PAT_ARGS, approval_id: approvalId }));
    const rows = (await w.rows()).filter((r) => r.capability === "github.repo.transfer");
    assert.deepEqual(rows.map((r) => r.result), ["pending_approval", "committing", "ok"]);
    const intent = rows.find((r) => r.result === "committing");
    assert.ok(intent);
    assert.equal(intent.approval_id, approvalId);
    assert.deepEqual([intent.decision, intent.tier], ["escalate", 2]);
    assert.equal((await w.ledger.verify()).ok, true);
  });

  it("if the intent row cannot be written, the mutation is NOT performed", async () => {
    const w = makeWorld();
    const approvalId = await approvedTransfer(w);
    const who = client("oc_claude", ["github.read", "github.write"]);
    let appends = 0;
    const broken: GatewayDeps = {
      ...w.deps,
      ledger: async (input) => {
        appends += 1;
        if (appends === 1) throw new Error("db down"); // the intent row
        return w.ledger.append(input);
      },
    };
    const res = await callWith(who, "github_repo_transfer", { ...PAT_ARGS, approval_id: approvalId }, broken);
    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.equal(res.error, "ledger_unavailable");
      assert.equal(res.action_performed, false);
    }
    assert.equal(w.githubCalls.length, 0, "the transfer never ran");
  });

  it("if the OUTCOME row cannot be written, the mutation ran, the result is withheld, and the intent row is on the chain", async () => {
    const w = makeWorld();
    const approvalId = await approvedTransfer(w);
    const who = client("oc_claude", ["github.read", "github.write"]);
    let appends = 0;
    const broken: GatewayDeps = {
      ...w.deps,
      ledger: async (input) => {
        appends += 1;
        if (appends === 2) throw new Error("db down"); // the outcome row
        return w.ledger.append(input);
      },
    };
    const res = await callWith(who, "github_repo_transfer", { ...PAT_ARGS, approval_id: approvalId }, broken);
    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.equal(res.error, "ledger_unavailable");
      assert.equal(res.action_performed, true);
    }
    assert.deepEqual(w.githubCalls, ["GET /user", "GET /users/ECHO-OMEGA-PRIME", "POST /repos/echoomegaprime/cleanbrees/transfer"]);
    const intent = (await w.rows()).find((r) => r.capability === "github.repo.transfer" && r.result === "committing");
    assert.ok(intent, "the intent row is on the chain");
    assert.equal(intent.approval_id, approvalId);
    assert.equal((await w.ledger.verify()).ok, true);
  });
});

// ---------------------------------------------------------------------------
// Change 3: flag an entry only on a real auth rejection (401), not 403
// ---------------------------------------------------------------------------

describe("entry_use: 401 flags the entry, 403 does not", () => {
  it("a 403 returns site_forbidden and leaves the entry active; a 401 flags it", async () => {
    const w = makeWorld();
    const who = client("oc_43", ["vault.read", "vault.write"]);
    const secretA = "FORB-A-secret-00000000000000";
    const secretB = "FORB-B-secret-00000000000000";
    secretsToScan.add(secretA);
    secretsToScan.add(secretB);
    await seedEntry(w, who, { site: "forb.com", account: "a", kind: "api_key", secret: secretA });
    await seedEntry(w, who, { site: "forb.com", account: "b", kind: "api_key", secret: secretB });
    const useA = { site: "forb.com", account: "a", method: "GET", host: "forb.com", url_path: "/x", task: "t" };
    const useB = { site: "forb.com", account: "b", method: "GET", host: "forb.com", url_path: "/x", task: "t" };
    await firstRead(w, who, useA);
    await firstRead(w, who, useB);

    // 403 on A: not a credential failure.
    w.site.status.set(`Bearer ${secretA}`, 403);
    const forbidden = expectFail(await w.call(who, "entry_use", { ...useA, task: "forbidden read" }), "site_forbidden");
    assert.equal(forbidden.status, 403);
    assert.equal(forbidden.entry_flagged_for_reentry, undefined);
    let entries = expectOk(await w.call(who, "entry_list", { site: "forb.com" })).entries as Array<Record<string, unknown>>;
    assert.equal(entries.find((e) => e.account === "a")?.status, "active");
    assert.equal(entries.find((e) => e.account === "b")?.status, "active");
    // A still works once the 403 clears.
    w.site.status.clear();
    expectOk(await w.call(who, "entry_use", { ...useA, task: "after forbidden" }));

    // 401 on B: the credential was rejected — flag B only.
    w.site.status.set(`Bearer ${secretB}`, 401);
    const rejected = expectFail(await w.call(who, "entry_use", { ...useB, task: "bad cred" }), "site_rejected_credential");
    assert.equal(rejected.entry_flagged_for_reentry, true);
    entries = expectOk(await w.call(who, "entry_list", { site: "forb.com" })).entries as Array<Record<string, unknown>>;
    assert.equal(entries.find((e) => e.account === "b")?.status, "needs_reentry");
    assert.equal(entries.find((e) => e.account === "a")?.status, "active");

    const rows = await w.rows();
    assert.ok(rows.some((r) => r.error === "site_forbidden" && r.http_status === 403 && r.result === "error"));
    assert.ok(rows.some((r) => r.error === "site_rejected_credential" && r.http_status === 401 && r.result === "error"));
    assert.equal((await w.ledger.verify()).ok, true);
    scan("403/401 results", everyResult);
  });
});

// ---------------------------------------------------------------------------
// Change 4: owner-only admin surface (local stdio only)
// ---------------------------------------------------------------------------

describe("owner-only admin surface (local stdio)", () => {
  let store: MemoryOAuthStore;
  before(() => {
    resetOAuth();
    store = new MemoryOAuthStore();
    configureOAuth({ store, env: { ECHO_VAULT_PUBLIC_URL: ORIGIN } });
  });
  after(() => resetOAuth());

  async function seedClient(id: string): Promise<void> {
    const now = Date.now();
    await store.createClient({
      client_id: id,
      client_name: "Managed",
      redirect_uris: ["http://127.0.0.1:1/cb"],
      requested_scopes: ["github.read"],
      granted_scopes: ["github.read"],
      status: "approved",
      created_at: now,
      approved_at: now,
      revoked_at: null,
    });
  }

  const local = client("local:owner", [], "local");

  it("a local identity can list, re-scope and revoke a client", async () => {
    const w = makeWorld();
    await seedClient("oc_managed");
    const listed = expectOk(await w.call(local, "admin_list_clients"));
    assert.ok((listed.clients as Array<{ client_id: string }>).some((c) => c.client_id === "oc_managed"));
    const set = expectOk(await w.call(local, "admin_set_client_scopes", { client_id: "oc_managed", scopes: ["github.read", "github.write"] }));
    assert.deepEqual([...((set.client as { granted_scopes: string[] }).granted_scopes)].sort(), ["github.read", "github.write"]);
    const rev = expectOk(await w.call(local, "admin_revoke_client", { client_id: "oc_managed" }));
    assert.equal((rev as { ok: boolean }).ok, true);
    const after = expectOk(await w.call(local, "admin_list_clients"));
    assert.equal((after.clients as Array<{ client_id: string; status: string }>).find((c) => c.client_id === "oc_managed")?.status, "revoked");
    // Every admin call is ledgered under the local client id.
    assert.ok((await w.rows()).some((r) => r.client_id === "local:owner" && r.capability === "vault.admin.clients.revoke" && r.result === "ok"));
  });

  it("every remote identity is denied every admin tool (tier 3)", async () => {
    const w = makeWorld();
    const remote = client("oc_remote", [...SUPPORTED_SCOPES]);
    const workload = client("workload:svc", [...SUPPORTED_SCOPES], "workload");
    const calls: Array<[string, Record<string, unknown>]> = [
      ["admin_list_clients", {}],
      ["admin_set_client_scopes", { client_id: "oc_x", scopes: ["github.read"] }],
      ["admin_revoke_client", { client_id: "oc_x" }],
      ["admin_list_grants", {}],
      ["admin_revoke_grant", { client_id: "oc_x", entry_id: `ve_${"0".repeat(32)}` }],
      ["admin_list_entries", {}],
      ["admin_set_rotation", { entry_id: `ve_${"0".repeat(32)}`, mode: "manual", interval_days: 30 }],
      ["admin_rotate_entry", { entry_id: `ve_${"0".repeat(32)}` }],
      ["admin_rotation_due", {}],
      ["admin_purge_entry", { entry_id: `ve_${"0".repeat(32)}`, confirm: `PURGE ve_${"0".repeat(32)}` }],
      ["admin_anchor_now", {}],
      ["admin_verify_anchor", { line: "ECHO-VAULT-ANCHOR v1 seq=1 hash=" + "0".repeat(64) + " rows=1 at=2026-11-14T10:00:00.000Z unsigned" }],
      ["admin_digest_now", {}],
      ["admin_digest_now", { from: "2026-11-13", to: "2026-11-14", send: true }],
    ];
    for (const who of [remote, workload]) {
      for (const [name, args] of calls) expectFail(await w.call(who, name, args), "tier3_human_only");
    }
    assert.equal(w.telegram.length, 0, "a refused admin_anchor_now sends nothing");
    assert.equal(w.anchors.size, 0);
    assert.ok((await w.rows()).every((r) => r.decision === "deny" && r.tier === 3));
  });

  it("admin_digest_now: oauth and workload identities are denied, build nothing and send nothing", async () => {
    const w = makeWorld();
    const state = new MemoryDigestStateStore();
    const deps: GatewayDeps = { ...w.deps, digest: { ledger: w.ledger, state, fetch: w.deps.approvals?.fetch, env: ENV } };
    const remote = client("oc_remote", [...SUPPORTED_SCOPES]);
    const workload = client("workload:svc", [...SUPPORTED_SCOPES], "workload");
    for (const who of [remote, workload]) {
      for (const args of [{}, { send: true }, { from: "2026-11-13", send: true }]) {
        const refused = expectFail(await callWith(who, "admin_digest_now", args, deps), "tier3_human_only");
        assert.equal("data" in refused, false);
      }
    }
    assert.equal(w.telegram.length, 0, "nothing was sent to Telegram");
    assert.equal(await state.lastSent(), null);
    const rows = await w.rows();
    assert.equal(rows.length, 6);
    assert.ok(rows.every((r) => r.capability === "vault.admin.digest" && r.decision === "deny" && r.tier === 3 && r.result === "denied"));
  });

  it("admin_digest_now: the local owner gets the structured digest; send=true sends it once per window", async () => {
    const w = makeWorld();
    const agent = client("oc_agent", ["vault.read", "vault.write"]);
    const secret = "DIGEST-secret-0000000000000000";
    secretsToScan.add(secret);
    await seedEntry(w, agent, { site: "dig.com", account: "a", kind: "api_key", secret });
    const use = { site: "dig.com", account: "a", method: "GET", host: "dig.com", url_path: "/x", task: "read the dashboard" };
    await firstRead(w, agent, use);
    expectFail(await w.call(client("oc_other", []), "entry_use", use), "missing_scope");
    const before = (await w.rows()).length;
    const sentBefore = w.telegram.length;

    const day = new Date().toISOString().slice(0, 10);
    const from = `${day}T00:00:00.000Z`;
    const to = new Date(Date.parse(from) + 86_400_000).toISOString();
    const deps: GatewayDeps = {
      ...w.deps,
      digest: { ledger: w.ledger, state: new MemoryDigestStateStore(), fetch: w.deps.approvals?.fetch, env: ENV },
    };

    // Build only: nothing is sent.
    const built = expectOk(await callWith(local, "admin_digest_now", { from: day }, deps));
    const digest = built.digest as Digest;
    assert.deepEqual(digest.window, { from, to });
    assert.equal(digest.total_actions, before);
    assert.deepEqual(digest.chain, { ok: true, count: before });
    assert.equal(digest.grants.created, 1);
    assert.equal(digest.approvals.requested, 1);
    assert.equal(digest.approvals.granted, 1);
    assert.ok(digest.clients.some((c) => c.client_id === "oc_agent" && c.entries_used === 1));
    assert.ok(digest.anomalies.new_clients.some((c) => c.client_id === "oc_other"));
    assert.equal(typeof built.text, "string");
    assert.match(String(built.text), /^ECHO Vault daily digest\n/);
    assert.equal("send" in built, false);
    assert.equal(w.telegram.length, sentBefore);

    // send=true: one Telegram message, then already_sent.
    const sent = expectOk(await callWith(local, "admin_digest_now", { from: day, send: true }, deps));
    assert.equal((sent.send as { sent: boolean }).sent, true);
    assert.equal(w.telegram.length, sentBefore + 1);
    const message = w.telegram[w.telegram.length - 1];
    assert.equal(message.method, "sendMessage");
    assert.equal(message.payload.text, sent.text);
    assert.equal("reply_markup" in message.payload, false);
    const again = expectOk(await callWith(local, "admin_digest_now", { from: day, send: true }, deps));
    assert.deepEqual(again.send, { sent: false, reason: "already_sent", window: { from, to } });
    assert.equal(w.telegram.length, sentBefore + 1, "no second message");

    // The default window is the previous UTC day: nothing happened then.
    const yesterday = expectOk(await callWith(local, "admin_digest_now", {}, deps)).digest as Digest;
    assert.equal(yesterday.window.to, from);
    assert.equal(yesterday.total_actions, 0);

    // Bad input is refused before anything runs; the admin calls themselves are ledgered.
    expectFail(await callWith(local, "admin_digest_now", { from: "2026-11-13T00:00:00" }, deps), "invalid_arguments");
    expectFail(await callWith(local, "admin_digest_now", { send: "yes" }, deps), "invalid_arguments");
    expectFail(await callWith(local, "admin_digest_now", { body: "x" }, deps), "invalid_arguments");
    assert.ok((await w.rows()).some((r) => r.client_id === "local:owner" && r.capability === "vault.admin.digest" && r.result === "ok"));
    assert.equal(JSON.stringify([built, sent]).includes("vault://"), false, "no credential ref in the digest");
  });

  it("admin_revoke_grant forces the client's next read to re-prompt; admin_list_entries shows full metadata", async () => {
    const w = makeWorld();
    const agent = client("oc_agent", ["vault.read", "vault.write"]);
    const secret = "ADMIN-secret-00000000000000";
    secretsToScan.add(secret);
    const id = await seedEntry(w, agent, { site: "adm.com", account: "a", kind: "api_key", secret });
    const use = { site: "adm.com", account: "a", method: "GET", host: "adm.com", url_path: "/x", task: "t" };
    await firstRead(w, agent, use);
    expectOk(await w.call(agent, "entry_use", { ...use, task: "again" })); // no prompt (grant covers it)

    const grants = expectOk(await w.call(local, "admin_list_grants", { client_id: agent.client_id })).grants as Array<Record<string, unknown>>;
    assert.equal(grants.length, 1);
    assert.equal(grants[0].host, "adm.com");
    const removed = expectOk(await w.call(local, "admin_revoke_grant", { client_id: agent.client_id, entry_id: id }));
    assert.equal((removed as { removed: boolean }).removed, true);
    expectFail(await w.call(agent, "entry_use", { ...use, task: "after revoke" }), "approval_required");

    const entries = expectOk(await w.call(local, "admin_list_entries", { site: "adm.com" })).entries as Array<Record<string, unknown>>;
    const e = entries.find((x) => x.account === "a");
    assert.ok(e && "fingerprint" in e && "secret_length" in e, "owner view includes fingerprint and length");
  });

  it("rotation + purge admin tools: owner-only, metadata-only results, agents stay tier-3 denied", async () => {
    const w = makeWorld();
    const agent = client("oc_agent", ["vault.read", "vault.write"]);
    const tokenId = "0123456789abcdef0123456789abcdef";
    const oldToken = "gw-old-cloudflare-token-AAAAAAAAAAAAA-01";
    const newToken = "gw-new-cloudflare-token-BBBBBBBBBBBBB-02";
    secretsToScan.add(oldToken);
    secretsToScan.add(newToken);
    const id = await seedEntry(w, agent, { site: "cloudflare.com", account: "ops", kind: "api_key", secret: oldToken });
    const cfCalls: Array<{ url: string; method: string; auth: string }> = [];
    const cfFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const auth = new Headers(init?.headers).get("authorization") ?? "";
      cfCalls.push({ url: String(input), method: init?.method ?? "GET", auth });
      if (auth !== `Bearer ${oldToken}`) return new Response(JSON.stringify({ success: false, errors: [{ message: auth }] }), { status: 401 });
      return new Response(JSON.stringify({ success: true, errors: [], messages: [], result: newToken }), { status: 200 });
    }) as typeof fetch;
    const t0 = Date.now();
    const deps = (now: number): GatewayDeps => ({ ...w.deps, fetch: cfFetch, now: () => now, cards: { ...w.deps.cards, now: () => now } });
    const stored = async () => (await (w.deps.cards!.backend!).get(`echo_vault_entry_${id}`, "entry", "test")).secret;

    // Policy: validation errors are sanitized codes; a refused policy changes nothing.
    expectFail(await callWith(local, "admin_set_rotation", { entry_id: id, mode: "auto", interval_days: 30 }, deps(t0)), "rotation_unsupported");
    expectFail(await callWith(local, "admin_set_rotation", { entry_id: id, mode: "hourly" }, deps(t0)), "invalid_arguments");
    expectFail(await callWith(local, "admin_set_rotation", { entry_id: id, mode: "manual", provider_token_id: oldToken }, deps(t0)), "invalid_provider_token_id");
    const set = expectOk(await callWith(local, "admin_set_rotation", { entry_id: id, mode: "auto", interval_days: 30, provider_token_id: tokenId }, deps(t0)));
    assert.equal(set.auto_supported, true);
    assert.equal((set.entry as Record<string, unknown>).rotation_mode, "auto");
    assert.equal((set.entry as Record<string, unknown>).provider_token_id, tokenId);

    // Due list.
    assert.deepEqual(expectOk(await callWith(local, "admin_rotation_due", {}, deps(t0))).entries, []);
    const later = t0 + 31 * 86_400_000;
    const due = expectOk(await callWith(local, "admin_rotation_due", {}, deps(later))).entries as Array<Record<string, unknown>>;
    assert.deepEqual(due.map((e) => e.id), [id]);

    // Rotate: the new secret lands in the vault only; the result is metadata.
    const rotated = expectOk(await callWith(local, "admin_rotate_entry", { entry_id: id }, deps(later)));
    assert.deepEqual(cfCalls, [{ url: `https://api.cloudflare.com/client/v4/user/tokens/${tokenId}/value`, method: "PUT", auth: `Bearer ${oldToken}` }]);
    assert.equal(await stored(), newToken);
    assert.equal((rotated.entry as Record<string, unknown>).rotation_count, 1);
    assert.equal(rotated.provider, "cloudflare");
    assert.deepEqual(expectOk(await callWith(local, "admin_rotation_due", {}, deps(later))).entries, []);
    expectFail(await callWith(local, "admin_rotate_entry", { entry_id: `ve_${"0".repeat(32)}` }, deps(later)), "entry_not_found");

    // Agents: the rotate/revoke tools stay tier 3, and agent views never show rotation internals.
    expectFail(await w.call(agent, "credential_rotate", { credential_ref: "vault://cloudflare/ops" }), "tier3_human_only");
    expectFail(await w.call(agent, "credential_revoke", { credential_ref: "vault://cloudflare/ops" }), "tier3_human_only");
    expectFail(await w.call(agent, "admin_rotate_entry", { entry_id: id }), "tier3_human_only");
    expectFail(await w.call(agent, "admin_purge_entry", { entry_id: id, confirm: `PURGE ${id}` }), "tier3_human_only");
    const seenByAgent = expectOk(await w.call(agent, "entry_list", { site: "cloudflare.com" })).entries as Array<Record<string, unknown>>;
    assert.equal("provider_token_id" in seenByAgent[0], false);
    assert.equal(await stored(), newToken, "a denied purge destroys nothing");

    // Purge: refused without the exact confirmation, then irreversible.
    await w.grants.add({
      client_id: agent.client_id, entry_id: id, host: "api.cloudflare.com", path_prefix: "/client/v4/user", approval_id: "A".repeat(24),
      granted_at: new Date(later).toISOString(), expires_at: new Date(later + 3_600_000).toISOString(), max_uses: null, uses_remaining: null,
    });
    for (const confirm of ["PURGE", "yes", `purge ${id}`, `PURGE ${id} `, `PURGE ve_${"0".repeat(32)}`]) {
      expectFail(await callWith(local, "admin_purge_entry", { entry_id: id, confirm }, deps(later)), "confirmation_required");
    }
    expectFail(await callWith(local, "admin_purge_entry", { entry_id: id }, deps(later)), "invalid_arguments");
    assert.equal(await stored(), newToken);
    const purged = expectOk(await callWith(local, "admin_purge_entry", { entry_id: id, confirm: `PURGE ${id}` }, deps(later)));
    assert.equal(purged.purged, true);
    assert.equal(purged.secret_disposal, "overwritten");
    assert.equal(purged.grants_removed, 1);
    const filler = await stored();
    assert.ok(filler !== newToken && filler !== oldToken && filler.length === 86, "the stored value was overwritten with random bytes");
    secretsToScan.add(filler);
    assert.equal((await w.grants.list({ entry_id: id })).length, 0);
    assert.equal((await w.entries.list({ includeDeleted: true })).some((e) => e.id === id), false);
    const use = { site: "cloudflare.com", account: "ops", method: "GET", host: "api.cloudflare.com", url_path: "/client/v4/user", task: "after purge" };
    expectFail(await w.call(agent, "entry_use", use), "entry_not_found");
    expectFail(await callWith(local, "admin_purge_entry", { entry_id: id, confirm: `PURGE ${id}` }, deps(later)), "entry_not_found");

    const rows = await w.rows();
    const caps = (c: string) => rows.filter((r) => r.capability === c);
    assert.deepEqual(caps("vault.entry.rotate").map((r) => r.result), ["ok", "error"]);
    assert.deepEqual(caps("vault.entry.purge").map((r) => r.result), ["ok", "error"]);
    assert.equal(caps("vault.entry.purge")[0].resource, "entry:cloudflare.com/ops");
    assert.equal(caps("vault.entry.purge")[0].client_id, "local:owner");
    assert.ok(caps("vault.admin.entries.purge").some((r) => r.result === "ok" && r.client_id === "local:owner"));
    assert.ok(caps("vault.admin.entries.purge").some((r) => r.result === "error" && r.error === "confirmation_required"));
    assert.ok(caps("vault.admin.entries.rotate").some((r) => r.result === "ok"));
    scan("ledger rows after rotation and purge", rows);
  });

  it("admin_anchor_now anchors the head; audit_verify reports the newest anchor's verdict; admin_verify_anchor checks a line", async () => {
    const w = makeWorld();
    const reader = client("oc_auditor", ["audit.read", "vault.read"]);
    const before = expectOk(await w.call(reader, "audit_verify"));
    assert.equal(before.ok, true);
    assert.equal(before.anchor, null, "nothing anchored yet");
    assert.ok("head" in before && before.count === 0, "existing audit_verify fields are unchanged");

    const anchored = expectOk(await w.call(local, "admin_anchor_now"));
    assert.equal(anchored.status, "anchored");
    assert.equal(anchored.seq, 1);
    assert.equal(anchored.signed, false);
    assert.equal(w.telegram.length, 1);
    const line = String(w.telegram[0].payload.text);
    assert.match(line, /^ECHO-VAULT-ANCHOR v1 seq=1 hash=[0-9a-f]{64} rows=1 at=\S+ unsigned$/);
    assert.ok(!/oc_auditor|audit\.verify|local:owner/.test(line), "no ledger payload in the anchor message");

    const after = expectOk(await w.call(reader, "audit_verify"));
    assert.deepEqual(Object.keys(after).sort(), ["anchor", "count", "head", "ok"]);
    const anchor = after.anchor as { seq: number; anchored_at: string; verdict: string };
    assert.deepEqual(Object.keys(anchor).sort(), ["anchored_at", "seq", "verdict"]);
    assert.equal(anchor.seq, 1);
    assert.equal(anchor.verdict, "ok");

    const checked = expectOk(await w.call(local, "admin_verify_anchor", { line }));
    assert.equal(checked.verdict, "ok");
    assert.equal(checked.known_locally, true);
    expectFail(await w.call(local, "admin_verify_anchor", { line: "ECHO-VAULT-ANCHOR v1 seq=1" }), "anchor_line_invalid");
    expectFail(await w.call(local, "admin_verify_anchor", {}), "invalid_arguments");

    // The whole ledger is wiped: the (now empty, then regrown) chain still verifies, the anchor does not.
    const total = (await w.rows()).length;
    for (let seq = total; seq >= 1; seq -= 1) w.ledgerStore.deleteForTests(seq);
    const cut = expectOk(await w.call(reader, "audit_verify"));
    assert.equal(cut.ok, true, "the hash chain alone cannot see the truncation");
    assert.equal((cut.anchor as { verdict: string }).verdict, "truncated");
    // That audit_verify call was itself ledgered, so seq 1 now holds a different row than the one anchored.
    assert.equal(expectOk(await w.call(local, "admin_verify_anchor", { line })).verdict, "rewritten");
    const refused = expectFail(await w.call(local, "admin_anchor_now"), "ledger_rewritten");
    assert.equal(refused.alert_sent, true);
    assert.match(String(w.telegram[w.telegram.length - 1].payload.text), /^ECHO-VAULT-ANCHOR ALERT v1 reason=rewritten seq=1 /);
    assert.equal(w.anchors.size, 1);
  });

  it("audit_verify reports truncated when rows after the anchor are deleted", async () => {
    const w = makeWorld();
    const reader = client("oc_auditor", ["audit.read", "vault.read"]);
    for (let i = 0; i < 3; i += 1) expectOk(await w.call(reader, "vault_status"));
    expectOk(await w.call(local, "admin_anchor_now"));
    const total = (await w.rows()).length; // 3 reads + the admin_anchor_now row (written after the anchor was taken)
    assert.equal(total, 4);
    assert.equal(((await w.anchors.latest("telegram")) as { seq: number }).seq, 3);
    w.ledgerStore.deleteForTests(4);
    w.ledgerStore.deleteForTests(3);
    w.ledgerStore.deleteForTests(2);
    const cut = expectOk(await w.call(reader, "audit_verify"));
    assert.equal(cut.ok, true);
    assert.equal((cut.anchor as { verdict: string }).verdict, "truncated");
  });
});
