// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Offline coverage for the provider tools, through dispatchTool only.
 *
 * Everything is faked: the vault is a FakeVaultBackend, the ledger and approval
 * stores are in memory, Telegram is an injected fetch, and the provider itself
 * is `globalThis.fetch` (the transport ../http.ts uses), replaced for the whole
 * file by a recorder that plays GitHub, Cloudflare, OpenAI, xAI and Stripe.
 * `node --test` runs each file in its own process, so the replacement cannot
 * leak into another test file. No network, no real vault, no real credential.
 *
 * For every provider tool:
 *   - the request that leaves the broker (method, URL, auth header, body);
 *   - the result shape on success, with provider-supplied secrets redacted;
 *   - provider 401 / 403 / 429 / 5xx, a network error and a non-JSON body:
 *     a clean error (stable code, no stack, no secret) and a matching ledger row;
 *   - capability, tier and scope agree with the policy registry;
 *   - a body that echoes the credential is redacted;
 *   - a client without the scope is denied before any network call.
 */
import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { FakeVaultBackend } from "../backend.ts";
import { handleMcpRequest } from "../mcp.ts";
import { PROVIDER_POLICIES } from "../policy.ts";
import { CredentialStore } from "../store.ts";
import type { CredentialType, ProviderId } from "../types.ts";
import { decideApproval, MemoryApprovalStore, parseCallbackData, type ApprovalOptions } from "./approvals.ts";
import type { ClientIdentity, LedgerEntry } from "./contracts.ts";
import { dispatchTool, TOOL_DEFINITIONS, type GatewayDeps, type GatewayResult } from "./gateway.ts";
import { InstallationTokenCache } from "./github-app.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";
import { SUPPORTED_SCOPES } from "./oauth-server.ts";
import { lookupCapability, requiredScope } from "./policy-engine.ts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Obviously fake, built from parts so no scanner mistakes them for real keys. */
const SECRETS: Record<ProviderId, string> = {
  github: ["ghp", "TESTONLYproviderTools0000000000000001"].join("_"),
  cloudflare: ["cfat", "TESTONLYproviderTools", "0000000000000002"].join("_"),
  openai: ["sk", "TESTONLYproviderTools0000000000000003"].join("-"),
  xai: ["xai", "TESTONLYproviderTools0000000000000004"].join("-"),
  stripe: ["sk", "test", "TESTONLYproviderTools0000000000005"].join("_"),
};
const REFS: Record<ProviderId, string> = {
  github: "vault://github/echoomegaprime",
  cloudflare: "vault://cloudflare/global_api_key",
  openai: "vault://openai/api_key",
  xai: "vault://xai/api_key",
  stripe: "vault://stripe/secret_key",
};
const APPROVER_ID = "424242";
const APPROVAL_ENV: NodeJS.ProcessEnv = {
  TELEGRAM_BOT_TOKEN: "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789",
  ECHO_VAULT_APPROVER_TELEGRAM_ID: APPROVER_ID,
  ECHO_VAULT_PUBLIC_URL: "https://vault.example.test",
  ECHO_VAULT_APPROVAL_HMAC_KEY: "test-only-approval-hmac-key-0123456789abcdef",
  ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET: "test-webhook-secret-0123456789",
};
const SHA = "0123456789abcdef0123456789abcdef01234567";

// ---------------------------------------------------------------------------
// The provider: globalThis.fetch, recorded and scripted
// ---------------------------------------------------------------------------

interface ProviderCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
  redirect: string | undefined;
}
type Reply = { status: number; body?: string; contentType?: string } | { fail: unknown };

const provider = {
  calls: [] as ProviderCall[],
  reply: null as Reply | null,
  json(status: number, body: unknown): void {
    this.reply = { status, body: JSON.stringify(body), contentType: "application/json" };
  },
};

const realFetch = globalThis.fetch;
const captured: string[] = [];
const restores: Array<() => void> = [];
const everyResult: unknown[] = [];
const everyRow: unknown[] = [];

before(() => {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, key) => {
      headers[key] = value;
    });
    provider.calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers,
      body: typeof init?.body === "string" ? init.body : null,
      redirect: init?.redirect,
    });
    const reply = provider.reply;
    if (!reply) throw new Error("the test did not script a provider reply");
    if ("fail" in reply) throw reply.fail;
    return new Response(reply.status === 204 ? null : (reply.body ?? ""), {
      status: reply.status,
      headers: reply.contentType ? { "content-type": reply.contentType } : {},
    });
  }) as typeof fetch;
  restores.push(() => {
    globalThis.fetch = realFetch;
  });
  // Capture process output (the vault logger writes JSON lines to stderr) and scan it at the end.
  for (const stream of [process.stdout, process.stderr]) {
    const orig = stream.write.bind(stream);
    const isErr = stream === process.stderr;
    stream.write = ((chunk: unknown, enc?: unknown, cb?: unknown) => {
      captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("latin1"));
      return isErr ? true : orig(chunk as never, enc as never, cb as never);
    }) as typeof stream.write;
    restores.push(() => {
      stream.write = orig as typeof stream.write;
    });
  }
});

beforeEach(() => {
  provider.calls.length = 0;
  provider.reply = null;
});

after(() => {
  for (const restore of restores) restore();
  assertClean("captured process output", captured.join("\n"), { stacks: false });
  assertClean("every tool result", everyResult);
  assertClean("every ledger row", everyRow);
});

/** No secret (raw, `Bearer`-prefixed or URL-encoded) and nothing that looks like a stack trace. */
function assertClean(label: string, value: unknown, opts: { stacks?: boolean } = {}): void {
  const blob = typeof value === "string" ? value : JSON.stringify(value);
  for (const secret of Object.values(SECRETS)) {
    assert.equal(blob.includes(secret), false, `${label} contains a raw credential`);
    assert.equal(blob.includes(encodeURIComponent(secret)), false, `${label} contains a URL-encoded credential`);
  }
  if (opts.stacks === false) return;
  assert.doesNotMatch(blob, /\\n\s+at\s|\n\s+at\s/, `${label} contains a stack trace`);
  assert.doesNotMatch(blob, /node:internal|\.ts:\d+:\d+|"stack"\s*:/, `${label} contains a stack frame`);
}

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

async function makeWorld(opts: { seed?: ProviderId[] } = {}) {
  const store = new CredentialStore(new FakeVaultBackend());
  for (const p of opts.seed ?? (Object.keys(SECRETS) as ProviderId[])) {
    const account = REFS[p].split("/").pop() as string;
    const type: CredentialType = p === "github" ? "pat" : "api_key";
    await store.put({ provider: p, account, type, secret: SECRETS[p], source: "test:provider-tools" });
  }
  const ledgerStore = new MemoryLedgerStore();
  const ledger = new Ledger({ store: ledgerStore });
  const telegram: Array<Record<string, unknown>> = [];
  const telegramFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    assert.ok(String(input).startsWith("https://api.telegram.org/bot"), "approval fetch used for a non-Telegram URL");
    telegram.push(JSON.parse(String(init?.body ?? "{}")));
    return new Response(JSON.stringify({ ok: true, result: { message_id: telegram.length } }), { status: 200 });
  }) as typeof fetch;
  const approvals: ApprovalOptions = { store: new MemoryApprovalStore(), fetch: telegramFetch, env: APPROVAL_ENV };
  const deps: GatewayDeps = {
    ledger: (input) => ledger.append(input),
    listLedger: (o) => ledger.list(o),
    verifyLedger: () => ledger.verify(),
    ledgerHead: () => ledger.head(),
    approvals,
    rules: [],
    store,
  };
  const rows = async (): Promise<LedgerEntry[]> => {
    const all = await ledgerStore.scanAscending(0, 10_000);
    everyRow.push(all);
    return all;
  };
  const call = async (identity: ClientIdentity, name: string, args: unknown = {}): Promise<GatewayResult> => {
    const result = await dispatchTool(identity, name, args, deps);
    everyResult.push(result);
    return result;
  };
  /** The owner taps Approve: replay the button's callback data through decideApproval. */
  const approve = async (approvalId: string): Promise<void> => {
    type Keyboard = { inline_keyboard: Array<Array<{ text: string; callback_data: string }>> };
    const buttons = telegram.flatMap((m) => (m.reply_markup as Keyboard | undefined)?.inline_keyboard?.[0] ?? []);
    const data = buttons.find((b) => b.text === "Approve" && b.callback_data.includes(approvalId))?.callback_data;
    const parsed = parseCallbackData(data);
    assert.ok(parsed, "no Approve button for that approval");
    const decided = await decideApproval(parsed.id, parsed.action, APPROVER_ID, parsed.mac, approvals);
    assert.equal(decided.ok, true, JSON.stringify(decided));
  };
  return { deps, call, rows, approve, ledger, telegram, store };
}

function client(scopes: string[], id = "oc_provider_tools"): ClientIdentity {
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

function last<T>(items: T[]): T {
  assert.ok(items.length > 0, "expected at least one item");
  return items[items.length - 1];
}

// ---------------------------------------------------------------------------
// One spec per provider tool
// ---------------------------------------------------------------------------

interface Spec {
  tool: string;
  provider: ProviderId;
  args: Record<string, unknown>;
  capability: string;
  resource: string;
  scope: string;
  tier: 0 | 1;
  request: { method: string; url: string; body?: unknown };
  /** What the provider answers on success, and what the caller must get. */
  success: { status: number; body: unknown; data: unknown };
  /** The ledger row carries the provider's HTTP status on success (raw `{status, body}` results only). */
  ledgerStatus?: number;
  /** Error codes that differ from the default mapping. */
  errors?: Partial<Record<"401" | "403" | "429" | "500" | "503" | "network", string>>;
  /** A 2xx body that is not JSON: an error for the typed tools, raw text for the pass-through ones. */
  nonJson: string | "text";
}

const DEFAULT_ERRORS = {
  "401": "provider_rejected_credential",
  "403": "provider_forbidden",
  "429": "provider_rate_limited",
  "500": "provider_unavailable",
  "503": "provider_unavailable",
  network: "provider_request_failed",
} as const;

const REPO_BODY = {
  id: 1,
  full_name: "echoomegaprime/echo-credential-broker",
  name: "echo-credential-broker",
  private: true,
  description: "broker",
  default_branch: "main",
  html_url: "https://github.com/echoomegaprime/echo-credential-broker",
  owner: { login: "echoomegaprime", id: 314902331 },
  visibility: "private",
  permissions: { admin: true },
};
const MODELS_BODY = { object: "list", data: [{ id: "model-a", object: "model", owned_by: "system" }] };
const ZONE_BODY = { success: true, errors: [], messages: [], result: { id: "023e105f4ecef8ad9ca31a8372d0c353", name: "example.com", status: "active" } };
const BALANCE_BODY = { object: "balance", available: [{ amount: 1200, currency: "usd" }], pending: [{ amount: 0, currency: "usd" }], livemode: false };

const SPECS: Spec[] = [
  {
    tool: "github_get_user",
    provider: "github",
    args: {},
    capability: "github.user.read",
    resource: "github:user",
    scope: "github.read",
    tier: 0,
    request: { method: "GET", url: "https://api.github.com/user" },
    success: {
      status: 200,
      body: { login: "echoomegaprime", id: 314902331, email: "owner@example.test", plan: { name: "pro" } },
      data: { login: "echoomegaprime", id: 314902331, authenticated: true },
    },
    // githubGetUser reports every failure as an unusable credential, with the status in `detail`.
    errors: {
      "401": "credential_unavailable",
      "403": "credential_unavailable",
      "429": "credential_unavailable",
      "500": "credential_unavailable",
      "503": "credential_unavailable",
      network: "credential_unavailable",
    },
    nonJson: "credential_unavailable",
  },
  {
    tool: "github_get_repository",
    provider: "github",
    args: { owner: "echoomegaprime", repo: "echo-credential-broker" },
    capability: "github.repo.read",
    resource: "github:echoomegaprime/echo-credential-broker",
    scope: "github.read",
    tier: 0,
    request: { method: "GET", url: "https://api.github.com/repos/echoomegaprime/echo-credential-broker" },
    success: {
      status: 200,
      body: REPO_BODY,
      data: {
        full_name: "echoomegaprime/echo-credential-broker",
        name: "echo-credential-broker",
        private: true,
        description: "broker",
        default_branch: "main",
        html_url: "https://github.com/echoomegaprime/echo-credential-broker",
        owner: "echoomegaprime",
        visibility: "private",
      },
    },
    nonJson: "provider_malformed_response",
  },
  {
    tool: "github_get_file",
    provider: "github",
    args: { owner: "echoomegaprime", repo: "echo-credential-broker", path: "/docs/My File.md", ref: "feat/x y" },
    capability: "github.contents.read",
    resource: "github:echoomegaprime/echo-credential-broker",
    scope: "github.read",
    tier: 0,
    request: {
      method: "GET",
      url: "https://api.github.com/repos/echoomegaprime/echo-credential-broker/contents/docs/My%20File.md?ref=feat%2Fx%20y",
    },
    success: {
      status: 200,
      body: {
        name: "My File.md",
        path: "docs/My File.md",
        sha: SHA,
        size: 5,
        type: "file",
        encoding: "base64",
        content: "aGVsbG8=",
        html_url: "https://github.com/echoomegaprime/echo-credential-broker/blob/main/docs/My%20File.md",
        download_url: "https://raw.githubusercontent.com/echoomegaprime/echo-credential-broker/main/docs/My%20File.md?token=AAAA",
      },
      data: {
        name: "My File.md",
        path: "docs/My File.md",
        sha: SHA,
        size: 5,
        type: "file",
        encoding: "base64",
        content: "aGVsbG8=",
        html_url: "https://github.com/echoomegaprime/echo-credential-broker/blob/main/docs/My%20File.md",
      },
    },
    nonJson: "provider_malformed_response",
  },
  {
    tool: "github_list_repositories",
    provider: "github",
    args: { per_page: 5 },
    capability: "github.repo.list",
    resource: "github:user/repos",
    scope: "github.read",
    tier: 0,
    request: { method: "GET", url: "https://api.github.com/user/repos?per_page=5&sort=updated" },
    success: {
      status: 200,
      body: [
        { ...REPO_BODY, updated_at: "2026-11-01T00:00:00Z" },
        { full_name: "echoomegaprime/other", private: false, description: null, updated_at: "2026-10-01T00:00:00Z", ssh_url: "git@github.com:x/y.git" },
      ],
      data: {
        repositories: [
          { full_name: "echoomegaprime/echo-credential-broker", private: true, description: "broker", updated_at: "2026-11-01T00:00:00Z" },
          { full_name: "echoomegaprime/other", private: false, description: null, updated_at: "2026-10-01T00:00:00Z" },
        ],
      },
    },
    nonJson: "provider_malformed_response",
  },
  {
    tool: "github_create_branch",
    provider: "github",
    args: { owner: "echoomegaprime", repo: "echo-credential-broker", branch: "agent/provider-tests", from_sha: SHA },
    capability: "github.branch.create",
    resource: "github:echoomegaprime/echo-credential-broker",
    scope: "github.write",
    tier: 1,
    request: {
      method: "POST",
      url: "https://api.github.com/repos/echoomegaprime/echo-credential-broker/git/refs",
      body: { ref: "refs/heads/agent/provider-tests", sha: SHA },
    },
    success: {
      status: 201,
      body: { ref: "refs/heads/agent/provider-tests", object: { sha: SHA, type: "commit" } },
      data: { status: 201, body: { ref: "refs/heads/agent/provider-tests", object: { sha: SHA, type: "commit" } } },
    },
    ledgerStatus: 201,
    nonJson: "text",
  },
  {
    tool: "cloudflare_zone_get",
    provider: "cloudflare",
    args: { zone_id: "023e105f4ecef8ad9ca31a8372d0c353" },
    capability: "cloudflare.zone.read",
    resource: "cloudflare:zone/023e105f4ecef8ad9ca31a8372d0c353",
    scope: "cloudflare.read",
    tier: 0,
    request: { method: "GET", url: "https://api.cloudflare.com/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353" },
    success: { status: 200, body: ZONE_BODY, data: { status: 200, body: ZONE_BODY } },
    ledgerStatus: 200,
    nonJson: "provider_malformed_response",
  },
  {
    tool: "openai_account_status",
    provider: "openai",
    args: {},
    capability: "openai.account.read",
    resource: "openai:account",
    scope: "openai.read",
    tier: 0,
    request: { method: "GET", url: "https://api.openai.com/v1/models" },
    success: { status: 200, body: MODELS_BODY, data: { status: 200, body: MODELS_BODY } },
    ledgerStatus: 200,
    nonJson: "provider_malformed_response",
  },
  {
    tool: "xai_account_status",
    provider: "xai",
    args: {},
    capability: "xai.account.read",
    resource: "xai:account",
    scope: "xai.read",
    tier: 0,
    request: { method: "GET", url: "https://api.x.ai/v1/models" },
    success: { status: 200, body: MODELS_BODY, data: { status: 200, body: MODELS_BODY } },
    ledgerStatus: 200,
    nonJson: "provider_malformed_response",
  },
  {
    tool: "stripe_balance",
    provider: "stripe",
    args: {},
    capability: "stripe.balance.read",
    resource: "stripe:balance",
    scope: "stripe.read",
    tier: 0,
    request: { method: "GET", url: "https://api.stripe.com/v1/balance" },
    success: { status: 200, body: BALANCE_BODY, data: { status: 200, body: BALANCE_BODY } },
    ledgerStatus: 200,
    nonJson: "provider_malformed_response",
  },
  {
    tool: "credential_use",
    provider: "cloudflare",
    args: { credential_ref: REFS.cloudflare, provider: "cloudflare", operation: "GET", resource: "/client/v4/user/tokens/verify" },
    capability: "cloudflare.api.read",
    resource: "cloudflare:/client/v4/user/tokens/verify",
    scope: "cloudflare.read",
    tier: 0,
    request: { method: "GET", url: "https://api.cloudflare.com/client/v4/user/tokens/verify" },
    success: {
      status: 200,
      body: { success: true, result: { id: "tok", status: "active" } },
      data: { status: 200, body: { success: true, result: { id: "tok", status: "active" } } },
    },
    ledgerStatus: 200,
    nonJson: "text",
  },
  {
    tool: "provider_request",
    provider: "github",
    args: { credential_ref: REFS.github, provider: "github", method: "GET", path: "/repos/echoomegaprime/echo-credential-broker/issues?state=open&per_page=1" },
    capability: "github.api.read",
    resource: "github:echoomegaprime/echo-credential-broker",
    scope: "github.read",
    tier: 0,
    request: { method: "GET", url: "https://api.github.com/repos/echoomegaprime/echo-credential-broker/issues?state=open&per_page=1" },
    success: { status: 200, body: [{ number: 7, title: "an issue" }], data: { status: 200, body: [{ number: 7, title: "an issue" }] } },
    ledgerStatus: 200,
    nonJson: "text",
  },
];

/** The request that left the broker carries the credential the right way, and nothing else of the caller's. */
function assertRequest(spec: Spec): void {
  assert.equal(provider.calls.length, 1, "exactly one request to the provider");
  const sent = provider.calls[0];
  assert.equal(sent.method, spec.request.method);
  assert.equal(sent.url, spec.request.url);
  const url = new URL(sent.url);
  assert.equal(url.protocol, "https:");
  assert.equal(url.hostname, PROVIDER_POLICIES[spec.provider].hosts[0], "the credential only goes to its provider's API host");
  assert.equal(sent.headers.authorization, `Bearer ${SECRETS[spec.provider]}`);
  assert.equal(sent.headers["user-agent"], "Echo-Credential-Broker/1.0");
  assert.equal(sent.redirect, "error", "a redirect must never carry the Authorization header elsewhere");
  if (spec.provider === "github") {
    assert.equal(sent.headers.accept, "application/vnd.github+json");
    assert.equal(sent.headers["x-github-api-version"], "2022-11-28");
  } else {
    assert.equal(sent.headers.accept, "application/json");
  }
  if (spec.request.body === undefined) {
    assert.equal(sent.body, null, "a read sends no body");
    assert.equal(sent.headers["content-type"], undefined);
  } else {
    assert.deepEqual(JSON.parse(String(sent.body)), spec.request.body);
    assert.equal(sent.headers["content-type"], "application/json");
  }
  // The credential is in the Authorization header and nowhere else.
  assert.equal(sent.url.includes(SECRETS[spec.provider]), false);
  assert.equal(String(sent.body).includes(SECRETS[spec.provider]), false);
}

for (const spec of SPECS) {
  describe(`${spec.tool} (offline)`, () => {
    const who = client([spec.scope]);
    const ref = REFS[spec.provider];
    const errorFor = (key: keyof typeof DEFAULT_ERRORS): string => spec.errors?.[key] ?? DEFAULT_ERRORS[key];

    it("is published and its capability, tier and scope match the policy registry", () => {
      assert.ok(TOOL_DEFINITIONS.some((t) => t.name === spec.tool));
      const registered = lookupCapability(spec.capability);
      assert.ok(registered, `${spec.capability} is not in the registry`);
      assert.equal(registered.tier, spec.tier);
      assert.equal(registered.access, spec.tier === 0 ? "read" : "write");
      assert.equal(requiredScope(spec.capability), spec.scope);
      assert.ok((SUPPORTED_SCOPES as readonly string[]).includes(spec.scope));
    });

    it("sends the right request and returns the expected shape; the ledger records it", async () => {
      const w = await makeWorld();
      provider.json(spec.success.status, spec.success.body);
      const data = expectOk(await w.call(who, spec.tool, spec.args));
      assertRequest(spec);
      assert.deepEqual(data, spec.success.data);

      const all = await w.rows();
      assert.equal(all.length, 1, "one ledger row per call");
      const row = all[0];
      assert.deepEqual(
        [row.client_id, row.capability, row.resource, row.decision, row.tier, row.result, row.credential_ref, row.error],
        [who.client_id, spec.capability, spec.resource, "allow", spec.tier, "ok", ref, undefined],
      );
      if (spec.ledgerStatus !== undefined) assert.equal(row.http_status, spec.ledgerStatus);
      assert.deepEqual(await w.ledger.verify(), { ok: true, count: 1 });
      assertClean("ledger row", row);
    });

    it("provider 401 / 403 / 429 / 500 / 503 each become a clean error", async () => {
      for (const status of [401, 403, 429, 500, 503] as const) {
        const w = await makeWorld();
        provider.calls.length = 0;
        provider.json(status, { message: `upstream said ${status}`, documentation_url: "https://example.test/docs" });
        const expected = errorFor(String(status) as keyof typeof DEFAULT_ERRORS);
        const failure = expectFail(await w.call(who, spec.tool, spec.args), expected);
        assert.equal(provider.calls.length, 1, `${status}: one attempt, no blind retry`);
        assertClean(`${spec.tool} ${status}`, failure);
        assert.equal(failure.credential_ref, ref);
        if (expected.startsWith("provider_")) {
          assert.equal(failure.status, status);
          assert.deepEqual(failure.body, { message: `upstream said ${status}`, documentation_url: "https://example.test/docs" });
        } else {
          assert.equal(failure.detail, `http_${status}`);
        }
        const row = last(await w.rows());
        assert.deepEqual([row.capability, row.decision, row.tier, row.result, row.error, row.credential_ref], [
          spec.capability,
          "allow",
          spec.tier,
          "error",
          expected,
          ref,
        ]);
        if (expected.startsWith("provider_")) assert.equal(row.http_status, status);
      }
    });

    it("a network error becomes a clean error: no stack, no secret", async () => {
      const w = await makeWorld();
      const secret = SECRETS[spec.provider];
      const boom = new TypeError(`fetch failed: connect ECONNREFUSED while sending Authorization: Bearer ${secret}`);
      boom.stack = `TypeError: fetch failed ${secret}\n    at node:internal/deps/undici/undici:13510:13\n    at authorizedProviderFetch (http.ts:75:17)`;
      (boom as { cause?: unknown }).cause = new Error(`getaddrinfo ENOTFOUND with ${secret}`);
      provider.reply = { fail: boom };
      const expected = errorFor("network");
      const failure = expectFail(await w.call(who, spec.tool, spec.args), expected);
      assertClean(`${spec.tool} network error`, failure);
      assert.equal(failure.status, undefined);
      assert.equal(typeof failure.detail, "string");
      assert.ok(String(failure.detail).length <= 300);
      const row = last(await w.rows());
      assert.deepEqual([row.capability, row.result, row.error, row.http_status], [spec.capability, "error", expected, undefined]);
      assertClean("ledger row", row);
    });

    it("a 2xx body that is not JSON is handled cleanly", async () => {
      const w = await makeWorld();
      provider.reply = { status: spec.success.status, body: "{\"truncated\": tru", contentType: "application/json" };
      const result = await w.call(who, spec.tool, spec.args);
      assertClean(`${spec.tool} malformed body`, result);
      const row = last(await w.rows());
      if (spec.nonJson === "text") {
        // Pass-through tools hand back the raw text with the status; nothing is parsed, nothing throws.
        assert.deepEqual(expectOk(result), { status: spec.success.status, body: "{\"truncated\": tru" });
        assert.equal(row.result, "ok");
      } else {
        const failure = expectFail(result, spec.nonJson);
        assert.equal(failure.credential_ref, ref);
        assert.deepEqual([row.result, row.error], ["error", spec.nonJson]);
      }
      // An HTML error page from a proxy in front of the provider is the same case.
      provider.reply = { status: spec.success.status, body: "<html><body>Bad gateway</body></html>", contentType: "text/html" };
      const html = await w.call(who, spec.tool, spec.args);
      assertClean(`${spec.tool} html body`, html);
      if (spec.nonJson !== "text") expectFail(html, spec.nonJson);
    });

    it("a response that echoes the credential is redacted", async () => {
      const w = await makeWorld();
      const secret = SECRETS[spec.provider];
      const echo = {
        ...(Array.isArray(spec.success.body) ? { items: spec.success.body } : (spec.success.body as Record<string, unknown>)),
        login: `echo ${secret}`,
        full_name: `Bearer ${secret}`,
        name: secret,
        description: `Authorization: Bearer ${secret}`,
        message: `you sent ${secret}`,
        token: secret,
        headers: { Authorization: `Bearer ${secret}`, "x-api-key": secret },
        nested: [{ deep: { value: `key=${secret}` } }],
      };
      // Success path.
      provider.json(spec.success.status, Array.isArray(spec.success.body) ? [echo] : echo);
      const ok = await w.call(who, spec.tool, spec.args);
      assert.equal(ok.ok, true, JSON.stringify(ok));
      assertClean(`${spec.tool} echo (success)`, ok);
      // Error path: the provider's error body is returned to the caller, so it must be redacted too.
      provider.json(403, echo);
      const denied = await w.call(who, spec.tool, spec.args);
      assert.equal(denied.ok, false);
      assertClean(`${spec.tool} echo (error)`, denied);
      // Non-JSON path.
      provider.reply = { status: spec.success.status, body: `oops ${secret} Bearer ${secret}`, contentType: "text/plain" };
      assertClean(`${spec.tool} echo (text)`, await w.call(who, spec.tool, spec.args));
      assertClean("ledger rows", await w.rows());
    });

    it("a client without the scope is denied before any network call", async () => {
      const w = await makeWorld();
      provider.json(spec.success.status, spec.success.body);
      // Every other scope, including the sibling read/write scope of the same provider: no scope implies another.
      const others = (SUPPORTED_SCOPES as readonly string[]).filter((s) => s !== spec.scope);
      for (const identity of [client([], "oc_no_scopes"), client(others, "oc_other_scopes")]) {
        const denied = expectFail(await w.call(identity, spec.tool, spec.args), "missing_scope");
        assert.equal(denied.tier, spec.tier);
      }
      assert.equal(provider.calls.length, 0, "the provider was contacted without the scope");
      const all = await w.rows();
      assert.equal(all.length, 2);
      for (const row of all) {
        assert.deepEqual([row.capability, row.resource, row.decision, row.tier, row.result, row.error, row.credential_ref], [
          spec.capability,
          spec.resource,
          "deny",
          spec.tier,
          "denied",
          "missing_scope",
          undefined,
        ]);
      }
    });

    it("fails closed without a network call when the vault has no such credential", async () => {
      const w = await makeWorld({ seed: [] });
      provider.json(spec.success.status, spec.success.body);
      const failure = expectFail(await w.call(who, spec.tool, spec.args), "credential_unavailable");
      assert.equal(failure.credential_ref, ref);
      assert.equal(provider.calls.length, 0, "no anonymous fallback");
      const row = last(await w.rows());
      assert.deepEqual([row.capability, row.result, row.error], [spec.capability, "error", "credential_unavailable"]);
    });

    it("refuses another provider's credential reference before any network call", async () => {
      const w = await makeWorld();
      provider.json(spec.success.status, spec.success.body);
      const foreign = REFS[spec.provider === "stripe" ? "github" : "stripe"];
      expectFail(await w.call(who, spec.tool, { ...spec.args, credential_ref: foreign }), "provider_mismatch");
      expectFail(await w.call(who, spec.tool, { ...spec.args, credential_ref: "not-a-ref" }), "invalid_credential_ref");
      assert.equal(provider.calls.length, 0);
    });
  });
}

// ---------------------------------------------------------------------------
// Regressions for the fixes made with this suite (see docs/ops/test-coverage.md)
// ---------------------------------------------------------------------------

describe("regressions: provider failures are failures for the caller", () => {
  it("github_get_repository: a 404 is an error, not `ok` with a fabricated public repository", async () => {
    const w = await makeWorld();
    provider.json(404, { message: "Not Found", status: "404" });
    const result = await w.call(client(["github.read"]), "github_get_repository", { owner: "echoomegaprime", repo: "does-not-exist" });
    const failure = expectFail(result, "provider_http_error");
    assert.equal(failure.status, 404);
    assert.equal(JSON.stringify(result).includes("public"), false, "must not invent visibility for a repository it could not read");
    const row = last(await w.rows());
    assert.deepEqual([row.result, row.error, row.http_status], ["error", "provider_http_error", 404]);
  });

  it("github_get_file: a 404 is an error, not `ok` with an empty object", async () => {
    const w = await makeWorld();
    provider.json(404, { message: "Not Found" });
    const failure = expectFail(
      await w.call(client(["github.read"]), "github_get_file", { owner: "echoomegaprime", repo: "r", path: "missing.md" }),
      "provider_http_error",
    );
    assert.equal(failure.status, 404);
    assert.equal(last(await w.rows()).result, "error");
  });

  it("github_list_repositories: a rejected credential is an error, not `ok` with an empty list", async () => {
    const w = await makeWorld();
    provider.json(401, { message: "Bad credentials" });
    expectFail(await w.call(client(["github.read"]), "github_list_repositories"), "provider_rejected_credential");
    const row = last(await w.rows());
    assert.deepEqual([row.result, row.error, row.http_status], ["error", "provider_rejected_credential", 401]);
  });

  it("account probes: result and ledger agree when the provider rejects the credential", async () => {
    const probes: Array<[string, string, Record<string, unknown>]> = [
      ["cloudflare_zone_get", "cloudflare.read", { zone_id: "abc" }],
      ["openai_account_status", "openai.read", {}],
      ["xai_account_status", "xai.read", {}],
      ["stripe_balance", "stripe.read", {}],
    ];
    for (const [tool, scope, args] of probes) {
      const w = await makeWorld();
      provider.json(401, { error: { message: "Invalid API key", type: "invalid_request_error" } });
      const result = await w.call(client([scope]), tool, args);
      assert.equal(result.ok, false, `${tool} reported ok:true for a 401`);
      const row = last(await w.rows());
      assert.equal(row.result, "error");
      assert.equal(row.http_status, 401);
    }
  });

  it("MCP tools/call marks a provider rejection as an error", async () => {
    const w = await makeWorld();
    provider.json(401, { error: { message: "Invalid API key" } });
    const res = (await handleMcpRequest(
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "openai_account_status", arguments: {} } },
      client(["openai.read"]),
      w.deps,
    )) as { result: { isError: boolean; structuredContent: { ok: boolean; error: string; status: number } } };
    assert.equal(res.result.isError, true);
    assert.equal(res.result.structuredContent.error, "provider_rejected_credential");
    assert.equal(res.result.structuredContent.status, 401);
    assertClean("mcp result", res);
  });

  it("other 4xx answers keep their status and the provider's message", async () => {
    const w = await makeWorld();
    provider.json(422, { message: "Reference already exists" });
    const failure = expectFail(
      await w.call(client(["github.write"]), "github_create_branch", { owner: "echoomegaprime", repo: "r", branch: "agent/x", from_sha: SHA }),
      "provider_http_error",
    );
    assert.equal(failure.status, 422);
    assert.deepEqual(failure.body, { message: "Reference already exists" });
    assert.equal(failure.detail, "The provider answered 422.");
  });

  it("a JSON body that contains an `Authorization: …` string is still returned as JSON", async () => {
    // ../http.ts used to redact the serialized text before parsing it; the greedy
    // Authorization rule ate the rest of the document and the body came back as text.
    const w = await makeWorld();
    provider.json(200, { object: "list", note: "send Authorization: Bearer <key> with every call", data: [{ id: "model-a" }], after: "kept" });
    const data = expectOk(await w.call(client(["openai.read"]), "openai_account_status"));
    assert.deepEqual(data, { status: 200, body: { object: "list", note: "send Authorization: [REDACTED]", data: [{ id: "model-a" }], after: "kept" } });
  });

  it("an empty 2xx answer from a typed tool is malformed, not a success", async () => {
    const w = await makeWorld();
    provider.reply = { status: 204 };
    expectFail(await w.call(client(["stripe.read"]), "stripe_balance"), "provider_malformed_response");
  });
});

// ---------------------------------------------------------------------------
// Tool-specific behaviour
// ---------------------------------------------------------------------------

describe("typed provider tools: arguments cannot steer the request elsewhere", () => {
  it("cloudflare_zone_get percent-encodes the zone id into one path segment", async () => {
    const w = await makeWorld();
    provider.json(200, ZONE_BODY);
    expectOk(await w.call(client(["cloudflare.read"]), "cloudflare_zone_get", { zone_id: "abc/dns_records?per_page=1#x" }));
    assert.equal(provider.calls[0].url, "https://api.cloudflare.com/client/v4/zones/abc%2Fdns_records%3Fper_page%3D1%23x");
  });

  it("cloudflare_zone_get refuses a zone id that walks up the path, before any network call", async () => {
    const w = await makeWorld();
    provider.json(200, ZONE_BODY);
    const failure = expectFail(await w.call(client(["cloudflare.read"]), "cloudflare_zone_get", { zone_id: "../../user/tokens" }), "invalid_resource");
    assert.equal(provider.calls.length, 0);
    assertClean("traversal failure", failure);
    expectFail(await w.call(client(["cloudflare.read"]), "cloudflare_zone_get", {}), "invalid_arguments");
    expectFail(await w.call(client(["cloudflare.read"]), "cloudflare_zone_get", { zone_id: 7 }), "invalid_arguments");
    assert.equal(provider.calls.length, 0);
  });

  it("github_get_file refuses a path that walks out of the repository", async () => {
    const w = await makeWorld();
    provider.json(200, {});
    expectFail(
      await w.call(client(["github.read"]), "github_get_file", { owner: "echoomegaprime", repo: "r", path: "../../../user" }),
      "invalid_resource",
    );
    assert.equal(provider.calls.length, 0);
  });

  it("github tools validate owner, repo, branch and sha before any network call", async () => {
    const w = await makeWorld();
    provider.json(200, {});
    const who = client(["github.read", "github.write"]);
    expectFail(await w.call(who, "github_get_repository", { owner: "bad/owner", repo: "r" }), "invalid_arguments");
    expectFail(await w.call(who, "github_get_repository", { owner: "echoomegaprime", repo: "a/b" }), "invalid_arguments");
    expectFail(await w.call(who, "github_get_file", { owner: "echoomegaprime", repo: "r" }), "invalid_arguments");
    expectFail(await w.call(who, "github_create_branch", { owner: "echoomegaprime", repo: "r", branch: "agent/x", from_sha: "main" }), "invalid_arguments");
    expectFail(await w.call(who, "github_create_branch", { owner: "echoomegaprime", repo: "r", branch: "bad..name", from_sha: SHA }), "invalid_arguments");
    expectFail(await w.call(who, "github_list_repositories", { per_page: "5" }), "invalid_arguments");
    expectFail(await w.call(who, "github_get_user", { headers: { authorization: "Bearer x" } }), "invalid_arguments");
    assert.equal(provider.calls.length, 0);
  });

  it("github_list_repositories defaults to 30 per page and caps at 100", async () => {
    const w = await makeWorld();
    const who = client(["github.read"]);
    provider.json(200, []);
    assert.deepEqual(expectOk(await w.call(who, "github_list_repositories")), { repositories: [] });
    expectOk(await w.call(who, "github_list_repositories", { per_page: 1000 }));
    assert.deepEqual(provider.calls.map((c) => c.url), [
      "https://api.github.com/user/repos?per_page=30&sort=updated",
      "https://api.github.com/user/repos?per_page=100&sort=updated",
    ]);
  });

  it("github_get_user uses the named account's credential", async () => {
    const w = await makeWorld();
    const other = ["ghp", "TESTONLYsecondAccount0000000000000009"].join("_");
    await w.store.put({ provider: "github", account: "ECHO-OMEGA-PRIME", type: "pat", secret: other, source: "test:provider-tools" });
    provider.json(200, { login: "ECHO-OMEGA-PRIME", id: 264607697 });
    const data = expectOk(await w.call(client(["github.read"]), "github_get_user", { credential_ref: "vault://github/ECHO-OMEGA-PRIME" }));
    assert.equal(data.login, "ECHO-OMEGA-PRIME");
    assert.equal(provider.calls[0].headers.authorization, `Bearer ${other}`);
    assert.equal(last(await w.rows()).credential_ref, "vault://github/ECHO-OMEGA-PRIME");
    assert.equal(JSON.stringify(data).includes(other), false);
  });
});

describe("generic proxy (credential_use / provider_request)", () => {
  const PROXIES: Array<{ tool: string; shape: (provider: string, method: string, path: string, body?: unknown) => Record<string, unknown> }> = [
    {
      tool: "credential_use",
      shape: (p, method, path, body) => ({ credential_ref: REFS[p as ProviderId], provider: p, operation: method, resource: path, ...(body === undefined ? {} : { body }) }),
    },
    {
      tool: "provider_request",
      shape: (p, method, path, body) => ({ credential_ref: REFS[p as ProviderId], provider: p, method, path, ...(body === undefined ? {} : { body }) }),
    },
  ];

  for (const { tool, shape } of PROXIES) {
    it(`${tool}: every provider's GET goes to that provider's host with its own credential`, async () => {
      const paths: Record<ProviderId, string> = {
        github: "/user",
        cloudflare: "/client/v4/zones?per_page=1",
        openai: "/v1/models",
        xai: "/v1/models",
        stripe: "/v1/balance",
      };
      for (const p of Object.keys(paths) as ProviderId[]) {
        const w = await makeWorld();
        provider.calls.length = 0;
        provider.json(200, { ok: true });
        const data = expectOk(await w.call(client([`${p}.read`]), tool, shape(p, "GET", paths[p])));
        assert.deepEqual(data, { status: 200, body: { ok: true } });
        assert.equal(provider.calls.length, 1);
        assert.equal(provider.calls[0].url, `https://${PROVIDER_POLICIES[p].hosts[0]}${paths[p]}`);
        assert.equal(provider.calls[0].headers.authorization, `Bearer ${SECRETS[p]}`);
        const row = last(await w.rows());
        assert.deepEqual([row.capability, row.decision, row.tier, row.result, row.http_status, row.credential_ref], [
          `${p}.api.read`,
          "allow",
          0,
          "ok",
          200,
          REFS[p],
        ]);
      }
    });

    it(`${tool}: the method is case-insensitive and a body on GET is never sent`, async () => {
      const w = await makeWorld();
      provider.json(200, {});
      expectOk(await w.call(client(["github.read"]), tool, shape("github", "get", "/user", { should: "not be sent" })));
      assert.equal(provider.calls[0].method, "GET");
      assert.equal(provider.calls[0].body, null);
    });

    it(`${tool}: absolute URLs, other hosts and path traversal are refused before any network call`, async () => {
      const w = await makeWorld();
      provider.json(200, {});
      const who = client(["github.read"]);
      for (const path of [
        "https://attacker.example/steal",
        "//attacker.example/steal",
        "user",
        "/repos/../../admin",
        "/repos/%2e%2e/%2e%2e/admin",
        "/x\\y",
        "/redirect?to=https://attacker.example/",
      ]) {
        const result = await w.call(who, tool, shape("github", "GET", path));
        assert.equal(result.ok, false, `${path} was accepted`);
        assertClean(`${tool} ${path}`, result);
      }
      assert.equal(provider.calls.length, 0);
      const all = await w.rows();
      assert.ok(all.every((r) => r.result === "error" && r.decision === "deny"));
    });

    it(`${tool}: unknown providers, unknown arguments and caller-supplied headers are refused`, async () => {
      const w = await makeWorld();
      provider.json(200, {});
      const who = client([...SUPPORTED_SCOPES]);
      expectFail(await w.call(who, tool, { ...shape("github", "GET", "/user"), provider: "gitlab" }), "invalid_arguments");
      expectFail(await w.call(who, tool, { ...shape("github", "GET", "/user"), headers: { Authorization: "Bearer mine" } }), "invalid_arguments");
      expectFail(await w.call(who, tool, { ...shape("github", "GET", "/user"), host: "attacker.example" }), "invalid_arguments");
      expectFail(await w.call(who, tool, { ...shape("github", "TRACE", "/user") }), "invalid_arguments");
      // A GitHub credential can never be sent to another provider's host.
      expectFail(await w.call(who, tool, { ...shape("stripe", "GET", "/v1/balance"), credential_ref: REFS.github }), "provider_mismatch");
      const noRef = shape("github", "GET", "/user");
      delete noRef.credential_ref;
      expectFail(await w.call(who, tool, noRef), "invalid_arguments");
      assert.equal(provider.calls.length, 0);
    });

    it(`${tool}: a write needs the write scope, then an approval; nothing reaches the provider first`, async () => {
      const w = await makeWorld();
      provider.json(201, { id: 1 });
      const args = shape("github", "POST", "/repos/echoomegaprime/r/issues", { title: "hello" });
      const denied = expectFail(await w.call(client(["github.read"]), tool, args), "missing_scope");
      assert.equal(denied.tier, 2);
      const pending = expectFail(await w.call(client(["github.read", "github.write"]), tool, args), "approval_required");
      assert.equal(pending.tier, 2);
      assert.equal(provider.calls.length, 0, "the credential was used before the owner approved");
      const all = await w.rows();
      assert.deepEqual(all.map((r) => [r.capability, r.resource, r.decision, r.tier, r.result]), [
        ["github.api.write", "github:echoomegaprime/r", "deny", 2, "denied"],
        ["github.api.write", "github:echoomegaprime/r", "escalate", 2, "pending_approval"],
      ]);
      // The owner sees the method, host and path, and the body size — not the body, not a secret.
      const prompt = JSON.stringify(w.telegram);
      assert.match(prompt, /POST https:\/\/api\.github\.com\/repos\/echoomegaprime\/r\/issues/);
      assertClean("telegram prompt", prompt);
    });

    it(`${tool}: an approved write is sent once with its JSON body, with intent and outcome ledgered`, async () => {
      const w = await makeWorld();
      const who = client(["github.write"]);
      const args = shape("github", "POST", "/repos/echoomegaprime/r/issues", { title: "hello" });
      const pending = expectFail(await w.call(who, tool, args), "approval_required");
      await w.approve(String(pending.approval_id));
      provider.json(201, { number: 12 });
      const data = expectOk(await w.call(who, tool, { ...args, approval_id: pending.approval_id }));
      assert.deepEqual(data, { status: 201, body: { number: 12 } });
      assert.equal(provider.calls.length, 1);
      const sent = provider.calls[0];
      assert.deepEqual([sent.method, sent.url, sent.body, sent.headers["content-type"]], [
        "POST",
        "https://api.github.com/repos/echoomegaprime/r/issues",
        JSON.stringify({ title: "hello" }),
        "application/json",
      ]);
      assert.equal(sent.headers.authorization, `Bearer ${SECRETS.github}`);
      const all = await w.rows();
      assert.deepEqual(all.map((r) => [r.decision, r.tier, r.result, r.http_status]), [
        ["escalate", 2, "pending_approval", undefined],
        ["escalate", 2, "committing", undefined],
        ["escalate", 2, "ok", 201],
      ]);
      assert.ok(all.slice(1).every((r) => r.approval_id === pending.approval_id));
      // Single use: the same approval cannot send the request again, and a different body does not fit it.
      expectFail(await w.call(who, tool, { ...args, approval_id: pending.approval_id }), "approval_already_consumed");
      assert.equal(provider.calls.length, 1);
    });

    it(`${tool}: an approval does not cover a changed body`, async () => {
      const w = await makeWorld();
      const who = client(["github.write"]);
      const args = shape("github", "POST", "/repos/echoomegaprime/r/issues", { title: "hello" });
      const pending = expectFail(await w.call(who, tool, args), "approval_required");
      await w.approve(String(pending.approval_id));
      provider.json(201, {});
      expectFail(
        await w.call(who, tool, { ...shape("github", "POST", "/repos/echoomegaprime/r/issues", { title: "something else" }), approval_id: pending.approval_id }),
        "approval_digest_mismatch",
      );
      assert.equal(provider.calls.length, 0);
    });

    it(`${tool}: Stripe writes are tier 3 and refused outright`, async () => {
      const w = await makeWorld();
      provider.json(200, {});
      const denied = expectFail(await w.call(client([...SUPPORTED_SCOPES]), tool, shape("stripe", "POST", "/v1/refunds", { charge: "ch_1" })), "tier3_human_only");
      assert.equal(denied.tier, 3);
      assert.equal(provider.calls.length, 0);
      assert.equal(w.telegram.length, 0, "tier 3 never pages the owner");
    });

    it(`${tool}: a provider error passes its status and message through as a failure`, async () => {
      const w = await makeWorld();
      provider.json(404, { message: "Not Found" });
      const failure = expectFail(await w.call(client(["github.read"]), tool, shape("github", "GET", "/repos/echoomegaprime/nope")), "provider_http_error");
      assert.deepEqual([failure.status, failure.body, failure.credential_ref], [404, { message: "Not Found" }, REFS.github]);
      const row = last(await w.rows());
      assert.deepEqual([row.resource, row.result, row.error, row.http_status], ["github:echoomegaprime/nope", "error", "provider_http_error", 404]);
    });
  }

  it("known limitation: HEAD is published and classified as a read, but the v1 broker refuses it cleanly", async () => {
    const w = await makeWorld();
    provider.json(200, {});
    const failure = expectFail(
      await w.call(client(["github.read"]), "provider_request", { credential_ref: REFS.github, provider: "github", method: "HEAD", path: "/user" }),
      "operation_not_allowed",
    );
    assert.equal(provider.calls.length, 0);
    assertClean("HEAD failure", failure);
    const row = last(await w.rows());
    assert.deepEqual([row.capability, row.tier, row.result, row.error], ["github.api.read", 0, "error", "operation_not_allowed"]);
  });

  it("a method the provider policy does not allow is refused after approval, without a network call", async () => {
    // OpenAI allows GET and POST only; DELETE is a tier-2 write that the broker then refuses.
    const w = await makeWorld();
    const who = client(["openai.write"]);
    const args = { credential_ref: REFS.openai, provider: "openai", method: "DELETE", path: "/v1/files/file-1" };
    const pending = expectFail(await w.call(who, "provider_request", args), "approval_required");
    await w.approve(String(pending.approval_id));
    provider.json(200, {});
    expectFail(await w.call(who, "provider_request", { ...args, approval_id: pending.approval_id }), "operation_not_allowed");
    assert.equal(provider.calls.length, 0);
  });
});

// ---------------------------------------------------------------------------
// github_create_draft_pr (v2 GitHub capability: its transport is deps.github.fetch)
// ---------------------------------------------------------------------------

describe("github_create_draft_pr (offline)", () => {
  const ARGS = { owner: "echoomegaprime", repo: "echo-credential-broker", title: "Add provider tests", head: "agent/provider-tests", base: "main", body: "Adds tests." };

  /** GitHub as deps.github.fetch sees it. No App key in env, so the capability falls back to the account PAT. */
  async function githubWorld(pulls: { status: number; body: unknown }) {
    const w = await makeWorld();
    const calls: Array<{ line: string; auth: string; body: string | null }> = [];
    const githubFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      assert.equal(url.origin, "https://api.github.com");
      const method = init?.method ?? "GET";
      calls.push({
        line: `${method} ${url.pathname}`,
        auth: new Headers(init?.headers).get("authorization") ?? "",
        body: typeof init?.body === "string" ? init.body : null,
      });
      const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
      if (url.pathname === "/user") return json(200, { login: "echoomegaprime", id: 314902331 });
      if (method === "POST" && url.pathname === "/repos/echoomegaprime/echo-credential-broker/pulls") return json(pulls.status, pulls.body);
      return json(404, { message: "Not Found" });
    }) as typeof fetch;
    const deps: GatewayDeps = { ...w.deps, github: { store: w.store, fetch: githubFetch, env: {}, tokenCache: new InstallationTokenCache() } };
    const call = async (identity: ClientIdentity, args: unknown): Promise<GatewayResult> => {
      const result = await dispatchTool(identity, "github_create_draft_pr", args, deps);
      everyResult.push(result);
      return result;
    };
    return { ...w, calls, call };
  }

  it("matches the registry: tier 1, scope github.write", () => {
    assert.deepEqual([lookupCapability("github.pr.create_draft")?.tier, requiredScope("github.pr.create_draft")], [1, "github.write"]);
  });

  it("opens a draft PR with the account credential and returns PR metadata only", async () => {
    const secret = SECRETS.github;
    const w = await githubWorld({
      status: 201,
      body: {
        number: 42,
        html_url: "https://github.com/echoomegaprime/echo-credential-broker/pull/42",
        draft: true,
        state: "open",
        head: { ref: "agent/provider-tests" },
        base: { ref: "main" },
        body: `echo ${secret}`,
        _links: { self: { href: `https://api.github.com/x?access_token=${secret}` } },
      },
    });
    const data = expectOk(await w.call(client(["github.write"]), ARGS));
    assert.deepEqual(data, {
      number: 42,
      html_url: "https://github.com/echoomegaprime/echo-credential-broker/pull/42",
      draft: true,
      state: "open",
      head: "agent/provider-tests",
      base: "main",
    });
    const post = last(w.calls);
    assert.equal(post.line, "POST /repos/echoomegaprime/echo-credential-broker/pulls");
    assert.equal(post.auth, `Bearer ${secret}`);
    assert.deepEqual(JSON.parse(String(post.body)), { title: ARGS.title, head: ARGS.head, base: ARGS.base, draft: true, body: ARGS.body });
    assert.equal(provider.calls.length, 0, "the v2 capability uses its own injected transport");
    const row = last(await w.rows());
    assert.deepEqual([row.capability, row.resource, row.decision, row.tier, row.result, row.credential_ref, row.http_status], [
      "github.pr.create_draft",
      "github:echoomegaprime/echo-credential-broker",
      "allow",
      1,
      "ok",
      REFS.github,
      201,
    ]);
    assertClean("draft pr result", data);
  });

  it("provider 401 / 403 / 422 / 429 / 503 each become a clean github_http_<status> error", async () => {
    for (const status of [401, 403, 422, 429, 503]) {
      const w = await githubWorld({ status, body: { message: `upstream said ${status} to Bearer ${SECRETS.github}` } });
      const failure = expectFail(await w.call(client(["github.write"]), ARGS), `github_http_${status}`);
      assertClean(`draft pr ${status}`, failure);
      const row = last(await w.rows());
      assert.deepEqual([row.capability, row.tier, row.result, row.error, row.http_status], ["github.pr.create_draft", 1, "error", `github_http_${status}`, status]);
      assertClean("ledger row", row);
    }
  });

  it("a network error becomes a clean error", async () => {
    const w = await makeWorld();
    const failing = (async () => {
      throw new TypeError(`fetch failed while sending Bearer ${SECRETS.github}`);
    }) as typeof fetch;
    const deps: GatewayDeps = { ...w.deps, github: { store: w.store, fetch: failing, env: {}, tokenCache: new InstallationTokenCache() } };
    const result = await dispatchTool(client(["github.write"]), "github_create_draft_pr", ARGS, deps);
    everyResult.push(result);
    assert.equal(result.ok, false);
    assertClean("draft pr network error", result);
    assert.equal(last(await w.rows()).result, "error");
  });

  it("is denied before any network call without github.write, for an unregistered owner, or with bad arguments", async () => {
    const w = await githubWorld({ status: 201, body: {} });
    expectFail(await w.call(client(["github.read"]), ARGS), "missing_scope");
    expectFail(await w.call(client(["github.write"]), { ...ARGS, title: undefined }), "invalid_arguments");
    const stranger = await w.call(client(["github.write"]), { ...ARGS, owner: "someone-else" });
    assert.equal(stranger.ok, false);
    const same = await w.call(client(["github.write"]), { ...ARGS, base: ARGS.head });
    assert.equal(same.ok, false);
    assert.equal(w.calls.length, 0);
    assert.equal(provider.calls.length, 0);
  });
});

// ---------------------------------------------------------------------------
// The two metadata tools no other test runs to success through dispatchTool
// ---------------------------------------------------------------------------

describe("vault_find and vault_metadata (offline)", () => {
  it("vault_find returns candidates without a value; vault_metadata returns metadata without a value", async () => {
    const w = await makeWorld();
    const who = client(["vault.read"]);
    const found = expectOk(await w.call(who, "vault_find", { query: "github" }));
    assert.equal(found.status, "EXACT");
    assert.deepEqual(found.candidates, [{ service: "github", username: "echoomegaprime", key_shape: "fake" }]);
    const meta = expectOk(await w.call(who, "vault_metadata", { credential_ref: REFS.stripe }));
    assert.deepEqual([meta.ref, meta.provider, meta.account, meta.type, meta.status], [REFS.stripe, "stripe", "secret_key", "api_key", "imported"]);
    expectFail(await w.call(who, "vault_find", { query: "g" }), "query_too_short");
    expectFail(await w.call(who, "vault_metadata", { credential_ref: "vault://github/unknown" }), "credential_unavailable");
    expectFail(await w.call(client(["github.read"]), "vault_find", { query: "github" }), "missing_scope");
    assert.equal(provider.calls.length, 0);
    const all = await w.rows();
    assert.deepEqual(all.map((r) => [r.capability, r.tier, r.result]), [
      ["vault.find", 0, "ok"],
      ["vault.metadata", 0, "ok"],
      ["vault.find", 0, "error"],
      ["vault.metadata", 0, "error"],
      ["vault.find", 0, "denied"],
    ]);
    assertClean("metadata results", [found, meta]);
  });
});
