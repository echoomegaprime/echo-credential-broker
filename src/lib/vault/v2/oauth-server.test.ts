// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { after, before, beforeEach, describe, it } from "node:test";
import { MemoryOAuthStore, SqlOAuthStore, type OAuthStore } from "./oauth-store.ts";
import {
  CODE_TTL_MS,
  SUPPORTED_SCOPES,
  configureOAuth,
  handleAuthorizationServerMetadata,
  handleAuthorize,
  handlePreflight,
  handleProtectedResourceMetadata,
  handleRegister,
  handleRevoke,
  handleToken,
  resetOAuth,
  resolveOAuthConfig,
  s256Challenge,
  sha256Hex,
  type ClientApprovalRequest,
  type ClientApprovalStatus,
  type OwnerApprover,
} from "./oauth-server.ts";
import { authenticateRequest, listClients, revokeClient } from "./identity.ts";
import { MemoryRateLimitStore, RATE_LIMIT_KEY_PATTERN, setDefaultRateLimitStore, type RateLimitStore } from "./rate-limit-store.ts";

// Failed-attempt counts default to the shared SQL store; this file runs them in memory.
setDefaultRateLimitStore(new MemoryRateLimitStore());

// ---------------------------------------------------------------------------
// Output capture: everything this file's code writes to stderr / console is
// buffered (and kept out of the test report) so leak tests can scan it.
// ---------------------------------------------------------------------------

const captured: string[] = [];
const origStderrWrite = process.stderr.write.bind(process.stderr);
const origConsole = { log: console.log, info: console.info, warn: console.warn, error: console.error, debug: console.debug };
before(() => {
  process.stderr.write = ((chunk: unknown) => {
    captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  for (const k of Object.keys(origConsole) as Array<keyof typeof origConsole>) {
    console[k] = (...args: unknown[]) => {
      captured.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ") + "\n");
    };
  }
});
after(() => {
  process.stderr.write = origStderrWrite as typeof process.stderr.write;
  Object.assign(console, origConsole);
});

/** Every raw secret the tests ever saw (tokens, codes, verifiers, pending handles). */
const rawSecrets = new Set<string>();
/** Every error response body / error redirect the tests ever saw. */
const errorOutputs: string[] = [];

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const BASE = "http://localhost:8080";
const RESOURCE = `${BASE}/api/mcp`;
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";

class FakeClock {
  t = Date.UTC(2026, 10, 14, 12, 0, 0);
  now(): number {
    return this.t;
  }
  advance(ms: number): void {
    this.t += ms;
  }
}

class FakeApprover implements OwnerApprover {
  requests: Array<ClientApprovalRequest & { approval_id: string }> = [];
  statuses = new Map<string, ClientApprovalStatus>();
  private n = 0;
  async requestClientApproval(req: ClientApprovalRequest): Promise<{ approval_id: string }> {
    const approval_id = `ap_${++this.n}`;
    this.requests.push({ ...req, approval_id });
    this.statuses.set(approval_id, "pending");
    return { approval_id };
  }
  async checkClientApproval(id: string): Promise<ClientApprovalStatus> {
    return this.statuses.get(id) ?? "expired";
  }
  decideLast(status: ClientApprovalStatus): void {
    const last = this.requests.at(-1);
    assert.ok(last, "no approval was requested");
    this.statuses.set(last.approval_id, status);
  }
}

interface Harness {
  store: MemoryOAuthStore | OAuthStore;
  clock: FakeClock;
  approver: FakeApprover;
}

function setup(env: Record<string, string> = {}, store: OAuthStore = new MemoryOAuthStore()): Harness {
  const clock = new FakeClock();
  const approver = new FakeApprover();
  resetOAuth();
  configureOAuth({ store, clock, approver, env: { ECHO_VAULT_PUBLIC_URL: BASE, ...env } });
  return { store, clock, approver };
}

async function noteError(res: Response): Promise<Response> {
  if (res.status >= 300) {
    const body = await res.clone().text();
    errorOutputs.push(body);
    const loc = res.headers.get("location");
    if (loc && /[?&]error=/.test(loc)) errorOutputs.push(loc);
  }
  return res;
}

async function register(body: unknown): Promise<Response> {
  return noteError(
    await handleRegister(
      new Request(`${BASE}/api/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      }),
    ),
  );
}

async function registerClient(extra: Record<string, unknown> = {}): Promise<string> {
  const res = await register({ client_name: "Claude", redirect_uris: [REDIRECT], ...extra });
  assert.equal(res.status, 201);
  return ((await res.json()) as { client_id: string }).client_id;
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  rawSecrets.add(verifier);
  return { verifier, challenge: s256Challenge(verifier) };
}

async function authorize(params: Record<string, string>): Promise<Response> {
  const url = `${BASE}/api/oauth/authorize?${new URLSearchParams(params).toString()}`;
  return noteError(await handleAuthorize(new Request(url)));
}

function authParams(clientId: string, challenge: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "st-123",
    resource: RESOURCE,
    ...extra,
  };
}

function pollUrlFrom(html: string): string {
  const m = /http-equiv="refresh" content="\d+;url=([^"]+)"/.exec(html);
  assert.ok(m, "waiting page must meta-refresh to a poll URL");
  const url = m[1].replace(/&amp;/g, "&");
  rawSecrets.add(new URL(url).searchParams.get("pending") ?? "");
  return url;
}

async function poll(url: string): Promise<Response> {
  return noteError(await handleAuthorize(new Request(url)));
}

async function token(form: Record<string, string>): Promise<Response> {
  return noteError(
    await handleToken(
      new Request(`${BASE}/api/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(form).toString(),
      }),
    ),
  );
}

async function revoke(form: Record<string, string>): Promise<Response> {
  return noteError(
    await handleRevoke(
      new Request(`${BASE}/api/oauth/revoke`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(form).toString(),
      }),
    ),
  );
}

interface TokenSet {
  access_token: string;
  refresh_token: string;
  scope: string;
  token_type: string;
  expires_in: number;
}

async function tokenJson(res: Response): Promise<TokenSet> {
  assert.equal(res.status, 200, await res.clone().text());
  const body = (await res.json()) as TokenSet;
  rawSecrets.add(body.access_token);
  rawSecrets.add(body.refresh_token);
  return body;
}

/** Register (or reuse) a client, authorize, have the owner approve, return the code. */
async function obtainCode(
  h: Harness,
  opts: { clientId?: string; scope?: string } = {},
): Promise<{ clientId: string; code: string; verifier: string; location: URL }> {
  const clientId = opts.clientId ?? (await registerClient());
  const { verifier, challenge } = pkce();
  const res = await authorize(authParams(clientId, challenge, opts.scope ? { scope: opts.scope } : {}));
  assert.equal(res.status, 200);
  const pollUrl = pollUrlFrom(await res.text());
  h.approver.decideLast("approved");
  const done = await poll(pollUrl);
  assert.equal(done.status, 302);
  const location = new URL(done.headers.get("location") ?? "");
  const code = location.searchParams.get("code") ?? "";
  rawSecrets.add(code);
  return { clientId, code, verifier, location };
}

async function fullFlow(h: Harness, opts: { scope?: string } = {}) {
  const { clientId, code, verifier } = await obtainCode(h, opts);
  const tokens = await tokenJson(
    await token({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, redirect_uri: REDIRECT, resource: RESOURCE }),
  );
  return { clientId, code, verifier, tokens };
}

function bearer(tokenValue: string): Headers {
  return new Headers({ authorization: `Bearer ${tokenValue}` });
}

// ---------------------------------------------------------------------------
// Configuration + metadata
// ---------------------------------------------------------------------------

describe("configuration (fail closed)", () => {
  it("requires ECHO_VAULT_PUBLIC_URL to be an https origin (http only for localhost outside production)", () => {
    assert.throws(() => resolveOAuthConfig({}), /not set/);
    assert.throws(() => resolveOAuthConfig({ ECHO_VAULT_PUBLIC_URL: "http://vault.example.com" }), /https/);
    assert.throws(() => resolveOAuthConfig({ ECHO_VAULT_PUBLIC_URL: "https://vault.example.com/sub" }), /origin/);
    assert.throws(() => resolveOAuthConfig({ ECHO_VAULT_PUBLIC_URL: "https://vault.example.com/?x=1" }), /query/);
    assert.throws(() => resolveOAuthConfig({ ECHO_VAULT_PUBLIC_URL: "https://vault.example.com/#f" }), /fragment/);
    assert.throws(() => resolveOAuthConfig({ ECHO_VAULT_PUBLIC_URL: "https://u:p@vault.example.com" }), /credentials/);
    assert.throws(
      () => resolveOAuthConfig({ ECHO_VAULT_PUBLIC_URL: "http://localhost:8080", NODE_ENV: "production" }),
      /https/,
    );
    assert.equal(resolveOAuthConfig({ ECHO_VAULT_PUBLIC_URL: "https://Vault.Example.com/" }).issuer, "https://vault.example.com");
    assert.equal(resolveOAuthConfig({ ECHO_VAULT_PUBLIC_URL: "http://localhost:8080" }).resource, RESOURCE);
  });

  it("every endpoint answers 503 (and authenticates nobody) when unconfigured", async () => {
    resetOAuth();
    configureOAuth({ store: new MemoryOAuthStore(), approver: new FakeApprover(), env: {} });
    assert.equal((await handleAuthorizationServerMetadata(new Request(`${BASE}/x`))).status, 503);
    assert.equal((await handleProtectedResourceMetadata(new Request(`${BASE}/x`))).status, 503);
    assert.equal((await register({ redirect_uris: [REDIRECT] })).status, 503);
    assert.equal((await authorize({ client_id: "oc_x" })).status, 503);
    assert.equal((await token({ grant_type: "refresh_token" })).status, 503);
    assert.equal((await revoke({ token: "x" })).status, 503);
  });
});

describe("metadata documents", () => {
  beforeEach(() => setup());

  it("serves RFC 8414 authorization-server metadata (S256 only, public clients)", async () => {
    const res = await handleAuthorizationServerMetadata(new Request(`${BASE}/.well-known/oauth-authorization-server`));
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("access-control-allow-origin"), "*");
    const md = (await res.json()) as Record<string, unknown>;
    assert.equal(md.issuer, BASE);
    assert.equal(md.authorization_endpoint, `${BASE}/api/oauth/authorize`);
    assert.equal(md.token_endpoint, `${BASE}/api/oauth/token`);
    assert.equal(md.registration_endpoint, `${BASE}/api/oauth/register`);
    assert.equal(md.revocation_endpoint, `${BASE}/api/oauth/revoke`);
    assert.deepEqual(md.code_challenge_methods_supported, ["S256"]);
    assert.deepEqual(md.response_types_supported, ["code"]);
    assert.deepEqual(md.grant_types_supported, ["authorization_code", "refresh_token"]);
    assert.deepEqual(md.token_endpoint_auth_methods_supported, ["none"]);
    assert.deepEqual(md.scopes_supported, [
      "github.read",
      "github.write",
      "cloudflare.read",
      "cloudflare.write",
      "openai.read",
      "openai.write",
      "stripe.read",
      "xai.read",
      "xai.write",
      "vault.read",
      "vault.write",
      "audit.read",
    ]);
    assert.equal(md.authorization_response_iss_parameter_supported, true);
  });

  it("serves RFC 9728 protected-resource metadata for /api/mcp", async () => {
    const res = await handleProtectedResourceMetadata(new Request(`${BASE}/.well-known/oauth-protected-resource`));
    assert.equal(res.status, 200);
    const md = (await res.json()) as Record<string, unknown>;
    assert.equal(md.resource, RESOURCE);
    assert.deepEqual(md.authorization_servers, [BASE]);
    assert.deepEqual(md.bearer_methods_supported, ["header"]);
    assert.deepEqual(md.scopes_supported, [...SUPPORTED_SCOPES]);
  });

  it("answers CORS preflight without credentials", () => {
    const res = handlePreflight();
    assert.equal(res.status, 204);
    assert.equal(res.headers.get("access-control-allow-origin"), "*");
    assert.equal(res.headers.get("access-control-allow-credentials"), null);
  });
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

describe("dynamic client registration", () => {
  let h: Harness;
  beforeEach(() => {
    h = setup();
  });

  it("registers a public client with an oc_ id, no secret, and NO granted scopes", async () => {
    const res = await register({
      client_name: "Claude",
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: "client_secret_basic",
      grant_types: ["authorization_code", "refresh_token", "client_credentials"],
      scope: "github.read github.write bogus.scope",
    });
    assert.equal(res.status, 201);
    assert.equal(res.headers.get("cache-control"), "no-store");
    const body = (await res.json()) as Record<string, unknown>;
    assert.match(String(body.client_id), /^oc_[A-Za-z0-9_-]{22}$/);
    assert.equal(body.client_secret, undefined);
    assert.equal(body.token_endpoint_auth_method, "none");
    assert.deepEqual(body.grant_types, ["authorization_code", "refresh_token"]);
    assert.equal(body.scope, "github.read github.write");
    const [client] = await listClients();
    assert.equal(client.status, "registered");
    assert.deepEqual(client.granted_scopes, []);
  });

  it("rejects bad redirect URIs", async () => {
    const bad: unknown[] = [
      "http://evil.example/cb",
      "https://claude.ai/cb#frag",
      "https://claude.ai/cb#",
      "javascript:alert(1)",
      "cursor://callback",
      "/relative/cb",
      "https://user:pass@claude.ai/cb",
      "http://127.0.0.2/cb",
      "http://localhost.evil.example/cb",
      "https://claude.ai/c b",
      "",
      42,
    ];
    for (const uri of bad) {
      const res = await register({ client_name: "x", redirect_uris: [uri] });
      assert.equal(res.status, 400, `expected rejection for ${String(uri)}`);
      assert.equal(((await res.json()) as { error: string }).error, "invalid_redirect_uri");
    }
    for (const body of [{}, { redirect_uris: [] }, { redirect_uris: "https://claude.ai/cb" }]) {
      const res = await register(body);
      assert.equal(((await res.json()) as { error: string }).error, "invalid_redirect_uri");
    }
  });

  it("allows loopback redirect URIs for desktop/CLI clients", async () => {
    for (const uri of ["http://localhost:33418/callback", "http://127.0.0.1:8976/cb", "http://[::1]:5000/cb"]) {
      const res = await register({ client_name: "Claude Code", redirect_uris: [uri] });
      assert.equal(res.status, 201, uri);
    }
  });

  it("validates client metadata (name length, control/bidi chars, response types, JSON)", async () => {
    const long = await register({ client_name: "x".repeat(101), redirect_uris: [REDIRECT] });
    assert.equal(((await long.json()) as { error: string }).error, "invalid_client_metadata");
    const bidi = await register({ client_name: "Cla\u202Eude", redirect_uris: [REDIRECT] });
    assert.equal(bidi.status, 400);
    const rt = await register({ client_name: "x", redirect_uris: [REDIRECT], response_types: ["token"] });
    assert.equal(rt.status, 400);
    const notJson = await handleRegister(
      new Request(`${BASE}/api/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: "{" }),
    );
    assert.equal(notJson.status, 400);
    const big = await register({ client_name: "x", redirect_uris: [REDIRECT], pad: "y".repeat(20_000) });
    assert.equal(big.status, 413);
  });

  it("enforces ECHO_VAULT_OAUTH_MAX_CLIENTS and prunes never-approved clients after 24h", async () => {
    h = setup({ ECHO_VAULT_OAUTH_MAX_CLIENTS: "2" });
    await registerClient();
    await registerClient();
    const third = await register({ client_name: "third", redirect_uris: [REDIRECT] });
    assert.equal(third.status, 429);
    h.clock.advance(25 * 60 * 60 * 1000);
    assert.equal((await register({ client_name: "fourth", redirect_uris: [REDIRECT] })).status, 201);
    assert.equal((await listClients()).length, 1);
  });
});

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

describe("authorization endpoint", () => {
  let h: Harness;
  let clientId: string;
  beforeEach(async () => {
    h = setup();
    clientId = await registerClient();
  });

  async function expectPageError(params: Record<string, string>, status = 400): Promise<string> {
    const res = await authorize(params);
    assert.equal(res.status, status);
    assert.equal(res.headers.get("location"), null, "must not redirect");
    assert.equal(h.approver.requests.length, 0, "must not ping the owner");
    return res.text();
  }

  it("rejects missing PKCE, plain PKCE, and a missing method", async () => {
    const { challenge } = pkce();
    const noChallenge = authParams(clientId, challenge);
    delete (noChallenge as Record<string, string | undefined>).code_challenge;
    await expectPageError(noChallenge);
    await expectPageError(authParams(clientId, challenge, { code_challenge_method: "plain" }));
    const noMethod = authParams(clientId, challenge);
    delete (noMethod as Record<string, string | undefined>).code_challenge_method;
    await expectPageError(noMethod);
    await expectPageError(authParams(clientId, "short"));
  });

  it("rejects a redirect_uri that is not an exact registered match, and never redirects to it", async () => {
    const { challenge } = pkce();
    for (const redirect_uri of [`${REDIRECT}/x`, `${REDIRECT}?a=1`, "https://evil.example/cb", REDIRECT.toUpperCase()]) {
      await expectPageError(authParams(clientId, challenge, { redirect_uri }));
    }
    const missing = authParams(clientId, challenge);
    delete (missing as Record<string, string | undefined>).redirect_uri;
    await expectPageError(missing);
  });

  it("rejects unknown clients, wrong response_type, foreign resource, unknown scope, repeated params", async () => {
    const { challenge } = pkce();
    const html = await expectPageError(authParams("oc_AAAAAAAAAAAAAAAAAAAAAA", challenge));
    assert.match(html, /not registered/);
    await expectPageError(authParams(clientId, challenge, { response_type: "token" }));
    await expectPageError(authParams(clientId, challenge, { resource: "https://other.example/api/mcp" }));
    await expectPageError(authParams(clientId, challenge, { scope: "github.admin" }));
    const dup = `${BASE}/api/oauth/authorize?${new URLSearchParams(authParams(clientId, challenge)).toString()}&client_id=${clientId}`;
    assert.equal((await handleAuthorize(new Request(dup))).status, 400);
  });

  it("renders an escaped, script-free approval page with strict headers", async () => {
    const evilId = await registerClient({ client_name: `<script>alert("x")</script>&'` });
    const { challenge } = pkce();
    const res = await authorize(authParams(evilId, challenge));
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /Approve this connection on your phone/);
    assert.ok(!html.includes("<script"), "client_name must be escaped");
    assert.ok(html.includes("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&#39;"));
    assert.match(html, /claude\.ai/);
    const csp = res.headers.get("content-security-policy") ?? "";
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.ok(!csp.includes("unsafe-inline"));
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("x-frame-options"), "DENY");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal(h.approver.requests.length, 1);
    assert.deepEqual(h.approver.requests[0], {
      client_id: evilId,
      client_name: `<script>alert("x")</script>&'`,
      requested_scopes: ["github.read", "cloudflare.read", "vault.read"],
      redirect_host: "claude.ai",
      is_new_client: true,
      approval_id: "ap_1",
    });
  });

  it("keeps waiting while pending, then issues a code bound to state + iss once approved", async () => {
    const { challenge } = pkce();
    const res = await authorize(authParams(clientId, challenge, { scope: "github.read github.write" }));
    const pollUrl = pollUrlFrom(await res.text());
    const stillWaiting = await poll(pollUrl);
    assert.equal(stillWaiting.status, 200);
    assert.match(await stillWaiting.text(), /Approve this connection/);
    h.approver.decideLast("approved");
    const done = await poll(pollUrl);
    assert.equal(done.status, 302);
    assert.equal(done.headers.get("cache-control"), "no-store");
    const loc = new URL(done.headers.get("location") ?? "");
    assert.equal(`${loc.origin}${loc.pathname}`, REDIRECT);
    assert.match(loc.searchParams.get("code") ?? "", /^evc_[A-Za-z0-9_-]{43}$/);
    rawSecrets.add(loc.searchParams.get("code") ?? "");
    assert.equal(loc.searchParams.get("state"), "st-123");
    assert.equal(loc.searchParams.get("iss"), BASE);
    // The pending handle is single-use.
    assert.equal((await poll(pollUrl)).status, 400);
    const [client] = await listClients();
    assert.equal(client.status, "approved");
    assert.deepEqual(client.granted_scopes, ["github.read", "github.write"]);
  });

  it("owner denial blocks the client without redirecting, and stops further owner pings", async () => {
    const { challenge } = pkce();
    const pollUrl = pollUrlFrom(await (await authorize(authParams(clientId, challenge))).text());
    h.approver.decideLast("denied");
    const denied = await poll(pollUrl);
    assert.equal(denied.status, 403);
    assert.equal(denied.headers.get("location"), null);
    assert.equal((await listClients())[0].status, "denied");
    const again = await authorize(authParams(clientId, pkce().challenge));
    assert.equal(again.status, 403);
    assert.equal(h.approver.requests.length, 1);
  });

  it("expires pending requests (owner timeout or local TTL)", async () => {
    const first = pollUrlFrom(await (await authorize(authParams(clientId, pkce().challenge))).text());
    h.approver.decideLast("expired");
    assert.equal((await poll(first)).status, 400);
    const second = pollUrlFrom(await (await authorize(authParams(clientId, pkce().challenge))).text());
    h.clock.advance(11 * 60 * 1000);
    h.approver.decideLast("approved");
    assert.equal((await poll(second)).status, 400, "an approval after the local TTL must not issue a code");
  });

  it("caps pending authorizations (ECHO_VAULT_OAUTH_MAX_PENDING)", async () => {
    h = setup({ ECHO_VAULT_OAUTH_MAX_PENDING: "2" });
    clientId = await registerClient();
    assert.equal((await authorize(authParams(clientId, pkce().challenge))).status, 200);
    assert.equal((await authorize(authParams(clientId, pkce().challenge))).status, 200);
    assert.equal((await authorize(authParams(clientId, pkce().challenge))).status, 429);
    assert.equal(h.approver.requests.length, 2);
  });

  it("re-authorizing an approved client still needs the owner, stays within its grant, and redirects errors", async () => {
    await obtainCode(h, { clientId, scope: "github.read" });
    const { challenge } = pkce();
    const res = await authorize(authParams(clientId, challenge, { scope: "github.read github.write" }));
    assert.equal(res.status, 200);
    const last = h.approver.requests.at(-1);
    assert.equal(last?.is_new_client, false);
    assert.deepEqual(last?.requested_scopes, ["github.read"]);
    // Trusted (approved) client: protocol errors go back to its redirect_uri with state + iss.
    const onlyUngranted = await authorize(authParams(clientId, challenge, { scope: "github.write" }));
    assert.equal(onlyUngranted.status, 302);
    const loc = new URL(onlyUngranted.headers.get("location") ?? "");
    assert.equal(loc.searchParams.get("error"), "invalid_scope");
    assert.equal(loc.searchParams.get("state"), "st-123");
    assert.equal(loc.searchParams.get("iss"), BASE);
    const plain = await authorize(authParams(clientId, challenge, { code_challenge_method: "plain" }));
    assert.equal(new URL(plain.headers.get("location") ?? "").searchParams.get("error"), "invalid_request");
  });

  it("fails closed (503) when no OwnerApprover is wired", async () => {
    configureOAuth({ approver: null });
    const res = await authorize(authParams(clientId, pkce().challenge));
    assert.equal(res.status, 503);
  });
});

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

describe("token endpoint", () => {
  let h: Harness;
  beforeEach(() => {
    h = setup();
  });

  it("happy path: register → authorize → owner approves → code → token → authenticateRequest", async () => {
    const { clientId, tokens } = await fullFlow(h, { scope: "github.read github.write vault.read" });
    assert.match(tokens.access_token, /^eva_[A-Za-z0-9_-]{43}$/);
    assert.match(tokens.refresh_token, /^evr_[A-Za-z0-9_-]{43}$/);
    assert.equal(tokens.token_type, "Bearer");
    assert.equal(tokens.expires_in, 3600);
    assert.equal(tokens.scope, "github.read github.write vault.read");
    const identity = await authenticateRequest(bearer(tokens.access_token));
    assert.deepEqual(identity, {
      client_id: clientId,
      name: "Claude",
      kind: "oauth",
      scopes: ["github.read", "github.write", "vault.read"],
    });
  });

  it("returns no-store token responses", async () => {
    const { clientId, code, verifier } = await obtainCode(h);
    const res = await token({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId });
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("pragma"), "no-cache");
    await tokenJson(res);
  });

  it("rejects code reuse and revokes the tokens minted from that code", async () => {
    const { clientId, code, verifier, tokens } = await fullFlow(h);
    const again = await token({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId });
    assert.equal(again.status, 400);
    assert.equal(((await again.json()) as { error: string }).error, "invalid_grant");
    assert.equal(await authenticateRequest(bearer(tokens.access_token)), null);
    const refreshed = await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId });
    assert.equal(refreshed.status, 400);
  });

  it("rejects a wrong PKCE verifier (and the code is then spent)", async () => {
    const { clientId, code, verifier } = await obtainCode(h);
    const wrong = pkce().verifier;
    const res = await token({ grant_type: "authorization_code", code, code_verifier: wrong, client_id: clientId });
    assert.equal(res.status, 400);
    assert.deepEqual(await res.json(), { error: "invalid_grant", error_description: "PKCE verification failed" });
    const retry = await token({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId });
    assert.equal(retry.status, 400);
    const missing = await token({ grant_type: "authorization_code", code, client_id: clientId });
    assert.equal(((await missing.json()) as { error: string }).error, "invalid_request");
  });

  it("rejects an expired code (60-second TTL)", async () => {
    const { clientId, code, verifier } = await obtainCode(h);
    h.clock.advance(CODE_TTL_MS + 1);
    const res = await token({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId });
    assert.equal(res.status, 400);
    assert.equal(((await res.json()) as { error_description: string }).error_description, "authorization code expired");
  });

  it("binds codes to client_id, redirect_uri, and resource", async () => {
    const other = await registerClient({ client_name: "Other" });
    let c = await obtainCode(h);
    let res = await token({ grant_type: "authorization_code", code: c.code, code_verifier: c.verifier, client_id: other });
    assert.equal(((await res.json()) as { error: string }).error, "invalid_grant");
    c = await obtainCode(h, { clientId: c.clientId });
    res = await token({
      grant_type: "authorization_code",
      code: c.code,
      code_verifier: c.verifier,
      client_id: c.clientId,
      redirect_uri: "https://claude.ai/other",
    });
    assert.equal(((await res.json()) as { error: string }).error, "invalid_grant");
    c = await obtainCode(h, { clientId: c.clientId });
    res = await token({
      grant_type: "authorization_code",
      code: c.code,
      code_verifier: c.verifier,
      client_id: c.clientId,
      resource: "https://other.example/api/mcp",
    });
    assert.equal(((await res.json()) as { error: string }).error, "invalid_target");
  });

  it("rejects client secrets, unknown clients, bad grant types, and non-form bodies", async () => {
    const { clientId, code, verifier } = await obtainCode(h);
    let res = await token({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, client_secret: "s3cret-value" });
    assert.equal(res.status, 401);
    res = await token({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: "oc_AAAAAAAAAAAAAAAAAAAAAA" });
    assert.equal(((await res.json()) as { error: string }).error, "invalid_client");
    res = await token({ grant_type: "password", client_id: clientId });
    assert.equal(((await res.json()) as { error: string }).error, "unsupported_grant_type");
    res = await token({ grant_type: "authorization_code", code, code_verifier: verifier });
    assert.equal(((await res.json()) as { error: string }).error, "invalid_request");
    const jsonBody = await handleToken(
      new Request(`${BASE}/api/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ grant_type: "authorization_code" }),
      }),
    );
    assert.equal(jsonBody.status, 400);
  });

  it("rotates refresh tokens; reusing a rotated one revokes the whole family", async () => {
    const { clientId, tokens: first } = await fullFlow(h);
    const second = await tokenJson(await token({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: clientId }));
    assert.notEqual(second.access_token, first.access_token);
    assert.notEqual(second.refresh_token, first.refresh_token);
    assert.ok(await authenticateRequest(bearer(second.access_token)));

    const replay = await token({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: clientId });
    assert.equal(replay.status, 400);
    assert.equal(((await replay.json()) as { error: string }).error, "invalid_grant");
    assert.equal(await authenticateRequest(bearer(first.access_token)), null);
    assert.equal(await authenticateRequest(bearer(second.access_token)), null);
    const afterKill = await token({ grant_type: "refresh_token", refresh_token: second.refresh_token, client_id: clientId });
    assert.equal(afterKill.status, 400);
  });

  it("refresh can narrow but never widen scope, and keeps the original grant on the new refresh token", async () => {
    const { clientId, tokens } = await fullFlow(h, { scope: "github.read vault.read" });
    const wider = await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId, scope: "github.write" });
    assert.equal(((await wider.json()) as { error: string }).error, "invalid_scope");
    const narrow = await tokenJson(
      await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId, scope: "vault.read" }),
    );
    assert.equal(narrow.scope, "vault.read");
    const back = await tokenJson(await token({ grant_type: "refresh_token", refresh_token: narrow.refresh_token, client_id: clientId }));
    assert.equal(back.scope, "github.read vault.read");
  });

  it("rate-limits failed token attempts per client (injectable clock)", async () => {
    resetOAuth();
    const store = new MemoryOAuthStore();
    const clock = new FakeClock();
    const approver = new FakeApprover();
    configureOAuth({ store, clock, approver, env: { ECHO_VAULT_PUBLIC_URL: BASE }, rateLimit: { maxFailures: 3, windowMs: 60_000 } });
    h = { store, clock, approver };
    const { clientId, tokens } = await fullFlow(h);
    for (let i = 0; i < 3; i++) {
      const res = await token({ grant_type: "refresh_token", refresh_token: `evr_${"A".repeat(43)}`, client_id: clientId });
      assert.equal(res.status, 400);
    }
    const blocked = await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId });
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers.get("retry-after")) > 0);
    clock.advance(61_000);
    await tokenJson(await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId }));
  });
});

// ---------------------------------------------------------------------------
// Failed-attempt limits over the shared rate-limit store
// ---------------------------------------------------------------------------

describe("token endpoint: failed-attempt limits live in the shared store", () => {
  const LIMIT = { maxFailures: 3, windowMs: 60_000 };
  const BAD_REFRESH = `evr_${"A".repeat(43)}`;

  /** A memory store whose operations can be switched off one by one. */
  class FlakyStore implements RateLimitStore {
    readonly kind = "sql" as const;
    readonly inner = new MemoryRateLimitStore();
    down = new Set<"hit" | "count" | "reset">();
    private gate(op: "hit" | "count" | "reset"): void {
      if (this.down.has(op)) throw new Error(`db down during ${op}`);
    }
    async hit(key: string, windowMs: number, now: number, limit?: number) {
      this.gate("hit");
      return this.inner.hit(key, windowMs, now, limit);
    }
    async count(key: string, windowMs: number, now: number) {
      this.gate("count");
      return this.inner.count(key, windowMs, now);
    }
    async reset(key: string) {
      this.gate("reset");
      return this.inner.reset(key);
    }
    async prune(now: number) {
      return this.inner.prune(now);
    }
  }

  function wire(store: OAuthStore, clock: FakeClock, rateLimitStore: RateLimitStore): Harness {
    const approver = new FakeApprover();
    resetOAuth();
    configureOAuth({ store, clock, approver, env: { ECHO_VAULT_PUBLIC_URL: BASE }, rateLimit: LIMIT, rateLimitStore });
    return { store, clock, approver };
  }

  const refresh = (clientId: string, refreshToken: string) =>
    token({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId });

  it("a restart (fresh OAuth context over the same store) keeps the client blocked with the same Retry-After", async () => {
    const store = new MemoryOAuthStore();
    const clock = new FakeClock();
    const limits = new MemoryRateLimitStore();
    const h = wire(store, clock, limits);
    const { clientId, tokens } = await fullFlow(h);
    for (let i = 0; i < 3; i++) assert.equal((await refresh(clientId, BAD_REFRESH)).status, 400);
    clock.advance(10_000);
    const blocked = await refresh(clientId, tokens.refresh_token);
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get("retry-after"), "50");

    // "Restart": every piece of in-process state is dropped; only the stores remain.
    wire(store, clock, limits);
    const still = await refresh(clientId, tokens.refresh_token);
    assert.equal(still.status, 429);
    assert.equal(still.headers.get("retry-after"), "50");
    assert.equal((await still.json()).error, "temporarily_unavailable");

    // The block lifts when the oldest failure leaves the window, as before.
    clock.advance(50_000);
    await tokenJson(await refresh(clientId, tokens.refresh_token));
  });

  it("a successful grant clears the client's failures in the store", async () => {
    const limits = new MemoryRateLimitStore();
    const h = wire(new MemoryOAuthStore(), new FakeClock(), limits);
    const { clientId, tokens } = await fullFlow(h);
    assert.equal(limits.keys().length, 0);
    for (let i = 0; i < 2; i++) assert.equal((await refresh(clientId, BAD_REFRESH)).status, 400);
    assert.equal(limits.keys().length, 1);
    await tokenJson(await refresh(clientId, tokens.refresh_token));
    assert.equal(limits.keys().length, 0);
  });

  it("stored keys are hashes: no client_id, token, code or verifier ever becomes a key", async () => {
    const limits = new MemoryRateLimitStore();
    const h = wire(new MemoryOAuthStore(), new FakeClock(), limits);
    const { clientId, tokens } = await fullFlow(h);
    const { verifier } = pkce();
    const bogusCode = `evc_${"B".repeat(43)}`;
    rawSecrets.add(bogusCode);
    await refresh(clientId, BAD_REFRESH);
    await token({ grant_type: "authorization_code", code: bogusCode, code_verifier: verifier, client_id: clientId });
    // A caller that puts a token where the client_id belongs.
    await refresh(tokens.refresh_token, tokens.refresh_token);
    await refresh(tokens.access_token, BAD_REFRESH);
    const keys = limits.keys();
    assert.equal(keys.length, 2); // the real client + one shared "malformed" bucket
    for (const key of keys) {
      assert.match(key, RATE_LIMIT_KEY_PATTERN);
      assert.ok(key.startsWith("oauth.token:"));
      for (const raw of [clientId, tokens.refresh_token, tokens.access_token, BAD_REFRESH, bogusCode, verifier, "malformed"]) {
        assert.equal(key.includes(raw), false);
      }
    }
  });

  it("store unreachable → the token endpoint fails closed (503 rate_limit_unavailable) and nothing is consumed", async () => {
    const limits = new FlakyStore();
    const h = wire(new MemoryOAuthStore(), new FakeClock(), limits);
    const { clientId, tokens } = await fullFlow(h);
    limits.down.add("count");
    const before = captured.length;
    const res = await refresh(clientId, tokens.refresh_token);
    assert.equal(res.status, 503);
    assert.equal(res.headers.get("retry-after"), "5");
    const body = await res.json();
    assert.equal(body.error, "temporarily_unavailable");
    assert.match(body.error_description, /^rate_limit_unavailable/);
    assert.equal(body.access_token, undefined);
    const logs = captured.slice(before).join("");
    assert.match(logs, /oauth_rate_limit_unavailable/);
    assert.match(logs, /rate_limit_store_error/);
    assert.equal(logs.includes("db down"), false);
    // The valid refresh token was not rotated by the refused request: it still works once the store is back.
    limits.down.clear();
    await tokenJson(await refresh(clientId, tokens.refresh_token));
  });

  it("a failed attempt is still refused when the failure cannot be recorded", async () => {
    const limits = new FlakyStore();
    const h = wire(new MemoryOAuthStore(), new FakeClock(), limits);
    const { clientId } = await fullFlow(h);
    limits.down.add("hit");
    const before = captured.length;
    const res = await refresh(clientId, BAD_REFRESH);
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, "invalid_grant");
    assert.match(captured.slice(before).join(""), /oauth_rate_limit_unavailable/);
  });

  it("a completed grant is not lost when clearing the failures fails; the stale failures keep counting", async () => {
    const limits = new FlakyStore();
    const h = wire(new MemoryOAuthStore(), new FakeClock(), limits);
    const { clientId, tokens } = await fullFlow(h);
    for (let i = 0; i < 2; i++) await refresh(clientId, BAD_REFRESH);
    limits.down.add("reset");
    const rotated = await tokenJson(await refresh(clientId, tokens.refresh_token));
    assert.match(rotated.refresh_token, /^evr_/);
    assert.equal(limits.inner.keys().length, 1);
    limits.down.clear();
    await refresh(clientId, BAD_REFRESH); // third failure in the window
    assert.equal((await refresh(clientId, rotated.refresh_token)).status, 429);
  });
});

// ---------------------------------------------------------------------------
// Revocation + owner kill switch
// ---------------------------------------------------------------------------

describe("revocation", () => {
  let h: Harness;
  beforeEach(() => {
    h = setup();
  });

  it("revokes an access token (RFC 7009) and answers 200 for unknown tokens", async () => {
    const { clientId, tokens } = await fullFlow(h);
    assert.equal((await revoke({ token: tokens.access_token, client_id: clientId, token_type_hint: "access_token" })).status, 200);
    assert.equal(await authenticateRequest(bearer(tokens.access_token)), null);
    // The refresh token of the same grant still works.
    await tokenJson(await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId }));
    assert.equal((await revoke({ token: "eva_unknown" })).status, 200);
    assert.equal((await revoke({})).status, 400);
  });

  it("revoking a refresh token revokes its family; a mismatched client_id revokes nothing", async () => {
    const { clientId, tokens } = await fullFlow(h);
    const other = await registerClient({ client_name: "Other" });
    assert.equal((await revoke({ token: tokens.refresh_token, client_id: other })).status, 200);
    assert.ok(await authenticateRequest(bearer(tokens.access_token)), "foreign client must not revoke");
    assert.equal((await revoke({ token: tokens.refresh_token, client_id: clientId })).status, 200);
    assert.equal(await authenticateRequest(bearer(tokens.access_token)), null);
    assert.equal((await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId })).status, 400);
  });

  it("revokeClient kills every token the client holds and blocks re-authorization", async () => {
    const a = await fullFlow(h);
    const b = await obtainCode(h, { clientId: a.clientId });
    const bTokens = await tokenJson(
      await token({ grant_type: "authorization_code", code: b.code, code_verifier: b.verifier, client_id: a.clientId }),
    );
    const result = await revokeClient(a.clientId);
    assert.equal(result.ok, true);
    assert.equal(result.tokens_revoked, 4);
    assert.equal(await authenticateRequest(bearer(a.tokens.access_token)), null);
    assert.equal(await authenticateRequest(bearer(bTokens.access_token)), null);
    assert.equal((await token({ grant_type: "refresh_token", refresh_token: bTokens.refresh_token, client_id: a.clientId })).status, 400);
    assert.equal((await authorize(authParams(a.clientId, pkce().challenge))).status, 403);
    assert.deepEqual(await revokeClient("oc_doesnotexist"), { ok: false, tokens_revoked: 0 });
  });
});

// ---------------------------------------------------------------------------
// Storage + leak invariants
// ---------------------------------------------------------------------------

describe("secret handling", () => {
  it("stores codes, tokens, and pending handles only as sha256 hashes", async () => {
    const h = setup();
    const { code, verifier, tokens } = await fullFlow(h);
    const refreshed = await tokenJson(
      await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: (await listClients())[0].client_id }),
    );
    const snap = (h.store as MemoryOAuthStore).snapshot();
    const dump = JSON.stringify(snap);
    for (const raw of [code, verifier, tokens.access_token, tokens.refresh_token, refreshed.access_token, refreshed.refresh_token]) {
      assert.ok(!dump.includes(raw), "raw secret found in store");
    }
    assert.ok(!/ev[acpr]_[A-Za-z0-9_-]{20}/.test(dump), "no raw ev*_ value may be persisted");
    const hashes = new Set(snap.tokens.map((t) => t.token_hash));
    assert.ok(hashes.has(sha256Hex(tokens.access_token)));
    assert.ok(hashes.has(sha256Hex(tokens.refresh_token)));
    assert.ok(snap.codes.some((c) => c.code_hash === sha256Hex(code)));
    for (const t of snap.tokens) assert.match(t.token_hash, /^[0-9a-f]{64}$/);
    for (const p of snap.pending) assert.match(p.id_hash, /^[0-9a-f]{64}$/);
    await assert.rejects(
      (h.store as MemoryOAuthStore).saveToken({ ...snap.tokens[0], token_hash: tokens.access_token }),
      /refused_unhashed/,
    );
  });

  it("never writes a raw token/code/verifier to logs or error responses", async () => {
    const h = setup({ ECHO_VAULT_DEBUG: "1" });
    const start = captured.length;
    const { clientId, code, verifier, tokens } = await fullFlow(h);
    // Drive the failure paths with the real secrets in hand. (Rotate first: the
    // code replay below correctly revokes the whole family.)
    const rotated = await tokenJson(await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId }));
    await token({ grant_type: "refresh_token", refresh_token: rotated.refresh_token, client_id: "oc_AAAAAAAAAAAAAAAAAAAAAA" });
    await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId });
    await token({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId });
    await token({ grant_type: "authorization_code", code: `evc_${"B".repeat(43)}`, code_verifier: verifier, client_id: clientId });
    await revoke({ token: rotated.access_token, client_id: clientId });
    await authenticateRequest(new Headers({ authorization: `Bearer ${rotated.access_token}`, "x-echo-agent": "claude" }));
    const logs = captured.slice(start).join("");
    assert.match(logs, /oauth_tokens_issued/, "log capture must be live");
    assert.match(logs, /oauth_refresh_reuse_detected/);
    assert.match(logs, /oauth_code_reuse_detected/);

    const everything = logs + "\n" + errorOutputs.join("\n");
    for (const raw of rawSecrets) {
      if (raw) assert.ok(!everything.includes(raw), "a raw secret leaked into logs or an error response");
    }
    assert.ok(!/\bev[acpr]_[A-Za-z0-9_-]{43}\b/.test(everything), "no ev*_ bearer value in logs/errors");
    assert.ok(!logs.includes("[REDACTED"), "nothing should have needed redaction — raw values must never reach the logger");
  });
});

// ---------------------------------------------------------------------------
// SQL store parity (PGlite + the real migration file)
// ---------------------------------------------------------------------------

describe("SqlOAuthStore over PGlite with migrations/0002_vault_oauth.sql", () => {
  type PgLike = { exec(sql: string): Promise<unknown>; query<T>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>; close(): Promise<void> };
  let pg: PgLike;
  let store: SqlOAuthStore;

  before(async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    pg = new PGlite() as unknown as PgLike;
    await pg.exec(readFileSync(new URL("../../../../migrations/0002_vault_oauth.sql", import.meta.url), "utf8"));
    const sql = { query: async (text: string, params: unknown[] = []) => (await pg.query(text, params)).rows };
    store = new SqlOAuthStore(async () => sql as never);
  });
  after(async () => {
    await pg?.close();
  });

  it("runs the full flow, rotation, and reuse detection against Postgres semantics", async () => {
    const h = setup({}, store);
    const { clientId, code, verifier, tokens } = await fullFlow(h, { scope: "github.read vault.read" });
    assert.deepEqual((await authenticateRequest(bearer(tokens.access_token)))?.scopes, ["github.read", "vault.read"]);
    const again = await token({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId });
    assert.equal(again.status, 400);
    assert.equal(await authenticateRequest(bearer(tokens.access_token)), null, "code reuse revokes the family in SQL too");

    const fresh = await fullFlow(h);
    const rotated = await tokenJson(
      await token({ grant_type: "refresh_token", refresh_token: fresh.tokens.refresh_token, client_id: fresh.clientId }),
    );
    assert.ok(await authenticateRequest(bearer(rotated.access_token)));
    assert.equal((await token({ grant_type: "refresh_token", refresh_token: fresh.tokens.refresh_token, client_id: fresh.clientId })).status, 400);
    assert.equal(await authenticateRequest(bearer(rotated.access_token)), null);

    const rows = await pg.query<Record<string, unknown>>("select * from vault_oauth_tokens");
    const dump = JSON.stringify(rows.rows, (_k, v) => (typeof v === "bigint" ? Number(v) : v));
    for (const raw of [tokens.access_token, tokens.refresh_token, rotated.access_token, rotated.refresh_token]) {
      assert.ok(!dump.includes(raw));
    }
    assert.equal((await listClients()).length, 2);
  });

  it("the schema itself refuses a raw (unhashed) token", async () => {
    const [client] = await listClients();
    await assert.rejects(
      pg.query(
        `insert into vault_oauth_tokens (token_hash, kind, client_id, family_id, scopes, resource, created_at, expires_at)
         values ($1, 'access', $2, 'fam_x', '[]'::jsonb, $3, 0, 1)`,
        [`eva_${"C".repeat(43)}`, client.client_id, RESOURCE],
      ),
    );
  });
});
