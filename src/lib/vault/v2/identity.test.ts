// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, beforeEach, describe, it } from "node:test";
import { MemoryOAuthStore } from "./oauth-store.ts";
import {
  configureOAuth,
  handleAuthorize,
  handleRegister,
  handleToken,
  resetOAuth,
  s256Challenge,
  sha256Hex,
  type ClientApprovalRequest,
  type ClientApprovalStatus,
  type OwnerApprover,
} from "./oauth-server.ts";
import {
  DEFAULT_LOCAL_SCOPES,
  authenticateRequest,
  listClients,
  localIdentity,
  revokeClient,
  setClientScopes,
  wwwAuthenticateHeader,
} from "./identity.ts";

// Keep the vault logger's stderr lines out of the test report.
const origStderrWrite = process.stderr.write.bind(process.stderr);
before(() => {
  process.stderr.write = (() => true) as typeof process.stderr.write;
});
after(() => {
  process.stderr.write = origStderrWrite as typeof process.stderr.write;
});

const BASE = "http://localhost:8080";
const REDIRECT = "http://127.0.0.1:33418/callback";

class FakeClock {
  t = Date.UTC(2026, 10, 14, 12, 0, 0);
  now(): number {
    return this.t;
  }
}

class AutoApprover implements OwnerApprover {
  requests: ClientApprovalRequest[] = [];
  decision: ClientApprovalStatus = "approved";
  async requestClientApproval(req: ClientApprovalRequest): Promise<{ approval_id: string }> {
    this.requests.push(req);
    return { approval_id: `ap_${this.requests.length}` };
  }
  async checkClientApproval(): Promise<ClientApprovalStatus> {
    return this.decision;
  }
}

let store: MemoryOAuthStore;
let clock: FakeClock;
let env: Record<string, string | undefined>;

beforeEach(() => {
  store = new MemoryOAuthStore();
  clock = new FakeClock();
  env = { ECHO_VAULT_PUBLIC_URL: BASE };
  resetOAuth();
  configureOAuth({ store, clock, approver: new AutoApprover(), env });
});

/** register → authorize → (auto) approve → code → token. */
async function connect(scope: string, name = "Claude Code"): Promise<{ clientId: string; access: string; refresh: string }> {
  const reg = await handleRegister(
    new Request(`${BASE}/api/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_name: name, redirect_uris: [REDIRECT] }),
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
  const body = (await res.json()) as { access_token: string; refresh_token: string };
  return { clientId, access: body.access_token, refresh: body.refresh_token };
}

describe("authenticateRequest", () => {
  it("never trusts self-asserted caller headers", async () => {
    assert.equal(await authenticateRequest(new Headers({ "x-echo-agent": "claude" })), null);
    assert.equal(await authenticateRequest(new Headers({ "x-echo-caller": "claude" })), null);
    assert.equal(await authenticateRequest(new Headers({ "x-echo-agent": "claude", "x-echo-caller": "echo" })), null);
  });

  it("ignores x-echo-agent even alongside a valid token (identity comes from the token only)", async () => {
    const { clientId, access } = await connect("github.read");
    const id = await authenticateRequest(new Headers({ authorization: `Bearer ${access}`, "x-echo-agent": "vault-console" }));
    assert.equal(id?.client_id, clientId);
    assert.equal(id?.name, "Claude Code");
    assert.equal(id?.kind, "oauth");
  });

  it("returns the identity with exactly the granted scopes", async () => {
    const { clientId, access } = await connect("github.read cloudflare.read");
    assert.deepEqual(await authenticateRequest(new Headers({ authorization: `Bearer ${access}` })), {
      client_id: clientId,
      name: "Claude Code",
      kind: "oauth",
      scopes: ["github.read", "cloudflare.read"],
    });
    // Scheme is case-insensitive.
    assert.ok(await authenticateRequest(new Headers({ authorization: `bearer ${access}` })));
  });

  it("rejects malformed, foreign, refresh, unknown, and non-Bearer credentials", async () => {
    const { access, refresh } = await connect("vault.read");
    const cases = [
      `Bearer`,
      `Bearer `,
      `Basic ${Buffer.from("a:b").toString("base64")}`,
      `Bearer ${refresh}`,
      `Bearer eva_${"A".repeat(43)}`,
      `Bearer ${access}x`,
      `Bearer ghp_${"a".repeat(36)}`,
      `Bearer ${access}, Bearer ${access}`,
      `Token ${access}`,
    ];
    for (const value of cases) {
      assert.equal(await authenticateRequest(new Headers({ authorization: value })), null, value.slice(0, 12));
    }
  });

  it("rejects expired tokens (1-hour TTL)", async () => {
    const { access } = await connect("vault.read");
    clock.t += 60 * 60 * 1000;
    assert.equal(await authenticateRequest(new Headers({ authorization: `Bearer ${access}` })), null);
  });

  it("rejects a token whose audience is not this MCP resource", async () => {
    const { clientId, access } = await connect("vault.read");
    const rec = await store.getToken(sha256Hex(access));
    assert.ok(rec);
    const forged = `eva_${randomBytes(32).toString("base64url")}`;
    await store.saveToken({ ...rec, token_hash: sha256Hex(forged), resource: "https://other.example/api/mcp" });
    assert.equal(await authenticateRequest(new Headers({ authorization: `Bearer ${forged}` })), null);
    assert.equal((await authenticateRequest(new Headers({ authorization: `Bearer ${access}` })))?.client_id, clientId);
  });

  it("fails closed when ECHO_VAULT_PUBLIC_URL is missing or not https", async () => {
    const { access } = await connect("vault.read");
    configureOAuth({ env: {} });
    assert.equal(await authenticateRequest(new Headers({ authorization: `Bearer ${access}` })), null);
    configureOAuth({ env: { ECHO_VAULT_PUBLIC_URL: "http://vault.example.com" } });
    assert.equal(await authenticateRequest(new Headers({ authorization: `Bearer ${access}` })), null);
  });

  it("fails closed when the store throws", async () => {
    const { access } = await connect("vault.read");
    store.getToken = async () => {
      throw new Error("db down");
    };
    assert.equal(await authenticateRequest(new Headers({ authorization: `Bearer ${access}` })), null);
  });
});

describe("owner console", () => {
  it("revokeClient → every token of that client authenticates as null", async () => {
    const { clientId, access } = await connect("github.read");
    const other = await connect("github.read", "Other");
    assert.deepEqual(await revokeClient(clientId), { ok: true, tokens_revoked: 2 });
    assert.equal(await authenticateRequest(new Headers({ authorization: `Bearer ${access}` })), null);
    assert.ok(await authenticateRequest(new Headers({ authorization: `Bearer ${other.access}` })), "other clients unaffected");
    const view = (await listClients()).find((c) => c.client_id === clientId);
    assert.equal(view?.status, "revoked");
    assert.deepEqual(view?.granted_scopes, []);
    assert.match(String(view?.revoked_at), /^2026-11-14T12:00:00/);
  });

  it("setClientScopes narrows live tokens immediately and validates input", async () => {
    const { clientId, access } = await connect("github.read github.write");
    const view = await setClientScopes(clientId, ["github.read"]);
    assert.deepEqual(view.granted_scopes, ["github.read"]);
    assert.deepEqual((await authenticateRequest(new Headers({ authorization: `Bearer ${access}` })))?.scopes, ["github.read"]);
    await assert.rejects(setClientScopes(clientId, ["github.admin"]), /unknown_scope/);
    await assert.rejects(setClientScopes("oc_missing", ["vault.read"]), /client_not_found/);
    await revokeClient(clientId);
    await assert.rejects(setClientScopes(clientId, ["vault.read"]), /client_not_approved/);
  });

  it("listClients exposes no secrets", async () => {
    const { access, refresh } = await connect("vault.read");
    const dump = JSON.stringify(await listClients());
    assert.ok(!dump.includes(access) && !dump.includes(refresh));
    assert.ok(!/ev[acpr]_/.test(dump));
  });
});

describe("wwwAuthenticateHeader", () => {
  it("points at the RFC 9728 protected-resource metadata", () => {
    assert.equal(
      wwwAuthenticateHeader(),
      `Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource"`,
    );
    assert.equal(
      wwwAuthenticateHeader({ error: "insufficient_scope", scope: ["github.write", "bogus"] }),
      `Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource", error="insufficient_scope", scope="github.write"`,
    );
  });

  it("degrades without leaking config when unconfigured", () => {
    configureOAuth({ env: {} });
    assert.equal(wwwAuthenticateHeader(), 'Bearer realm="echo-vault"');
  });
});

describe("localIdentity (stdio only; trust = OS process boundary)", () => {
  it("defaults to read-only scopes", () => {
    assert.deepEqual(localIdentity("Claude"), {
      client_id: "local:claude",
      name: "claude",
      kind: "local",
      scopes: [...DEFAULT_LOCAL_SCOPES],
    });
    assert.deepEqual(DEFAULT_LOCAL_SCOPES, ["github.read", "cloudflare.read", "vault.read"]);
  });

  it("reads ECHO_VAULT_LOCAL_SCOPES and drops unknown scopes", () => {
    env.ECHO_VAULT_LOCAL_SCOPES = " vault.read , github.write,root.everything ";
    assert.deepEqual(localIdentity("echo").scopes, ["github.write", "vault.read"]);
    env.ECHO_VAULT_LOCAL_SCOPES = "";
    assert.deepEqual(localIdentity("echo").scopes, [...DEFAULT_LOCAL_SCOPES]);
  });

  it("rejects unsafe names", () => {
    for (const bad of ["", " ", "../etc", "a b", "x".repeat(65), "oc_fake:thing", "-lead"]) {
      assert.throws(() => localIdentity(bad), /invalid_local_identity_name/, bad);
    }
  });
});
