// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { after, before, describe, it } from "node:test";
import { inspect } from "node:util";
import { decodeJwt, decodeProtectedHeader, jwtVerify } from "jose";
import { FakeVaultBackend } from "../backend.ts";
import { CredentialStore } from "../store.ts";
import {
  createAppJwt,
  getGithubCredential,
  GithubCredentialError,
  InstallationTokenCache,
  TOKEN_REFRESH_BEFORE_EXPIRY_MS,
  type GithubAppDeps,
  type GithubCredentialHandle,
} from "./github-app.ts";

// ---------------------------------------------------------------------------
// Fixtures (all fake; nothing here ever reaches the network or the real vault)
// ---------------------------------------------------------------------------

const RSA = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
});
const PUBLIC_KEY = createPublicKey(RSA.publicKey);
const PEM_BODY_LINE = RSA.privateKey.split("\n")[3];
const APP_ID = "123456";
const PATS: Record<string, string> = {
  echoomegaprime: "ghp_TESTONLYechoPAT000000000000000000001",
  "ECHO-OMEGA-PRIME": "ghp_TESTONLYorgPAT0000000000000000000002",
  bobmcwilliams4: "github_pat_TESTONLY_bob_0000000000000000000003",
};
const IDS: Record<string, number> = { echoomegaprime: 314902331, "ECHO-OMEGA-PRIME": 264607697, bobmcwilliams4: 235318155 };
const ENV = {
  ECHO_VAULT_GITHUB_APP_ID_REF: "vault://github/echo-app-id",
  ECHO_VAULT_GITHUB_APP_KEY_REF: "vault://github/echo-app-key",
  ECHO_VAULT_GITHUB_INSTALLATIONS: JSON.stringify({ echoomegaprime: 111, "ECHO-OMEGA-PRIME": "222" }),
};
const START = Date.parse("2026-11-14T12:00:00.000Z");

/** Every secret value any test produced — scanned for in outputs, logs, errors. */
const SECRETS = new Set<string>([...Object.values(PATS), RSA.privateKey, PEM_BODY_LINE]);
const captured: string[] = [];
const restoreWrites: Array<() => void> = [];

function capture(stream: NodeJS.WriteStream): void {
  const orig = stream.write.bind(stream);
  stream.write = ((chunk: unknown, enc?: unknown, cb?: unknown) => {
    captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
    return orig(chunk as never, enc as never, cb as never);
  }) as typeof stream.write;
  restoreWrites.push(() => {
    stream.write = orig as typeof stream.write;
  });
}

function assertNoSecret(label: string, value: unknown): void {
  const blobs =
    typeof value === "string"
      ? [value]
      : [JSON.stringify(value) ?? "", inspect(value, { depth: 8, showHidden: true, getters: false })];
  if (value instanceof Error) blobs.push(value.message, value.stack ?? "", String((value as { detail?: string }).detail));
  for (const blob of blobs) {
    for (const secret of SECRETS) {
      if (secret.length >= 8 && blob.includes(secret)) assert.fail(`${label} leaked a secret value`);
    }
    assert.equal(/Bearer\s+(gh|eyJ)/.test(blob), false, `${label} leaked an Authorization value`);
  }
}

interface Call {
  method: string;
  path: string;
  auth: string | null;
  body: unknown;
}

interface FakeOptions {
  installationAccount?: { login: string; id: number };
  mintStatus?: number;
  user?: Record<string, { login: string; id: number }>;
  newTokenFormat?: boolean;
  extra?: (call: Call) => Response | undefined;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function makeGithub(clock: { now: number }, opts: FakeOptions = {}) {
  const calls: Call[] = [];
  const jwts: string[] = [];
  const tokens: string[] = [];
  const installations: Record<number, string> = { 111: "echoomegaprime", 222: "ECHO-OMEGA-PRIME" };
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    assert.equal(url.protocol, "https:");
    assert.equal(url.hostname, "api.github.com");
    const headers = new Headers(init?.headers);
    const call: Call = {
      method: init?.method ?? "GET",
      path: url.pathname + url.search,
      auth: headers.get("authorization"),
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    assert.equal(headers.get("x-github-api-version"), "2022-11-28");
    assert.equal(headers.get("accept"), "application/vnd.github+json");
    assert.equal(init?.redirect, "error");

    const appMatch = /^\/app\/installations\/(\d+)(\/access_tokens)?$/.exec(url.pathname);
    if (appMatch) {
      const jwt = (call.auth ?? "").replace(/^Bearer /, "");
      jwts.push(jwt);
      SECRETS.add(jwt);
      await jwtVerify(jwt, PUBLIC_KEY, { algorithms: ["RS256"], issuer: APP_ID, currentDate: new Date(clock.now) });
      const id = Number(appMatch[1]);
      const login = installations[id];
      if (!login) return json(404, { message: "Not Found" });
      if (!appMatch[2]) {
        const account = opts.installationAccount ?? { login, id: IDS[login] };
        return json(200, { id, account: { ...account, type: "User" }, suspended_at: null });
      }
      if (opts.mintStatus && opts.mintStatus !== 201) return json(opts.mintStatus, { message: "The permissions requested are not granted to this installation." });
      const n = tokens.length + 1;
      const token = opts.newTokenFormat
        ? `ghs_${APP_ID}_eyJhbGciOiJSUzI1NiJ9.eyJ0ZXN0b25seSI6${n}TESTONLYxyz.c2lnbmF0dXJlVEVTVE9OTFk${n}`
        : `ghs_TESTONLYmint${String(n).padStart(24, "0")}`;
      tokens.push(token);
      SECRETS.add(token);
      const body = (call.body ?? {}) as { permissions?: Record<string, string>; repositories?: string[] };
      return json(201, {
        token,
        expires_at: new Date(clock.now + 3_600_000).toISOString().replace(".000Z", "Z"),
        permissions: body.permissions ?? { contents: "read", metadata: "read" },
        repository_selection: body.repositories ? "selected" : "all",
      });
    }
    if (url.pathname === "/user") {
      const pat = (call.auth ?? "").replace(/^Bearer /, "");
      const login = Object.keys(PATS).find((k) => PATS[k] === pat);
      if (!login) return json(401, { message: "Bad credentials" });
      const user = opts.user?.[login] ?? { login, id: IDS[login] };
      return json(200, { ...user, type: "User" });
    }
    const extra = opts.extra?.(call);
    if (extra) return extra;
    return json(404, { message: "Not Found" });
  }) as typeof fetch;
  return { calls, jwts, tokens, fetchImpl };
}

async function makeStore(): Promise<CredentialStore> {
  const store = new CredentialStore(new FakeVaultBackend());
  await store.put({ provider: "github", account: "echo-app-id", type: "api_key", secret: APP_ID, source: "test" });
  await store.put({ provider: "github", account: "echo-app-key", type: "api_key", secret: RSA.privateKey, source: "test" });
  for (const [login, pat] of Object.entries(PATS)) {
    await store.put({ provider: "github", account: login, type: "pat", secret: pat, source: "test" });
  }
  return store;
}

async function setup(opts: FakeOptions = {}, env: Record<string, string> = ENV) {
  const clock = { now: START };
  const gh = makeGithub(clock, opts);
  const deps: GithubAppDeps = {
    store: await makeStore(),
    fetch: gh.fetchImpl,
    now: () => clock.now,
    env,
    tokenCache: new InstallationTokenCache(),
  };
  return { clock, gh, deps };
}

const ECHO = { account_login: "echoomegaprime", account_id: 314902331, purpose: "github.repo.read" };
const BOB = { account_login: "bobmcwilliams4", account_id: 235318155, purpose: "github.repo.read" };

async function rejectsWith(promise: Promise<unknown>, code: string): Promise<GithubCredentialError> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof GithubCredentialError, `expected GithubCredentialError, got ${String(error)}`);
    assert.equal(error.code, code, error.message);
    assertNoSecret(`error ${code}`, error);
    return error;
  }
  assert.fail(`expected rejection with ${code}`);
}

// ---------------------------------------------------------------------------

describe("github-app", () => {
  before(() => {
    capture(process.stdout);
    capture(process.stderr);
  });
  after(() => {
    for (const restore of restoreWrites) restore();
    assertNoSecret("captured process output", captured.join("\n"));
  });

  describe("app JWT", () => {
    it("is RS256 with iat = now-60s, exp = now+9min, iss = app id", async () => {
      const nowMs = START + 789;
      const jwt = await createAppJwt({ appId: APP_ID, privateKeyPem: RSA.privateKey, nowMs });
      SECRETS.add(jwt);
      const header = decodeProtectedHeader(jwt);
      assert.equal(header.alg, "RS256");
      const claims = decodeJwt(jwt);
      const nowS = Math.floor(nowMs / 1000);
      assert.equal(claims.iat, nowS - 60);
      assert.equal(claims.exp, nowS + 540);
      assert.ok((claims.exp as number) - nowS <= 600, "GitHub rejects exp more than 10 minutes ahead");
      assert.equal(claims.iss, APP_ID);
      await jwtVerify(jwt, PUBLIC_KEY, { algorithms: ["RS256"], currentDate: new Date(nowMs) });
    });

    it("accepts PKCS#8 and \\n-escaped PEMs, rejects non-RSA keys and bad app ids", async () => {
      const pkcs8 = createPublicKey(RSA.publicKey) && generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" }).toString();
      await createAppJwt({ appId: "Iv23liTESTONLY", privateKeyPem: pkcs8, nowMs: START });
      await createAppJwt({ appId: APP_ID, privateKeyPem: RSA.privateKey.replace(/\n/g, "\\n"), nowMs: START });
      const ed = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
      await assert.rejects(createAppJwt({ appId: APP_ID, privateKeyPem: ed, nowMs: START }), /app_private_key_not_rsa/);
      await assert.rejects(createAppJwt({ appId: "12; drop", privateKeyPem: RSA.privateKey, nowMs: START }), /app_id_invalid/);
    });

    it("is what the broker sends to GitHub when minting", async () => {
      const { clock, gh, deps } = await setup();
      await getGithubCredential(ECHO, deps);
      assert.equal(gh.jwts.length, 2, "installation lookup + token mint");
      const claims = decodeJwt(gh.jwts[1]);
      assert.equal(claims.iat, Math.floor(clock.now / 1000) - 60);
      assert.equal(claims.exp, Math.floor(clock.now / 1000) + 540);
      assert.equal(claims.iss, APP_ID);
    });
  });

  describe("installation tokens", () => {
    it("verifies the installation account, forwards down-scoping, and injects the token only inside use()", async () => {
      const { gh, deps } = await setup({
        extra: (call) => (call.path === "/repos/echoomegaprime/cleanbrees" ? json(200, { full_name: "echoomegaprime/cleanbrees", private: true }) : undefined),
      });
      const handle = await getGithubCredential(
        { ...ECHO, repositories: ["cleanbrees", "alpha", "cleanbrees"], repository_ids: [9, 3], permissions: { contents: "write", metadata: "read" } },
        deps,
      );
      assert.equal(handle.kind, "installation");
      assert.equal(handle.path, "installation");
      assert.equal(handle.installation_id, 111);
      assert.equal(handle.credential_ref, "vault://github/echo-app-key");
      assert.equal(handle.expires_at, new Date(START + 3_600_000).toISOString());
      assert.deepEqual(handle.permissions, { contents: "write", metadata: "read" });
      assert.equal(handle.repository_selection, "selected");
      assert.equal(handle.fallback_reason, undefined);

      const mint = gh.calls.find((c) => c.method === "POST");
      assert.equal(mint?.path, "/app/installations/111/access_tokens");
      assert.deepEqual(mint?.body, { repositories: ["alpha", "cleanbrees"], repository_ids: [3, 9], permissions: { contents: "write", metadata: "read" } });
      assert.equal(gh.calls[0].path, "/app/installations/111");

      const repo = await handle.use(async (api) => {
        const res = await api.request("GET", "/repos/echoomegaprime/cleanbrees");
        return { status: res.status, full_name: (res.json as { full_name: string }).full_name };
      });
      assert.deepEqual(repo, { status: 200, full_name: "echoomegaprime/cleanbrees" });
      assert.equal(gh.calls.at(-1)?.auth, `Bearer ${gh.tokens[0]}`);
      assertNoSecret("handle", handle);
      assertNoSecret("use() result", repo);
    });

    it("omits scope fields that were not requested", async () => {
      const { gh, deps } = await setup();
      await getGithubCredential(ECHO, deps);
      assert.deepEqual(gh.calls.find((c) => c.method === "POST")?.body, {});
    });

    it("caches per scope in memory and refreshes 5 minutes before expiry", async () => {
      const { clock, gh, deps } = await setup();
      const mints = () => gh.calls.filter((c) => c.method === "POST").length;
      const scoped = { ...ECHO, repositories: ["cleanbrees"] };
      const first = await getGithubCredential(scoped, deps);
      assert.equal(first.cached, false);
      const second = await getGithubCredential({ ...scoped, purpose: "github.contents.write" }, deps);
      assert.equal(second.cached, true);
      assert.equal(mints(), 1);
      await getGithubCredential({ ...ECHO, repositories: ["other"] }, deps);
      assert.equal(mints(), 2, "a different scope gets its own token");

      clock.now = START + 3_600_000 - TOKEN_REFRESH_BEFORE_EXPIRY_MS - 1000;
      assert.equal((await getGithubCredential(scoped, deps)).cached, true);
      assert.equal(mints(), 2);
      clock.now = START + 3_600_000 - TOKEN_REFRESH_BEFORE_EXPIRY_MS;
      const refreshed = await getGithubCredential(scoped, deps);
      assert.equal(refreshed.cached, false);
      assert.equal(mints(), 3);
      assert.equal(refreshed.expires_at, new Date(clock.now + 3_600_000).toISOString());

      assertNoSecret("cache", deps.tokenCache);
      assert.equal(inspect(deps.tokenCache), `InstallationTokenCache { size: ${deps.tokenCache?.size} }`);
    });

    it("dedupes concurrent mints for the same scope", async () => {
      const { gh, deps } = await setup();
      const handles = await Promise.all(Array.from({ length: 5 }, () => getGithubCredential(ECHO, deps)));
      assert.equal(gh.calls.filter((c) => c.method === "POST").length, 1);
      assert.ok(handles.every((h) => h.kind === "installation"));
    });

    it("refuses use() once the token is about to expire", async () => {
      const { clock, deps } = await setup();
      const handle = await getGithubCredential(ECHO, deps);
      clock.now = START + 3_600_000 - 10_000;
      await rejectsWith(handle.use(() => "x"), "credential_expired");
    });

    it("fails closed — no PAT fallback — when the installation belongs to another account", async () => {
      const { gh, deps } = await setup({ installationAccount: { login: "echoomegaprime", id: 1 } });
      await rejectsWith(getGithubCredential(ECHO, deps), "identity_mismatch");
      assert.equal(gh.calls.some((c) => c.method === "POST" || c.path === "/user"), false);
      const other = await setup({ installationAccount: { login: "EchoOmegaPrime", id: 314902331 } });
      await rejectsWith(getGithubCredential(ECHO, other.deps), "identity_mismatch");
    });

    it("treats GitHub 5xx as unavailable, not as a reason to use the PAT", async () => {
      const { gh, deps } = await setup({ mintStatus: 502 });
      await rejectsWith(getGithubCredential(ECHO, deps), "github_unavailable");
      assert.equal(gh.calls.some((c) => c.path === "/user"), false);
    });
  });

  describe("PAT fallback", () => {
    it("uses vault://github/<login> after GET /user matches login AND id exactly", async () => {
      const { gh, deps } = await setup({
        extra: (call) => (call.path === "/repos/bobmcwilliams4/x" ? json(200, { full_name: "bobmcwilliams4/x" }) : undefined),
      });
      const handle = await getGithubCredential(BOB, deps);
      assert.equal(handle.kind, "pat");
      assert.equal(handle.path, "pat_fallback");
      assert.equal(handle.fallback_reason, "no_installation_configured");
      assert.equal(handle.credential_ref, "vault://github/bobmcwilliams4");
      assert.equal(handle.pat_kind, "fine_grained");
      assert.equal(handle.expires_at, undefined);
      assert.deepEqual(gh.calls.map((c) => c.path), ["/user"]);
      assert.equal(gh.calls[0].auth, `Bearer ${PATS.bobmcwilliams4}`);
      const out = await handle.use((api) => api.request("GET", "/repos/bobmcwilliams4/x"));
      assert.equal((out.json as { full_name: string }).full_name, "bobmcwilliams4/x");
      assertNoSecret("pat handle", handle);
      assertNoSecret("pat use()", out);
    });

    it("fails closed on an id mismatch or a login that differs only in case", async () => {
      const a = await setup({ user: { bobmcwilliams4: { login: "bobmcwilliams4", id: 1 } } });
      await rejectsWith(getGithubCredential(BOB, a.deps), "identity_mismatch");
      const b = await setup({ user: { bobmcwilliams4: { login: "BobMcWilliams4", id: 235318155 } } });
      await rejectsWith(getGithubCredential(BOB, b.deps), "identity_mismatch");
      assert.deepEqual(b.gh.calls.map((c) => c.path), ["/user"], "nothing runs after a mismatch");
    });

    it("falls back when GitHub refuses the down-scoped installation token (422)", async () => {
      const { deps } = await setup({ mintStatus: 422 });
      const handle = await getGithubCredential({ ...ECHO, permissions: { administration: "write" } }, deps);
      assert.equal(handle.path, "pat_fallback");
      assert.equal(handle.fallback_reason, "installation_token_denied_http_422");
      assert.equal(handle.pat_kind, "classic");
    });

    it("records why the installation path was skipped", async () => {
      const unconfigured = await setup({}, { ECHO_VAULT_GITHUB_INSTALLATIONS: ENV.ECHO_VAULT_GITHUB_INSTALLATIONS });
      assert.equal((await getGithubCredential(ECHO, unconfigured.deps)).fallback_reason, "app_not_configured");
      const garbled = await setup({}, { ...ENV, ECHO_VAULT_GITHUB_INSTALLATIONS: "{nope" });
      assert.equal((await getGithubCredential(ECHO, garbled.deps)).fallback_reason, "installations_config_invalid");
      const forced = await setup();
      const handle = await getGithubCredential({ ...ECHO, installation_unsupported_reason: "transfer_requires_user_token" }, forced.deps);
      assert.equal(handle.fallback_reason, "transfer_requires_user_token");
      assert.equal(forced.gh.calls.some((c) => c.path.startsWith("/app/")), false);
      const orgViaStringId = await setup();
      const org = await getGithubCredential({ account_login: "ECHO-OMEGA-PRIME", account_id: 264607697, purpose: "p" }, orgViaStringId.deps);
      assert.equal(org.installation_id, 222);
    });

    it("rejects a missing PAT and a PAT GitHub does not accept", async () => {
      const { deps } = await setup();
      const empty = new CredentialStore(new FakeVaultBackend());
      await rejectsWith(getGithubCredential(BOB, { ...deps, store: empty }), "credential_unavailable");
      const wrong = new CredentialStore(new FakeVaultBackend());
      await wrong.put({ provider: "github", account: "bobmcwilliams4", type: "pat", secret: "ghp_TESTONLYrevoked00000000000000000000", source: "test" });
      SECRETS.add("ghp_TESTONLYrevoked00000000000000000000");
      await rejectsWith(getGithubCredential(BOB, { ...deps, store: wrong }), "credential_unavailable");
    });
  });

  describe("exact registry", () => {
    it("refuses unknown accounts, case variants, and mismatched ids before any network call", async () => {
      const { gh, deps } = await setup();
      await rejectsWith(getGithubCredential({ ...ECHO, account_login: "octocat" }, deps), "unknown_account");
      await rejectsWith(getGithubCredential({ ...ECHO, account_login: "EchoOmegaPrime" }, deps), "unknown_account");
      await rejectsWith(getGithubCredential({ ...ECHO, account_id: 264607697 }, deps), "identity_mismatch");
      await rejectsWith(getGithubCredential({ ...ECHO, repositories: ["../etc"] }, deps), "invalid_request");
      await rejectsWith(getGithubCredential({ ...ECHO, permissions: { contents: "owner" as never } }, deps), "invalid_request");
      await rejectsWith(getGithubCredential({ ...ECHO, repositories: Array.from({ length: 501 }, (_, i) => `r${i}`) }, deps), "invalid_request");
      assert.equal(gh.calls.length, 0);
    });
  });

  describe("token never escapes", () => {
    for (const newTokenFormat of [false, true]) {
      it(`scrubs echoed tokens, invalidates the requester, and keeps handles opaque (${newTokenFormat ? "ghs_APPID_JWT" : "classic ghs_"} format)`, async () => {
        let current = "";
        const { gh, deps } = await setup({
          newTokenFormat,
          extra: (call) => {
            current = (call.auth ?? "").replace(/^Bearer /, "");
            if (call.path === "/echo-json") return json(200, { leaked: current, nested: { header: `Authorization: Bearer ${current}` } });
            if (call.path === "/echo-text") return new Response(`token=${current} plain`, { status: 200, headers: { "content-type": "text/plain" } });
            return undefined;
          },
        });
        const handle: GithubCredentialHandle = await getGithubCredential(ECHO, deps);
        const token = gh.tokens[0];
        assert.ok(token && SECRETS.has(token));

        const echoed = await handle.use(async (api) => [await api.request("GET", "/echo-json"), await api.request("POST", "/echo-text", { body: { a: 1 } })]);
        assert.equal(current, token, "the fake transport did receive the token");
        assertNoSecret("echoed responses", echoed);

        let stash: { request: (m: "GET", p: string) => Promise<unknown> } | undefined;
        const returnedRequester = await handle.use((api) => {
          stash = api;
          return api;
        });
        assert.equal(JSON.stringify(returnedRequester), "{}");
        await rejectsWith(stash!.request("GET", "/echo-json") as Promise<unknown>, "requester_inactive");

        // Simulates hostile in-process code that can see the transport (the documented limit):
        // even then, use() refuses to return the value.
        await rejectsWith(handle.use(async (api) => {
          await api.request("GET", "/echo-json");
          return { smuggled: [current] };
        }), "token_escape_blocked");

        const failing = await setup({ newTokenFormat });
        const failingHandle = await getGithubCredential(ECHO, failing.deps);
        const failingToken = failing.gh.tokens[0];
        const throwingDeps = {
          ...failing.deps,
          fetch: (async () => {
            throw new Error(`connect ECONNRESET while sending Authorization: Bearer ${failingToken}`);
          }) as typeof fetch,
        };
        const refetched = await getGithubCredential(ECHO, throwingDeps); // cached → no network
        await rejectsWith(refetched.use((api) => api.request("GET", "/x")), "github_unavailable");
        await rejectsWith(failingHandle.use(() => {
          throw new Error(`callback failed near ${"x".repeat(3)}`);
        }).catch((e: Error) => {
          throw new GithubCredentialError("invalid_request", e.message);
        }), "invalid_request");

        for (const view of [handle, handle.metadata(), handle.toJSON(), Object.values(handle), inspect(handle, { showHidden: true })]) {
          assertNoSecret("handle view", view);
        }
        assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(handle))).sort(), Object.keys(handle.metadata()).sort());
      });
    }

    it("only ever talks to api.github.com with an allowlisted method", async () => {
      const { deps } = await setup();
      const handle = await getGithubCredential(ECHO, deps);
      for (const path of ["https://evil.example/steal", "//evil.example/x", "/repos/../../etc", "repos/x"]) {
        await rejectsWith(handle.use((api) => api.request("GET", path)), "invalid_request");
      }
      await rejectsWith(handle.use((api) => api.request("TRACE" as "GET", "/user")), "invalid_request");
    });
  });
});
