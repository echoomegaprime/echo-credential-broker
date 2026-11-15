// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { after, before, describe, it } from "node:test";
import { inspect } from "node:util";
import { FakeVaultBackend } from "../backend.ts";
import { CredentialStore } from "../store.ts";
import type { ClientIdentity } from "./contracts.ts";
import { InstallationTokenCache, type GithubAppDeps } from "./github-app.ts";
import {
  classifyContentsWrite,
  encodeContentPath,
  GITHUB_CAPABILITIES,
  githubContentsWrite,
  githubPrCreateDraft,
  githubRepoGet,
  githubRepoTransfer,
  githubResourceFor,
  isValidBranchName,
  resolveContentsWriteTarget,
  type GithubCapabilityContext,
  type GithubCapabilityResult,
} from "./github-capabilities.ts";

// ---------------------------------------------------------------------------
// Fixtures (fake vault, fake GitHub; no network)
// ---------------------------------------------------------------------------

const { privateKey: APP_KEY } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
});
const PATS: Record<string, string> = {
  echoomegaprime: "ghp_TESTONLYcapsEcho00000000000000000001",
  "ECHO-OMEGA-PRIME": "ghp_TESTONLYcapsOrg000000000000000000002",
  bobmcwilliams4: "ghp_TESTONLYcapsBob000000000000000000003",
};
const ACCOUNTS: Record<string, { id: number; type: string }> = {
  echoomegaprime: { id: 314902331, type: "User" },
  "ECHO-OMEGA-PRIME": { id: 264607697, type: "Organization" },
  bobmcwilliams4: { id: 235318155, type: "User" },
};
const ENV = {
  ECHO_VAULT_GITHUB_APP_ID_REF: "vault://github/echo-app-id",
  ECHO_VAULT_GITHUB_APP_KEY_REF: "vault://github/echo-app-key",
  ECHO_VAULT_GITHUB_INSTALLATIONS: JSON.stringify({ echoomegaprime: 111, "ECHO-OMEGA-PRIME": 222 }),
};
const CLIENT: ClientIdentity = { client_id: "oc_testclient", name: "Claude", kind: "oauth", scopes: ["github.read", "github.write"] };
const SECRETS = new Set<string>([...Object.values(PATS), APP_KEY, APP_KEY.split("\n")[2]]);
const captured: string[] = [];
const restores: Array<() => void> = [];

interface Call {
  method: string;
  path: string;
  auth: string;
  body: Record<string, unknown> | undefined;
}

interface FakeOptions {
  users?: Record<string, { login: string; id: number; type: string }>;
  denyInstallationWrites?: boolean;
  repoStatus?: number;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function fakeGithub(opts: FakeOptions = {}) {
  const calls: Call[] = [];
  const installations: Record<string, string> = { "111": "echoomegaprime", "222": "ECHO-OMEGA-PRIME" };
  let minted = 0;
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    assert.equal(url.origin, "https://api.github.com");
    const auth = new Headers(init?.headers).get("authorization") ?? "";
    const call: Call = {
      method: init?.method ?? "GET",
      path: url.pathname,
      auth,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    const bearer = auth.replace(/^Bearer /, "");
    if (bearer.startsWith("eyJ")) SECRETS.add(bearer);
    const isInstallationToken = bearer.startsWith("ghs_");
    const m = (re: RegExp) => re.exec(url.pathname);

    let r: RegExpExecArray | null;
    if ((r = m(/^\/app\/installations\/(\d+)$/))) {
      const login = installations[r[1]];
      return json(200, { id: Number(r[1]), account: { login, id: ACCOUNTS[login].id, type: ACCOUNTS[login].type } });
    }
    if ((r = m(/^\/app\/installations\/(\d+)\/access_tokens$/))) {
      minted += 1;
      const token = `ghs_TESTONLYcaps${String(minted).padStart(24, "0")}`;
      SECRETS.add(token);
      return json(201, { token, expires_at: new Date(Date.now() + 3_600_000).toISOString(), permissions: call.body?.permissions });
    }
    if (url.pathname === "/user") {
      const login = Object.keys(PATS).find((k) => PATS[k] === bearer);
      return login ? json(200, { login, id: ACCOUNTS[login].id }) : json(401, { message: "Bad credentials" });
    }
    if ((r = m(/^\/users\/([^/]+)$/))) {
      const login = decodeURIComponent(r[1]);
      const user = opts.users?.[login] ?? (ACCOUNTS[login] ? { login, ...ACCOUNTS[login] } : null);
      return user ? json(200, user) : json(404, { message: "Not Found" });
    }
    if ((r = m(/^\/repos\/([^/]+)\/([^/]+)$/)) && call.method === "GET") {
      if (opts.repoStatus) return json(opts.repoStatus, { message: "Not Found" });
      const [owner, repo] = [decodeURIComponent(r[1]), decodeURIComponent(r[2])];
      return json(200, {
        full_name: `${owner}/${repo}`,
        name: repo,
        owner: { login: owner, type: ACCOUNTS[owner]?.type ?? "User", node_id: "x" },
        private: true,
        visibility: "private",
        default_branch: "main",
        archived: false,
        html_url: `https://github.com/${owner}/${repo}`,
        description: "test repo",
        clone_url: "https://github.com/x.git",
        permissions: { admin: true },
      });
    }
    if ((r = m(/^\/repos\/([^/]+)\/([^/]+)\/transfer$/)) && call.method === "POST") {
      const owner = decodeURIComponent(r[1]);
      return json(202, {
        full_name: `${owner}/${r[2]}`,
        html_url: `https://github.com/${owner}/${r[2]}`,
        owner: { login: owner, type: ACCOUNTS[owner].type },
        node_id: "R_x",
      });
    }
    if ((r = m(/^\/repos\/([^/]+)\/([^/]+)\/contents\/(.+)$/)) && call.method === "PUT") {
      if (opts.denyInstallationWrites && isInstallationToken) return json(403, { message: "Resource not accessible by integration" });
      return json(201, {
        content: { path: decodeURIComponent(r[3]), sha: "a".repeat(40), download_url: "https://raw.githubusercontent.com/x" },
        commit: { sha: "b".repeat(40), html_url: "https://github.com/commit/b" },
      });
    }
    if ((r = m(/^\/repos\/([^/]+)\/([^/]+)\/pulls$/)) && call.method === "POST") {
      return json(201, {
        number: 7,
        html_url: "https://github.com/pull/7",
        draft: call.body?.draft,
        state: "open",
        head: { ref: call.body?.head },
        base: { ref: call.body?.base },
        user: { login: "x" },
      });
    }
    return json(404, { message: "Not Found" });
  }) as typeof fetch;
  return { calls, fetchImpl };
}

async function setup(opts: FakeOptions = {}) {
  const store = new CredentialStore(new FakeVaultBackend());
  await store.put({ provider: "github", account: "echo-app-id", type: "api_key", secret: "123456", source: "test" });
  await store.put({ provider: "github", account: "echo-app-key", type: "api_key", secret: APP_KEY, source: "test" });
  for (const [login, pat] of Object.entries(PATS)) await store.put({ provider: "github", account: login, type: "pat", secret: pat, source: "test" });
  const gh = fakeGithub(opts);
  const deps: GithubAppDeps = { store, fetch: gh.fetchImpl, env: ENV, tokenCache: new InstallationTokenCache() };
  const ctx: GithubCapabilityContext = { client: CLIENT, deps };
  return { gh, ctx };
}

const results: unknown[] = [];
function track<T extends GithubCapabilityResult>(result: T): T {
  results.push(result);
  return result;
}

function expectError(result: GithubCapabilityResult, error: string): void {
  assert.equal(result.ok, false, inspect(result));
  if (!result.ok) assert.equal(result.error, error, result.detail);
}

function assertNoSecrets(label: string, value: unknown): void {
  const blob = typeof value === "string" ? value : `${JSON.stringify(value)}\n${inspect(value, { depth: 10 })}`;
  for (const secret of SECRETS) if (blob.includes(secret)) assert.fail(`${label} leaked a secret value`);
  assert.equal(/Bearer\s+(gh|eyJ)/.test(blob), false, `${label} leaked an Authorization value`);
}

const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");

// ---------------------------------------------------------------------------

describe("github capabilities", () => {
  before(() => {
    for (const stream of [process.stdout, process.stderr]) {
      const orig = stream.write.bind(stream);
      stream.write = ((chunk: unknown, enc?: unknown, cb?: unknown) => {
        captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
        return orig(chunk as never, enc as never, cb as never);
      }) as typeof stream.write;
      restores.push(() => {
        stream.write = orig as typeof stream.write;
      });
    }
  });
  after(() => {
    for (const restore of restores) restore();
    assertNoSecrets("every capability result", results);
    assertNoSecrets("captured process output", captured.join("\n"));
  });

  it("exports exactly the four capability IDs", () => {
    assert.deepEqual(Object.keys(GITHUB_CAPABILITIES).sort(), [
      "github.contents.write",
      "github.pr.create_draft",
      "github.repo.read",
      "github.repo.transfer",
    ]);
    assert.equal(GITHUB_CAPABILITIES["github.repo.transfer"], githubRepoTransfer);
    assert.equal(Object.isFrozen(GITHUB_CAPABILITIES), true);
  });

  describe("github.repo.transfer", () => {
    it("validates owners against the registry and params strictly, before any network call", async () => {
      const { gh, ctx } = await setup();
      const base = { owner: "echoomegaprime", repo: "cleanbrees", new_owner: "ECHO-OMEGA-PRIME" };
      const cases: Array<[Record<string, unknown>, string]> = [
        [{ ...base, owner: "octocat" }, "owner_not_allowed"],
        [{ ...base, owner: "Echoomegaprime" }, "owner_not_allowed"],
        [{ ...base, new_owner: "octocat" }, "new_owner_not_allowed"],
        [{ ...base, new_owner: "echo-omega-prime" }, "new_owner_not_allowed"],
        [{ ...base, owner: "echo/../x" }, "invalid_params"],
        [{ ...base, owner: "-echo" }, "invalid_params"],
        [{ ...base, repo: "../etc" }, "invalid_params"],
        [{ ...base, repo: ".." }, "invalid_params"],
        [{ ...base, repo: "x/y" }, "invalid_params"],
        [{ ...base, repo: "cleanbrees.git" }, "invalid_params"],
        [{ ...base, new_name: "a b" }, "invalid_params"],
        [{ ...base, new_owner: "echoomegaprime" }, "invalid_params"],
        [{ ...base, team_ids: [1] }, "invalid_params"],
        [{ ...base, token: "x" }, "invalid_params"],
      ];
      for (const [params, error] of cases) expectError(track(await githubRepoTransfer(params, ctx)), error);
      assert.equal(gh.calls.length, 0);
    });

    it("POSTs {new_owner, new_name} to /repos/{owner}/{repo}/transfer on the exact-identity PAT", async () => {
      const { gh, ctx } = await setup();
      const result = track(
        await githubRepoTransfer(
          { owner: "echoomegaprime", repo: "cleanbrees", new_owner: "ECHO-OMEGA-PRIME", new_name: "cleanbrees-v2", approval_id: "ap_123" },
          ctx,
        ),
      );
      assert.equal(result.ok, true, inspect(result));
      assert.deepEqual(gh.calls.map((c) => `${c.method} ${c.path}`), [
        "GET /user",
        "GET /users/ECHO-OMEGA-PRIME",
        "POST /repos/echoomegaprime/cleanbrees/transfer",
      ]);
      const post = gh.calls[2];
      assert.deepEqual(post.body, { new_owner: "ECHO-OMEGA-PRIME", new_name: "cleanbrees-v2" });
      assert.equal(post.auth, `Bearer ${PATS.echoomegaprime}`);
      if (!result.ok) return;
      assert.deepEqual(result.data, {
        status: 202,
        accepted_for_processing: true,
        full_name: "echoomegaprime/cleanbrees",
        html_url: "https://github.com/echoomegaprime/cleanbrees",
        from: "echoomegaprime/cleanbrees",
        to: "ECHO-OMEGA-PRIME/cleanbrees-v2",
        source_owner_type: "User",
        target_owner_type: "Organization",
        requires_new_owner_acceptance: false,
        note: result.data.note,
      });
      assert.deepEqual(result.audit, {
        credential_ref: "vault://github/echoomegaprime",
        credential_path: "pat_fallback",
        fallback_reason: "transfer_requires_user_token",
        http_status: 202,
      });
    });

    it("reports that a personal → personal transfer needs the new owner to accept", async () => {
      const { gh, ctx } = await setup();
      const result = track(await githubRepoTransfer({ owner: "echoomegaprime", repo: "cleanbrees", new_owner: "bobmcwilliams4" }, ctx));
      assert.equal(result.ok, true);
      if (!result.ok) return;
      assert.equal(result.data.requires_new_owner_acceptance, true);
      assert.match(String(result.data.note), /accept within one day/);
      assert.deepEqual(gh.calls.at(-1)?.body, { new_owner: "bobmcwilliams4" });
    });

    it("refuses when the destination login no longer maps to the registry id", async () => {
      const { gh, ctx } = await setup({ users: { bobmcwilliams4: { login: "bobmcwilliams4", id: 1, type: "User" } } });
      const result = track(await githubRepoTransfer({ owner: "echoomegaprime", repo: "cleanbrees", new_owner: "bobmcwilliams4" }, ctx));
      expectError(result, "identity_mismatch");
      assert.equal(gh.calls.some((c) => c.path.endsWith("/transfer")), false);
    });
  });

  describe("github.contents.write", () => {
    const write = { owner: "echoomegaprime", repo: "cleanbrees", path: "docs/a b.md", content_base64: b64("# hello\n"), message: "docs: add" };

    it("refuses the default branch without allow_default_branch: true", async () => {
      const { gh, ctx } = await setup();
      const refused = track(await githubContentsWrite({ ...write, branch: "main" }, ctx));
      expectError(refused, "default_branch_write_refused");
      assert.equal(gh.calls.some((c) => c.method === "PUT"), false);
      expectError(track(await githubContentsWrite({ ...write, branch: "main", allow_default_branch: "true" }, ctx)), "invalid_params");

      const allowed = track(await githubContentsWrite({ ...write, branch: "main", allow_default_branch: true }, ctx));
      assert.equal(allowed.ok, true, inspect(allowed));
      if (allowed.ok) assert.equal(allowed.data.classification, "default_branch");
    });

    it("writes an agent branch with a down-scoped installation token and the right path/body", async () => {
      const { gh, ctx } = await setup();
      const result = track(await githubContentsWrite({ ...write, branch: "agent/fix-docs", sha: "c".repeat(40) }, ctx));
      assert.equal(result.ok, true, inspect(result));
      const mint = gh.calls.find((c) => c.path.endsWith("/access_tokens"));
      assert.deepEqual(mint?.body, { repositories: ["cleanbrees"], permissions: { contents: "write", metadata: "read" } });
      const put = gh.calls.find((c) => c.method === "PUT");
      assert.equal(put?.path, "/repos/echoomegaprime/cleanbrees/contents/docs/a%20b.md");
      assert.deepEqual(put?.body, { message: "docs: add", content: write.content_base64, branch: "agent/fix-docs", sha: "c".repeat(40) });
      assert.match(put?.auth ?? "", /^Bearer ghs_/);
      if (!result.ok) return;
      assert.deepEqual(result.data, {
        full_name: "echoomegaprime/cleanbrees",
        path: "docs/a b.md",
        branch: "agent/fix-docs",
        classification: "agent_branch",
        default_branch: "main",
        created: true,
        content_sha: "a".repeat(40),
        commit_sha: "b".repeat(40),
        commit_html_url: "https://github.com/commit/b",
      });
      assert.equal(result.audit.credential_path, "installation");
      assert.equal(result.audit.installation_id, 111);
      assert.equal(result.audit.credential_ref, "vault://github/echo-app-key");
    });

    it("retries once on the PAT when GitHub says the installation cannot do it", async () => {
      const { gh, ctx } = await setup({ denyInstallationWrites: true });
      const result = track(await githubContentsWrite({ ...write, branch: "agent/x" }, ctx));
      assert.equal(result.ok, true, inspect(result));
      const puts = gh.calls.filter((c) => c.method === "PUT");
      assert.equal(puts.length, 2);
      assert.match(puts[0].auth, /^Bearer ghs_/);
      assert.equal(puts[1].auth, `Bearer ${PATS.echoomegaprime}`);
      assert.equal(result.audit.credential_path, "pat_fallback");
      assert.equal(result.audit.fallback_reason, "installation_forbidden_for_operation");
    });

    it("refuses traversal, workflow files, bad branches, bad base64 and secret-bearing content offline", async () => {
      const { gh, ctx } = await setup();
      const cases: Array<[Record<string, unknown>, string]> = [
        ...["../secrets", "a/../../b", "/abs", "a//b", "a/", ".git/config", "a\\b", "%2e%2e/x", "./x", ""].map(
          (path) => [{ ...write, branch: "agent/x", path }, "invalid_params"] as [Record<string, unknown>, string],
        ),
        [{ ...write, branch: "agent/x", path: ".github/workflows/ci.yml" }, "workflow_path_refused"],
        [{ ...write, branch: "agent/x", path: ".GitHub/Workflows/ci.yml" }, "workflow_path_refused"],
        ...["main..x", "-x", "refs/heads/main", "a b", "x.lock", "a/.hidden", "x/", "a~1", "HEAD", "a@{1}"].map(
          (branch) => [{ ...write, branch }, "invalid_params"] as [Record<string, unknown>, string],
        ),
        [{ ...write, branch: "agent/x", content_base64: "not base64!" }, "invalid_params"],
        [{ ...write, branch: "agent/x", content_base64: b64(`token = ${PATS.bobmcwilliams4}`) }, "content_contains_secret"],
        [{ ...write, branch: "agent/x", content_base64: b64("-----BEGIN RSA PRIVATE KEY-----\nabc") }, "content_contains_secret"],
        [{ ...write, branch: "agent/x", message: `leak ${PATS.echoomegaprime}` }, "content_contains_secret"],
        [{ ...write, branch: "agent/x", sha: "nothex" }, "invalid_params"],
        [{ ...write, branch: "agent/x", owner: "bobmcwilliams5" }, "owner_not_allowed"],
      ];
      for (const [params, error] of cases) expectError(track(await githubContentsWrite(params, ctx)), error);
      assert.equal(gh.calls.length, 0);
    });

    it("classifyContentsWrite is a pure agent/default/other classifier", () => {
      const c = (branch: string, default_branch = "main", agent_branch_prefixes?: string[]) =>
        classifyContentsWrite({ branch, default_branch, agent_branch_prefixes });
      assert.equal(c("main"), "default_branch");
      assert.equal(c("refs/heads/main"), "default_branch");
      assert.equal(c(""), "default_branch");
      assert.equal(c("agent/fix"), "agent_branch");
      assert.equal(c("claude/session-1"), "agent_branch");
      assert.equal(c("agent/"), "other_branch");
      assert.equal(c("feature/x"), "other_branch");
      assert.equal(c("Main"), "other_branch");
      assert.equal(c("bots/x", "trunk", ["bots/"]), "agent_branch");
      assert.equal(c("agent/x", "trunk", ["bots/"]), "other_branch");
    });

    it("resolveContentsWriteTarget looks up the default branch for capability selection", async () => {
      const { ctx } = await setup();
      const target = track(await resolveContentsWriteTarget({ owner: "echoomegaprime", repo: "cleanbrees", branch: "main" }, ctx));
      assert.equal(target.ok, true);
      if (target.ok) assert.deepEqual(target.data, { classification: "default_branch", default_branch: "main" });
    });
  });

  describe("github.pr.create_draft and github.repo.read", () => {
    it("opens a draft PR against the default branch when base is omitted", async () => {
      const { gh, ctx } = await setup();
      const result = track(await githubPrCreateDraft({ owner: "ECHO-OMEGA-PRIME", repo: "cleanbrees", title: "Docs", head: "agent/docs", body: "Adds docs." }, ctx));
      assert.equal(result.ok, true, inspect(result));
      const post = gh.calls.find((c) => c.method === "POST" && c.path.endsWith("/pulls"));
      assert.equal(post?.path, "/repos/ECHO-OMEGA-PRIME/cleanbrees/pulls");
      assert.deepEqual(post?.body, { title: "Docs", head: "agent/docs", base: "main", draft: true, body: "Adds docs." });
      assert.deepEqual(gh.calls.find((c) => c.path.endsWith("/access_tokens"))?.body, {
        repositories: ["cleanbrees"],
        permissions: { pull_requests: "write", metadata: "read" },
      });
      if (result.ok) assert.deepEqual(result.data, { number: 7, html_url: "https://github.com/pull/7", draft: true, state: "open", head: "agent/docs", base: "main" });
      expectError(track(await githubPrCreateDraft({ owner: "ECHO-OMEGA-PRIME", repo: "cleanbrees", title: "x", head: "main" }, ctx)), "invalid_params");
      expectError(track(await githubPrCreateDraft({ owner: "ECHO-OMEGA-PRIME", repo: "cleanbrees", title: "x", head: "a", base: "a" }, ctx)), "invalid_params");
      expectError(track(await githubPrCreateDraft({ owner: "ECHO-OMEGA-PRIME", repo: "cleanbrees", title: PATS.bobmcwilliams4, head: "agent/x" }, ctx)), "content_contains_secret");
    });

    it("returns only safe repository fields", async () => {
      const { ctx } = await setup();
      const result = track(await githubRepoGet({ owner: "bobmcwilliams4", repo: "notes" }, ctx));
      assert.equal(result.ok, true, inspect(result));
      if (!result.ok) return;
      assert.deepEqual(Object.keys(result.data).sort(), [
        "archived", "default_branch", "description", "full_name", "html_url", "name", "owner", "owner_type", "private", "visibility",
      ]);
      assert.equal(result.audit.credential_path, "pat_fallback");
      assert.equal(result.audit.fallback_reason, "no_installation_configured");
      expectError(track(await githubRepoGet({ owner: "octocat", repo: "x" }, ctx)), "owner_not_allowed");
    });

    it("surfaces GitHub errors without secret material", async () => {
      const { ctx } = await setup({ repoStatus: 404 });
      const result = track(await githubRepoGet({ owner: "echoomegaprime", repo: "missing" }, ctx));
      expectError(result, "github_http_404");
      assert.equal(result.audit.http_status, 404);
    });

    it("requires an authenticated client identity", async () => {
      const { ctx } = await setup();
      expectError(track(await githubRepoGet({ owner: "echoomegaprime", repo: "x" }, { ...ctx, client: undefined as never })), "invalid_client");
    });
  });

  describe("helpers", () => {
    it("encodes content paths and canonical resources", () => {
      assert.equal(encodeContentPath("docs/ü n.md"), "docs/%C3%BC%20n.md");
      assert.equal(encodeContentPath("a/../b"), null);
      assert.equal(githubResourceFor({ owner: "ECHO-OMEGA-PRIME", repo: "cleanbrees" }), "github:ECHO-OMEGA-PRIME/cleanbrees");
      assert.equal(githubResourceFor({ owner: "x/..", repo: "y" }), null);
      assert.equal(isValidBranchName("agent/feature-1.2"), true);
    });
  });
});
