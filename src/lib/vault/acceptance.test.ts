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
import { vaultList } from "./tools.ts";
import { useCredential } from "./broker.ts";
import { assertSafeDestination } from "./policy.ts";
import { handleMcpRequest } from "./mcp.ts";
import { ensureImported } from "./importer.ts";
import { getStore } from "./store.ts";
import { FORBIDDEN_TOOLS } from "./types.ts";
import type { ClientIdentity } from "./v2/contracts.ts";
import { dispatchTool, type GatewayDeps } from "./v2/gateway.ts";
import { Ledger, MemoryLedgerStore } from "./v2/ledger.ts";

/** An authenticated client as a transport would hand it to the gateway (read scopes only). */
const CLIENT: ClientIdentity = {
  client_id: "local:acceptance-test",
  name: "acceptance-test",
  kind: "local",
  scopes: ["github.read", "vault.read"],
};

/**
 * The "live" block talks to the real vault gate and to GitHub. It only runs
 * when explicitly requested AND the gate credential is present; otherwise it
 * is reported as skipped, not failed. (It used to run unconditionally, so the
 * whole file failed on any machine without production credentials.)
 */
const LIVE = process.env.ECHO_VAULT_LIVE_TESTS === "1" && Boolean(process.env.ECHO_SDK_API_KEY);

const FAKE_PAT = "github_pat_TESTONLY_LEAKPROBE_ABCDEF0123456789ZZZZ";
const FAKE_GHP = "ghp_TESTONLYLEAKPROBE0000000000000000";
const GITHUB_REF = "vault://github/echoomegaprime";

const captured: string[] = [];

function installCapture(): void {
  // Under `node --test` the child's stdout carries the runner's binary event
  // stream; rewriting those bytes as text corrupts it. Redact process output
  // only when this file runs on its own. The capture below records either way.
  if (!process.env.NODE_TEST_CONTEXT) installProcessRedaction();
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
  const ledger = new Ledger({ store: new MemoryLedgerStore() });
  const deps: GatewayDeps = { store, ledger: (input) => ledger.append(input) };

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
      CLIENT,
      deps,
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
    const result = await dispatchTool(CLIENT, "credential_health", { credential_ref: "vault://github/does-not-exist" }, deps);
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error, "credential_unavailable");
      assert.equal(result.credential_ref, "vault://github/does-not-exist");
    }
  });

  it("rejects get_secret and every other forbidden tool", async () => {
    for (const name of FORBIDDEN_TOOLS) {
      const result = await dispatchTool(CLIENT, name, {}, deps);
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.error, "tool_forbidden");
    }
    const denied = await ledger.list({ capability: "vault.secret.reveal" });
    assert.equal(denied.length, FORBIDDEN_TOOLS.length);
    assert.ok(denied.every((row) => row.result === "denied" && row.tier === 3));
  });

  it("a caller without an authenticated identity gets nothing", async () => {
    for (const bogus of [null, undefined, "claude", { client_id: "claude" }, { client_id: "", kind: "oauth", scopes: [] }]) {
      const result = await dispatchTool(bogus as never, "vault_list", {}, deps);
      assert.deepEqual(result, { ok: false, error: "unauthenticated" });
    }
  });

  it("redacts Authorization headers in serialized payloads", () => {
    const leaked = redactString(`Authorization: Bearer ${FAKE_PAT}`);
    assert.equal(leaked.includes(FAKE_PAT), false);
    assert.match(leaked, /\[REDACTED/);
  });
});

describe("live GitHub credential (sandbox import)", { skip: LIVE ? false : "set ECHO_VAULT_LIVE_TESTS=1 and ECHO_SDK_API_KEY to run against the real vault" }, () => {
  const LIVE_CLIENT: ClientIdentity = { ...CLIENT, scopes: ["github.read", "vault.read"] };
  const liveLedger = new Ledger({ store: new MemoryLedgerStore() });
  const liveDeps: GatewayDeps = { ledger: (input) => liveLedger.append(input) };

  it("2-4. health, public lookup, and private repo via real vault credential", async () => {
    await ensureImported();
    const store = getStore();
    const meta = store.getMetadata(GITHUB_REF);
    if (!meta) {
      assert.fail("sandbox GitHub credential was not imported");
    }

    const health = await dispatchTool(LIVE_CLIENT, "credential_health", { credential_ref: GITHUB_REF }, liveDeps);
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

    const repo = await dispatchTool(
      LIVE_CLIENT,
      "github_get_repository",
      { owner: "echoomegaprime", repo: "echo-continuity-fabric" },
      liveDeps,
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

});

describe("process output", () => {
  it("10. scan of this process output finds no GitHub token prefixes", () => {
    const blob = captured.join("\n");
    assertNoTokenLeak("final process scan", blob);
  });
});
