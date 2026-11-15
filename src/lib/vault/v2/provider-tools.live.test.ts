// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Live, opt-in, READ-ONLY checks of the provider tools against the real
 * providers, with the real credentials, through dispatchTool only.
 *
 * Every live test is SKIPPED unless all of these hold (same master gate as
 * ../acceptance.test.ts, plus one switch per provider):
 *
 *   ECHO_VAULT_LIVE_TESTS=1        master switch
 *   ECHO_SDK_API_KEY               set: the vault gate credential (never read here, only its presence)
 *   ECHO_VAULT_LIVE_<PROVIDER>=1   GITHUB | CLOUDFLARE | OPENAI | XAI | STRIPE
 *
 * Optional, none of them secret:
 *   ECHO_VAULT_LIVE_<PROVIDER>_REF        vault:// reference to use instead of the tool's default
 *   ECHO_VAULT_LIVE_CLOUDFLARE_ZONE_ID    zone to read; otherwise the first zone the credential lists
 *
 * Rules this file keeps:
 *   - Read-only. Only the tools in LIVE_TOOLS are ever dispatched, each client
 *     holds `<provider>.read` and nothing else, and every request is a GET.
 *     Nothing is created, changed, transferred, rotated or deleted.
 *   - The credential is read only by the vault's own path (the default
 *     CredentialStore, the one the tools use). The test resolves the value in
 *     process solely to assert that it appears nowhere; it is never printed,
 *     never put in an assertion message, never written anywhere.
 *   - With no opt-in the file runs to completion with zero network calls; the
 *     last test proves it.
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { redactString } from "../redaction.ts";
import { parseVaultRef } from "../refs.ts";
import { getStore } from "../store.ts";
import type { ProviderId } from "../types.ts";
import type { ClientIdentity, LedgerEntry } from "./contracts.ts";
import { dispatchTool, type GatewayDeps, type GatewayResult } from "./gateway.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";
import { lookupCapability } from "./policy-engine.ts";

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

const PROVIDER_FLAGS: Record<ProviderId, string> = {
  github: "ECHO_VAULT_LIVE_GITHUB",
  cloudflare: "ECHO_VAULT_LIVE_CLOUDFLARE",
  openai: "ECHO_VAULT_LIVE_OPENAI",
  xai: "ECHO_VAULT_LIVE_XAI",
  stripe: "ECHO_VAULT_LIVE_STRIPE",
};
const DEFAULT_REFS: Record<ProviderId, string> = {
  github: "vault://github/echoomegaprime",
  cloudflare: "vault://cloudflare/global_api_key",
  openai: "vault://openai/api_key",
  xai: "vault://xai/api_key",
  stripe: "vault://stripe/secret_key",
};

/** `false` = run; a string = skip, with the reason shown in the report. Reads flags only, never a value it would print. */
function liveSkip(provider: ProviderId, env: NodeJS.ProcessEnv = process.env): false | string {
  const flag = PROVIDER_FLAGS[provider];
  if (env.ECHO_VAULT_LIVE_TESTS !== "1") return `set ECHO_VAULT_LIVE_TESTS=1, ECHO_SDK_API_KEY and ${flag}=1 to run against the real ${provider} API`;
  if (!env.ECHO_SDK_API_KEY) return "ECHO_SDK_API_KEY is not set: the vault gate cannot be reached";
  if (env[flag] !== "1") return `set ${flag}=1 to run against the real ${provider} API`;
  return false;
}

const SKIP: Record<ProviderId, false | string> = {
  github: liveSkip("github"),
  cloudflare: liveSkip("cloudflare"),
  openai: liveSkip("openai"),
  xai: liveSkip("xai"),
  stripe: liveSkip("stripe"),
};
const ANY_LIVE = Object.values(SKIP).some((s) => s === false);

/** The only tools this file may dispatch, with the capability each maps to. All tier 0, all reads. */
const LIVE_TOOLS: Readonly<Record<string, string>> = Object.freeze({
  github_get_user: "github.user.read",
  github_list_repositories: "github.repo.list",
  cloudflare_zone_get: "cloudflare.zone.read",
  openai_account_status: "openai.account.read",
  xai_account_status: "xai.account.read",
  stripe_balance: "stripe.balance.read",
  provider_request: "<provider>.api.read",
});

// ---------------------------------------------------------------------------
// Instrumentation: count every network call, capture every log line
// ---------------------------------------------------------------------------

let fetchCalls = 0;
const fetchMethods: string[] = [];
const captured: string[] = [];
const restores: Array<() => void> = [];
/** Resolved credential values, held only to prove their absence. Never printed. */
const resolvedSecrets = new Set<string>();

before(() => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    fetchCalls += 1;
    fetchMethods.push(`${(init?.method ?? "GET").toUpperCase()} ${new URL(String(input instanceof Request ? input.url : input)).hostname}`);
    return realFetch(input, init);
  }) as typeof fetch;
  restores.push(() => {
    globalThis.fetch = realFetch;
  });
  for (const stream of [process.stdout, process.stderr]) {
    const orig = stream.write.bind(stream);
    const isErr = stream === process.stderr;
    stream.write = ((chunk: unknown, enc?: unknown, cb?: unknown) => {
      captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("latin1"));
      // stdout carries the test runner's stream; the vault logger's stderr lines stay out of the report.
      return isErr ? true : orig(chunk as never, enc as never, cb as never);
    }) as typeof stream.write;
    restores.push(() => {
      stream.write = orig as typeof stream.write;
    });
  }
});

after(() => {
  for (const restore of restores) restore();
  assertNoSecret("captured process output", captured.join("\n"));
});

/** The message is fixed text: a failure must never print what it found. */
function assertNoSecret(label: string, value: unknown): void {
  const blob = typeof value === "string" ? value : JSON.stringify(value);
  for (const secret of resolvedSecrets) {
    const forms = [secret, encodeURIComponent(secret), Buffer.from(secret, "utf8").toString("base64"), Buffer.from(`:${secret}`, "utf8").toString("base64")];
    for (const form of forms) assert.equal(blob.includes(form), false, `${label} contains a credential value`);
  }
}

// ---------------------------------------------------------------------------
// Live harness
// ---------------------------------------------------------------------------

function refFor(provider: ProviderId): string {
  const override = process.env[`${PROVIDER_FLAGS[provider]}_REF`]?.trim();
  if (!override) return DEFAULT_REFS[provider];
  const parsed = parseVaultRef(override);
  assert.ok(parsed && parsed.provider === provider, `${PROVIDER_FLAGS[provider]}_REF must be a vault://${provider}/<account> reference`);
  return parsed.raw;
}

function liveWorld(provider: ProviderId) {
  const ledgerStore = new MemoryLedgerStore();
  const ledger = new Ledger({ store: ledgerStore });
  // No `store`: the gateway uses the default CredentialStore, i.e. the real vault path the tools use in production.
  const deps: GatewayDeps = { ledger: (input) => ledger.append(input) };
  const identity: ClientIdentity = { client_id: `local:live-${provider}`, name: `live-${provider}`, kind: "local", scopes: [`${provider}.read`] };
  const ref = refFor(provider);
  const results: GatewayResult[] = [];

  const call = async (tool: string, args: Record<string, unknown>): Promise<Record<string, unknown>> => {
    assert.ok(Object.hasOwn(LIVE_TOOLS, tool), "this tool is not on the read-only live list");
    if (tool === "provider_request") assert.equal(args.method, "GET", "the live suite only sends GET");
    const result = await dispatchTool(identity, tool, args, deps);
    results.push(result);
    // Only the fixed error code is ever shown, redacted for good measure.
    if (!result.ok) assert.fail(`${tool} failed: ${redactString(String(result.error))}${typeof result.status === "number" ? ` (HTTP ${result.status})` : ""}`);
    return result.data as Record<string, unknown>;
  };

  /** After the calls: a ledger row per call, and the credential value nowhere. */
  const verify = async (expected: Array<{ capability: string; http_status?: number }>): Promise<void> => {
    const rows: LedgerEntry[] = await ledgerStore.scanAscending(0, 1000);
    assert.equal(rows.length, expected.length, "one ledger row per live call");
    rows.forEach((row, i) => {
      assert.equal(row.capability, expected[i].capability);
      assert.equal(lookupCapability(row.capability)?.access, "read");
      assert.deepEqual([row.client_id, row.decision, row.tier, row.result, row.credential_ref], [identity.client_id, "allow", 0, "ok", ref]);
      if (expected[i].http_status !== undefined) assert.equal(row.http_status, expected[i].http_status);
    });
    assert.equal((await ledger.verify()).ok, true, "ledger chain intact");

    // The same path the tool used. The value stays in this process and is only compared.
    const secret = await getStore().resolveSecret(ref);
    assert.ok(typeof secret === "string" && secret.length >= 8, "the credential could not be resolved for the negative assertion");
    resolvedSecrets.add(secret);
    assertNoSecret("tool results", results);
    assertNoSecret("ledger rows", rows);
    assertNoSecret("process output so far", captured.join("\n"));
  };

  return { call, verify, ref };
}

// ---------------------------------------------------------------------------
// Always-on checks (no network)
// ---------------------------------------------------------------------------

describe("live suite gating", () => {
  it("needs the master switch, the gate credential AND the provider's own switch", () => {
    const all = { ECHO_VAULT_LIVE_TESTS: "1", ECHO_SDK_API_KEY: "present" };
    for (const provider of Object.keys(PROVIDER_FLAGS) as ProviderId[]) {
      const flag = PROVIDER_FLAGS[provider];
      assert.equal(typeof liveSkip(provider, {}), "string");
      assert.equal(typeof liveSkip(provider, { [flag]: "1" }), "string", "a provider switch alone is not enough");
      assert.equal(typeof liveSkip(provider, { ...all }), "string", "the master switch alone is not enough");
      assert.equal(typeof liveSkip(provider, { ECHO_VAULT_LIVE_TESTS: "1", [flag]: "1" }), "string", "no gate credential, no live run");
      assert.equal(typeof liveSkip(provider, { ...all, [flag]: "true" }), "string", "only the exact value 1 opts in");
      assert.equal(typeof liveSkip(provider, { ...all, ECHO_VAULT_LIVE_TESTS: "yes", [flag]: "1" }), "string");
      assert.equal(liveSkip(provider, { ...all, [flag]: "1" }), false);
      // One provider's switch never enables another.
      for (const other of Object.keys(PROVIDER_FLAGS) as ProviderId[]) {
        if (other !== provider) assert.equal(typeof liveSkip(other, { ...all, [flag]: "1" }), "string");
      }
    }
  });

  it("the live tool list is read-only by construction", () => {
    for (const [tool, capability] of Object.entries(LIVE_TOOLS)) {
      assert.doesNotMatch(tool, /create|update|write|transfer|rotate|revoke|delete|merge|admin/, tool);
      for (const provider of Object.keys(PROVIDER_FLAGS)) {
        const spec = lookupCapability(capability.replace("<provider>", provider));
        assert.ok(spec, capability);
        assert.deepEqual([spec.tier, spec.access], [0, "read"], capability);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Live, read-only
// ---------------------------------------------------------------------------

describe("live GitHub (read-only)", () => {
  it("github_get_user returns the authenticated account", { skip: SKIP.github }, async () => {
    const w = liveWorld("github");
    const data = await w.call("github_get_user", { credential_ref: w.ref });
    assert.equal(typeof data.login, "string");
    assert.ok(Number.isInteger(data.id) && (data.id as number) > 0);
    assert.equal(data.authenticated, true);
    assert.deepEqual(Object.keys(data).sort(), ["authenticated", "id", "login"]);
    await w.verify([{ capability: "github.user.read" }]);
  });

  it("github_list_repositories lists repositories as metadata", { skip: SKIP.github }, async () => {
    const w = liveWorld("github");
    const data = await w.call("github_list_repositories", { credential_ref: w.ref, per_page: 2 });
    const repos = data.repositories as Array<Record<string, unknown>>;
    assert.ok(Array.isArray(repos) && repos.length <= 2);
    for (const repo of repos) {
      assert.match(String(repo.full_name), /^[^/\s]+\/[^/\s]+$/);
      assert.equal(typeof repo.private, "boolean");
    }
    await w.verify([{ capability: "github.repo.list" }]);
  });

  it("provider_request GET /rate_limit goes through the generic proxy", { skip: SKIP.github }, async () => {
    const w = liveWorld("github");
    const data = await w.call("provider_request", { credential_ref: w.ref, provider: "github", method: "GET", path: "/rate_limit" });
    assert.equal(data.status, 200);
    const body = data.body as { resources?: { core?: { limit?: unknown } } };
    assert.equal(typeof body.resources?.core?.limit, "number");
    await w.verify([{ capability: "github.api.read", http_status: 200 }]);
  });
});

describe("live Cloudflare (read-only)", () => {
  it("cloudflare_zone_get reads one zone", { skip: SKIP.cloudflare }, async () => {
    const w = liveWorld("cloudflare");
    const expected: Array<{ capability: string; http_status?: number }> = [];
    let zoneId = process.env.ECHO_VAULT_LIVE_CLOUDFLARE_ZONE_ID?.trim();
    if (!zoneId) {
      // Discover a zone with a read: GET /zones?per_page=1.
      const listed = await w.call("provider_request", { credential_ref: w.ref, provider: "cloudflare", method: "GET", path: "/client/v4/zones?per_page=1" });
      expected.push({ capability: "cloudflare.api.read", http_status: 200 });
      zoneId = (listed.body as { result?: Array<{ id?: string }> }).result?.[0]?.id;
      assert.ok(zoneId, "the credential lists no zone; set ECHO_VAULT_LIVE_CLOUDFLARE_ZONE_ID");
    }
    assert.match(zoneId, /^[0-9a-f]{32}$/, "a Cloudflare zone id is 32 hex characters");
    const data = await w.call("cloudflare_zone_get", { credential_ref: w.ref, zone_id: zoneId });
    expected.push({ capability: "cloudflare.zone.read", http_status: 200 });
    assert.equal(data.status, 200);
    const body = data.body as { success?: boolean; result?: { id?: string; name?: string } };
    assert.equal(body.success, true);
    assert.equal(body.result?.id, zoneId);
    assert.equal(typeof body.result?.name, "string");
    await w.verify(expected);
  });
});

for (const [provider, tool, capability] of [
  ["openai", "openai_account_status", "openai.account.read"],
  ["xai", "xai_account_status", "xai.account.read"],
] as const) {
  describe(`live ${provider} (read-only)`, () => {
    it(`${tool} lists models`, { skip: SKIP[provider] }, async () => {
      const w = liveWorld(provider);
      const data = await w.call(tool, { credential_ref: w.ref });
      assert.equal(data.status, 200);
      const body = data.body as { object?: string; data?: Array<{ id?: unknown }> };
      assert.equal(body.object, "list");
      assert.ok(Array.isArray(body.data) && body.data.length > 0);
      assert.equal(typeof body.data[0].id, "string");
      await w.verify([{ capability, http_status: 200 }]);
    });
  });
}

describe("live Stripe (read-only)", () => {
  it("stripe_balance reads the balance object", { skip: SKIP.stripe }, async () => {
    const w = liveWorld("stripe");
    const data = await w.call("stripe_balance", { credential_ref: w.ref });
    assert.equal(data.status, 200);
    const body = data.body as { object?: string; available?: unknown; livemode?: unknown };
    assert.equal(body.object, "balance");
    assert.ok(Array.isArray(body.available));
    assert.equal(typeof body.livemode, "boolean");
    await w.verify([{ capability: "stripe.balance.read", http_status: 200 }]);
  });
});

// ---------------------------------------------------------------------------
// Must stay LAST: proves the skip path (and the read-only path) after everything above ran
// ---------------------------------------------------------------------------

describe("live suite network accounting", () => {
  it("without any opt-in, this file makes no network call at all", { skip: ANY_LIVE ? "a live provider is enabled" : false }, () => {
    assert.equal(fetchCalls, 0, "a skipped live suite reached the network");
    assert.equal(getStore().count(), 0, "a skipped live suite touched the vault");
    assert.equal(resolvedSecrets.size, 0);
  });

  it("with an opt-in, every network call was a GET to a provider or a POST to the vault gate", { skip: ANY_LIVE ? false : "no live provider is enabled" }, () => {
    const gateHost = new URL(process.env.ECHO_SDK_GATE_URL || "https://forge.echo-op.com").hostname;
    for (const call of fetchMethods) {
      const [method, host] = call.split(" ");
      if (host === gateHost) assert.equal(method, "POST", "the vault gate is called with POST /sdk/invoke");
      else assert.equal(method, "GET", "a live provider request was not a GET");
    }
  });
});
