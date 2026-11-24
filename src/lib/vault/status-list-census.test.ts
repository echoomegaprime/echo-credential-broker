import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import { FakeVaultBackend } from "./backend.ts";
import { ensureImported, resetImportForTests } from "./importer.ts";
import { CredentialStore } from "./store.ts";
import { vaultList, vaultMetadata, vaultStatus } from "./tools.ts";
import type { CredentialMetadata } from "./types.ts";

/**
 * Regression tests for the 2026-11-24 defect: after a broker restart,
 * vault_status reported credential_count 0 and vault_list [] while
 * vault_find located every credential in Vault A. Cause: status/list read
 * only the process-local metadata cache, populated solely by that process's
 * own put() calls and a one-shot memoized locate() of five hardcoded
 * default refs whose exact coordinates Vault A does not use.
 *
 * These tests seed the backend DIRECTLY (simulating credentials that
 * already live in Vault A under non-default coordinates) and exercise a
 * FRESH CredentialStore — zero broker put() calls — then require
 * status/list/metadata to agree with find.
 */
const SEED: Array<{ service: string; username: string }> = [
  { service: "github", username: "ECHO_OMEGA_PRIME_PAT" },
  { service: "github", username: "GITHUB_PAT" },
  { service: "cloudflare", username: "api_token" },
  { service: "openai", username: "OPENAI_API_KEY" },
  { service: "stripe", username: "STRIPE_SECRET_KEY" },
  { service: "xai", username: "XAI_API_KEY" },
];

async function seededBackend(): Promise<FakeVaultBackend> {
  const backend = new FakeVaultBackend();
  for (const { service, username } of SEED) {
    await backend.put(service, username, `test-secret-${service}-${username}`, "test", "test");
  }
  return backend;
}

const seedRefs = SEED.map(({ service, username }) => `vault://${service}/${username}`).sort();

describe("vault_status / vault_list census (cold start, zero put calls)", () => {
  beforeEach(() => {
    resetImportForTests();
  });

  it("status count and imported refs match what the vault actually holds", async () => {
    const store = new CredentialStore(await seededBackend());
    assert.equal(store.count(), 0, "fresh store cache must start empty — that was the defect setup");

    const result = await vaultStatus({ caller: "census-test", store });
    assert.equal(result.ok, true);
    if (!result.ok) return;
    const data = result.data as { credential_count: number; imported: string[] };
    assert.equal(data.credential_count, SEED.length);
    assert.deepEqual([...data.imported].sort(), seedRefs);
  });

  it("list agrees with find for every provider", async () => {
    const store = new CredentialStore(await seededBackend());

    const result = await vaultList({ caller: "census-test", store });
    assert.equal(result.ok, true);
    if (!result.ok) return;
    const creds = (result.data as { credentials: CredentialMetadata[] }).credentials;
    assert.deepEqual(creds.map((c) => c.ref).sort(), seedRefs);

    for (const provider of ["github", "cloudflare", "openai", "stripe", "xai"] as const) {
      const found = await store.find(provider);
      const expected = found.candidates.map((c) => `vault://${provider}/${c.username}`).sort();
      const listed = creds.filter((c) => c.provider === provider).map((c) => c.ref).sort();
      assert.deepEqual(listed, expected, `list/find disagree for ${provider}`);
    }
  });

  it("census-registered refs resolve: has() is true and metadata carries the vault coordinate", async () => {
    const store = new CredentialStore(await seededBackend());
    await store.syncFromVault({ force: true });
    for (const ref of seedRefs) {
      assert.equal(await store.has(ref), true, `${ref} should be usable after census`);
    }
    const meta = store.getMetadata("vault://github/ECHO_OMEGA_PRIME_PAT");
    assert.equal(meta?.source, "vault:github/ECHO_OMEGA_PRIME_PAT");
  });

  it("census never overwrites a record this process put() itself", async () => {
    const backend = await seededBackend();
    const store = new CredentialStore(backend);
    await store.put({
      provider: "github",
      account: "echoomegaprime",
      type: "pat",
      secret: "test-secret-put",
      source: "test:put",
    });
    await store.syncFromVault({ force: true });
    const meta = store.getMetadata("vault://github/echoomegaprime");
    assert.equal(meta?.type, "pat");
    assert.equal(meta?.source, "test:put");
    assert.equal(store.count(), SEED.length + 1);
  });
});

describe("vault_metadata discover-on-miss", () => {
  it("locates a ref the process has never cached instead of reporting it unavailable", async () => {
    const store = new CredentialStore(await seededBackend());
    assert.equal(store.getMetadata("vault://openai/OPENAI_API_KEY"), null, "precondition: not cached");

    const result = await vaultMetadata({ caller: "census-test", store }, "vault://openai/OPENAI_API_KEY");
    assert.equal(result.ok, true);
    if (!result.ok) return;
    const meta = result.data as CredentialMetadata;
    assert.equal(meta.provider, "openai");
    assert.equal(meta.account, "OPENAI_API_KEY");
    // …and the miss repopulated the cache.
    assert.equal(store.getMetadata("vault://openai/OPENAI_API_KEY")?.account, "OPENAI_API_KEY");
  });

  it("still fails closed for a ref the vault does not hold", async () => {
    const store = new CredentialStore(await seededBackend());
    const result = await vaultMetadata({ caller: "census-test", store }, "vault://openai/NO_SUCH_KEY");
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.error, "credential_unavailable");
  });
});

describe("ensureImported is retryable, not memoized-once", () => {
  beforeEach(() => {
    resetImportForTests();
  });

  it("an empty sweep does not latch — a later call finds credentials seeded afterwards", async () => {
    const backend = new FakeVaultBackend();
    const store = new CredentialStore(backend);

    const first = await ensureImported(store);
    assert.deepEqual(first.imported, [], "empty vault must report empty");

    for (const { service, username } of SEED) {
      await backend.put(service, username, `test-secret-${service}-${username}`, "test", "test");
    }
    const second = await ensureImported(store);
    assert.deepEqual([...second.imported].sort(), seedRefs);
    assert.equal(store.count(), SEED.length);
  });
});
