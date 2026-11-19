// library-first: echo.functions.search → no existing impl found (2026-11-19)
/**
 * Bulk import. Everything is in memory: stores, the vault backend and the
 * ledger. No network, no real vault, no real credential — fake secrets are
 * assembled at runtime so no token-shaped literal sits in the repo.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { fingerprint, locateSecret, scanText } from "../../../../scripts/credential-scan.mjs";
import { DeletableFakeVaultBackend, FakeVaultBackend } from "../backend.ts";
import { MemoryCardStore, MemoryEntryStore, secretFingerprint, useEntry, type EntryStore } from "./cards.ts";
import type { ClientIdentity, LedgerEntryInput } from "./contracts.ts";
import { applyImport, planImport, type PlannedEntry, type ScanFinding, type ScanManifest } from "./import.ts";

const KEY = Buffer.alloc(32, 9);
const SECRETS = {
  google: "AIza" + "Sy" + "B1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R",
  github: "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3lM6",
  github2: "ghp_" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9Oo8",
  generic: "v9Kq2Lx7Rm4Tn8Wz1Yb5Cd3Fg6Hj0",
  genericUnknown: "p4Zx8Qw2Er6Ty0Ui3Op7As1Df5Gh9",
};

/** A tiny on-disk world: path → file text. */
const FILES: Record<string, string> = {
  "/srv/app/.env": [`YOUTUBE_API_KEY=${SECRETS.google}`, `GITHUB_TOKEN=${SECRETS.github}`, "PORT=8080"].join("\n"),
  "/srv/other/.env": [`GH=${SECRETS.github}`, `token ${SECRETS.github2}`].join("\n"),
  "/srv/keys/id_rsa": `-----BEGIN ${"OPENSSH"} PRIVATE KEY-----`,
  "/srv/misc/.env": [`TWILIO_AUTH_TOKEN="${SECRETS.generic}"`, `MYSTERY_API_KEY="${SECRETS.genericUnknown}"`].join("\n"),
};

function manifestOf(files: Record<string, string> = FILES): ScanManifest {
  const findings: ScanFinding[] = [];
  for (const [path, text] of Object.entries(files)) {
    for (const f of scanText(text, KEY)) findings.push({ path, file: path.split("/").pop(), ...f } as ScanFinding);
  }
  return { scanner: "echo-vault-credential-scan", node: "testnode", contains_secret_values: false, findings };
}

function resolverOf(files: Record<string, string> = FILES) {
  return async (entry: PlannedEntry): Promise<string | null> => {
    for (const src of entry.sources) {
      const line = files[src.path]?.split(/\r?\n/)[src.line - 1];
      if (typeof line !== "string") continue;
      const value = locateSecret(line, { detector: src.detector, fingerprint: entry.scan_fingerprint }, KEY);
      if (value) return value;
    }
    return null;
  };
}

function world(backend: FakeVaultBackend = new FakeVaultBackend(), entries: EntryStore = new MemoryEntryStore()) {
  const ledger: LedgerEntryInput[] = [];
  const deps = {
    entries,
    cards: new MemoryCardStore(),
    backend,
    ledger: async (input: LedgerEntryInput) => {
      ledger.push(JSON.parse(JSON.stringify(input)));
    },
    env: {} as NodeJS.ProcessEnv,
    now: () => Date.parse("2026-11-19T04:00:00.000Z"),
  };
  return { deps, ledger, backend, entries };
}

const noSecrets = (value: unknown) => {
  const text = JSON.stringify(value);
  for (const s of Object.values(SECRETS)) assert.ok(!text.includes(s), "a secret value leaked");
};

describe("credential-scan: reading a finding back", () => {
  it("names the variable a provider token was assigned to", () => {
    const [f] = scanText(`YOUTUBE_API_KEY=${SECRETS.google}`, KEY);
    assert.equal(f.detector, "google_api_key");
    assert.equal(f.key_name, "YOUTUBE_API_KEY");
  });

  it("locateSecret returns the value only for the matching fingerprint", () => {
    const line = `GITHUB_TOKEN=${SECRETS.github}`;
    const [f] = scanText(line, KEY);
    assert.equal(locateSecret(line, f, KEY), SECRETS.github);
    assert.equal(locateSecret(`GITHUB_TOKEN=${SECRETS.github2}`, f, KEY), null, "a changed line must not import a different secret");
    assert.equal(locateSecret(line, f, Buffer.alloc(32, 1)), null, "another node's key must not match");
    assert.equal(locateSecret(line, { detector: "private_key_pem", fingerprint: null }, KEY), null);
    const g = `X_API_KEY="${SECRETS.generic}"`;
    assert.equal(locateSecret(g, scanText(g, KEY)[0], KEY), SECRETS.generic);
  });
});

describe("vault import: planning", () => {
  it("plans one entry per distinct secret and never holds a value", () => {
    const plan = planImport(manifestOf());
    noSecrets(plan);
    assert.deepEqual(
      plan.entries.map((e) => `${e.site}/${e.account}`),
      ["github.com/github_token", `github.com/imported-${fingerprint(SECRETS.github2, KEY).slice(0, 8)}`, "google.com/youtube_api_key"],
    );
    const gh = plan.entries.find((e) => e.account === "github_token");
    assert.equal(gh?.sources.length, 2, "the same token in two files is one entry with two sources");
    assert.equal(gh?.kind, "api_key");
    assert.match(gh?.purpose ?? "", /^import testnode\/\.env$/);
    assert.equal(plan.node, "testnode");
  });

  it("skips what cannot be an entry and says why", () => {
    const plan = planImport(manifestOf());
    const reasons = Object.fromEntries(plan.skipped.map((s) => [`${s.path}:${s.line}`, s.reason]));
    assert.equal(reasons["/srv/keys/id_rsa:1"], "private_key_file");
    assert.equal(reasons["/srv/misc/.env:1"], "generic_not_requested");
    assert.equal(reasons["/srv/misc/.env:2"], "generic_not_requested");
  });

  it("imports generic assignments only when asked, and only for a recognised service", () => {
    const plan = planImport(manifestOf(), { includeGeneric: true });
    assert.ok(plan.entries.some((e) => e.site === "twilio.com" && e.account === "twilio_auth_token"));
    assert.ok(!plan.entries.some((e) => e.account === "mystery_api_key"));
    assert.equal(plan.skipped.find((s) => s.key_name === "MYSTERY_API_KEY")?.reason, "unknown_provider");
  });

  it("can be limited to named sites", () => {
    const plan = planImport(manifestOf(), { onlySites: ["https://www.Google.com/"] });
    assert.deepEqual(plan.entries.map((e) => e.site), ["google.com"]);
    assert.ok(plan.skipped.some((s) => s.reason === "provider_not_selected"));
  });

  it("is deterministic, and refuses a manifest that might hold values", () => {
    assert.deepEqual(planImport(manifestOf()), planImport(manifestOf()));
    assert.throws(() => planImport({ findings: [] } as ScanManifest), /reference-only/);
    assert.throws(() => planImport({ contains_secret_values: true, findings: [] } as ScanManifest), /reference-only/);
  });
});

describe("vault import: applying", () => {
  it("a dry run reads the sources and writes nothing", async () => {
    const w = world();
    const res = await applyImport(planImport(manifestOf()), { ...w.deps, resolveSecret: resolverOf(), dryRun: true });
    noSecrets(res);
    assert.equal(res.dry_run, true);
    assert.equal(res.counts.would_import, 3);
    assert.equal((await w.entries.list({})).length, 0);
    assert.equal(w.ledger.length, 0);
  });

  it("stores each secret, records the entry and writes a ledger row without the value", async () => {
    const w = world();
    const res = await applyImport(planImport(manifestOf()), { ...w.deps, resolveSecret: resolverOf(), actor: "local:import@testnode" });
    noSecrets(res);
    noSecrets(w.ledger);
    assert.equal(res.counts.imported, 3);
    const entries = await w.entries.list({});
    noSecrets(entries);
    assert.equal(entries.length, 3);
    const yt = entries.find((e) => e.account === "youtube_api_key");
    assert.ok(yt);
    assert.equal(yt.site, "google.com");
    assert.equal(yt.status, "active");
    assert.equal(yt.fingerprint, secretFingerprint(SECRETS.google));
    assert.equal(yt.secret_length, SECRETS.google.length);
    assert.equal(w.ledger.length, 3);
    for (const row of w.ledger) {
      assert.equal(row.capability, "vault.entry.import");
      assert.equal(row.client_id, "local:import@testnode");
      assert.equal(row.result, "ok");
      assert.match(row.credential_ref ?? "", /^vault:\/\/entry\/ve_[0-9a-f]{32}$/);
    }
    // The stored secret is the real one: an entry use receives it.
    const client: ClientIdentity = { client_id: "oc_claude_test", name: "Claude", kind: "oauth", scopes: [] };
    const used = await useEntry(yt.id, client, "check the imported value", (secret) => secret === SECRETS.google, w.deps);
    assert.equal(used.result, true);
  });

  it("is idempotent: a second run imports nothing", async () => {
    const w = world();
    const plan = planImport(manifestOf());
    await applyImport(plan, { ...w.deps, resolveSecret: resolverOf() });
    const again = await applyImport(plan, { ...w.deps, resolveSecret: resolverOf() });
    assert.equal(again.counts.imported, 0);
    assert.equal(again.counts.exists, 3);
    assert.equal((await w.entries.list({})).length, 3);
    assert.equal(w.ledger.length, 3);
  });

  it("does not store the same secret twice under another account", async () => {
    const w = world();
    await applyImport(planImport(manifestOf({ "/a/.env": `GITHUB_TOKEN=${SECRETS.github}` })), { ...w.deps, resolveSecret: resolverOf({ "/a/.env": `GITHUB_TOKEN=${SECRETS.github}` }) });
    const files = { "/b/.env": `OTHER_NAME=${SECRETS.github}` };
    const res = await applyImport(planImport(manifestOf(files)), { ...w.deps, resolveSecret: resolverOf(files) });
    assert.equal(res.counts.already_stored, 1);
    assert.equal((await w.entries.list({})).length, 1);
  });

  it("an account name already taken by a different secret does not swallow the credential", async () => {
    const w = world();
    const first = { "/a/.env": `GITHUB_TOKEN=${SECRETS.github}` };
    await applyImport(planImport(manifestOf(first)), { ...w.deps, resolveSecret: resolverOf(first) });
    // Another node, same variable name, a different token.
    const second = { "/b/.env": `GITHUB_TOKEN=${SECRETS.github2}` };
    const res = await applyImport(planImport(manifestOf(second)), { ...w.deps, resolveSecret: resolverOf(second) });
    assert.equal(res.counts.imported, 1);
    assert.equal(res.counts.exists, 0);
    const accounts = (await w.entries.list({ site: "github.com" })).map((e) => e.account).sort();
    assert.deepEqual(accounts, ["github_token", `github_token-${fingerprint(SECRETS.github2, KEY).slice(0, 8)}`]);
    // And running that second import again is a no-op.
    const again = await applyImport(planImport(manifestOf(second)), { ...w.deps, resolveSecret: resolverOf(second) });
    assert.equal(again.counts.exists, 1);
    assert.equal(again.counts.imported, 0);
    assert.equal((await w.entries.list({})).length, 2);
  });

  it("a fingerprint collision is not treated as the same secret", async () => {
    // Force every entry of the site to share the short fingerprint, as a 32-bit collision would.
    class CollidingStore extends MemoryEntryStore {
      override async insert(row: Parameters<MemoryEntryStore["insert"]>[0]) {
        return super.insert({ ...row, fingerprint: "00000000" });
      }
      override async list(filter: Parameters<MemoryEntryStore["list"]>[0]) {
        return (await super.list(filter)).map((e) => ({ ...e, fingerprint: secretFingerprint(SECRETS.github2) }));
      }
    }
    const w = world(new FakeVaultBackend(), new CollidingStore());
    const first = { "/a/.env": `GITHUB_TOKEN=${SECRETS.github}` };
    await applyImport(planImport(manifestOf(first)), { ...w.deps, resolveSecret: resolverOf(first) });
    const second = { "/b/.env": `SECOND_TOKEN=${SECRETS.github2}` };
    const res = await applyImport(planImport(manifestOf(second)), { ...w.deps, resolveSecret: resolverOf(second) });
    assert.equal(res.counts.already_stored, 0, "a different secret with a matching fingerprint must still be imported");
    assert.equal(res.counts.imported, 1);
    assert.equal((await w.entries.list({})).length, 2);
  });

  it("an entry-store outage costs one entry, not the batch", async () => {
    class FlakyStore extends MemoryEntryStore {
      calls = 0;
      override async findIdentity(...args: Parameters<MemoryEntryStore["findIdentity"]>) {
        this.calls++;
        if (this.calls === 2) throw new Error("db blip");
        return super.findIdentity(...args);
      }
    }
    const w = world(new FakeVaultBackend(), new FlakyStore());
    const res = await applyImport(planImport(manifestOf()), { ...w.deps, resolveSecret: resolverOf() });
    assert.equal(res.counts.store_unavailable, 1);
    assert.equal(res.counts.imported, 2);
    assert.equal(res.outcomes.length, 3);
    noSecrets(res);
  });

  it("an outage while checking for duplicates also costs only that entry", async () => {
    class FlakyList extends MemoryEntryStore {
      calls = 0;
      override async list(filter: Parameters<MemoryEntryStore["list"]>[0]) {
        this.calls++;
        if (this.calls === 1) throw new Error("db blip");
        return super.list(filter);
      }
    }
    const store = new FlakyList();
    const w = world(new FakeVaultBackend(), store);
    const res = await applyImport(planImport(manifestOf()), { ...w.deps, resolveSecret: resolverOf() });
    assert.equal(res.counts.store_unavailable, 1);
    assert.equal(res.counts.imported, 2);
  });

  it("reports a source that changed since the scan and keeps going", async () => {
    const w = world();
    const changed = { ...FILES, "/srv/app/.env": "YOUTUBE_API_KEY=rotated-elsewhere\nGITHUB_TOKEN=gone\nPORT=8080", "/srv/other/.env": "GH=gone" };
    const res = await applyImport(planImport(manifestOf()), { ...w.deps, resolveSecret: resolverOf(changed) });
    assert.equal(res.counts.source_unreadable, 3);
    assert.equal(res.counts.imported, 0);
    assert.equal((await w.entries.list({})).length, 0);
  });

  it("a vault outage fails that entry without leaving a row", async () => {
    class DownBackend extends FakeVaultBackend {
      override async put(): Promise<never> {
        throw new Error("gate down");
      }
    }
    const w = world(new DownBackend());
    const res = await applyImport(planImport(manifestOf()), { ...w.deps, resolveSecret: resolverOf() });
    assert.equal(res.counts.vault_unavailable, 3);
    assert.equal((await w.entries.list({})).length, 0);
    assert.ok(w.ledger.every((r) => r.result === "error" && r.error === "vault_unavailable"));
    noSecrets(w.ledger);
  });

  it("takes the secret back out of the backend when the entry row cannot be written", async () => {
    class BrokenStore extends MemoryEntryStore {
      override async insert(): Promise<never> {
        throw new Error("db down");
      }
    }
    const backend = new DeletableFakeVaultBackend();
    const w = world(backend, new BrokenStore());
    const res = await applyImport(planImport(manifestOf({ "/a/.env": `GITHUB_TOKEN=${SECRETS.github}` })), {
      ...w.deps,
      resolveSecret: resolverOf({ "/a/.env": `GITHUB_TOKEN=${SECRETS.github}` }),
    });
    assert.equal(res.counts.store_failed, 1);
    assert.equal((backend as unknown as { secrets: Map<string, string> }).secrets.size, 0, "no orphaned secret in the backend");
  });
});
