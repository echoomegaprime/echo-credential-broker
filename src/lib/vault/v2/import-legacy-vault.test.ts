// library-first: echo.functions.search → no existing impl found (2026-11-19)
/**
 * Legacy Cloudflare vault import. In memory only: a fake of the old worker's
 * API, the fake vault backend and memory stores. Fake secrets are assembled at
 * runtime so no token-shaped literal sits in the repo.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { fingerprint } from "../../../../scripts/credential-scan.mjs";
import { FakeVaultBackend } from "../backend.ts";
import { MemoryCardStore, MemoryEntryStore } from "./cards.ts";
import type { LedgerEntryInput } from "./contracts.ts";
import { applyImport } from "./import.ts";
import { fetchLegacyVault, LegacyVaultError, legacySourcePath, planLegacyVault, siteForService, type LegacyItem } from "./import-legacy-vault.ts";

const KEY = Buffer.alloc(32, 7);
const fp = (s: string) => fingerprint(s, KEY);
const API_KEY = "old-" + "worker-" + "key-0123456789";
const S = {
  twilio: "tw" + "9Kq2Lx7Rm4Tn8Wz1Yb5Cd3Fg6Hj0",
  ghPass: "correct-" + "horse-battery-staple-42",
  ghKey: "gk" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0",
  mystery: "my" + "p4Zx8Qw2Er6Ty0Ui3Op7As1Df5Gh9",
};

interface OldRow { id: number; service: string; username: string; category: string; password: string; api_key: string; notes: string }
const ROWS: OldRow[] = [
  { id: 1, service: "Twilio", username: "", category: "api", password: "", api_key: S.twilio, notes: "do not read" },
  { id: 2, service: "https://github.com/login", username: "bob@example.com", category: "dev", password: S.ghPass, api_key: S.ghKey, notes: "" },
  { id: 3, service: "twilio backup", username: "", category: "api", password: "", api_key: S.twilio, notes: "" },
  { id: 4, service: "Mystery Portal", username: "bob", category: "general", password: "", api_key: S.mystery, notes: "" },
  { id: 5, service: "OpenAI", username: "", category: "ai", password: "", api_key: "[DECRYPT_ERROR]", notes: "" },
  { id: 6, service: "Empty", username: "", category: "general", password: "", api_key: "", notes: "" },
];

function fakeWorker(rows: OldRow[] = ROWS, opts: { failList?: number; rateLimitOnce?: boolean } = {}) {
  const calls: string[] = [];
  let limited = opts.rateLimitOnce === true;
  const fetchImpl = (async (input: URL | string, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(url.pathname + url.search);
    const headers = new Headers(init?.headers);
    if (headers.get("X-Echo-API-Key") !== API_KEY) return new Response("{}", { status: 401 });
    if (url.pathname === "/list") {
      if (opts.failList) return new Response("{}", { status: opts.failList });
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const page = rows.slice(offset, offset + 2).map(({ id, service, username, category, notes }) => ({ id, service, username, category, notes }));
      return Response.json({ credentials: page, total: rows.length, has_more: offset + page.length < rows.length });
    }
    if (url.pathname === "/get") {
      if (limited) {
        limited = false;
        return new Response("{}", { status: 429 });
      }
      if (url.searchParams.get("reveal") !== "true") return new Response("{}", { status: 400 });
      const row = rows.find((r) => r.id === Number(url.searchParams.get("id")));
      return row ? Response.json(row) : new Response("{}", { status: 404 });
    }
    return new Response("{}", { status: 404 });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const noSleep = async () => undefined;
const pull = (w = fakeWorker()) =>
  fetchLegacyVault({ baseUrl: "https://old.example", apiKey: API_KEY, fingerprint: fp, fetch: w.fetchImpl, sleep: noSleep });

function world() {
  const backend = new FakeVaultBackend();
  const entries = new MemoryEntryStore();
  const ledger: LedgerEntryInput[] = [];
  return { backend, entries, ledger, deps: { backend, entries, cards: new MemoryCardStore(), ledger: async (e: LedgerEntryInput) => void ledger.push(e) } };
}

describe("siteForService", () => {
  it("maps URLs, domains and known names; leaves the rest unmapped", () => {
    assert.equal(siteForService("https://www.GitHub.com/login"), "github.com");
    assert.equal(siteForService("dash.cloudflare.com"), "dash.cloudflare.com");
    assert.equal(siteForService("Twilio (main)"), "twilio.com");
    assert.equal(siteForService("Eleven Labs"), "elevenlabs.io");
    assert.equal(siteForService("Mystery Portal"), null);
  });
});

describe("fetchLegacyVault", () => {
  it("pages the list, reveals each row, and returns values only in the secrets map", async () => {
    const w = fakeWorker();
    const got = await pull(w);
    assert.equal(got.rows, 6);
    assert.deepEqual(w.calls.filter((c) => c.startsWith("/list")), ["/list?limit=500&offset=0", "/list?limit=500&offset=2", "/list?limit=500&offset=4"]);
    assert.equal(got.items.length, 6); // twilio, gh password, gh key, twilio again, mystery, openai (undecryptable)
    assert.equal(got.secrets.get(legacySourcePath(2, "password")), S.ghPass);
    assert.equal(got.secrets.size, 5);
    const text = JSON.stringify(got.items);
    for (const v of [...Object.values(S), "do not read", API_KEY]) assert.ok(!text.includes(v));
    assert.equal(got.items.find((i) => i.id === 5)?.fingerprint, null);
  });

  it("retries a rate limit and reports failures as codes", async () => {
    const got = await fetchLegacyVault({ baseUrl: "https://old.example", apiKey: API_KEY, fingerprint: fp, fetch: fakeWorker(ROWS, { rateLimitOnce: true }).fetchImpl, sleep: noSleep });
    assert.equal(got.rows, 6);
    const code = async (p: Promise<unknown>) => p.then(() => "none", (e) => (e instanceof LegacyVaultError ? e.code : "other"));
    assert.equal(await code(fetchLegacyVault({ baseUrl: "https://old.example", apiKey: "wrong-key-000000", fingerprint: fp, fetch: fakeWorker().fetchImpl, sleep: noSleep })), "source_key_rejected");
    assert.equal(await code(fetchLegacyVault({ baseUrl: "https://old.example", apiKey: API_KEY, fingerprint: fp, fetch: fakeWorker(ROWS, { failList: 500 }).fetchImpl, sleep: noSleep })), "source_unavailable");
    assert.equal(await code(fetchLegacyVault({ baseUrl: "http://old.example", apiKey: API_KEY, fingerprint: fp, fetch: fakeWorker().fetchImpl, sleep: noSleep })), "source_url_not_https");
    assert.equal(await code(fetchLegacyVault({ baseUrl: "https://old.example", apiKey: "", fingerprint: fp, fetch: fakeWorker().fetchImpl, sleep: noSleep })), "source_key_missing");
  });
});

describe("planLegacyVault", () => {
  it("plans one entry per distinct secret and kind, and skips what it cannot place", async () => {
    const { items } = await pull();
    const plan = planLegacyVault(items);
    assert.deepEqual(
      plan.entries.map((e) => [e.site, e.account, e.kind, e.sources.length]),
      [
        ["github.com", "bob@example.com", "api_key", 1],
        ["github.com", "bob@example.com", "password", 1],
        ["twilio.com", "twilio", "api_key", 2],
      ],
    );
    assert.equal(plan.entries[2]?.purpose, "import cloudflare-vault/api");
    assert.deepEqual(plan.skipped.map((s) => [s.line, s.reason]).sort(), [[4, "unknown_provider"], [5, "legacy_decrypt_failed"]]);
    const text = JSON.stringify(plan);
    for (const v of Object.values(S)) assert.ok(!text.includes(v));
  });

  it("files unmapped services under a reserved domain when asked, and honours --only-site", async () => {
    const { items } = await pull();
    const all = planLegacyVault(items, { includeUnmapped: true });
    assert.ok(all.entries.some((e) => e.site === "mystery-portal.legacy-vault.invalid" && e.account === "bob"));
    const only = planLegacyVault(items, { onlySites: ["twilio.com"] });
    assert.deepEqual(only.entries.map((e) => e.site), ["twilio.com"]);
  });

  it("keeps two different secrets with the same identity apart, and hides secret-shaped service names", () => {
    const a = "aa" + "1111222233334444aaaa";
    const b = "bb" + "5555666677778888bbbb";
    const items: LegacyItem[] = [
      { id: 1, service: "stripe", username: "", category: "pay", field: "api_key", fingerprint: fp(a) },
      { id: 2, service: "Stripe", username: "", category: "pay", field: "api_key", fingerprint: fp(b) },
      { id: 3, service: "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3lM6", username: "", category: "x", field: "api_key", fingerprint: null },
    ];
    const plan = planLegacyVault(items);
    assert.equal(plan.entries.length, 2);
    assert.equal(new Set(plan.entries.map((e) => e.account)).size, 2);
    assert.equal(plan.skipped[0]?.provider, "[redacted]");
  });
});

describe("legacy import end to end", () => {
  it("previews without writing, imports once, and finds everything on a second run", async () => {
    const w = world();
    const got = await pull();
    const plan = planLegacyVault(got.items, { includeUnmapped: true });
    const resolveSecret = async (e: { sources: { path: string }[] }) => e.sources.map((s) => got.secrets.get(s.path)).find(Boolean) ?? null;

    const preview = await applyImport(plan, { ...w.deps, resolveSecret, dryRun: true });
    assert.equal(preview.counts.would_import, 4);
    assert.equal((await w.entries.list({})).length, 0);

    const first = await applyImport(plan, { ...w.deps, resolveSecret });
    assert.equal(first.counts.imported, 4);
    const stored = await w.entries.list({});
    assert.deepEqual(stored.map((e) => e.kind).sort(), ["api_key", "api_key", "api_key", "password"]);
    assert.ok(w.ledger.every((l) => l.capability === "vault.entry.import"));
    const dump = JSON.stringify([first, stored, w.ledger]);
    for (const v of Object.values(S)) assert.ok(!dump.includes(v));

    const second = await applyImport(planLegacyVault((await pull()).items, { includeUnmapped: true }), { ...w.deps, resolveSecret });
    assert.equal(second.counts.exists, 4);
    assert.equal(second.counts.imported, 0);
  });
});
