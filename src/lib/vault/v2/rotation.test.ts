// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Rotation + real delete. Everything is in-memory or faked: stores, the vault
 * backend, Telegram and Cloudflare. No network, no real vault.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, describe, it } from "node:test";
import type { Sql } from "../../db.ts";
import { DeletableFakeVaultBackend, FakeVaultBackend, type VaultBackend } from "../backend.ts";
import {
  deleteEntry,
  EntryError,
  flagForReentry,
  getEntryMetadata,
  MemoryCardStore,
  MemoryEntryStore,
  requestCard,
  secretFingerprint,
  SqlCardStore,
  SqlEntryStore,
  submitCard,
  useEntry,
  type CardStore,
  type EntryMetadata,
  type EntryStore,
} from "./cards.ts";
import type { ClientIdentity, LedgerEntryInput } from "./contracts.ts";
import { MemoryEntryGrantStore, SqlEntryGrantStore, type EntryGrant, type EntryGrantStore } from "./entry-grants.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";
import {
  cloudflareTokenRotator,
  findRotator,
  listRotatorProviders,
  purgeEntry,
  PUT_ATTEMPTS,
  rotateDueEntries,
  rotateEntry,
  RotationError,
  setEntryRotation,
  type RotationDeps,
  type Rotator,
} from "./rotation.ts";

const ENV: NodeJS.ProcessEnv = {
  TELEGRAM_BOT_TOKEN: "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789",
  ECHO_VAULT_APPROVER_TELEGRAM_ID: "424242",
  ECHO_VAULT_PUBLIC_URL: "https://vault.example.test/",
};
const DAY = 86_400_000;
const CLAUDE: ClientIdentity = { client_id: "oc_claude_test", name: "Claude", kind: "oauth", scopes: [] };
const TOKEN_ID = "0123456789abcdef0123456789abcdef";
// Deliberately NOT provider-shaped, so pattern redaction cannot mask a leak. 40 chars like a real Cloudflare token.
const OLD = "old-cf-token-value-AAAAAAAAAAAAAAAAAA-01";
const NEW = "new-cf-token-value-BBBBBBBBBBBBBBBBBB-02";
const NEW2 = "new-cf-token-value-CCCCCCCCCCCCCCCCCC-03";
const OTHER = "some other site password 9911";
const ALL = [OLD, NEW, NEW2, OTHER];

interface CfCall {
  url: string;
  method: string;
  auth: string;
  contentType: string;
  body: string;
  redirect: string;
}

/** A fake Cloudflare: PUT …/user/tokens/{id}/value rolls the token when the bearer is the live one. */
function fakeCloudflare(live: string, next: string[]) {
  const state = { live, calls: [] as CfCall[], mode: "ok" as "ok" | "throw" | "garbage" | "no_result" | number };
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const call: CfCall = {
      url: String(input),
      method: init?.method ?? "GET",
      auth: headers.get("authorization") ?? "",
      contentType: headers.get("content-type") ?? "",
      body: typeof init?.body === "string" ? init.body : "",
      redirect: String(init?.redirect ?? ""),
    };
    state.calls.push(call);
    const json = (status: number, body: unknown) =>
      new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (state.mode === "throw") throw new TypeError(`fetch failed (${call.auth})`);
    if (typeof state.mode === "number") {
      // An error body that echoes the credential, as a hostile/buggy provider might.
      return json(state.mode, { success: false, errors: [{ code: 9109, message: `Invalid token ${call.auth}` }], result: null });
    }
    if (call.auth !== `Bearer ${state.live}`) {
      return json(401, { success: false, errors: [{ code: 1000, message: `Invalid API Token ${call.auth}` }], result: null });
    }
    const value = next.shift();
    assert.ok(value, "fake cloudflare ran out of tokens");
    state.live = value;
    if (state.mode === "garbage") return json(200, `<html>${value}</html>`);
    if (state.mode === "no_result") return json(200, { success: true, errors: [], messages: [], result: null });
    return json(200, { success: true, errors: [], messages: [], result: value });
  }) as typeof fetch;
  return { state, fetch: fetchImpl };
}

function captureOutput() {
  const chunks: string[] = [];
  const restores: Array<() => void> = [];
  for (const stream of [process.stderr]) {
    const orig = stream.write;
    stream.write = ((chunk: unknown) => {
      chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
      return true;
    }) as typeof stream.write;
    restores.push(() => {
      stream.write = orig;
    });
  }
  return { text: () => chunks.join("\n"), restore: () => restores.forEach((r) => r()) };
}

interface Stores {
  entries: EntryStore;
  cards: CardStore;
  grants: EntryGrantStore;
  dump: () => Promise<unknown[]>;
}

function memoryStores(): Stores {
  const entries = new MemoryEntryStore();
  const cards = new MemoryCardStore();
  const grants = new MemoryEntryGrantStore();
  return { entries, cards, grants, dump: async () => [...entries.dumpForTests(), ...cards.dumpForTests(), ...(await grants.list())] };
}

function makeWorld(stores: Stores = memoryStores(), backend: VaultBackend = new FakeVaultBackend()) {
  const tgTexts: string[] = [];
  const tgFetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    tgTexts.push(String(JSON.parse(String(init?.body ?? "{}")).text ?? ""));
    return new Response(JSON.stringify({ ok: true, result: { message_id: 1 } }), { status: 200 });
  }) as typeof fetch;
  const ledgerStore = new MemoryLedgerStore();
  const ledger = new Ledger({ store: ledgerStore });
  const ledgerInputs: LedgerEntryInput[] = [];
  const clock = { t: Date.parse("2026-11-14T12:00:00.000Z") };
  const seen: unknown[] = [];
  const sleeps: number[] = [];
  const cf = fakeCloudflare(OLD, [NEW, NEW2]);
  const deps: RotationDeps = {
    entries: stores.entries,
    cards: stores.cards,
    grants: stores.grants,
    backend,
    ledger: async (input) => {
      ledgerInputs.push(JSON.parse(JSON.stringify(input)));
      return ledger.append(input);
    },
    fetch: tgFetch,
    rotatorFetch: cf.fetch,
    env: ENV,
    now: () => clock.t,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
    actor: "local:owner",
  };
  const keep = <T>(value: T): T => {
    seen.push(value);
    return value;
  };
  const fails = async (p: Promise<unknown>, code: string): Promise<EntryError> => {
    try {
      keep(await p);
    } catch (err) {
      const e = err as EntryError;
      seen.push({ name: e.name, code: e.code, message: e.message, stack: e.stack });
      assert.ok(err instanceof EntryError, `expected a sanitized error, got ${e.name}: ${e.message}`);
      assert.equal(e.code, code);
      return e;
    }
    throw new assert.AssertionError({ message: `expected rejection with ${code}` });
  };
  const enter = async (site: string, account: string, secret: string, kind: "api_key" | "password" = "api_key"): Promise<EntryMetadata> => {
    await requestCard({ client: CLAUDE, site, account, kind, reason: "seed" }, deps);
    const token = /\/card\/([A-Za-z0-9_-]{43})/.exec(tgTexts[tgTexts.length - 1])?.[1];
    assert.ok(token);
    const res = await submitCard(token, { secret }, deps);
    assert.equal(res.ok, true);
    return (res as { ok: true; entry: EntryMetadata }).entry;
  };
  const stored = async (id: string): Promise<string | null> => {
    try {
      return (await backend.get(`echo_vault_entry_${id}`, "entry", "test")).secret;
    } catch {
      return null;
    }
  };
  const rows = () => ledgerStore.scanAscending(0, 10_000);
  /** Serialize EVERYTHING observable and assert no secret appears, raw, JSON-escaped or base64. */
  const assertNoLeak = async (logs: string, secrets: string[] = ALL): Promise<void> => {
    const haystacks: Record<string, string> = {
      "returned values and thrown errors": JSON.stringify(seen),
      "log lines": logs,
      "ledger rows": JSON.stringify(await rows()),
      "ledger inputs": JSON.stringify(ledgerInputs),
      "store rows": JSON.stringify(await stores.dump()),
      "telegram payloads": JSON.stringify(tgTexts),
    };
    for (const [where, text] of Object.entries(haystacks)) {
      for (const secret of secrets) {
        assert.ok(!text.includes(secret), `raw secret found in ${where}`);
        assert.ok(!text.includes(JSON.stringify(secret).slice(1, -1)), `escaped secret found in ${where}`);
        assert.ok(!text.includes(Buffer.from(secret).toString("base64")), `base64 secret found in ${where}`);
      }
    }
  };
  return { deps, clock, cf, seen, sleeps, keep, fails, enter, stored, rows, ledgerInputs, assertNoLeak, stores, backend };
}

/** A Cloudflare entry in auto mode, due every 30 days. */
async function cloudflareEntry(w: ReturnType<typeof makeWorld>, account = "ops@example.com"): Promise<EntryMetadata> {
  const e = await w.enter("cloudflare.com", account, OLD);
  return (await setEntryRotation(e.id, { mode: "auto", interval_days: 30, provider_token_id: TOKEN_ID }, w.deps)).entry;
}

describe("vault v2 rotation — rotators", () => {
  it("only Cloudflare API-token entries with a 32-hex token id are supported", async () => {
    const w = makeWorld();
    const cf = await w.enter("cloudflare.com", "ops@example.com", OLD);
    const gh = await w.enter("github.com", "bob", OTHER);
    assert.deepEqual(listRotatorProviders(), ["cloudflare"]);
    assert.equal(findRotator(cf), null, "no provider_token_id yet");
    assert.equal(findRotator({ ...cf, provider_token_id: TOKEN_ID })?.provider, "cloudflare");
    assert.equal(findRotator({ ...cf, site: "dash.cloudflare.com", provider_token_id: TOKEN_ID })?.provider, "cloudflare");
    assert.equal(findRotator({ ...cf, site: "notcloudflare.com", provider_token_id: TOKEN_ID }), null);
    assert.equal(findRotator({ ...cf, kind: "password", provider_token_id: TOKEN_ID }), null);
    assert.equal(findRotator({ ...cf, provider_token_id: "../../accounts/x" }), null);
    assert.equal(findRotator({ ...gh, provider_token_id: TOKEN_ID }), null);

    // mode auto is refused unless something can actually rotate the entry.
    await w.fails(setEntryRotation(gh.id, { mode: "auto", interval_days: 30, provider_token_id: TOKEN_ID }, w.deps), "rotation_unsupported");
    await w.fails(setEntryRotation(cf.id, { mode: "auto", interval_days: 30 }, w.deps), "rotation_unsupported");
    await w.fails(setEntryRotation(cf.id, { mode: "auto", interval_days: 30, provider_token_id: "not-hex" }, w.deps), "rotation_unsupported");
    assert.equal((await getEntryMetadata(cf.id, w.deps))?.rotation_mode, "manual", "a refused policy changes nothing");
    const manual = w.keep(await setEntryRotation(gh.id, { mode: "manual", interval_days: 90 }, w.deps));
    assert.equal(manual.auto_supported, false);
    const auto = w.keep(await setEntryRotation(cf.id, { mode: "auto", interval_days: 30, provider_token_id: TOKEN_ID }, w.deps));
    assert.equal(auto.auto_supported, true);
    assert.equal(auto.entry.rotation_mode, "auto");
    assert.equal(auto.entry.provider_token_id, TOKEN_ID);
    await w.fails(setEntryRotation("ve_" + "0".repeat(32), { mode: "manual" }, w.deps), "entry_not_found");
  });
});

describe("vault v2 rotation — rotateEntry (Cloudflare roll token, fake fetch)", () => {
  it("rolls the token: exact request, new secret stored, old secret gone, nothing secret anywhere", async () => {
    const w = makeWorld();
    const out = captureOutput();
    try {
      const entry = await cloudflareEntry(w);
      const other = await w.enter("github.com", "bob", OTHER, "password");
      w.clock.t += 31 * DAY;
      const res = w.keep(await rotateEntry(entry.id, w.deps));

      // The provider call, exactly as documented.
      assert.equal(w.cf.state.calls.length, 1);
      const call = w.cf.state.calls[0];
      assert.equal(call.method, "PUT");
      assert.equal(call.url, `https://api.cloudflare.com/client/v4/user/tokens/${TOKEN_ID}/value`);
      assert.equal(call.auth, `Bearer ${OLD}`);
      assert.equal(call.contentType, "application/json");
      assert.equal(call.body, "{}");
      assert.equal(call.redirect, "error");

      // Vault: the new secret replaced the old one under the SAME entry key; other entries untouched.
      assert.equal(await w.stored(entry.id), NEW);
      assert.equal(await w.stored(other.id), OTHER);
      assert.equal(w.cf.state.live, NEW);

      // Metadata only, updated after the put.
      assert.equal(res.provider, "cloudflare");
      assert.deepEqual(res.warnings, []);
      const nowIso = new Date(w.clock.t).toISOString();
      assert.equal(res.entry.id, entry.id);
      assert.equal(res.entry.fingerprint, secretFingerprint(NEW));
      assert.equal(res.entry.secret_length, NEW.length);
      assert.equal(res.entry.last_rotated_at, nowIso);
      assert.equal(res.entry.rotation_count, 1);
      assert.equal(res.entry.rotate_by, new Date(w.clock.t + 30 * DAY).toISOString());
      assert.equal(res.entry.last_rotation_error, null);
      assert.equal(res.entry.status, "active");
      assert.deepEqual(Object.keys(res).sort(), ["entry", "provider", "warnings"]);

      // The rotated entry is usable with the new secret (and only inside useEntry).
      const used = await useEntry(entry.id, CLAUDE, "use after rotation", (s) => s === NEW, w.deps);
      assert.equal(used.result, true);

      // Ledger: exactly one row for the attempt.
      const rot = (await w.rows()).filter((r) => r.capability === "vault.entry.rotate");
      assert.equal(rot.length, 1);
      assert.equal(rot[0].result, "ok");
      assert.equal(rot[0].client_id, "local:owner");
      assert.equal(rot[0].resource, "entry:cloudflare.com/ops@example.com");
      assert.equal(rot[0].credential_ref, `vault://entry/${entry.id}`);

      // A second rotation uses the new secret as the bearer.
      w.clock.t += 31 * DAY;
      const again = w.keep(await rotateEntry(entry.id, w.deps));
      assert.equal(w.cf.state.calls[1].auth, `Bearer ${NEW}`);
      assert.equal(await w.stored(entry.id), NEW2);
      assert.equal(again.entry.rotation_count, 2);
    } finally {
      out.restore();
    }
    assert.match(out.text(), /vault_entry_rotated/);
    await w.assertNoLeak(out.text());
  });

  it("a provider failure keeps the old secret, sets a short error code and ledgers the attempt", async () => {
    const w = makeWorld();
    const out = captureOutput();
    try {
      const entry = await cloudflareEntry(w);
      for (const [mode, code] of [
        [403, "provider_http_403"],
        [500, "provider_http_500"],
        ["throw", "provider_unreachable"],
      ] as const) {
        w.cf.state.mode = mode;
        const err = await w.fails(rotateEntry(entry.id, w.deps), code);
        assert.ok(err instanceof RotationError);
        assert.equal(err.providerRotated, false);
        const meta = (await getEntryMetadata(entry.id, w.deps))!;
        assert.equal(meta.last_rotation_error, code);
        assert.equal(meta.status, "active");
        assert.equal(meta.rotation_count, 0);
        assert.equal(meta.fingerprint, secretFingerprint(OLD));
        assert.equal(meta.rotate_by, entry.rotate_by, "a failed attempt does not move the schedule");
        assert.equal(await w.stored(entry.id), OLD, "old secret kept");
      }
      const rot = (await w.rows()).filter((r) => r.capability === "vault.entry.rotate");
      assert.deepEqual(rot.map((r) => [r.result, r.error]), [
        ["error", "provider_http_403"],
        ["error", "provider_http_500"],
        ["error", "provider_unreachable"],
      ]);
      // The next success clears the code.
      w.cf.state.mode = "ok";
      const ok = w.keep(await rotateEntry(entry.id, w.deps));
      assert.equal(ok.entry.last_rotation_error, null);
      assert.equal(await w.stored(entry.id), NEW);
    } finally {
      out.restore();
    }
    await w.assertNoLeak(out.text());
  });

  it("refuses unsupported, flagged, deleted and unknown entries without calling the provider", async () => {
    const w = makeWorld();
    const out = captureOutput();
    try {
      const gh = await w.enter("github.com", "bob", OTHER, "password");
      await w.fails(rotateEntry(gh.id, w.deps), "rotation_unsupported");
      assert.equal((await getEntryMetadata(gh.id, w.deps))?.last_rotation_error, "rotation_unsupported");
      const entry = await cloudflareEntry(w);
      await flagForReentry(entry.id, "401", w.deps);
      await w.fails(rotateEntry(entry.id, w.deps), "entry_needs_reentry");
      await deleteEntry(entry.id, w.deps);
      await w.fails(rotateEntry(entry.id, w.deps), "entry_not_found");
      await w.fails(rotateEntry("ve_" + "0".repeat(32), w.deps), "entry_not_found");
      await w.fails(rotateEntry("not-an-id", w.deps), "entry_not_found");
      assert.equal(w.cf.state.calls.length, 0);
      assert.equal(await w.stored(entry.id), OLD);
      assert.equal((await w.rows()).filter((r) => r.capability === "vault.entry.rotate" && r.result === "error").length, 5);

      // A rotator that throws a raw error carrying the secret: only a fixed code/message comes out.
      const leaky: Rotator = {
        provider: "leaky",
        supports: () => true,
        rotate: async (secret) => {
          throw new Error(`upstream said: bad token ${secret}`);
        },
      };
      const e2 = await w.enter("leaky.example", "x", OTHER + "-b");
      const err = await w.fails(rotateEntry(e2.id, { ...w.deps, rotators: [leaky] }), "rotator_failed");
      assert.equal(err.message, "The rotator failed");
    } finally {
      out.restore();
    }
    await w.assertNoLeak(out.text(), [...ALL, OTHER + "-b"]);
  });

  it("worst case: provider rotated but the vault cannot store the new secret → retried, loud, distinct code, entry flagged", async () => {
    class FlakyBackend extends FakeVaultBackend {
      failPuts = 0;
      puts = 0;
      override async put(service: string, username: string, secret: string, note: string, reason: string) {
        this.puts += 1;
        if (this.failPuts > 0) {
          this.failPuts -= 1;
          throw new Error(`vault write failed for ${secret}`);
        }
        return super.put(service, username, secret, note, reason);
      }
    }
    const backend = new FlakyBackend();
    const w = makeWorld(memoryStores(), backend);
    const out = captureOutput();
    try {
      const entry = await cloudflareEntry(w);

      // Transient failures: the put is retried and the rotation succeeds.
      backend.failPuts = PUT_ATTEMPTS - 1;
      backend.puts = 0;
      const ok = w.keep(await rotateEntry(entry.id, w.deps));
      assert.equal(backend.puts, PUT_ATTEMPTS);
      assert.deepEqual(w.sleeps, [250, 500, 1000, 2000]);
      assert.equal(await w.stored(entry.id), NEW);
      assert.equal(ok.entry.rotation_count, 1);

      // Persistent failure: the provider has rotated (NEW → NEW2), nothing could be stored.
      backend.failPuts = 1000;
      backend.puts = 0;
      const err = await w.fails(rotateEntry(entry.id, w.deps), "rotated_but_not_stored");
      assert.ok(err instanceof RotationError && err.providerRotated);
      assert.equal(backend.puts, PUT_ATTEMPTS);
      assert.equal(w.cf.state.live, NEW2, "the provider side really rotated");
      assert.equal(await w.stored(entry.id), NEW, "the vault still holds the now-dead previous value");
      const meta = (await getEntryMetadata(entry.id, w.deps))!;
      assert.equal(meta.status, "needs_reentry", "a dead token must not keep being used");
      assert.equal(meta.last_rotation_error, "rotated_but_not_stored");
      assert.equal(meta.rotation_count, 1);
      await w.fails(useEntry(entry.id, CLAUDE, "use dead token", () => 1, w.deps), "entry_needs_reentry");
      const last = (await w.rows()).filter((r) => r.capability === "vault.entry.rotate").pop()!;
      assert.equal(last.result, "error");
      assert.equal(last.error, "rotated_but_not_stored");
      assert.match(out.text(), /"level":"error","component":"echo-credential-broker","event":"vault_entry_rotation_SECRET_LOST"/);
    } finally {
      out.restore();
    }
    await w.assertNoLeak(out.text());
  });

  it("a 2xx answer without a usable secret is the same worst case (and its body is never surfaced)", async () => {
    for (const mode of ["garbage", "no_result"] as const) {
      const w = makeWorld();
      const out = captureOutput();
      try {
        const entry = await cloudflareEntry(w);
        w.cf.state.mode = mode;
        await w.fails(rotateEntry(entry.id, w.deps), "rotated_but_not_stored");
        const meta = (await getEntryMetadata(entry.id, w.deps))!;
        assert.equal(meta.status, "needs_reentry");
        assert.equal(meta.last_rotation_error, "rotated_but_not_stored");
        assert.equal(await w.stored(entry.id), OLD);
      } finally {
        out.restore();
      }
      await w.assertNoLeak(out.text());
    }
  });

  it("a ledger outage after the put is a warning, never a lost secret", async () => {
    const w = makeWorld();
    const out = captureOutput();
    try {
      const entry = await cloudflareEntry(w);
      let ledgerDown = true;
      const inner = w.deps.ledger!;
      const res = w.keep(
        await rotateEntry(entry.id, {
          ...w.deps,
          ledger: async (input) => {
            if (ledgerDown) throw new Error("ledger down");
            return inner(input);
          },
        }),
      );
      ledgerDown = false;
      assert.deepEqual(res.warnings, ["ledger_unavailable"]);
      assert.equal(await w.stored(entry.id), NEW);
      assert.equal(res.entry.fingerprint, secretFingerprint(NEW));
    } finally {
      out.restore();
    }
    await w.assertNoLeak(out.text());
  });
});

describe("vault v2 rotation — rotateDueEntries", () => {
  it("rotates due auto entries, reports due manual ones by id/label only, counts failures", async () => {
    const w = makeWorld();
    const out = captureOutput();
    try {
      const auto = await cloudflareEntry(w, "auto@example.com");
      const manual = await w.enter("github.com", "bob", OTHER, "password");
      await setEntryRotation(manual.id, { mode: "manual", interval_days: 10 }, w.deps);
      const notDue = await w.enter("gitlab.com", "bob", OTHER + "-2", "password");
      await setEntryRotation(notDue.id, { mode: "manual", interval_days: 400 }, w.deps);
      const never = await w.enter("example.org", "bob", OTHER + "-3", "password");

      const early = w.keep(await rotateDueEntries(w.clock.t + 5 * DAY, w.deps));
      assert.deepEqual(early, { due: 0, rotated: 0, failed: 0, warned: 0, needs_manual_rotation: [], failures: [] });
      assert.equal(w.cf.state.calls.length, 0);

      const at = w.clock.t + 45 * DAY;
      const res = w.keep(await rotateDueEntries(at, w.deps));
      assert.equal(res.due, 2);
      assert.equal(res.rotated, 1);
      assert.equal(res.failed, 0);
      assert.deepEqual(res.needs_manual_rotation, [{ id: manual.id, label: manual.label }]);
      assert.equal(await w.stored(auto.id), NEW);
      assert.equal((await getEntryMetadata(auto.id, w.deps))?.last_rotated_at, new Date(at).toISOString());
      assert.equal(await w.stored(never.id), OTHER + "-3");

      // Run again at the same time: the auto entry is no longer due, the manual one still is.
      const again = w.keep(await rotateDueEntries(at, w.deps));
      assert.equal(again.due, 1);
      assert.equal(again.rotated, 0);
      assert.equal(again.needs_manual_rotation.length, 1);
      assert.equal(w.cf.state.calls.length, 1);

      // A failing provider is counted, with the short code, and does not throw.
      w.cf.state.mode = 403;
      const failed = w.keep(await rotateDueEntries(at + 31 * DAY, w.deps));
      assert.equal(failed.rotated, 0);
      assert.equal(failed.failed, 1);
      assert.deepEqual(failed.failures, [{ id: auto.id, error: "provider_http_403" }]);
      assert.equal(await w.stored(auto.id), NEW);

      // An auto entry whose rotator went away is reported for manual rotation, not dropped.
      const none = w.keep(await rotateDueEntries(at + 31 * DAY, { ...w.deps, rotators: [] }));
      assert.equal(none.failed, 0);
      assert.ok(none.needs_manual_rotation.some((e) => e.id === auto.id));
      await w.fails(rotateDueEntries(Number.NaN, w.deps), "invalid_now");
    } finally {
      out.restore();
    }
    await w.assertNoLeak(out.text(), [...ALL, OTHER + "-2", OTHER + "-3"]);
  });
});

function grant(clientId: string, entryId: string, host: string, path: string): EntryGrant {
  return {
    client_id: clientId,
    entry_id: entryId,
    host,
    path_prefix: path,
    approval_id: "A".repeat(24),
    granted_at: "2026-11-14T12:00:00.000Z",
    expires_at: "2026-11-15T12:00:00.000Z",
    max_uses: null,
    uses_remaining: null,
  };
}

function purgeSuite(name: string, makeStores: () => Promise<Stores>) {
  describe(`vault v2 purge — ${name}`, () => {
    it("overwrites the secret (no backend delete), removes row, cards and grants, ledgers, and the entry is gone", async () => {
      const w = makeWorld(await makeStores());
      const out = captureOutput();
      try {
        const a = await w.enter("github.com", "bobmcw", OLD, "password");
        const b = await w.enter("github.com", "echo-bot", OTHER, "password");
        await w.stores.grants.add(grant("oc_one", a.id, "api.github.com", "/user"));
        await w.stores.grants.add(grant("oc_one", a.id, "api.github.com", "/repos"));
        await w.stores.grants.add(grant("oc_two", a.id, "api.github.com", "/user"));
        await w.stores.grants.add(grant("oc_one", b.id, "api.github.com", "/user"));

        const res = w.keep(await purgeEntry(a.id, w.deps));
        assert.deepEqual(res, {
          purged: true,
          entry_id: a.id,
          site: "github.com",
          account: "bobmcw",
          secret_disposal: "overwritten",
          grants_removed: 3,
          cards_removed: 1,
        });

        // The original value is destroyed: the key now holds 64 random bytes.
        const filler = await w.stored(a.id);
        assert.ok(filler && filler !== OLD);
        assert.match(filler, /^[A-Za-z0-9_-]{86}$/);
        w.seen.push({ filler_fingerprint: secretFingerprint(filler) });

        // Row, cards and grants are gone; the neighbour is untouched.
        assert.equal(await getEntryMetadata(a.id, w.deps), null);
        assert.equal((await w.stores.entries.list({ includeDeleted: true })).some((e) => e.id === a.id), false);
        assert.equal((await w.stores.grants.list({ entry_id: a.id })).length, 0);
        assert.equal((await w.stores.grants.list({ entry_id: b.id })).length, 1);
        assert.equal(JSON.stringify(await w.stores.dump()).includes(a.id), false, "no row references the purged entry");
        assert.equal((await getEntryMetadata(b.id, w.deps))?.status, "active");
        assert.equal((await getEntryMetadata(b.id, w.deps))?.is_default, false, "the default is not silently moved");
        assert.equal(await w.stored(b.id), OTHER);

        await w.fails(useEntry(a.id, CLAUDE, "use after purge", () => 1, w.deps), "entry_not_found");
        await w.fails(purgeEntry(a.id, w.deps), "entry_not_found");
        await w.fails(purgeEntry("nope", w.deps), "entry_not_found");

        const purges = (await w.rows()).filter((r) => r.capability === "vault.entry.purge");
        assert.deepEqual(purges.map((r) => [r.result, r.error]), [
          ["ok", undefined],
          ["error", "entry_not_found"],
          ["error", "entry_not_found"],
        ]);
        assert.equal(purges[0].resource, "entry:github.com/bobmcw");
        assert.equal(purges[0].credential_ref, `vault://entry/${a.id}`);
        assert.equal(purges[0].client_id, "local:owner");

        // The identity is free again.
        const fresh = await w.enter("github.com", "bobmcw", NEW, "password");
        assert.notEqual(fresh.id, a.id);
        assert.ok(filler);
        await w.assertNoLeak(out.text(), [...ALL, filler]);
      } finally {
        out.restore();
      }
    });

    it("uses a real backend delete when there is one; works on a soft-deleted entry", async () => {
      const backend = new DeletableFakeVaultBackend();
      const w = makeWorld(await makeStores(), backend);
      const out = captureOutput();
      try {
        const a = await w.enter("github.com", "bobmcw", OLD, "password");
        await deleteEntry(a.id, w.deps);
        assert.equal(await w.stored(a.id), OLD, "soft delete leaves the secret in place");
        const res = w.keep(await purgeEntry(a.id, w.deps));
        assert.equal(res.secret_disposal, "deleted");
        assert.equal(await w.stored(a.id), null, "the secret no longer exists in the backend");
        assert.equal(await getEntryMetadata(a.id, w.deps), null);
        // An entry whose secret is already missing can still be purged.
        const b = await w.enter("gitlab.com", "bob", OTHER, "password");
        await backend.delete(`echo_vault_entry_${b.id}`, "entry", "test");
        assert.equal((await purgeEntry(b.id, w.deps)).purged, true);
      } finally {
        out.restore();
      }
      await w.assertNoLeak(out.text());
    });

    it("never reports success, and never drops the row, while the secret is not destroyed", async () => {
      class StuckBackend extends FakeVaultBackend {
        mode: "ok" | "throw" | "ignore" = "ok";
        override async put(service: string, username: string, secret: string, note: string, reason: string) {
          if (this.mode === "throw") throw new Error(`vault down while writing ${secret}`);
          if (this.mode === "ignore") return { stored: true, service, version: 1, key_fingerprint: "x" };
          return super.put(service, username, secret, note, reason);
        }
      }
      const backend = new StuckBackend();
      const w = makeWorld(await makeStores(), backend);
      const out = captureOutput();
      try {
        const a = await w.enter("github.com", "bobmcw", OLD, "password");
        await w.stores.grants.add(grant("oc_one", a.id, "api.github.com", "/user"));

        backend.mode = "throw";
        await w.fails(purgeEntry(a.id, w.deps), "vault_unavailable");
        backend.mode = "ignore"; // the backend claims success but keeps the old value
        await w.fails(purgeEntry(a.id, w.deps), "purge_secret_not_destroyed");
        const meta = await getEntryMetadata(a.id, w.deps);
        assert.equal(meta?.status, "deleted", "the row survives (soft-deleted), still pointing at the secret");
        assert.equal(await w.stored(a.id), OLD);
        assert.equal((await w.stores.grants.list({ entry_id: a.id })).length, 1);
        await w.fails(useEntry(a.id, CLAUDE, "use during failed purge", () => 1, w.deps), "entry_not_found");

        // Secret destroyed but the ledger is down: no success, the row is kept, and a retry finishes the job.
        backend.mode = "ok";
        const inner = w.deps.ledger!;
        let down = true;
        const deps = { ...w.deps, ledger: async (i: LedgerEntryInput) => (down ? Promise.reject(new Error("down")) : inner(i)) };
        await w.fails(purgeEntry(a.id, deps), "ledger_unavailable");
        assert.notEqual(await w.stored(a.id), OLD);
        assert.equal((await getEntryMetadata(a.id, w.deps))?.status, "deleted");
        down = false;
        assert.equal((await purgeEntry(a.id, deps)).purged, true);
        assert.equal(await getEntryMetadata(a.id, w.deps), null);
        const purges = (await w.rows()).filter((r) => r.capability === "vault.entry.purge");
        assert.deepEqual(purges.map((r) => [r.result, r.error]), [
          ["error", "vault_unavailable"],
          ["error", "purge_secret_not_destroyed"],
          ["ok", undefined],
        ]);
      } finally {
        out.restore();
      }
      await w.assertNoLeak(out.text());
    });
  });
}

purgeSuite("memory stores", async () => memoryStores());

// SQL stores against a real (embedded) Postgres with the real migrations.
let pglite: Promise<import("@electric-sql/pglite").PGlite> | null = null;
const MIGRATIONS = ["0005_vault_entries.sql", "0006_vault_entry_grants.sql", "0007_vault_entry_rotation.sql"];
function migration(file: string): string {
  return readFileSync(new URL(`../../../../migrations/${file}`, import.meta.url), "utf8");
}
async function db(): Promise<import("@electric-sql/pglite").PGlite> {
  pglite ??= (async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const pg = new PGlite();
    for (const file of MIGRATIONS) await pg.exec(migration(file));
    return pg;
  })();
  return pglite;
}

purgeSuite("sql stores on PGlite", async () => {
  const pg = await db();
  await pg.exec("delete from vault_entry_grants; delete from vault_cards; delete from vault_entries;");
  const sql = { query: async (text: string, params: unknown[] = []) => (await pg.query(text, params)).rows } as unknown as Sql;
  const provider = async () => sql;
  return {
    entries: new SqlEntryStore(provider),
    cards: new SqlCardStore(provider),
    grants: new SqlEntryGrantStore(provider),
    dump: async () => [
      ...(await pg.query("select * from vault_entries")).rows,
      ...(await pg.query("select * from vault_cards")).rows,
      ...(await pg.query("select * from vault_entry_grants")).rows,
    ],
  };
});

describe("migrations/0007_vault_entry_rotation.sql (PGlite)", () => {
  it("applies, is re-runnable, defaults existing rows, enforces its checks, and adds no secret column", async () => {
    const pg = await db();
    await pg.exec(migration("0007_vault_entry_rotation.sql")); // idempotent
    await pg.exec("delete from vault_entry_grants; delete from vault_cards; delete from vault_entries;");
    const id = "ve_" + "a".repeat(32);
    await pg.query(
      `insert into vault_entries (id, site, account, purpose, label, kind, fingerprint, secret_length)
       values ($1, 'cloudflare.com', 'ops', 'general', 'l', 'api_key', 'deadbeef', 40)`,
      [id],
    );
    const row = (await pg.query<Record<string, unknown>>("select * from vault_entries where id = $1", [id])).rows[0];
    assert.equal(row.rotation_mode, "manual");
    assert.equal(row.rotate_interval_days, null);
    assert.equal(row.last_rotated_at, null);
    assert.equal(row.rotate_by, null);
    assert.equal(row.rotation_count, 0);
    assert.equal(row.last_rotation_error, null);
    assert.equal(row.provider_token_id, null);

    const set = (sqlText: string) => pg.query(`update vault_entries set ${sqlText} where id = '${id}'`);
    await assert.rejects(set("rotation_mode = 'weekly'"), /vault_entries_rotation_mode_check/);
    await assert.rejects(set("rotate_interval_days = 0"), /vault_entries_rotate_interval_check/);
    await assert.rejects(set("rotate_interval_days = 3651"), /vault_entries_rotate_interval_check/);
    await assert.rejects(set("rotation_count = -1"), /vault_entries_rotation_count_check/);
    await assert.rejects(set("last_rotation_error = 'Bad credentials: Bearer abc'"), /vault_entries_rotation_error_check/);
    await assert.rejects(set("provider_token_id = 'has space'"), /vault_entries_provider_token_id_check/);
    await set(`rotation_mode = 'auto', rotate_interval_days = 3650, rotation_count = 2, last_rotation_error = 'provider_http_403',
               provider_token_id = '${TOKEN_ID}', rotate_by = now()`);

    const cols = await pg.query<{ column_name: string }>(
      "select column_name from information_schema.columns where table_name = 'vault_entries'",
    );
    const names = cols.rows.map((r) => r.column_name);
    for (const n of ["rotation_mode", "rotate_interval_days", "last_rotated_at", "rotate_by", "rotation_count", "last_rotation_error", "provider_token_id"]) {
      assert.ok(names.includes(n), `missing column ${n}`);
    }
    for (const n of names) assert.ok(!/^(secret|password|value|token)$/.test(n), `unexpected column ${n}`);
    await pg.exec("delete from vault_entries;");
  });
});

after(async () => {
  if (pglite) await (await pglite).close();
});

// The exported rotator is the one in the registry (guards against a silent re-registration).
assert.equal(cloudflareTokenRotator.provider, "cloudflare");
