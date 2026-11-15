// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, describe, it } from "node:test";
import type { Sql } from "../../db.ts";
import { FakeVaultBackend } from "../backend.ts";
import type { ClientIdentity, LedgerEntryInput } from "./contracts.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";
import {
  CARD_TTL_MS,
  CardError,
  deleteEntry,
  EntryError,
  flagForReentry,
  getCardStatus,
  getEntryMetadata,
  listEntries,
  lookupCard,
  markUsed,
  MAX_PENDING_CARDS_PER_CLIENT,
  MemoryCardStore,
  MemoryEntryStore,
  normalizeSite,
  requestCard,
  resolveEntry,
  secretFingerprint,
  setDefault,
  SqlCardStore,
  SqlEntryStore,
  submitCard,
  updateEntryMetadata,
  useEntry,
} from "./cards.ts";
import type { CardsDeps, CardStore, EntryKind, EntryMetadata, EntryStore } from "./cards.ts";

const BOT_TOKEN = "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789";
const APPROVER = "424242";
const ENV: NodeJS.ProcessEnv = {
  TELEGRAM_BOT_TOKEN: BOT_TOKEN,
  ECHO_VAULT_APPROVER_TELEGRAM_ID: APPROVER,
  ECHO_VAULT_PUBLIC_URL: "https://vault.example.test/",
};

// Deliberately NOT provider-shaped, so pattern redaction cannot mask a leak.
const SECRET_A = "correct horse battery staple 41";
const SECRET_B = "Tr0ub4dor&3-second-account-pw";
const SECRET_C = "third-entry-secret-value-0099";
const SECRET_A2 = "rotated-replacement-secret-777";
const ALL_SECRETS = [SECRET_A, SECRET_B, SECRET_C, SECRET_A2];

const CLAUDE: ClientIdentity = { client_id: "oc_claude_test", name: "Claude", kind: "oauth", scopes: [] };
const CODEX: ClientIdentity = { client_id: "oc_codex_test", name: "Codex", kind: "oauth", scopes: [] };

interface TgCall {
  url: string;
  body: Record<string, any>;
}

function fakeTelegram(mode: "ok" | "throw" = "ok") {
  const calls: TgCall[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, body: JSON.parse(String(init?.body ?? "{}")) });
    if (mode === "throw") throw new TypeError(`fetch failed for ${url}`);
    return new Response(JSON.stringify({ ok: true, result: { message_id: 1 } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { calls, fetch: fetchImpl };
}

function captureOutput() {
  const chunks: string[] = [];
  const origErr = process.stderr.write;
  process.stderr.write = ((chunk: unknown) => {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  return {
    text: () => chunks.join("\n"),
    restore: () => {
      process.stderr.write = origErr;
    },
  };
}

interface Stores {
  entries: EntryStore;
  cards: CardStore;
  /** Every stored row of both tables, raw, for leak scans. */
  dump: () => Promise<unknown[]>;
}

function makeWorld(stores: Stores) {
  const tg = fakeTelegram();
  const backend = new FakeVaultBackend();
  const ledgerStore = new MemoryLedgerStore();
  const ledger = new Ledger({ store: ledgerStore });
  const ledgerInputs: LedgerEntryInput[] = [];
  const clock = { t: Date.parse("2026-11-14T12:00:00.000Z") };
  const seen: unknown[] = []; // every value returned or thrown to a caller
  const deps: CardsDeps = {
    entries: stores.entries,
    cards: stores.cards,
    backend,
    ledger: async (input) => {
      ledgerInputs.push(JSON.parse(JSON.stringify(input)));
      return ledger.append(input);
    },
    fetch: tg.fetch,
    env: ENV,
    now: () => clock.t,
  };
  const keep = <T>(value: T): T => {
    seen.push(value);
    return value;
  };
  const fails = async (p: Promise<unknown>, code: string): Promise<Error & { code: string }> => {
    try {
      keep(await p);
    } catch (err) {
      const e = err as Error & { code: string };
      seen.push({ name: e.name, code: e.code, message: e.message, stack: e.stack });
      assert.ok(err instanceof EntryError || err instanceof CardError, `expected a sanitized error, got ${e.name}`);
      assert.equal(e.code, code);
      return e;
    }
    throw new assert.AssertionError({ message: `expected rejection with ${code}` });
  };
  const lastToken = (): string => {
    const text = String(tg.calls[tg.calls.length - 1]?.body.text ?? "");
    const m = /https:\/\/vault\.example\.test\/card\/([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/.exec(text);
    assert.ok(m, "telegram message carries the card link");
    return m[1];
  };
  /** Full flow: agent requests a card, operator submits the secret. */
  const enter = async (
    client: ClientIdentity,
    req: { site: string; account?: string; purpose?: string; kind?: EntryKind },
    secret: string,
    typed: { site?: string; account?: string; purpose?: string } = {},
  ) => {
    const receipt = keep(
      await requestCard({ client, kind: "password", reason: "needed for a test task", ...req }, deps),
    );
    const token = lastToken();
    const result = keep(await submitCard(token, { ...typed, secret }, deps));
    return { receipt, token, result };
  };
  const entered = async (...args: Parameters<typeof enter>): Promise<EntryMetadata> => {
    const { result } = await enter(...args);
    assert.equal(result.ok, true, result.ok ? "" : `${result.code}: ${result.message}`);
    return (result as { ok: true; entry: EntryMetadata }).entry;
  };
  return { tg, backend, ledger, ledgerStore, ledgerInputs, clock, seen, deps, keep, fails, lastToken, enter, entered, stores };
}

type World = ReturnType<typeof makeWorld>;

async function vaultSecret(w: World, id: string): Promise<string> {
  return (await w.backend.get(`echo_vault_entry_${id}`, "entry", "test")).secret;
}

async function assertNoLeak(w: World, logs: string, secrets: string[] = ALL_SECRETS): Promise<void> {
  const haystacks: Record<string, string> = {
    "returned values and thrown errors": JSON.stringify(w.seen),
    "log lines": logs,
    "ledger rows": JSON.stringify(await w.ledgerStore.scanAscending(0, 1000)),
    "ledger inputs": JSON.stringify(w.ledgerInputs),
    "sql rows": JSON.stringify(await w.stores.dump()),
    "telegram payloads": JSON.stringify(w.tg.calls.map((c) => c.body)),
  };
  for (const [where, text] of Object.entries(haystacks)) {
    for (const secret of secrets) {
      assert.ok(!text.includes(secret), `raw secret found in ${where}`);
      assert.ok(!text.includes(JSON.stringify(secret).slice(1, -1)), `escaped secret found in ${where}`);
      assert.ok(!text.includes(Buffer.from(secret).toString("base64")), `base64 secret found in ${where}`);
    }
  }
}

function runSuite(name: string, makeStores: () => Promise<Stores>) {
  describe(`vault v2 cards — ${name}`, () => {
    it("stores two GitHub accounts side by side without overwrite; first is default", async () => {
      const w = makeWorld(await makeStores());
      const a = await w.entered(CLAUDE, { site: "https://www.GitHub.com/login", account: "bobmcw", purpose: "personal" }, SECRET_A);
      const b = await w.entered(CLAUDE, { site: "github.com", account: "echo-bot", purpose: "automation" }, SECRET_B);

      assert.notEqual(a.id, b.id);
      assert.equal(a.site, "github.com");
      assert.equal(a.label, "github.com — bobmcw — personal");
      assert.equal(b.label, "github.com — echo-bot — automation");
      assert.equal(a.is_default, true);
      assert.equal(b.is_default, false);
      assert.equal(a.fingerprint, secretFingerprint(SECRET_A));
      assert.equal(a.secret_length, SECRET_A.length);
      assert.equal(a.ref, `vault://entry/${a.id}`);
      assert.match(a.fingerprint, /^[0-9a-f]{8}$/);

      // Each entry has its own vault key; neither overwrote the other.
      assert.equal(await vaultSecret(w, a.id), SECRET_A);
      assert.equal(await vaultSecret(w, b.id), SECRET_B);

      const listed = await listEntries({ site: "GitHub.com" }, w.deps);
      assert.deepEqual(listed.map((e) => e.account).sort(), ["bobmcw", "echo-bot"]);
      assert.deepEqual((await listEntries({ query: "AUTOMATION" }, w.deps)).map((e) => e.id), [b.id]);
      assert.equal((await listEntries({ site: "gitlab.com" }, w.deps)).length, 0);
      assert.deepEqual(await getEntryMetadata(a.id, w.deps), listed.find((e) => e.id === a.id));
      assert.equal(await getEntryMetadata("ve_" + "0".repeat(32), w.deps), null);

      // Same identity again is a re-entry of the SAME entry, never a second row or an overwrite of another.
      const again = await w.entered(CLAUDE, { site: "github.com", account: "BobMcW" }, SECRET_A2);
      assert.equal(again.id, a.id);
      assert.equal((await listEntries({ site: "github.com" }, w.deps)).length, 2);
      assert.equal(await vaultSecret(w, b.id), SECRET_B);

      // A different kind for the same account is its own entry.
      const k = await w.entered(CLAUDE, { site: "github.com", account: "bobmcw", kind: "api_key" }, SECRET_C);
      assert.notEqual(k.id, a.id);
      assert.equal(k.kind, "api_key");
      assert.equal(await vaultSecret(w, a.id), SECRET_A2);
    });

    it("keeps at most one default per site and moves it atomically", async () => {
      const w = makeWorld(await makeStores());
      const a = await w.entered(CLAUDE, { site: "github.com", account: "one" }, SECRET_A);
      const b = await w.entered(CLAUDE, { site: "github.com", account: "two" }, SECRET_B);
      const other = await w.entered(CLAUDE, { site: "gitlab.com", account: "one" }, SECRET_C);
      assert.equal(other.is_default, true, "first entry of another site is its own default");

      const moved = await setDefault(b.id, w.deps);
      assert.equal(moved.is_default, true);
      const defaults = (await listEntries({ site: "github.com" }, w.deps)).filter((e) => e.is_default);
      assert.deepEqual(defaults.map((e) => e.id), [b.id]);
      assert.equal((await getEntryMetadata(a.id, w.deps))?.is_default, false);
      assert.equal((await getEntryMetadata(other.id, w.deps))?.is_default, true, "other sites are untouched");

      // Idempotent, and unknown/deleted ids are refused.
      assert.equal((await setDefault(b.id, w.deps)).is_default, true);
      await w.fails(setDefault("ve_" + "f".repeat(32), w.deps), "entry_not_found");
      await w.fails(setDefault("not-an-id", w.deps), "entry_not_found");

      // Deleting the default leaves the site without one; the next new entry takes it.
      await deleteEntry(b.id, w.deps);
      assert.equal((await listEntries({ site: "github.com" }, w.deps)).filter((e) => e.is_default).length, 0);
      await w.fails(setDefault(b.id, w.deps), "entry_not_found");
      const c = await w.entered(CLAUDE, { site: "github.com", account: "three" }, SECRET_B);
      assert.equal(c.is_default, true);
      assert.equal((await listEntries({ site: "github.com" }, w.deps)).filter((e) => e.is_default).length, 1);
    });

    it("resolves by site+account and by default; ambiguous and missing are clear errors", async () => {
      const w = makeWorld(await makeStores());
      const a = await w.entered(CLAUDE, { site: "github.com", account: "bobmcw" }, SECRET_A);
      const b = await w.entered(CLAUDE, { site: "github.com", account: "echo-bot" }, SECRET_B);

      assert.equal((await resolveEntry({ site: "github.com" }, w.deps)).id, a.id, "account omitted → default");
      assert.equal((await resolveEntry({ site: "GITHUB.com", account: "Echo-Bot" }, w.deps)).id, b.id);
      assert.equal((await resolveEntry({ site: "github.com", account: "bobmcw" }, w.deps)).id, a.id);

      const missingAccount = await w.fails(resolveEntry({ site: "github.com", account: "nobody" }, w.deps), "entry_not_found");
      assert.match(missingAccount.message, /bobmcw/);
      await w.fails(resolveEntry({ site: "example.org" }, w.deps), "entry_not_found");
      await w.fails(resolveEntry({ site: "not a domain!" }, w.deps), "invalid_site");

      // No default: a single candidate is unambiguous; several are never guessed between.
      const x = await w.entered(CLAUDE, { site: "ambig.example", account: "x" }, SECRET_A);
      await w.entered(CLAUDE, { site: "ambig.example", account: "y" }, SECRET_B);
      const t = await w.entered(CLAUDE, { site: "ambig.example", account: "t" }, SECRET_C);
      assert.equal(t.is_default, false);
      await deleteEntry(x.id, w.deps); // the default is gone; y and t remain, neither default
      const ambiguous = await w.fails(resolveEntry({ site: "ambig.example" }, w.deps), "ambiguous_entry");
      assert.match(ambiguous.message, /specify account/);
      await deleteEntry(t.id, w.deps);
      assert.equal((await resolveEntry({ site: "ambig.example" }, w.deps)).account, "y", "single candidate");
      await w.entered(CLAUDE, { site: "ambig.example", account: "t" }, SECRET_C); // site had no default → takes it
      assert.equal((await resolveEntry({ site: "ambig.example" }, w.deps)).account, "t");

      // Same account, two kinds → kind is required.
      await w.entered(CLAUDE, { site: "ambig.example", account: "t", kind: "api_key" }, SECRET_C);
      await w.fails(resolveEntry({ site: "ambig.example", account: "t" }, w.deps), "ambiguous_entry");
      assert.equal((await resolveEntry({ site: "ambig.example", account: "t", kind: "api_key" }, w.deps)).kind, "api_key");
    });

    it("two clients each use a different account; the ledger records both; nothing leaks anywhere", async () => {
      const w = makeWorld(await makeStores());
      const out = captureOutput();
      let logs = "";
      try {
        const a = await w.entered(CLAUDE, { site: "github.com", account: "bobmcw", purpose: "personal" }, SECRET_A);
        const b = await w.entered(CODEX, { site: "github.com", account: "echo-bot", purpose: "automation" }, SECRET_B);

        const got: Array<{ who: string; correct: boolean; account: string }> = [];
        const r1 = w.keep(
          await useEntry(
            a.id,
            CLAUDE,
            "push a commit to the docs repo",
            async (secret, entry) => {
              got.push({ who: "claude", correct: secret === SECRET_A, account: entry.account });
              // A sloppy callback that tries to hand the secret back.
              return { status: 200, echoed: `password=${secret}`, nested: [secret], header: `Basic ${Buffer.from(secret).toString("utf8")}` };
            },
            w.deps,
          ),
        );
        const r2 = w.keep(
          await useEntry(
            b.id,
            CODEX,
            `open a PR (do not log ${SECRET_B})`,
            (secret, entry) => {
              got.push({ who: "codex", correct: secret === SECRET_B, account: entry.account });
              return secret; // returning the bare secret is scrubbed too
            },
            w.deps,
          ),
        );
        assert.deepEqual(got, [
          { who: "claude", correct: true, account: "bobmcw" },
          { who: "codex", correct: true, account: "echo-bot" },
        ]);
        assert.equal(r1.result.status, 200);
        assert.ok(!JSON.stringify(r1).includes(SECRET_A));
        assert.equal(r2.result, "[REDACTED_SECRET]");
        assert.deepEqual(Object.keys(r1).sort(), ["entry", "result"]);
        assert.equal(r1.entry.id, a.id);
        assert.equal(r1.entry.last_used_at, new Date(w.clock.t).toISOString());
        assert.equal((await getEntryMetadata(b.id, w.deps))?.last_used_at, new Date(w.clock.t).toISOString());

        // A callback that throws with the secret in its message.
        const boom = await w.fails(
          useEntry(a.id, CLAUDE, "failing task", () => {
            throw new Error(`upstream rejected https://user:${SECRET_A}@github.com/x`);
          }, w.deps),
          "entry_use_failed",
        );
        assert.ok(!boom.message.includes(SECRET_A));

        // Ledger: both uses, with client ids and entry refs.
        const uses = (await w.ledger.list({ capability: "vault.entry.use" })).reverse();
        assert.equal(uses.length, 3);
        assert.deepEqual(uses.map((u) => [u.client_id, u.resource, u.result]), [
          ["oc_claude_test", "entry:github.com/bobmcw", "ok"],
          ["oc_codex_test", "entry:github.com/echo-bot", "ok"],
          ["oc_claude_test", "entry:github.com/bobmcw", "error"],
        ]);
        assert.equal(uses[2].error, "entry_use_failed");
        const useInputs = w.ledgerInputs.filter((i) => i.capability === "vault.entry.use");
        assert.deepEqual(useInputs.map((i) => i.credential_ref), [
          `vault://entry/${a.id}`,
          `vault://entry/${b.id}`,
          `vault://entry/${a.id}`,
        ]);
        assert.equal((useInputs[0] as LedgerEntryInput & { task?: string }).task, "push a commit to the docs repo");
        // CONTRACT GAP (reported): ledger.ts only keeps credential_ref values whose first segment is a
        // known provider, so `vault://entry/<id>` is dropped at rest until the ledger accepts it.
        for (const [i, row] of uses.entries()) {
          const want = `vault://entry/${[a.id, b.id, a.id][i]}`;
          assert.ok(row.credential_ref === undefined || row.credential_ref === want);
        }
        const creates = await w.ledger.list({ capability: "vault.entry.create" });
        assert.deepEqual(creates.map((c) => c.client_id).sort(), ["oc_claude_test", "oc_codex_test"]);
        assert.equal((await w.ledger.list({ capability: "vault.card.request" })).length, 2);
        assert.deepEqual(await w.ledger.verify(), { ok: true, count: 7 });

        // Exercise every other API so its return values join the scan.
        w.keep(await listEntries({}, w.deps));
        w.keep(await resolveEntry({ site: "github.com" }, w.deps));
        w.keep(await markUsed(a.id, w.deps));
        w.keep(await updateEntryMetadata(a.id, { purpose: "main", verified: true }, w.deps));
        w.keep(await flagForReentry(b.id, `login failed with ${SECRET_B}`, w.deps));
        await w.fails(useEntry(b.id, CODEX, "use a flagged entry", () => "never", w.deps), "entry_needs_reentry");
        const re = await w.enter(CODEX, { site: "github.com", account: "echo-bot" }, SECRET_A2);
        w.keep(await getCardStatus(re.receipt.card_id, w.deps));
        w.keep(await lookupCard(re.token, w.deps));
        // Operator pastes the secret into the account field: rejected, not stored as metadata.
        const bad = await w.enter(CLAUDE, { site: "github.com" }, SECRET_C, { account: SECRET_C.replace(/ /g, "") });
        assert.equal(bad.result.ok, false);
        const bad2 = w.keep(await submitCard(bad.token, { account: `x${SECRET_C}x`, secret: SECRET_C }, w.deps));
        assert.equal(bad2.ok, false);
        w.keep(await deleteEntry(a.id, w.deps));
        await w.fails(useEntry(a.id, CLAUDE, "use a deleted entry", () => "never", w.deps), "entry_not_found");
        await w.fails(useEntry("garbage", CLAUDE, "bad id", () => "never", w.deps), "entry_not_found");
        await w.fails(useEntry(b.id, CLAUDE, "   ", () => "never", w.deps), "invalid_task");
      } finally {
        logs = out.text();
        out.restore();
      }

      assert.ok(logs.includes("vault_entry_used"), "uses are logged");
      assert.ok(logs.includes("vault_card_completed"));
      await assertNoLeak(w, logs);
      // The card token is operator-only: never in a log, ledger row, SQL row or agent-visible value.
      const tokens = w.tg.calls.map((c) => /\/card\/([A-Za-z0-9_-]{43})/.exec(String(c.body.text))?.[1] ?? "");
      assert.ok(tokens.length >= 4 && tokens.every((t) => t.length === 43));
      const agentVisible = [JSON.stringify(w.seen), logs];
      agentVisible.push(JSON.stringify(await w.ledgerStore.scanAscending(0, 1000)), JSON.stringify(await w.stores.dump()));
      for (const token of tokens) for (const text of agentVisible) assert.ok(!text.includes(token), "card token leaked");
      // And the vault itself really holds the values (the scan is not vacuous).
      assert.equal(await vaultSecret(w, (await resolveEntry({ site: "github.com", account: "echo-bot" }, w.deps)).id), SECRET_A2);
    });

    it("card tokens are single-use, expire after 30 minutes, and wrong tokens are rejected", async () => {
      const w = makeWorld(await makeStores());
      const receipt = await requestCard(
        { client: CLAUDE, site: "github.com", account: "bobmcw", kind: "password", reason: "deploy key rotation" },
        w.deps,
      );
      // The requester gets exactly these three fields — no token, no link.
      assert.deepEqual(Object.keys(receipt).sort(), ["card_id", "expires_at", "status"]);
      assert.equal(receipt.status, "pending");
      assert.equal(Date.parse(receipt.expires_at) - w.clock.t, CARD_TTL_MS);
      assert.equal(CARD_TTL_MS, 30 * 60 * 1000);
      const token = w.lastToken();
      assert.ok(Buffer.from(token, "base64url").length >= 32, "token carries at least 256 bits");
      assert.ok(!JSON.stringify(receipt).includes(token));

      // Telegram: one sendMessage to the operator, link preview off, no secret.
      assert.equal(w.tg.calls.length, 1);
      assert.ok(w.tg.calls[0].url.endsWith("/sendMessage"));
      assert.equal(String(w.tg.calls[0].body.chat_id), APPROVER);
      assert.deepEqual(w.tg.calls[0].body.link_preview_options, { is_disabled: true });
      assert.match(w.tg.calls[0].body.text, /Claude \(oc_claude_test\)/);

      // Only the hash is stored.
      const dump = JSON.stringify(await w.stores.dump());
      assert.ok(!dump.includes(token));

      assert.deepEqual(await getCardStatus(receipt.card_id, w.deps), {
        card_id: receipt.card_id,
        status: "pending",
        expires_at: receipt.expires_at,
      });
      await w.fails(getCardStatus(receipt.card_id, { ...w.deps, client: CODEX }), "card_not_found");
      await w.fails(getCardStatus("vc_" + "0".repeat(32), w.deps), "card_not_found");

      // Wrong tokens: malformed, well-formed-but-unknown, and one flipped character.
      const flipped = (token[0] === "A" ? "B" : "A") + token.slice(1);
      for (const wrong of ["", "short", "x".repeat(43), flipped, `${token}x`, receipt.card_id]) {
        const r = await submitCard(wrong, { secret: SECRET_A }, w.deps);
        assert.equal(r.ok, false);
        assert.equal(r.ok ? "" : r.code, "invalid_token");
        assert.deepEqual(await lookupCard(wrong, w.deps), { state: "invalid" });
      }
      assert.equal((await listEntries({}, w.deps)).length, 0);
      assert.equal((await lookupCard(token, w.deps)).state, "pending", "GET never consumes the token");

      // A rejected submission (bad secret) does not burn the card.
      const tooShort = await submitCard(token, { secret: "short" }, w.deps);
      assert.equal(tooShort.ok ? "" : tooShort.code, "invalid_input");

      // First valid submit wins; the second is refused and changes nothing.
      const first = await submitCard(token, { secret: SECRET_A }, w.deps);
      assert.equal(first.ok, true);
      const second = await submitCard(token, { secret: SECRET_B }, w.deps);
      assert.equal(second.ok ? "" : second.code, "already_used");
      assert.deepEqual(await lookupCard(token, w.deps), { state: "used" });
      const entries = await listEntries({}, w.deps);
      assert.equal(entries.length, 1);
      assert.equal(await vaultSecret(w, entries[0].id), SECRET_A);

      const done = await getCardStatus(receipt.card_id, w.deps);
      assert.equal(done.status, "completed");
      assert.equal(done.entry_id, entries[0].id);
      assert.deepEqual(done.entry, entries[0]);

      // Concurrent double-submit of a fresh card: exactly one wins.
      await requestCard({ client: CLAUDE, site: "race.example", account: "r", kind: "password", reason: "race" }, w.deps);
      const raceToken = w.lastToken();
      const race = await Promise.all([
        submitCard(raceToken, { secret: SECRET_B }, w.deps),
        submitCard(raceToken, { secret: SECRET_C }, w.deps),
      ]);
      assert.equal(race.filter((r) => r.ok).length, 1);
      assert.equal((await listEntries({ site: "race.example" }, w.deps)).length, 1);

      // Expiry.
      const late = await requestCard(
        { client: CLAUDE, site: "gitlab.com", account: "late", kind: "api_key", reason: "expiry test" },
        w.deps,
      );
      const lateToken = w.lastToken();
      w.clock.t += CARD_TTL_MS - 1;
      assert.equal((await getCardStatus(late.card_id, w.deps)).status, "pending");
      w.clock.t += 1;
      assert.equal((await getCardStatus(late.card_id, w.deps)).status, "expired");
      assert.deepEqual(await lookupCard(lateToken, w.deps), { state: "expired" });
      const expired = await submitCard(lateToken, { secret: SECRET_B }, w.deps);
      assert.equal(expired.ok ? "" : expired.code, "expired");
      assert.equal((await listEntries({ site: "gitlab.com" }, w.deps)).length, 0);
    });

    it("flagging one entry leaves the others active; re-entry keeps the id and replaces only the secret", async () => {
      const w = makeWorld(await makeStores());
      const a = await w.entered(CLAUDE, { site: "github.com", account: "bobmcw", purpose: "personal" }, SECRET_A);
      const b = await w.entered(CLAUDE, { site: "github.com", account: "echo-bot" }, SECRET_B);
      const c = await w.entered(CLAUDE, { site: "gitlab.com", account: "bobmcw" }, SECRET_C);

      const flagged = await flagForReentry(a.id, "401 from provider", w.deps);
      assert.equal(flagged.status, "needs_reentry");
      assert.equal(flagged.reentry_reason, "401 from provider");
      assert.equal(flagged.is_default, true, "flagging does not move the default");
      assert.equal((await getEntryMetadata(b.id, w.deps))?.status, "active");
      assert.equal((await getEntryMetadata(c.id, w.deps))?.status, "active");
      await w.fails(useEntry(a.id, CLAUDE, "use flagged", () => 1, w.deps), "entry_needs_reentry");
      assert.equal((await useEntry(b.id, CLAUDE, "use the other", () => "fine", w.deps)).result, "fine");
      assert.equal((await resolveEntry({ site: "github.com" }, w.deps)).status, "needs_reentry");

      // Re-entry card (by entry_id): fixed to the entry; operator-typed metadata is ignored.
      w.clock.t += 60_000;
      const receipt = await requestCard(
        { client: CLAUDE, site: "github.com", kind: "password", reason: "re-enter after 401", entry_id: a.id },
        w.deps,
      );
      assert.match(w.tg.calls[w.tg.calls.length - 1].body.text, /REPLACES the stored secret/);
      const result = await submitCard(
        w.lastToken(),
        { site: "evil.example", account: "someone-else", purpose: "hijack", secret: SECRET_A2 },
        w.deps,
      );
      assert.equal(result.ok, true);
      const after = (await getEntryMetadata(a.id, w.deps))!;
      assert.equal(result.ok && result.entry.id, a.id, "same entry id");
      assert.equal(result.ok && result.reentry, true);
      assert.equal(after.status, "active");
      assert.equal(after.reentry_reason, undefined);
      assert.equal(after.fingerprint, secretFingerprint(SECRET_A2));
      assert.equal(after.secret_length, SECRET_A2.length);
      for (const key of ["site", "account", "purpose", "label", "kind", "is_default", "created_at"] as const) {
        assert.equal(after[key], a[key], `${key} unchanged by re-entry`);
      }
      assert.equal((await listEntries({}, w.deps)).length, 3, "no entry was added");
      assert.equal((await listEntries({ site: "evil.example" }, w.deps)).length, 0);
      assert.equal(await vaultSecret(w, a.id), SECRET_A2);
      assert.equal(await vaultSecret(w, b.id), SECRET_B, "other entries' secrets are untouched");
      assert.equal(await vaultSecret(w, c.id), SECRET_C);
      assert.equal((await getCardStatus(receipt.card_id, w.deps)).entry_id, a.id);
      assert.equal((await w.ledger.list({ capability: "vault.entry.reentry" })).length, 1);
      const used = await useEntry(a.id, CLAUDE, "use after re-entry", (s) => s === SECRET_A2, w.deps);
      assert.equal(used.result, true);

      await w.fails(flagForReentry("ve_" + "0".repeat(32), "x", w.deps), "entry_not_found");
      await w.fails(
        requestCard({ client: CLAUDE, site: "gitlab.com", kind: "password", reason: "wrong site", entry_id: a.id }, w.deps),
        "entry_mismatch",
      );
    });

    it("delete affects exactly one entry", async () => {
      const w = makeWorld(await makeStores());
      const a = await w.entered(CLAUDE, { site: "github.com", account: "bobmcw" }, SECRET_A);
      const b = await w.entered(CLAUDE, { site: "github.com", account: "echo-bot" }, SECRET_B);
      const c = await w.entered(CLAUDE, { site: "gitlab.com", account: "bobmcw" }, SECRET_C);
      const before = { b: await getEntryMetadata(b.id, w.deps), c: await getEntryMetadata(c.id, w.deps) };

      const gone = await deleteEntry(a.id, w.deps);
      assert.equal(gone.status, "deleted");
      assert.equal(gone.is_default, false);
      assert.deepEqual(await getEntryMetadata(b.id, w.deps), before.b);
      assert.deepEqual(await getEntryMetadata(c.id, w.deps), before.c);
      assert.deepEqual((await listEntries({}, w.deps)).map((e) => e.id).sort(), [b.id, c.id].sort());
      assert.equal((await getEntryMetadata(a.id, w.deps))?.status, "deleted");
      await w.fails(deleteEntry(a.id, w.deps), "entry_not_found");
      await w.fails(useEntry(a.id, CLAUDE, "use deleted", () => 1, w.deps), "entry_not_found");
      await w.fails(resolveEntry({ site: "github.com", account: "bobmcw" }, w.deps), "entry_not_found");
      assert.equal((await useEntry(b.id, CLAUDE, "still works", (s) => s === SECRET_B, w.deps)).result, true);
      assert.equal((await useEntry(c.id, CLAUDE, "still works", (s) => s === SECRET_C, w.deps)).result, true);

      // The identity is free again: a new entry gets a NEW id and its own vault key.
      const reborn = await w.entered(CLAUDE, { site: "github.com", account: "bobmcw" }, SECRET_A2);
      assert.notEqual(reborn.id, a.id);
      assert.equal(await vaultSecret(w, reborn.id), SECRET_A2);

      // A pending re-entry card for an entry deleted meanwhile cannot resurrect it.
      await requestCard({ client: CLAUDE, site: "gitlab.com", account: "bobmcw", kind: "password", reason: "re" }, w.deps);
      const token = w.lastToken();
      await deleteEntry(c.id, w.deps);
      const r = await submitCard(token, { secret: SECRET_A }, w.deps);
      assert.equal(r.ok ? "" : r.code, "entry_gone");
      assert.equal(await vaultSecret(w, c.id), SECRET_C);
    });

    it("validates input, fails closed, and never overwrites on a clash", async () => {
      const w = makeWorld(await makeStores());
      assert.equal(normalizeSite(" HTTPS://user@WWW.Example.COM:8443/a/b?c#d "), "example.com");
      for (const bad of ["", "exa mple.com", "-bad.com", "a..b", "<script>", 42]) {
        assert.throws(() => normalizeSite(bad), (e: unknown) => e instanceof EntryError && e.code === "invalid_site");
      }

      const base = { client: CLAUDE, site: "github.com", kind: "password" as EntryKind, reason: "r" };
      await w.fails(requestCard({ ...base, kind: "ssh_key" as EntryKind }, w.deps), "invalid_kind");
      await w.fails(requestCard({ ...base, reason: "  " }, w.deps), "invalid_reason");
      await w.fails(requestCard({ ...base, account: "has space" }, w.deps), "invalid_account");
      await w.fails(requestCard({ ...base, account: "ghp_" + "a1B2".repeat(9) }, w.deps), "invalid_account");
      await w.fails(requestCard({ ...base, client: { ...CLAUDE, client_id: "" } }, w.deps), "invalid_client");
      await w.fails(requestCard(base, { ...w.deps, env: { ...ENV, ECHO_VAULT_PUBLIC_URL: "" } }), "public_url_not_configured");
      await w.fails(
        requestCard(base, { ...w.deps, env: { ...ENV, ECHO_VAULT_PUBLIC_URL: "http://vault.example.test" } }),
        "public_url_not_configured",
      );
      await w.fails(
        requestCard(base, { ...w.deps, env: { ...ENV, ECHO_VAULT_APPROVER_TELEGRAM_ID: "" } }),
        "approver_not_configured",
      );
      assert.equal(w.tg.calls.length, 0, "nothing was sent for rejected requests");
      assert.equal((await w.stores.dump()).length, 0, "nothing was stored for rejected requests");

      // Telegram down → the card is expired, not left usable.
      const down = fakeTelegram("throw");
      const out = captureOutput();
      try {
        await w.fails(requestCard(base, { ...w.deps, fetch: down.fetch }), "card_notification_failed");
      } finally {
        out.restore();
      }
      assert.ok(!out.text().includes(BOT_TOKEN), "bot token is not logged");
      const leftover = /\/card\/([A-Za-z0-9_-]{43})/.exec(String(down.calls[0].body.text))![1];
      assert.deepEqual(await lookupCard(leftover, w.deps), { state: "expired" });

      // Operator types an identity that already exists on a NEW card → refused, nothing overwritten, card still usable.
      const a = await w.entered(CLAUDE, { site: "github.com", account: "bobmcw" }, SECRET_A);
      const clash = await w.enter(CLAUDE, { site: "github.com" }, SECRET_B, { account: "BOBMCW" });
      assert.equal(clash.result.ok ? "" : clash.result.code, "entry_exists");
      assert.equal(await vaultSecret(w, a.id), SECRET_A);
      assert.equal((await getEntryMetadata(a.id, w.deps))?.fingerprint, secretFingerprint(SECRET_A));
      const retried = await submitCard(clash.token, { account: "other-acct", purpose: "ci", secret: SECRET_B }, w.deps);
      assert.equal(retried.ok, true);
      assert.equal(retried.ok && retried.entry.label, "github.com — other-acct — ci");

      // Vault write failure → nothing recorded, card released for a retry.
      const broken = new FakeVaultBackend();
      broken.put = async () => {
        throw new Error(`gate exploded while storing ${SECRET_C}`);
      };
      await requestCard({ ...base, account: "vault-down" }, w.deps);
      const t = w.lastToken();
      const out2 = captureOutput();
      let failed;
      try {
        failed = await submitCard(t, { secret: SECRET_C }, { ...w.deps, backend: broken });
      } finally {
        out2.restore();
      }
      assert.equal(failed.ok ? "" : failed.code, "vault_unavailable");
      assert.ok(!JSON.stringify(failed).includes(SECRET_C) && !out2.text().includes(SECRET_C));
      assert.equal(await (await w.stores.entries.findIdentity("github.com", "vault-down", "password")), null);
      assert.equal((await submitCard(t, { secret: SECRET_C }, w.deps)).ok, true, "same card works once the vault is back");

      // Metadata updates respect identity uniqueness.
      await w.fails(updateEntryMetadata(a.id, { account: "other-acct" }, w.deps), "entry_exists");
      const renamed = await updateEntryMetadata(a.id, { account: "bob2", purpose: "main" }, w.deps);
      assert.equal(renamed.label, "github.com — bob2 — main");
      assert.equal(renamed.fingerprint, a.fingerprint);
      await w.fails(updateEntryMetadata(a.id, { purpose: "bad\npurpose<>" }, w.deps), "invalid_purpose");

      // Per-client cap on open cards.
      const spam = makeWorld(await makeStores());
      for (let i = 0; i < MAX_PENDING_CARDS_PER_CLIENT; i += 1) await requestCard({ ...base, account: `acct${i}` }, spam.deps);
      await spam.fails(requestCard({ ...base, account: "one-too-many" }, spam.deps), "too_many_pending_cards");
      await requestCard({ ...base, client: CODEX }, spam.deps); // another client is unaffected
    });
  });
}

runSuite("memory stores", async () => {
  const entries = new MemoryEntryStore();
  const cards = new MemoryCardStore();
  return { entries, cards, dump: async () => [...entries.dumpForTests(), ...cards.dumpForTests()] };
});

// The SQL stores against a real (embedded) Postgres with the real migration.
let pglite: Promise<import("@electric-sql/pglite").PGlite> | null = null;
runSuite("sql stores on PGlite", async () => {
  pglite ??= (async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const pg = new PGlite();
    await pg.exec(readFileSync(new URL("../../../../migrations/0005_vault_entries.sql", import.meta.url), "utf8"));
    return pg;
  })();
  const pg = await pglite;
  await pg.exec("delete from vault_cards; delete from vault_entries;");
  const sql = {
    query: async (text: string, params: unknown[] = []) => (await pg.query(text, params)).rows,
  } as unknown as Sql;
  const provider = async () => sql;
  return {
    entries: new SqlEntryStore(provider),
    cards: new SqlCardStore(provider),
    dump: async () => [
      ...(await pg.query("select * from vault_entries")).rows,
      ...(await pg.query("select * from vault_cards")).rows,
    ],
  };
});

describe("vault v2 cards — SQL constraints (PGlite)", () => {
  it("the schema itself refuses a second default and a duplicate identity, and has no secret column", async () => {
    const pg = await pglite!;
    await pg.exec("delete from vault_cards; delete from vault_entries;");
    const ins = (id: string, account: string, isDefault: boolean) =>
      pg.query(
        `insert into vault_entries (id, site, account, purpose, label, kind, is_default, fingerprint, secret_length)
         values ($1, 'github.com', $2, 'general', 'l', 'password', $3, 'deadbeef', 12)`,
        [id, account, isDefault],
      );
    await ins("ve_" + "1".repeat(32), "one", true);
    await assert.rejects(ins("ve_" + "2".repeat(32), "two", true), /vault_entries_one_default_uidx/);
    await assert.rejects(ins("ve_" + "3".repeat(32), "ONE", false), /vault_entries_identity_uidx/);
    await ins("ve_" + "4".repeat(32), "two", false);
    await assert.rejects(
      pg.query("update vault_entries set is_default = true where account = 'two'"),
      /vault_entries_one_default_uidx/,
    );
    const cols = await pg.query<{ table_name: string; column_name: string }>(
      "select table_name, column_name from information_schema.columns where table_name in ('vault_entries', 'vault_cards')",
    );
    const names = cols.rows.map((r) => r.column_name);
    assert.ok(names.length > 20);
    for (const n of names) assert.ok(!/^(secret|password|value|token)$/.test(n), `unexpected column ${n}`);
    await pg.exec("delete from vault_entries;");
  });
});

after(async () => {
  if (pglite) await (await pglite).close();
});
