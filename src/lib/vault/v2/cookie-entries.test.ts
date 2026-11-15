// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * `cookie` entries end to end, in memory: card page (form + JSON submit),
 * multi-account entries, entry_use through the gateway (Cookie header, no
 * Authorization, redaction, Set-Cookie rotation, no_cookie_for_host), the SQL
 * migration, and a leak scan over everything a caller, a ledger row, a log line
 * or a page could carry. Fakes: the vault backend, Telegram, the site. No network.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, describe, it } from "node:test";
import type { Sql } from "../../db.ts";
import { FakeVaultBackend } from "../backend.ts";
import { CredentialStore } from "../store.ts";
import { MemoryApprovalStore } from "./approvals.ts";
import { CARD_JSON_HEADER, handleCardRequest, MAX_COOKIE_CARD_BODY_BYTES } from "./card-pages.ts";
import {
  getCardStatus,
  listEntries,
  MemoryCardStore,
  MemoryEntryStore,
  refreshCookieJar,
  requestCard,
  secretFingerprint,
  SqlCardStore,
  SqlEntryStore,
  submitCard,
  type CardsDeps,
} from "./cards.ts";
import type { ClientIdentity } from "./contracts.ts";
import { describeJar, parseCookieInput, parseStoredJar, serializeJar } from "./cookie-jar.ts";
import { MemoryEntryGrantStore } from "./entry-grants.ts";
import { dispatchTool, type GatewayDeps, type GatewayResult } from "./gateway.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";
import { MemoryRateLimitStore, setDefaultRateLimitStore } from "./rate-limit-store.ts";
import { handleTelegramWebhook } from "./telegram.ts";

setDefaultRateLimitStore(new MemoryRateLimitStore());

const ORIGIN = "https://vault.example.test";
const APPROVER_ID = 424242;
const WEBHOOK_SECRET = "test-webhook-secret-0123456789";
const ENV: NodeJS.ProcessEnv = {
  TELEGRAM_BOT_TOKEN: "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789",
  ECHO_VAULT_APPROVER_TELEGRAM_ID: String(APPROVER_ID),
  ECHO_VAULT_PUBLIC_URL: ORIGIN,
  ECHO_VAULT_APPROVAL_HMAC_KEY: "test-only-approval-hmac-key-0123456789abcdef",
  ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET: WEBHOOK_SECRET,
};
const SITE = "shop.example.com";
const LOCAL: ClientIdentity = { client_id: "local:owner", name: "owner", kind: "local", scopes: [] };

// Cookie values: not provider-shaped, and with characters that make the URL-encoded and base64 forms differ.
const ALICE_SID = "al/ice+sess=ion&tok-0001";
const ALICE_CSRF = "alice-csrf-value-0002";
const BOB_SID = "bo/b+session=value&-0003";
const ALICE_ROTATED = "al/ice+rotated=sess&-0004";
const BOB_ROTATED = "bob-rotated-session-0005";
const WIDE = "wide-domain-cookie-0006";
const APP_ONLY = "app-hostonly-cookie-0007";
const PATHED = "path-scoped-cookie-0008";
const JSON_SUBMITTED = "json+submitted/value=0009";
const FOREIGN_SET = "foreign-set-cookie-0010";
const REJECTED_PASTE = "rejected;paste-value-0011";
const SQL_VALUE = "sql-store-cookie-value-0012";
const ALL_VALUES = [ALICE_SID, ALICE_CSRF, BOB_SID, ALICE_ROTATED, BOB_ROTATED, WIDE, APP_ONLY, PATHED, JSON_SUBMITTED, FOREIGN_SET, REJECTED_PASTE, SQL_VALUE];

/** Every form of a value a leak could take. */
function variants(value: string): string[] {
  return [
    ...new Set([
      value,
      encodeURIComponent(value),
      new URLSearchParams({ v: value }).toString().slice(2),
      Buffer.from(value, "utf8").toString("base64"),
      Buffer.from(value, "utf8").toString("base64url"),
      JSON.stringify(value).slice(1, -1),
    ]),
  ];
}

function scan(label: string, haystack: unknown, values: string[] = ALL_VALUES): void {
  const text = typeof haystack === "string" ? haystack : JSON.stringify(haystack);
  for (const value of values) {
    for (const v of variants(value)) assert.equal(text.includes(v), false, `${label} contains a cookie value (${v === value ? "raw" : "encoded"})`);
  }
}

// Everything that left the system under test, scanned again at the end of the file.
const captured: string[] = [];
const everyResult: unknown[] = [];
const everyPage: string[] = [];
const everyLedger: unknown[] = [];
const everyRow: unknown[] = [];
let restore: (() => void) | null = null;

before(() => {
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: unknown) => {
    captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  restore = () => {
    process.stderr.write = orig as typeof process.stderr.write;
  };
});

after(() => {
  restore?.();
  // The scanner itself must trip on each encoding it claims to cover.
  for (const v of variants(ALICE_SID)) assert.throws(() => scan("self-test", `x${v}y`));
  assert.ok(captured.join("").includes("vault_entry_cookie_refreshed"), "logs were captured");
  scan("log lines", captured.join("\n"));
  scan("tool results", everyResult);
  scan("rendered pages and JSON answers", everyPage.join("\n"));
  scan("ledger rows", everyLedger);
  scan("stored rows (entries, cards)", everyRow);
});

interface SiteCall {
  host: string;
  path: string;
  method: string;
  cookie: string | null;
  authorization: string | null;
  userAgent: string | null;
}

function makeWorld(opts: { backend?: FakeVaultBackend } = {}) {
  const telegram: Array<{ method: string; payload: Record<string, unknown> }> = [];
  const telegramFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    assert.ok(url.startsWith("https://api.telegram.org/bot"));
    telegram.push({ method: url.split("/").pop() ?? "", payload: JSON.parse(String(init?.body ?? "{}")) });
    return new Response(JSON.stringify({ ok: true, result: { message_id: telegram.length } }), { status: 200 });
  }) as typeof fetch;

  // The site: echoes what it was sent in several encodings, rotates sessions, redirects to a login page.
  const site = { calls: [] as SiteCall[], reject: new Set<string>(), rotateTo: new Map<string, string>() };
  const siteFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const h = new Headers(init?.headers);
    const cookie = h.get("cookie");
    site.calls.push({ host: url.hostname, path: url.pathname, method: init?.method ?? "GET", cookie, authorization: h.get("authorization"), userAgent: h.get("user-agent") });
    const pairs = Object.fromEntries((cookie ?? "").split("; ").filter(Boolean).map((p) => [p.slice(0, p.indexOf("=")), p.slice(p.indexOf("=") + 1)]));
    const values = Object.values(pairs) as string[];
    const headers = new Headers({ "content-type": "application/json" });
    if ([...site.reject].some((v) => values.includes(v))) {
      return new Response(JSON.stringify({ message: "session expired", you_sent: cookie }), { status: 401, headers });
    }
    if (url.pathname === "/login-redirect") {
      headers.set("location", "/login?next=%2Faccount");
      return new Response(null, { status: 302, headers });
    }
    if (url.pathname === "/rotate") {
      const next = site.rotateTo.get(String(pairs.sid));
      if (next) {
        headers.append("set-cookie", `sid=${next}; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax`);
        headers.append("set-cookie", `theme=dark; Path=/`); // too short to store
        return new Response(JSON.stringify({ rotated: true, new_session: next, old: cookie }), { status: 200, headers });
      }
    }
    if (url.pathname === "/set-foreign") {
      headers.append("set-cookie", `sid=${FOREIGN_SET}; Domain=evil.example.net; Path=/`);
      headers.append("set-cookie", `sid=${FOREIGN_SET}; Domain=com; Path=/`);
      headers.append("set-cookie", `sid=${FOREIGN_SET}; Domain=other.${url.hostname}; Path=/`);
    }
    if (url.pathname === "/text") {
      return new Response(`Cookie: ${cookie}\nvalues: ${values.join(",")}\nencoded: ${values.map(encodeURIComponent).join(",")}`, { status: 200, headers: { "content-type": "text/plain" } });
    }
    return new Response(
      JSON.stringify({
        ok: true,
        path: url.pathname,
        cookies: pairs,
        headers: { Cookie: cookie, "X-Raw": cookie },
        raw: cookie,
        encoded: values.map(encodeURIComponent),
        form_encoded: values.map((v) => new URLSearchParams({ v }).toString().slice(2)),
        base64: values.map((v) => Buffer.from(v).toString("base64")),
        base64url: values.map((v) => Buffer.from(v).toString("base64url")),
      }),
      { status: 200, headers },
    );
  }) as typeof fetch;

  const backend = opts.backend ?? new FakeVaultBackend();
  const ledgerStore = new MemoryLedgerStore();
  const ledger = new Ledger({ store: ledgerStore });
  const approvalStore = new MemoryApprovalStore();
  const entries = new MemoryEntryStore();
  const cardStore = new MemoryCardStore();
  const cards: CardsDeps = { entries, cards: cardStore, backend, ledger: (input) => ledger.append(input), fetch: telegramFetch, env: ENV };
  let resolved = 0;
  const deps: GatewayDeps = {
    ledger: (input) => ledger.append(input),
    listLedger: (o) => ledger.list(o),
    verifyLedger: () => ledger.verify(),
    ledgerHead: () => ledger.head(),
    approvals: { store: approvalStore, fetch: telegramFetch, env: ENV },
    rules: [],
    store: new CredentialStore(backend),
    cards,
    grants: new MemoryEntryGrantStore(),
    fetch: siteFetch,
    resolveHost: async () => {
      resolved += 1;
      return ["93.184.216.34"];
    },
  };

  const call = async (identity: ClientIdentity, name: string, args: unknown = {}): Promise<GatewayResult> => {
    const result = await dispatchTool(identity, name, args, deps);
    everyResult.push(result);
    return result;
  };
  const tap = async (approvalId: string): Promise<void> => {
    const prompt = [...telegram].reverse().find((c) => {
      const keyboard = (c.payload.reply_markup as { inline_keyboard?: Array<Array<{ text: string; callback_data: string }>> } | undefined)?.inline_keyboard;
      return keyboard?.[0]?.some((b) => b.callback_data.includes(approvalId));
    });
    assert.ok(prompt, "no Telegram prompt for that approval");
    const buttons = (prompt.payload.reply_markup as { inline_keyboard: Array<Array<{ text: string; callback_data: string }>> }).inline_keyboard[0];
    const res = await handleTelegramWebhook(
      new Request(`${ORIGIN}/api/telegram/webhook`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-telegram-bot-api-secret-token": WEBHOOK_SECRET },
        body: JSON.stringify({ callback_query: { id: "cq1", from: { id: APPROVER_ID }, data: buttons.find((b) => b.text === "Approve")?.callback_data, message: { message_id: 1, chat: { id: APPROVER_ID } } } }),
      }),
      { store: approvalStore, fetch: telegramFetch, env: ENV },
    );
    assert.equal(res.status, 200);
  };
  const latestToken = (): string => {
    const text = [...telegram].reverse().find((c) => typeof c.payload.text === "string" && /\/card\//.test(c.payload.text as string));
    const token = /\/card\/([A-Za-z0-9_-]{43})/.exec(String(text?.payload.text))?.[1];
    assert.ok(token, "no card link was sent to the owner");
    return token;
  };
  /** A response of the card route, recorded for the leak scan. */
  const cardRequest = async (request: Request, token: string): Promise<{ status: number; text: string; headers: Headers }> => {
    const res = await handleCardRequest(request, token, cards);
    const text = await res.text();
    everyPage.push(`${res.status} ${JSON.stringify([...res.headers])}\n${text}`);
    return { status: res.status, text, headers: res.headers };
  };
  const formPost = (token: string, fields: Record<string, string>) =>
    cardRequest(
      new Request(`${ORIGIN}/card/${token}`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", origin: "null", "sec-fetch-site": "same-origin" },
        body: new URLSearchParams(fields).toString(),
      }),
      token,
    );
  const jsonPost = (token: string, body: unknown, headers: Record<string, string> = {}) =>
    cardRequest(
      new Request(`${ORIGIN}/card/${token}`, {
        method: "POST",
        headers: { "content-type": "application/json", [CARD_JSON_HEADER]: "submit", ...headers },
        body: typeof body === "string" ? body : JSON.stringify(body),
      }),
      token,
    );
  const requestCookieCard = async (who: ClientIdentity, account: string | undefined, site = SITE): Promise<string> => {
    const asked = await call(who, "entry_request_card", { site, ...(account ? { account } : {}), kind: "cookie", reason: "need this account's session" });
    assert.equal(asked.ok, true, JSON.stringify(asked));
    return latestToken();
  };
  /** Card flow: the agent asks, the owner pastes cookies into the form. Returns the entry id. */
  const seed = async (who: ClientIdentity, account: string, pasted: string, site = SITE): Promise<string> => {
    const token = await requestCookieCard(who, account, site);
    const res = await formPost(token, { secret: pasted });
    assert.equal(res.status, 200, res.text.slice(0, 300));
    const listed = (await call(who, "entry_list", { site })) as { ok: true; data: { entries: Array<Record<string, unknown>> } };
    const id = listed.data.entries.find((e) => e.account === account && e.kind === "cookie")?.id;
    assert.ok(typeof id === "string");
    return id;
  };
  /** entry_use as an agent whose owner approves the first read of each (entry, host, path). */
  const use = async (who: ClientIdentity, args: Record<string, unknown>): Promise<GatewayResult> => {
    let r = await call(who, "entry_use", args);
    if (!r.ok && r.error === "approval_required") {
      await tap(String(r.approval_id));
      r = await call(who, "entry_use", { ...args, approval_id: r.approval_id });
    }
    return r;
  };
  const rows = () => ledgerStore.scanAscending(0, 10_000);
  const finish = async (): Promise<void> => {
    everyLedger.push(await rows());
    everyRow.push(entries.dumpForTests(), cardStore.dumpForTests());
    assert.equal((await ledger.verify()).ok, true);
  };
  const jarOf = async (id: string) => parseStoredJar((await backend.get(`echo_vault_entry_${id}`, "entry", "test")).secret);
  return { deps, cards, call, tap, site, telegram, entries, cardStore, backend, ledger, rows, finish, seed, use, requestCookieCard, latestToken, cardRequest, formPost, jsonPost, jarOf, resolved: () => resolved };
}

function agent(id: string): ClientIdentity {
  return { client_id: id, name: id, kind: "oauth", scopes: ["vault.read", "vault.write"] };
}

function ok(result: GatewayResult): Record<string, unknown> {
  assert.equal(result.ok, true, JSON.stringify(result));
  return (result as { data: Record<string, unknown> }).data;
}

function failed(result: GatewayResult, error: string): Record<string, unknown> {
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal((result as { error: string }).error, error, JSON.stringify(result));
  return result as Record<string, unknown>;
}

const get = (account: string | undefined, path: string, extra: Record<string, unknown> = {}) => ({
  site: SITE,
  ...(account ? { account } : {}),
  method: "GET",
  url_path: path,
  task: "read the account page",
  ...extra,
});

// ---------------------------------------------------------------------------

describe("cookie entries: several accounts on one site", () => {
  it("two cookie entries for the same site coexist, the first is the default, and each is used on its own", async () => {
    const w = makeWorld();
    const who = agent("oc_cookie_multi");
    const alice = await w.seed(who, "alice@example.com", `sid=${ALICE_SID}; csrf=${ALICE_CSRF}; theme=dark`);
    const bob = await w.seed(who, "bob@example.com", `Cookie: sid=${BOB_SID}`);
    assert.notEqual(alice, bob);

    // What the agent sees: metadata without fingerprint, length or anything about the jar.
    const listed = ok(await w.call(who, "entry_list", { site: SITE })).entries as Array<Record<string, unknown>>;
    assert.deepEqual(listed.map((e) => [e.account, e.kind, e.is_default, e.status]), [
      ["alice@example.com", "cookie", true, "active"],
      ["bob@example.com", "cookie", false, "active"],
    ]);
    for (const e of listed) for (const k of ["fingerprint", "secret_length", "cookie_jar", "cookie_meta"]) assert.equal(k in e, false, k);

    // Stored once per account, as the canonical jar; nothing overwrote anything.
    assert.deepEqual((await w.jarOf(alice)).cookies.map((c) => [c.name, c.value, c.domain, c.hostOnly]), [["sid", ALICE_SID, "", true], ["csrf", ALICE_CSRF, "", true]]);
    assert.deepEqual((await w.jarOf(bob)).cookies.map((c) => [c.name, c.value]), [["sid", BOB_SID]]);

    const a = ok(await w.use(who, get("alice@example.com", "/account")));
    const b = ok(await w.use(who, get("bob@example.com", "/account")));
    const d = ok(await w.use(who, get(undefined, "/account"))); // no account → the site's default
    assert.deepEqual(w.site.calls.map((c) => c.cookie), [`sid=${ALICE_SID}; csrf=${ALICE_CSRF}`, `sid=${BOB_SID}`, `sid=${ALICE_SID}; csrf=${ALICE_CSRF}`]);
    // A Cookie header, no Authorization header, and the broker's honest User-Agent.
    for (const c of w.site.calls) {
      assert.equal(c.authorization, null);
      assert.equal(c.userAgent, "Echo-Credential-Broker/2.0");
      assert.equal(c.host, SITE);
    }
    assert.equal((a.entry as Record<string, unknown>).account, "alice@example.com");
    assert.equal((b.entry as Record<string, unknown>).account, "bob@example.com");
    assert.equal((d.entry as Record<string, unknown>).account, "alice@example.com");

    // The site echoed every cookie value (raw, in a header map, URL-encoded, base64): all redacted.
    for (const data of [a, b, d]) {
      assert.equal(data.status, 200);
      const body = data.body as Record<string, unknown>;
      assert.equal(body.path, "/account");
      assert.match(String((body.cookies as Record<string, unknown>).sid), /^\[REDACTED/);
      for (const list of [body.encoded, body.form_encoded, body.base64, body.base64url] as string[][]) {
        for (const item of list) assert.match(item, /REDACTED/);
      }
      for (const k of ["set-cookie", "set_cookie", "headers_received", "cookie_jar"]) assert.equal(k in data, false);
      scan("entry_use result", data);
    }
    // A plain-text echo is redacted too.
    const text = ok(await w.use(who, get("bob@example.com", "/text")));
    assert.equal(typeof text.body, "string");
    assert.ok(String(text.body).includes("REDACTED"));
    scan("text echo", text);

    // The owner (local stdio) sees the jar's metadata: names, domains, count, expiry — never a value.
    const admin = ok(await w.call(LOCAL, "admin_list_entries", { site: SITE })).entries as Array<Record<string, unknown>>;
    const aliceMeta = admin.find((e) => e.id === alice) as Record<string, unknown>;
    assert.deepEqual(aliceMeta.cookie_jar, { count: 2, names: ["csrf", "sid"], domains: [SITE], truncated: false, expires_at: null, session_cookies: 2 });
    assert.equal(aliceMeta.fingerprint, secretFingerprint(serializeJar(await w.jarOf(alice))));
    scan("owner listing", admin);

    const uses = (await w.rows()).filter((r) => r.capability === "vault.entry.use.read" && r.result === "ok");
    assert.equal(uses.length, 4);
    assert.ok(uses.every((r) => /^vault:\/\/entry\/ve_[0-9a-f]{32}$/.test(r.credential_ref ?? "") && r.http_status === 200));
    await w.finish();
  });
});

describe("cookie entries: Set-Cookie rotation", () => {
  it("applies the response's Set-Cookie to the stored jar, never returns it, and the next use sends the rotated value", async () => {
    const w = makeWorld();
    const who = agent("oc_cookie_rotate");
    const alice = await w.seed(who, "alice@example.com", `sid=${ALICE_SID}; csrf=${ALICE_CSRF}`);
    const bob = await w.seed(who, "bob@example.com", `sid=${BOB_SID}`);
    const before = (await listEntries({ site: SITE }, w.cards)).find((e) => e.id === alice)!;
    w.site.rotateTo.set(ALICE_SID, ALICE_ROTATED);

    const rotated = ok(await w.use(who, get("alice@example.com", "/rotate")));
    // The response echoed the NEW session value in its body: redacted, because it was armed before the body was read.
    assert.match(String((rotated.body as Record<string, unknown>).new_session), /^\[REDACTED/);
    assert.equal(JSON.stringify(rotated).toLowerCase().includes("set-cookie"), false);
    scan("rotation result", rotated);

    // Stored server-side: value and expiry updated, the short "theme" cookie not stored, bob untouched.
    const jar = await w.jarOf(alice);
    assert.deepEqual(jar.cookies.map((c) => [c.name, c.value, c.domain, c.secure, c.httpOnly]), [["sid", ALICE_ROTATED, "", true, true], ["csrf", ALICE_CSRF, "", false, false]]);
    assert.ok((jar.cookies[0].expires ?? 0) > Date.now() / 1000 + 3000);
    assert.deepEqual((await w.jarOf(bob)).cookies.map((c) => c.value), [BOB_SID]);
    const afterMeta = (await listEntries({ site: SITE }, w.cards)).find((e) => e.id === alice)!;
    assert.notEqual(afterMeta.fingerprint, before.fingerprint);
    assert.equal(afterMeta.fingerprint, secretFingerprint(serializeJar(jar)));
    assert.equal(afterMeta.status, "active");
    assert.equal(afterMeta.rotation_count, before.rotation_count, "a site refresh is not an owner rotation");
    assert.ok(afterMeta.cookie_jar?.expires_at, "earliest expiry is now known");

    // Second use: the rotated value is what goes out.
    ok(await w.use(who, get("alice@example.com", "/account")));
    assert.deepEqual(w.site.calls.map((c) => c.cookie), [`sid=${ALICE_SID}; csrf=${ALICE_CSRF}`, `sid=${ALICE_ROTATED}; csrf=${ALICE_CSRF}`]);

    const refresh = (await w.rows()).filter((r) => r.capability === "vault.entry.cookie_refresh");
    assert.deepEqual(refresh.map((r) => [r.result, r.client_id, r.credential_ref]), [["ok", who.client_id, `vault://entry/${alice}`]]);
    await w.finish();
  });

  it("a failed write-back does not fail the request; it is logged and ledgered, and the old jar stays", async () => {
    class FlakyBackend extends FakeVaultBackend {
      failPuts = false;
      override async put(...args: Parameters<FakeVaultBackend["put"]>): ReturnType<FakeVaultBackend["put"]> {
        if (this.failPuts) throw new Error(`gate down while storing ${args[2]}`);
        return super.put(...args);
      }
    }
    const backend = new FlakyBackend();
    const w = makeWorld({ backend });
    const who = agent("oc_cookie_flaky");
    const bob = await w.seed(who, "bob@example.com", `sid=${BOB_SID}`);
    w.site.rotateTo.set(BOB_SID, BOB_ROTATED);
    backend.failPuts = true;
    const logMark = captured.length;

    const res = ok(await w.use(who, get("bob@example.com", "/rotate")));
    assert.equal(res.status, 200);
    scan("result of a use whose write-back failed", res);
    assert.deepEqual((await w.jarOf(bob)).cookies.map((c) => c.value), [BOB_SID]);
    const refresh = (await w.rows()).filter((r) => r.capability === "vault.entry.cookie_refresh");
    assert.deepEqual(refresh.map((r) => [r.result, r.error]), [["error", "cookie_jar_persist_failed"]]);
    const logs = captured.slice(logMark).join("");
    assert.ok(logs.includes("vault_entry_cookie_refresh_failed"));
    scan("logs of the failed write-back", logs);
    // The use itself is on the ledger as ok.
    assert.ok((await w.rows()).some((r) => r.capability === "vault.entry.use.read" && r.result === "ok" && r.task === "read the account page"));
    await w.finish();
  });

  it("Set-Cookie for another site, a public suffix or a sibling host is ignored; refreshCookieJar refuses non-cookie targets", async () => {
    const w = makeWorld();
    const who = agent("oc_cookie_foreign");
    const bob = await w.seed(who, "bob@example.com", `sid=${BOB_SID}`);
    ok(await w.use(who, get("bob@example.com", "/set-foreign")));
    assert.deepEqual((await w.jarOf(bob)).cookies.map((c) => [c.value, c.domain]), [[BOB_SID, ""]]);
    assert.equal((await w.rows()).filter((r) => r.capability === "vault.entry.cookie_refresh").length, 0);

    // The write-back seam itself: only an active cookie entry, only a jar within the cap.
    const jar = parseCookieInput(`sid=${BOB_ROTATED}`, { site: SITE }).jar;
    assert.equal(await refreshCookieJar("ve_" + "0".repeat(32), who, serializeJar(jar), describeJar(jar, SITE), w.cards), false);
    assert.equal(await refreshCookieJar(bob, who, "x".repeat(40_000), describeJar(jar, SITE), w.cards), false);
    assert.deepEqual((await w.jarOf(bob)).cookies.map((c) => c.value), [BOB_SID]);
    assert.deepEqual(
      (await w.rows()).filter((r) => r.capability === "vault.entry.cookie_refresh").map((r) => r.error),
      ["cookie_jar_persist_failed", "cookie_jar_too_large"],
    );
    await w.finish();
  });
});

describe("cookie entries: which hosts and paths a jar may be sent to", () => {
  it("no matching cookie → no_cookie_for_host before any DNS lookup or request", async () => {
    const w = makeWorld();
    const who = agent("oc_cookie_hosts");
    await w.seed(who, "alice@example.com", `sid=${ALICE_SID}`); // header format: host-only, bound to the site
    ok(await w.use(who, get("alice@example.com", "/")));
    const sent = w.site.calls.length;
    const lookups = w.resolved();

    // api.<site> is an allowed host, but a host-only cookie of the site does not apply to it.
    const refused = failed(await w.use(who, get("alice@example.com", "/", { host: `api.${SITE}` })), "no_cookie_for_host");
    assert.match(String(refused.detail), /Nothing was sent/);
    assert.equal(w.site.calls.length, sent, "no request was made");
    assert.equal(w.resolved(), lookups, "no DNS lookup was made");
    const row = (await w.rows()).filter((r) => r.capability === "vault.entry.use.read").at(-1)!;
    assert.deepEqual([row.result, row.error, row.http_status], ["error", "no_cookie_for_host", undefined]);
    // Not a credential verdict: the entry stays active.
    assert.equal((await listEntries({ site: SITE }, w.cards))[0].status, "active");

    // Hosts outside the site are refused outright, also for cookie entries.
    for (const host of ["evil.com", `${SITE}.evil.com`, `not${SITE}`, "example.com", `bad host.${SITE}`]) {
      failed(await w.call(who, "entry_use", get("alice@example.com", "/", { host })), "hostname_not_allowed");
    }
    assert.equal(w.site.calls.length, sent);
    await w.finish();
  });

  it("a subdomain is usable only when a stored cookie covers it; path scope and expiry are honoured", async () => {
    const w = makeWorld();
    const who = agent("oc_cookie_sub");
    const soon = Math.floor(Date.now() / 1000) + 3600;
    const exported = JSON.stringify([
      { name: "wide", value: WIDE, domain: `.${SITE}`, path: "/", secure: true, httpOnly: true, hostOnly: false, expirationDate: soon },
      { name: "apponly", value: APP_ONLY, domain: `app.${SITE}`, path: "/", hostOnly: true, session: true },
      { name: "pathed", value: PATHED, domain: SITE, path: "/billing", hostOnly: true, session: true },
      { name: "elsewhere", value: FOREIGN_SET, domain: ".unrelated.org", path: "/" },
      { name: "pref", value: "en", domain: SITE },
    ]);
    const id = await w.seed(who, "carol@example.com", exported);
    assert.deepEqual((await w.jarOf(id)).cookies.map((c) => c.name), ["wide", "apponly", "pathed"]);

    const send = (host: string, path: string): Promise<GatewayResult> => w.use(who, get("carol@example.com", path, { host }));
    w.site.calls.length = 0;
    ok(await send(SITE, "/"));
    ok(await send(SITE, "/billing/invoices"));
    ok(await send(`app.${SITE}`, "/"));
    ok(await send(`deep.app.${SITE}`, "/"));
    assert.deepEqual(w.site.calls.map((c) => [c.host, c.cookie]), [
      [SITE, `wide=${WIDE}`],
      [SITE, `pathed=${PATHED}; wide=${WIDE}`],
      [`app.${SITE}`, `wide=${WIDE}; apponly=${APP_ONLY}`],
      [`deep.app.${SITE}`, `wide=${WIDE}`],
    ]);

    // A second, header-format entry for the same site has no domain cookie: subdomains are not covered.
    await w.seed(who, "dave@example.com", `sid=${BOB_SID}`);
    const before = w.site.calls.length;
    failed(await w.use(who, get("dave@example.com", "/", { host: `app.${SITE}` })), "no_cookie_for_host");
    ok(await w.use(who, get("dave@example.com", "/")));
    assert.deepEqual(w.site.calls.slice(before).map((c) => [c.host, c.cookie]), [[SITE, `sid=${BOB_SID}`]]);

    // A non-cookie entry keeps the old rule: the site or api.<site>, never another subdomain.
    const token = (ok(await w.call(who, "entry_request_card", { site: "bearer.example.com", account: "svc", kind: "api_key", reason: "seed" })), w.latestToken());
    assert.equal((await w.formPost(token, { secret: "plain-api-key-not-a-cookie-01" })).status, 200);
    failed(await w.call(who, "entry_use", { site: "bearer.example.com", account: "svc", method: "GET", url_path: "/", host: "app.bearer.example.com", task: "t" }), "hostname_not_allowed");
    await w.finish();
  });

  it("a 401 flags the cookie entry; a 302 to a login page is passed through and does not", async () => {
    const w = makeWorld();
    const who = agent("oc_cookie_401");
    const alice = await w.seed(who, "alice@example.com", `sid=${ALICE_SID}`);
    const bob = await w.seed(who, "bob@example.com", `sid=${BOB_SID}`);

    const redirect = ok(await w.use(who, get("alice@example.com", "/login-redirect")));
    assert.equal(redirect.status, 302);
    assert.equal(redirect.location, "/login?next=%2Faccount");
    assert.equal((await listEntries({ site: SITE }, w.cards)).find((e) => e.id === alice)?.status, "active");

    w.site.reject.add(BOB_SID);
    const rejected = failed(await w.use(who, get("bob@example.com", "/account")), "site_rejected_credential");
    assert.equal(rejected.entry_flagged_for_reentry, true);
    scan("401 result", rejected);
    const after = await listEntries({ site: SITE }, w.cards);
    assert.equal(after.find((e) => e.id === bob)?.status, "needs_reentry");
    assert.equal(after.find((e) => e.id === alice)?.status, "active");
    failed(await w.call(who, "entry_use", get("bob@example.com", "/account")), "entry_needs_reentry");

    // Re-entry through a card replaces only bob's jar and makes the entry usable again.
    ok(await w.call(who, "entry_request_card", { site: SITE, account: "bob@example.com", kind: "cookie", reason: "session expired", entry_id: bob }));
    const page = await w.formPost(w.latestToken(), { secret: `sid=${BOB_ROTATED}` });
    assert.equal(page.status, 200);
    assert.deepEqual((await w.jarOf(bob)).cookies.map((c) => c.value), [BOB_ROTATED]);
    assert.deepEqual((await w.jarOf(alice)).cookies.map((c) => c.value), [ALICE_SID]);
    const entry = (await listEntries({ site: SITE }, w.cards)).find((e) => e.id === bob)!;
    assert.deepEqual([entry.status, entry.rotation_count, entry.cookie_jar?.count], ["active", 1, 1]);
    ok(await w.use(who, get("bob@example.com", "/account")));
    assert.equal(w.site.calls.at(-1)?.cookie, `sid=${BOB_ROTATED}`);
    await w.finish();
  });
});

// ---------------------------------------------------------------------------

describe("cookie cards: the page", () => {
  it("GET shows a textarea and names the three formats; a valid paste creates the entry", async () => {
    const w = makeWorld();
    const who = agent("oc_cookie_page");
    const token = await w.requestCookieCard(who, "alice@example.com");
    const page = await w.cardRequest(new Request(`${ORIGIN}/card/${token}`), token);
    assert.equal(page.status, 200);
    assert.match(page.text, /<textarea id="f-secret" name="secret" rows="8"[^>]* required><\/textarea>/);
    assert.ok(!/type="password"/.test(page.text));
    for (const phrase of ["Cookie header", "JSON array", "Netscape cookies.txt"]) assert.ok(page.text.includes(phrase), phrase);
    const csp = page.headers.get("content-security-policy") ?? "";
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /form-action 'self'/);
    assert.ok(!/script-src|unsafe-inline|unsafe-eval|\*|connect-src/.test(csp), "the CSP is not relaxed for cookie cards");
    assert.ok(!/<script/i.test(page.text));

    const stored = await w.formPost(token, { secret: `sid=${ALICE_SID}; csrf=${ALICE_CSRF}; lang=en` });
    assert.equal(stored.status, 200);
    assert.match(stored.text, /Stored in vault/);
    assert.match(stored.text, /<dt>Cookies stored<\/dt><dd>2<\/dd>/);
    assert.match(stored.text, /1 with a value shorter than 8 characters/);
    assert.match(stored.text, /<dt>Kind<\/dt><dd>cookie<\/dd>/);
    scan("success page", stored.text);
    const [entry] = await listEntries({ site: SITE }, w.cards);
    assert.deepEqual([entry.kind, entry.account, entry.is_default, entry.cookie_jar?.count], ["cookie", "alice@example.com", true, 2]);
    // Single use.
    assert.equal((await w.cardRequest(new Request(`${ORIGIN}/card/${token}`), token)).status, 410);
    assert.equal((await w.formPost(token, { secret: `sid=${BOB_SID}` })).status, 410);
    await w.finish();
  });

  it("an invalid paste re-renders the form with a code and never echoes what was typed", async () => {
    const w = makeWorld();
    const who = agent("oc_cookie_badpaste");
    const token = await w.requestCookieCard(who, "alice@example.com");
    const cases: Array<[string, string]> = [
      [JSON.stringify([{ name: "sid", value: REJECTED_PASTE, domain: SITE }]), "invalid_cookie_value"],
      [`sid=${ALICE_SID}\r\nX-Injected: ${ALICE_CSRF}`, "invalid_cookie_header"],
      [`[{"name":"sid","value":"${ALICE_SID}"`, "invalid_cookie_json"],
      [JSON.stringify([{ name: "sid", value: ALICE_SID, domain: ".com" }]), "public_suffix_domain"],
      [JSON.stringify([{ name: "sid", value: ALICE_SID, domain: ".unrelated.org" }]), "no_usable_cookie"],
      ["theme=dark", "no_usable_cookie"],
      ["", "cookie_input_empty"],
    ];
    for (const [pasted, expected] of cases) {
      const res = await w.formPost(token, { secret: pasted });
      assert.equal(res.status, 400, expected);
      assert.ok(res.text.includes(`(${expected})`), `page names the code ${expected}`);
      assert.match(res.text, /<p class="err" role="alert">/);
      assert.match(res.text, /<textarea id="f-secret" name="secret"[^>]*><\/textarea>/, "the textarea is rendered empty");
      for (const typed of [REJECTED_PASTE, ALICE_SID, ALICE_CSRF, "X-Injected", "unrelated.org"]) assert.equal(res.text.includes(typed), false, `page echoes ${typed}`);
    }
    assert.equal((await listEntries({ site: SITE }, w.cards)).length, 0);
    // A value that fits the other fields must not become metadata.
    const misplaced = await w.formPost(token, { account: ALICE_SID, secret: `sid=${ALICE_SID}` });
    assert.equal(misplaced.status, 400);
    scan("misplaced value page", misplaced.text);
    // The card is still pending; a good paste then works.
    assert.equal((await w.formPost(token, { secret: `sid=${ALICE_SID}` })).status, 200);
    assert.equal((await listEntries({ site: SITE }, w.cards)).length, 1);
    await w.finish();
  });

  it("JSON submit: an extension posts the cookies once, gets metadata back, and the link is dead afterwards", async () => {
    const w = makeWorld();
    const who = agent("oc_cookie_json");
    const asked = ok(await w.call(who, "entry_request_card", { site: SITE, account: "erin@example.com", kind: "cookie", reason: "session for erin" }));
    const token = w.latestToken();
    const soon = Math.floor(Date.now() / 1000) + 7200;
    const cookies = [
      { name: "sid", value: JSON_SUBMITTED, domain: `.${SITE}`, path: "/", secure: true, httpOnly: true, hostOnly: false, expirationDate: soon, sameSite: "lax" },
      { name: "tracker", value: FOREIGN_SET, domain: ".ads.example.net", path: "/" },
      { name: "pref", value: "dark", domain: SITE, path: "/" },
    ];

    // Without the header: refused, nothing consumed. A web page cannot add it without a CORS preflight.
    const noHeader = await w.cardRequest(
      new Request(`${ORIGIN}/card/${token}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cookies }) }),
      token,
    );
    assert.equal(noHeader.status, 403);
    assert.deepEqual(JSON.parse(noHeader.text), { ok: false, error: "card_header_required" });
    // Malformed bodies: fixed codes, card still pending, nothing echoed.
    for (const [body, error] of [["{not json", "invalid_json"], [{ cookies: 7 }, "invalid_body"], [[1, 2], "invalid_body"], [{}, "invalid_body"]] as Array<[unknown, string]>) {
      const res = await w.jsonPost(token, body);
      assert.equal(res.status, 400);
      assert.deepEqual(JSON.parse(res.text), { ok: false, error, retryable: true });
    }
    const bad = await w.jsonPost(token, { cookies: [{ name: "sid", value: REJECTED_PASTE, domain: SITE }] });
    assert.equal(bad.status, 400);
    assert.deepEqual(JSON.parse(bad.text), { ok: false, error: "invalid_input", retryable: true, detail: "invalid_cookie_value" });
    const huge = await w.jsonPost(token, { cookies: "x".repeat(MAX_COOKIE_CARD_BODY_BYTES) });
    assert.equal(huge.status, 413);
    assert.equal((await getCardStatus(String(asked.card_id), w.cards)).status, "pending");

    // The real submit — from an extension origin, with fetch metadata a page would never be allowed to send it with.
    const res = await w.jsonPost(token, { cookies }, { origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop", "sec-fetch-site": "none" });
    assert.equal(res.status, 200);
    const answer = JSON.parse(res.text);
    assert.equal(answer.ok, true);
    assert.equal(answer.reentry, false);
    assert.deepEqual(Object.keys(answer.entry).sort(), ["account", "id", "is_default", "kind", "label", "purpose", "site"]);
    assert.deepEqual([answer.entry.site, answer.entry.account, answer.entry.kind], [SITE, "erin@example.com", "cookie"]);
    assert.deepEqual(answer.cookies, { stored: 1, skipped: { short_value: 1, expired: 0, other_site: 1 }, expires_at: new Date(soon * 1000).toISOString() });
    scan("JSON submit answer", res.text);
    // Write-only: JSON, no CORS grant, no cache, nothing an origin could read cross-site.
    assert.match(res.headers.get("content-type") ?? "", /^application\/json/);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("cross-origin-resource-policy"), "same-origin");
    for (const [name] of res.headers) assert.ok(!name.toLowerCase().startsWith("access-control-"), name);
    assert.ok(!res.text.includes(token));

    // Single use: the link is dead for the page, the form and a second JSON submit.
    assert.equal((await w.cardRequest(new Request(`${ORIGIN}/card/${token}`), token)).status, 410);
    assert.equal((await w.formPost(token, { secret: `sid=${ALICE_SID}` })).status, 410);
    const again = await w.jsonPost(token, { cookies });
    assert.equal(again.status, 410);
    assert.deepEqual(JSON.parse(again.text), { ok: false, error: "already_used" });
    assert.equal((await w.jsonPost("A".repeat(43), { cookies })).status, 404);
    assert.equal((await listEntries({ site: SITE }, w.cards)).length, 1);

    // The agent learns the entry exists — and nothing else.
    const status = ok(await w.call(who, "entry_card_status", { card_id: asked.card_id }));
    assert.equal(status.status, "completed");
    for (const k of ["fingerprint", "secret_length", "cookie_jar"]) assert.equal(k in (status.entry as Record<string, unknown>), false);
    // And it works: the domain cookie reaches the site.
    ok(await w.use(who, get("erin@example.com", "/")));
    assert.equal(w.site.calls.at(-1)?.cookie, `sid=${JSON_SUBMITTED}`);

    // A string in `cookies` is accepted too (any of the three formats); account may come in the body.
    const second = await w.requestCookieCard(who, undefined);
    const viaString = await w.jsonPost(second, { cookies: `sid=${BOB_SID}`, account: "frank@example.com", purpose: "second login" });
    assert.equal(viaString.status, 200);
    assert.equal(JSON.parse(viaString.text).entry.label, `${SITE} — frank@example.com — second login`);
    await w.finish();
  });

  it("JSON submit is only for cookie cards; other kinds answer as before, and cookies cannot be sent to them", async () => {
    const w = makeWorld();
    const who = agent("oc_cookie_kinds");
    ok(await w.call(who, "entry_request_card", { site: SITE, account: "svc", kind: "api_key", reason: "seed" }));
    const token = w.latestToken();
    const res = await w.jsonPost(token, { cookies: `sid=${ALICE_SID}` });
    assert.equal(res.status, 415);
    assert.match(res.headers.get("content-type") ?? "", /^text\/html/);
    const direct = await submitCard(token, { cookies: `sid=${ALICE_SID}` }, w.cards);
    assert.deepEqual([direct.ok, direct.ok ? "" : direct.code, direct.ok ? "" : direct.detail], [false, "invalid_input", "card_kind_not_cookie"]);
    assert.equal((await listEntries({ site: SITE }, w.cards)).length, 0);
    // A cookie paste typed into a password card is just a secret string: the kind decides, not the content.
    const page = await w.cardRequest(new Request(`${ORIGIN}/card/${token}`), token);
    assert.match(page.text, /name="secret" type="password"/);
    await w.finish();
  });
});

// ---------------------------------------------------------------------------

describe("cookie entries on the SQL stores (PGlite, migrations 0005 + 0007 + 0012)", () => {
  it("stores, refreshes and re-enters a cookie entry; the schema holds metadata only and keeps the old limits for other kinds", async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const pg = new PGlite();
    try {
      const migration = (f: string) => readFileSync(new URL(`../../../../migrations/${f}`, import.meta.url), "utf8");
      for (const f of ["0005_vault_entries.sql", "0007_vault_entry_rotation.sql", "0012_vault_cookie_entries.sql"]) await pg.exec(migration(f));
      await pg.exec(migration("0012_vault_cookie_entries.sql")); // idempotent
      const sql = { query: async (text: string, params: unknown[] = []) => (await pg.query(text, params)).rows } as unknown as Sql;
      const provider = async () => sql;
      const texts: string[] = [];
      const backend = new FakeVaultBackend();
      const ledger = new Ledger({ store: new MemoryLedgerStore() });
      const deps: CardsDeps = {
        entries: new SqlEntryStore(provider),
        cards: new SqlCardStore(provider),
        backend,
        ledger: (input) => ledger.append(input),
        fetch: (async (_i: RequestInfo | URL, init?: RequestInit) => {
          texts.push(String(JSON.parse(String(init?.body ?? "{}")).text ?? ""));
          return new Response(JSON.stringify({ ok: true, result: { message_id: 1 } }), { status: 200 });
        }) as typeof fetch,
        env: ENV,
      };
      const who = agent("oc_cookie_sql");
      const card = async (account: string, kind: "cookie" | "password") => {
        await requestCard({ client: who, site: SITE, account, kind, reason: "sql test" }, deps);
        return /\/card\/([A-Za-z0-9_-]{43})/.exec(texts.at(-1) ?? "")![1];
      };
      const soon = Math.floor(Date.now() / 1000) + 600;
      const first = await submitCard(await card("alice@example.com", "cookie"), { cookies: [{ name: "sid", value: SQL_VALUE, domain: `.${SITE}`, expirationDate: soon }] }, deps);
      assert.equal(first.ok, true);
      const second = await submitCard(await card("bob@example.com", "cookie"), { secret: `sid=${BOB_SID}` }, deps);
      assert.equal(second.ok, true);
      const samePassword = await submitCard(await card("alice@example.com", "password"), { secret: "a password for the same account" }, deps);
      assert.equal(samePassword.ok, true, "kind is part of the identity: a password entry for the same account coexists");
      if (!first.ok || !second.ok) throw new Error("unreachable");
      assert.deepEqual([first.entry.is_default, second.entry.is_default], [true, false]);
      assert.deepEqual(first.entry.cookie_jar, { count: 1, names: ["sid"], domains: [`.${SITE}`], truncated: false, expires_at: new Date(soon * 1000).toISOString(), session_cookies: 0 });

      // Site refresh.
      const jar = parseCookieInput([{ name: "sid", value: ALICE_ROTATED, domain: `.${SITE}` }, { name: "extra", value: WIDE, domain: SITE }], { site: SITE }).jar;
      assert.equal(await refreshCookieJar(first.entry.id, who, serializeJar(jar), describeJar(jar, SITE), deps), true);
      const [refreshed] = await listEntries({ site: SITE, query: "alice" }, deps);
      assert.deepEqual([refreshed.kind, refreshed.fingerprint, refreshed.secret_length, refreshed.cookie_jar?.count, refreshed.rotation_count], ["cookie", secretFingerprint(serializeJar(jar)), serializeJar(jar).length, 2, 0]);
      assert.equal((await backend.get(`echo_vault_entry_${first.entry.id}`, "entry", "t")).secret, serializeJar(jar));
      // refreshJarMeta never touches a non-cookie entry.
      if (samePassword.ok) assert.equal(await deps.entries!.refreshJarMeta(samePassword.entry.id, "deadbeef", 10, describeJar(jar), new Date().toISOString()), null);

      // Schema: no value column, and the widened limits apply to `cookie` only.
      const dump = [...(await pg.query("select * from vault_entries")).rows, ...(await pg.query("select * from vault_cards")).rows];
      everyRow.push(dump);
      scan("sql rows", dump);
      const cols = (await pg.query<{ column_name: string }>("select column_name from information_schema.columns where table_name in ('vault_entries','vault_cards')")).rows.map((r) => r.column_name);
      for (const n of cols) assert.ok(!/^(secret|password|value|token|cookies?|jar)$/.test(n), `unexpected column ${n}`);
      const ins = (id: string, kind: string, len: number, meta: string | null = null) =>
        pg.query(
          `insert into vault_entries (id, site, account, purpose, label, kind, fingerprint, secret_length, cookie_meta)
           values ($1, 'limits.example.com', $1, 'general', 'l', $2, 'deadbeef', $3, $4)`,
          [id, kind, len, meta],
        );
      await ins("ve_" + "a".repeat(32), "cookie", 32768);
      await assert.rejects(ins("ve_" + "b".repeat(32), "cookie", 32769), /vault_entries_secret_length_check/);
      await assert.rejects(ins("ve_" + "c".repeat(32), "api_key", 4097), /vault_entries_secret_length_check/);
      await assert.rejects(ins("ve_" + "d".repeat(32), "password", 12, '{"count":1}'), /vault_entries_cookie_meta_check/);
      await assert.rejects(ins("ve_" + "e".repeat(32), "session", 12), /vault_entries_kind_check/);
      everyLedger.push(await ledger.list({ limit: 100 }));
    } finally {
      await pg.close();
    }
  });
});
