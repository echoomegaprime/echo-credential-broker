// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * The browser injector channel end to end, in memory (and once on PGlite):
 * enrollment, `entry_inject` through the gateway with a Telegram approval on
 * every call, the two injector endpoints, sealing, the ledger, and a leak scan
 * over everything that left the system.
 *
 * The "injector" here is a SCRIPTED one: it generates a real P-256 key pair
 * with WebCrypto (private key non-extractable, as the extension does) and opens
 * the sealed blob with ECDH → HKDF-SHA256 → AES-256-GCM and the AAD, using only
 * the contract (docs/ops/injector-contract.md) — nothing from injector.ts. No
 * real extension and no browser are involved. Fakes: the vault backend,
 * Telegram. No network.
 */
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { after, before, describe, it } from "node:test";
import type { Sql } from "../../db.ts";
import { FakeVaultBackend } from "../backend.ts";
import { CredentialStore } from "../store.ts";
import { MemoryApprovalStore } from "./approvals.ts";
import { flagForReentry, MemoryCardStore, MemoryEntryStore, SqlCardStore, SqlEntryStore, submitCard, type CardsDeps } from "./cards.ts";
import type { ClientIdentity, LedgerEntryInput } from "./contracts.ts";
import { MemoryEntryGrantStore } from "./entry-grants.ts";
import { dispatchTool, type GatewayDeps, type GatewayResult } from "./gateway.ts";
import { handleInjectorRedeem, handleInjectorReport, MAX_INJECTOR_BODY_BYTES } from "./injector-http.ts";
import {
  cookiesForOrigin,
  MemoryInjectorStore,
  MemoryInjectTicketStore,
  REDEEM_MAX_PER_WINDOW,
  SqlInjectorStore,
  SqlInjectTicketStore,
  TICKET_TTL_MS,
  validatePublicJwk,
  type InjectorDeps,
} from "./injector.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";
import { MemoryRateLimitStore, setDefaultRateLimitStore, type RateLimitStore } from "./rate-limit-store.ts";
import { handleTelegramWebhook } from "./telegram.ts";

setDefaultRateLimitStore(new MemoryRateLimitStore());

const subtle = webcrypto.subtle;
const ORIGIN = "https://vault.example.test";
const APPROVER_ID = 515151;
const WEBHOOK_SECRET = "test-webhook-secret-injector-0123456789";
const ENV: NodeJS.ProcessEnv = {
  TELEGRAM_BOT_TOKEN: "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789",
  ECHO_VAULT_APPROVER_TELEGRAM_ID: String(APPROVER_ID),
  ECHO_VAULT_PUBLIC_URL: ORIGIN,
  ECHO_VAULT_APPROVAL_HMAC_KEY: "test-only-approval-hmac-key-0123456789abcdef",
  ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET: WEBHOOK_SECRET,
};
const SITE = "shop.example.com";
const LOCAL: ClientIdentity = { client_id: "local:owner", name: "owner", kind: "local", scopes: [] };

// Values with characters that make the encoded forms differ from the raw one.
const SID = "in/ject+sess=ion&tok-1001";
const CSRF = "inject-csrf-value-1002";
const APP_ONLY = "app-hostonly-cookie-1003";
const WIDE = "wide-domain+cookie/1004";
const OTHER_SUB = "other-subdomain-cookie-1005";
const PASSWORD = "p@ss/word+for=field&-1006";
const SQL_SID = "sql-store-session-1007";
const SQL_PASSWORD = "sql/store+password=1008";
const FLAGGED = "flagged-entry-password-1009";
const ALL_SECRETS = [SID, CSRF, APP_ONLY, WIDE, OTHER_SUB, PASSWORD, SQL_SID, SQL_PASSWORD, FLAGGED];

function variants(value: string): string[] {
  return [
    ...new Set([
      value,
      encodeURIComponent(value),
      new URLSearchParams({ v: value }).toString().slice(2),
      Buffer.from(value, "utf8").toString("base64"),
      Buffer.from(value, "utf8").toString("base64url"),
      Buffer.from(value, "utf8").toString("hex"),
      JSON.stringify(value).slice(1, -1),
    ]),
  ];
}

function scan(label: string, haystack: unknown, values: Iterable<string>, what: string): void {
  const text = typeof haystack === "string" ? haystack : JSON.stringify(haystack);
  for (const value of values) {
    for (const v of variants(value)) assert.equal(text.includes(v), false, `${label} contains ${what} (${v === value ? "raw" : "encoded"})`);
  }
}

// Everything that left the system under test. Scanned at the end of the file.
const captured: string[] = [];
const everyToolResult: unknown[] = []; // agent- and owner-visible tool results, EXCEPT the enroll results
const everyEnrollResult: unknown[] = []; // the one place an injector token may appear
const everyHttp: string[] = []; // status, headers and body of every injector endpoint response
const everyLedger: unknown[] = [];
const everyRow: unknown[] = []; // memory-store dumps and SQL rows
const everyTelegram: unknown[] = [];
/** Needles collected while the tests run. */
const injectorTokens = new Set<string>();
const rawTickets = new Set<string>();
const keyMaterial = new Set<string>(); // derived AES keys and ECDH shared secrets, as bytes rendered in hex/base64/base64url
let sealedBlobsOpened = 0;
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
  const logs = captured.join("\n");
  // The scanner must trip on each encoding it claims to cover, and the corpus must be real.
  for (const v of variants(SID)) assert.throws(() => scan("self-test", `x${v}y`, [SID], "a secret"));
  assert.ok(logs.includes("vault_inject_redeemed") && logs.includes("vault_inject_ticket_minted"), "logs were captured");
  assert.ok(sealedBlobsOpened >= 4 && keyMaterial.size >= 8 && injectorTokens.size >= 3 && rawTickets.size >= 5, "needles were collected");
  assert.ok(everyHttp.some((r) => r.includes('"sealed"')), "sealed responses are part of the corpus");

  const surfaces: Array<[string, unknown]> = [
    ["log lines", logs],
    ["tool results", everyToolResult],
    ["injector endpoint responses (incl. sealed blobs)", everyHttp.join("\n")],
    ["ledger rows", everyLedger],
    ["stored rows (memory dumps + SQL)", everyRow],
    ["Telegram payloads", everyTelegram],
  ];
  for (const [label, hay] of surfaces) {
    scan(label, hay, ALL_SECRETS, "a stored secret or cookie value");
    scan(label, hay, keyMaterial, "a derived key or shared secret");
    scan(label, hay, injectorTokens, "an injector token");
  }
  // The enroll result is the one place a token is shown; it still carries no secret and no key material.
  scan("enroll results", everyEnrollResult, ALL_SECRETS, "a stored secret");
  assert.ok([...injectorTokens].every((t) => JSON.stringify(everyEnrollResult).includes(t)), "each token appeared exactly where it is allowed: its enroll result");
  // A raw ticket is returned to the agent (tool result) and nowhere else.
  for (const [label, hay] of [surfaces[0], surfaces[2], surfaces[3], surfaces[4], surfaces[5]]) scan(label, hay, rawTickets, "a raw ticket");
});

// ---------------------------------------------------------------------------
// The scripted injector: what the extension does, from the contract alone
// ---------------------------------------------------------------------------

interface Sealed {
  alg: string;
  epk: { kty: string; crv: string; x: string; y: string };
  salt: string;
  iv: string;
  ct: string;
  aad: string;
}

const fromB64u = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url"));
const sha256hex = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

class TestInjector {
  id = "";
  token = "";
  readonly publicJwk: { kty: string; crv: string; x: string; y: string };
  private readonly privateKey: webcrypto.CryptoKey;
  private constructor(publicJwk: { kty: string; crv: string; x: string; y: string }, privateKey: webcrypto.CryptoKey) {
    this.publicJwk = publicJwk;
    this.privateKey = privateKey;
  }

  static async create(): Promise<TestInjector> {
    const pair = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as webcrypto.CryptoKeyPair;
    assert.equal(pair.privateKey.extractable, false, "the injector's private key is non-extractable");
    const jwk = await subtle.exportKey("jwk", pair.publicKey);
    return new TestInjector({ kty: "EC", crv: "P-256", x: String(jwk.x), y: String(jwk.y) }, pair.privateKey);
  }

  /** ECDH → HKDF-SHA256(salt, info) → AES-256-GCM(iv, aad). Rejects (throws) on any mismatch. */
  async open(sealed: Sealed, expect: { ticket: string; target_origin: string; mode: string }): Promise<Record<string, unknown>> {
    assert.equal(sealed.alg, "ECDH-ES+HKDF-SHA256+A256GCM");
    assert.deepEqual(Object.keys(sealed).sort(), ["aad", "alg", "ct", "epk", "iv", "salt"]);
    assert.deepEqual(Object.keys(sealed.epk).sort(), ["crv", "kty", "x", "y"], "the ephemeral key is public only");
    // The injector checks the AAD against what it asked for BEFORE decrypting.
    const expectedAad = `eit:${sha256hex(expect.ticket)}|${this.id}|${expect.target_origin}|${expect.mode}`;
    if (Buffer.from(sealed.aad, "base64url").toString("utf8") !== expectedAad) throw new Error("aad_mismatch");
    const salt = fromB64u(sealed.salt);
    const iv = fromB64u(sealed.iv);
    assert.deepEqual([salt.length, iv.length], [32, 12]);
    const epk = await subtle.importKey("jwk", { ...sealed.epk, ext: true }, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const z = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: epk }, this.privateKey, 256));
    const ikm = await subtle.importKey("raw", z, "HKDF", false, ["deriveKey", "deriveBits"]);
    const info = new TextEncoder().encode("echo-vault-injector-v1");
    const key = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info }, ikm, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const pt = await subtle.decrypt({ name: "AES-GCM", iv, additionalData: fromB64u(sealed.aad), tagLength: 128 }, key, fromB64u(sealed.ct));
    // For the leak scan only: the same K as raw bytes, and Z. Neither may appear anywhere.
    const k = Buffer.from(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, ikm, 256));
    for (const bytes of [k, Buffer.from(z)]) for (const enc of ["hex", "base64", "base64url"] as const) keyMaterial.add(bytes.toString(enc));
    sealedBlobsOpened += 1;
    return JSON.parse(new TextDecoder().decode(pt)) as Record<string, unknown>;
  }
}

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

interface HttpAnswer {
  status: number;
  headers: Headers;
  json: Record<string, unknown>;
  text: string;
}

function makeWorld(opts: { injectors?: InjectorDeps["injectors"]; tickets?: InjectorDeps["tickets"]; cards?: Partial<CardsDeps>; rateLimit?: RateLimitStore } = {}) {
  let clock = Date.parse("2026-11-14T12:00:00.000Z");
  const now = () => clock;
  const telegram: Array<{ method: string; payload: Record<string, unknown> }> = [];
  const telegramFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    assert.ok(url.startsWith("https://api.telegram.org/bot"));
    const payload = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    telegram.push({ method: url.split("/").pop() ?? "", payload });
    everyTelegram.push(payload);
    return new Response(JSON.stringify({ ok: true, result: { message_id: telegram.length } }), { status: 200 });
  }) as typeof fetch;

  const backend = new FakeVaultBackend();
  const ledgerStore = new MemoryLedgerStore();
  const ledger = new Ledger({ store: ledgerStore });
  let ledgerDown: ((row: LedgerEntryInput) => boolean) | null = null;
  const sink = async (input: LedgerEntryInput) => {
    if (ledgerDown?.(input)) throw new Error("ledger down");
    return ledger.append(input);
  };
  const approvalStore = new MemoryApprovalStore();
  const entries = opts.cards?.entries ?? new MemoryEntryStore();
  const cardStore = opts.cards?.cards ?? new MemoryCardStore();
  const cards: CardsDeps = { entries, cards: cardStore, backend, ledger: sink, fetch: telegramFetch, env: ENV, now };
  const injectors = opts.injectors ?? new MemoryInjectorStore();
  const tickets = opts.tickets ?? new MemoryInjectTicketStore();
  const rateLimit = opts.rateLimit ?? new MemoryRateLimitStore();
  const grants = new MemoryEntryGrantStore();
  const injector: InjectorDeps = { injectors, tickets, now, rateLimit, cards, ledger: sink };
  const deps: GatewayDeps = {
    ledger: sink,
    listLedger: (o) => ledger.list(o),
    verifyLedger: () => ledger.verify(),
    ledgerHead: () => ledger.head(),
    approvals: { store: approvalStore, fetch: telegramFetch, env: ENV, now, ledger: sink },
    rules: [],
    store: new CredentialStore(backend),
    cards,
    grants,
    now,
    injector,
    fetch: (async () => {
      throw new Error("entry_inject must never make a site request");
    }) as typeof fetch,
  };

  const call = async (identity: ClientIdentity, name: string, args: unknown = {}): Promise<GatewayResult> => {
    const result = await dispatchTool(identity, name, args, deps);
    (name === "admin_enroll_injector" && result.ok ? everyEnrollResult : everyToolResult).push(result);
    return result;
  };
  const prompts = () => telegram.filter((c) => c.method === "sendMessage" && (c.payload.reply_markup as { inline_keyboard?: unknown } | undefined)?.inline_keyboard);
  const tap = async (approvalId: string, decision: "Approve" | "Deny" = "Approve"): Promise<void> => {
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
        body: JSON.stringify({ callback_query: { id: "cq1", from: { id: APPROVER_ID }, data: buttons.find((b) => b.text === decision)?.callback_data, message: { message_id: 1, chat: { id: APPROVER_ID } } } }),
      }),
      { store: approvalStore, fetch: telegramFetch, env: ENV, now, ledger: sink },
    );
    assert.equal(res.status, 200);
  };
  /** Card flow: the agent asks, the owner types. Returns the entry id. */
  const seed = async (who: ClientIdentity, account: string, kind: "cookie" | "password", typed: string | { cookies: unknown }, site = SITE): Promise<string> => {
    const asked = await call(who, "entry_request_card", { site, account, kind, reason: "seed for the injector tests" });
    assert.equal(asked.ok, true, JSON.stringify(asked));
    const text = [...telegram].reverse().find((c) => typeof c.payload.text === "string" && /\/card\//.test(c.payload.text as string));
    const token = /\/card\/([A-Za-z0-9_-]{43})/.exec(String(text?.payload.text))?.[1] ?? "";
    const done = await submitCard(token, typeof typed === "string" ? { secret: typed } : typed, cards);
    assert.equal(done.ok, true, JSON.stringify(done));
    if (!done.ok) throw new Error("unreachable");
    return done.entry.id;
  };
  const enroll = async (name = "test browser"): Promise<TestInjector> => {
    const inj = await TestInjector.create();
    const r = await call(LOCAL, "admin_enroll_injector", { name, public_key_jwk: inj.publicJwk });
    assert.equal(r.ok, true, JSON.stringify(r));
    const d = (r as { data: Record<string, unknown> }).data;
    inj.id = String(d.injector_id);
    inj.token = String(d.injector_token);
    assert.match(inj.id, /^inj_[0-9a-f]{16}$/);
    assert.match(inj.token, /^ein_[A-Za-z0-9_-]{43}$/);
    injectorTokens.add(inj.token);
    return inj;
  };
  /** entry_inject with the owner approving on Telegram. Returns the mint result (ticket + metadata). */
  const inject = async (who: ClientIdentity, args: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const first = await call(who, "entry_inject", args);
    assert.equal(first.ok, false);
    assert.equal((first as { error: string }).error, "approval_required", JSON.stringify(first));
    const approvalId = String((first as { approval_id?: unknown }).approval_id);
    await tap(approvalId);
    const second = await call(who, "entry_inject", { ...args, approval_id: approvalId });
    assert.equal(second.ok, true, JSON.stringify(second));
    const data = (second as { data: Record<string, unknown> }).data;
    rawTickets.add(String(data.ticket));
    return { ...data, approval_id: approvalId };
  };
  const http = async (handler: typeof handleInjectorRedeem, path: string, token: string | null, body: unknown, init: { method?: string; headers?: Record<string, string>; raw?: string } = {}): Promise<HttpAnswer> => {
    const headers: Record<string, string> = { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...init.headers };
    const method = init.method ?? "POST";
    const res = await handler(new Request(`${ORIGIN}${path}`, { method, headers, body: method === "POST" ? (init.raw ?? JSON.stringify(body)) : undefined }), injector);
    const text = await res.text();
    everyHttp.push(`${res.status} ${JSON.stringify([...res.headers])}\n${text}`);
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      // not JSON
    }
    return { status: res.status, headers: res.headers, json, text };
  };
  const redeem = (inj: { token: string }, ticket: unknown, init?: Parameters<typeof http>[4]) => http(handleInjectorRedeem, "/api/injector/redeem", inj.token, { ticket }, init);
  const report = (inj: { token: string }, body: unknown) => http(handleInjectorReport, "/api/injector/report", inj.token, body);
  const rows = () => ledgerStore.scanAscending(0, 10_000);
  const finish = async (): Promise<void> => {
    everyLedger.push(await rows());
    if (entries instanceof MemoryEntryStore) everyRow.push(entries.dumpForTests());
    if (cardStore instanceof MemoryCardStore) everyRow.push(cardStore.dumpForTests());
    if (injectors instanceof MemoryInjectorStore) everyRow.push(injectors.dumpForTests());
    if (tickets instanceof MemoryInjectTicketStore) everyRow.push(tickets.dumpForTests());
    everyRow.push(await grants.list(), (rateLimit as MemoryRateLimitStore).keys?.() ?? []);
    assert.equal((await ledger.verify()).ok, true);
  };
  return {
    deps, cards, injector, injectors, tickets, grants, approvalStore, backend, telegram, prompts, call, tap, seed, enroll, inject, redeem, report, http, rows, finish,
    advance: (ms: number) => {
      clock += ms;
    },
    now,
    setLedgerDown: (fn: ((row: LedgerEntryInput) => boolean) | null) => {
      ledgerDown = fn;
    },
  };
}

function agent(id: string, scopes = ["vault.read", "vault.write"]): ClientIdentity {
  return { client_id: id, name: id, kind: "oauth", scopes };
}

function failed(result: GatewayResult, error: string): Record<string, unknown> {
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal((result as { error: string }).error, error, JSON.stringify(result));
  return result as Record<string, unknown>;
}

const COOKIES = { site: SITE, account: "alice@example.com", target_origin: `https://${SITE}`, mode: "cookies", task: "sign the owner's browser in to the shop" };
const FIELD = { site: SITE, account: "alice@example.com", target_origin: `https://${SITE}`, mode: "field", task: "type the shop password into the login form" };
const future = Math.floor(Date.parse("2027-06-01T00:00:00Z") / 1000);
/** A jar with cookies for the site, for one subdomain only, for another subdomain only, and a domain-wide one. */
const JAR = {
  cookies: [
    { name: "sid", value: SID, domain: SITE, hostOnly: true, path: "/", secure: true, httpOnly: true, expirationDate: future },
    { name: "csrf", value: CSRF, domain: SITE, hostOnly: true, path: "/account" },
    { name: "wide", value: WIDE, domain: `.${SITE}`, path: "/" },
    { name: "apponly", value: APP_ONLY, domain: `app.${SITE}`, hostOnly: true, path: "/" },
    { name: "othersub", value: OTHER_SUB, domain: `.other.${SITE}`, path: "/" },
  ],
};

// ---------------------------------------------------------------------------

describe("injector channel: sealed round trip", () => {
  it("cookies: approval → ticket → redeem → the scripted injector decrypts exactly the cookies that domain-match the origin", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_cookies");
    const entryId = await w.seed(who, "alice@example.com", "cookie", JAR);
    const inj = await w.enroll();

    const minted = await w.inject(who, COOKIES);
    assert.deepEqual(Object.keys(minted).sort(), ["approval_id", "entry", "expires_at", "injector_id", "mode", "target_origin", "ticket"]);
    assert.match(String(minted.ticket), /^eit_[A-Za-z0-9_-]{32}$/);
    assert.deepEqual(minted.entry, { id: entryId, label: `${SITE} — alice@example.com — general`, kind: "cookie" });
    assert.deepEqual([minted.injector_id, minted.target_origin, minted.mode], [inj.id, `https://${SITE}`, "cookies"]);
    assert.equal(Date.parse(String(minted.expires_at)) - w.now(), TICKET_TTL_MS);
    assert.equal(TICKET_TTL_MS, 120_000);

    const res = await w.redeem(inj, minted.ticket);
    assert.equal(res.status, 200, res.text);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal([...res.headers.keys()].some((h) => h.startsWith("access-control-")), false, "no CORS headers");
    assert.deepEqual(Object.keys(res.json).sort(), ["entry", "mode", "ok", "sealed", "target_origin"]);
    assert.deepEqual([res.json.ok, res.json.mode, res.json.target_origin], [true, "cookies", `https://${SITE}`]);
    assert.deepEqual(res.json.entry, { id: entryId, label: `${SITE} — alice@example.com — general`, kind: "cookie" });

    const sealed = res.json.sealed as Sealed;
    const want = { ticket: String(minted.ticket), target_origin: `https://${SITE}`, mode: "cookies" };
    const plain = await inj.open(sealed, want);
    assert.equal(plain.v, 1);
    const cookies = plain.cookies as Array<Record<string, unknown>>;
    // Host-only site cookies and the domain-wide cookie; nothing scoped to a subdomain.
    assert.deepEqual(cookies.map((c) => c.name).sort(), ["csrf", "sid", "wide"]);
    assert.deepEqual(cookies.find((c) => c.name === "sid"), { name: "sid", value: SID, domain: SITE, path: "/", secure: true, httpOnly: true, hostOnly: true, expires: future, sameSite: "unspecified" });
    assert.deepEqual(cookies.find((c) => c.name === "csrf"), { name: "csrf", value: CSRF, domain: SITE, path: "/account", secure: false, httpOnly: false, hostOnly: true, expires: null, sameSite: "unspecified" });
    assert.deepEqual(cookies.find((c) => c.name === "wide"), { name: "wide", value: WIDE, domain: SITE, path: "/", secure: false, httpOnly: false, hostOnly: false, expires: null, sameSite: "unspecified" });
    assert.equal(JSON.stringify(plain).includes(APP_ONLY) || JSON.stringify(plain).includes(OTHER_SUB), false);

    // Tampering: every field is authenticated or key-determining.
    const flip = (s: string) => {
      const b = Buffer.from(s, "base64url");
      b[Math.floor(b.length / 2)] ^= 0x01;
      return b.toString("base64url");
    };
    await assert.rejects(inj.open({ ...sealed, ct: flip(sealed.ct) }, want), "ciphertext");
    await assert.rejects(inj.open({ ...sealed, iv: flip(sealed.iv) }, want), "iv");
    await assert.rejects(inj.open({ ...sealed, salt: flip(sealed.salt) }, want), "salt");
    const otherEpk = await subtle.exportKey("jwk", ((await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as webcrypto.CryptoKeyPair).publicKey);
    await assert.rejects(inj.open({ ...sealed, epk: { kty: "EC", crv: "P-256", x: String(otherEpk.x), y: String(otherEpk.y) } }, want), "epk");
    // An AAD for another origin/mode/ticket: refused by the injector's own check, and by AES-GCM if that check is skipped.
    const forged = Buffer.from(`eit:${sha256hex(String(minted.ticket))}|${inj.id}|https://evil.example.net|cookies`).toString("base64url");
    await assert.rejects(inj.open({ ...sealed, aad: forged }, want), /aad_mismatch/);
    await assert.rejects(inj.open({ ...sealed, aad: forged }, { ...want, target_origin: "https://evil.example.net" }), "aad is bound into the tag");
    await assert.rejects(inj.open(sealed, { ...want, mode: "field" }), /aad_mismatch/);
    // Another injector's private key cannot open it.
    const stranger = await TestInjector.create();
    stranger.id = inj.id;
    await assert.rejects(stranger.open(sealed, want));

    // A subdomain target gets the subdomain's cookies and the domain-wide one — never another subdomain's.
    const sub = await w.inject(who, { ...COOKIES, target_origin: `https://app.${SITE}` });
    const subRes = await w.redeem(inj, sub.ticket);
    assert.equal(subRes.status, 200, subRes.text);
    const subPlain = await inj.open(subRes.json.sealed as Sealed, { ticket: String(sub.ticket), target_origin: `https://app.${SITE}`, mode: "cookies" });
    assert.deepEqual((subPlain.cookies as Array<{ name: string }>).map((c) => c.name).sort(), ["apponly", "wide"]);
    await w.finish();
  });

  it("field: the password entry's username and secret arrive sealed, and nowhere else", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_field");
    const entryId = await w.seed(who, "alice@example.com", "password", PASSWORD);
    const inj = await w.enroll("laptop");
    const minted = await w.inject(who, FIELD);
    const res = await w.redeem(inj, minted.ticket);
    assert.equal(res.status, 200, res.text);
    assert.deepEqual(res.json.entry, { id: entryId, label: `${SITE} — alice@example.com — general`, kind: "password" });
    assert.equal(res.text.includes(PASSWORD), false);
    const plain = await inj.open(res.json.sealed as Sealed, { ticket: String(minted.ticket), target_origin: `https://${SITE}`, mode: "field" });
    assert.deepEqual(plain, { v: 1, username: "alice@example.com", secret: PASSWORD });
    // Two redeems of two tickets never share a key, salt or IV.
    const again = await w.inject(who, FIELD);
    const res2 = await w.redeem(inj, again.ticket);
    const a = res.json.sealed as Sealed;
    const b = res2.json.sealed as Sealed;
    assert.ok(a.salt !== b.salt && a.iv !== b.iv && a.epk.x !== b.epk.x && a.ct !== b.ct);
    assert.deepEqual(await inj.open(b, { ticket: String(again.ticket), target_origin: `https://${SITE}`, mode: "field" }), plain);
    await w.finish();
  });
});

describe("injector channel: tickets", () => {
  it("single use, 120 s expiry, wrong injector (not burned), revoked injector, unknown ticket", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_tickets");
    await w.seed(who, "alice@example.com", "password", PASSWORD);
    const a = await w.enroll("a");
    const b = await w.enroll("b");
    const withA = { ...FIELD, injector_id: a.id };

    // Several injectors: the agent must say which.
    failed(await w.call(who, "entry_inject", FIELD), "injector_required");
    failed(await w.call(who, "entry_inject", { ...FIELD, injector_id: "inj_0000000000000000" }), "injector_not_found");

    // Wrong injector: 403, and the ticket is NOT burned — the bound injector still redeems it.
    const t1 = await w.inject(who, withA);
    const wrong = await w.redeem(b, t1.ticket);
    assert.deepEqual([wrong.status, wrong.json], [403, { ok: false, error: "ticket_wrong_injector" }]);
    const right = await w.redeem(a, t1.ticket);
    assert.equal(right.status, 200, right.text);
    await a.open(right.json.sealed as Sealed, { ticket: String(t1.ticket), target_origin: `https://${SITE}`, mode: "field" });
    // Single use.
    const replay = await w.redeem(a, t1.ticket);
    assert.deepEqual([replay.status, replay.json], [409, { ok: false, error: "ticket_used" }]);
    // The wrong injector learns nothing new afterwards either.
    assert.equal((await w.redeem(b, t1.ticket)).json.error, "ticket_wrong_injector");

    // Two parallel redeems of one ticket: exactly one gets ciphertext.
    const t2 = await w.inject(who, withA);
    const race = await Promise.all([w.redeem(a, t2.ticket), w.redeem(a, t2.ticket)]);
    assert.deepEqual(race.map((r) => r.status).sort(), [200, 409]);

    // Expiry: redeemable up to the last millisecond, gone at 120 s.
    const t3 = await w.inject(who, withA);
    w.advance(TICKET_TTL_MS - 1);
    assert.equal((await w.redeem(a, t3.ticket)).status, 200);
    const t4 = await w.inject(who, withA);
    w.advance(TICKET_TTL_MS);
    const expired = await w.redeem(a, t4.ticket);
    assert.deepEqual([expired.status, expired.json], [410, { ok: false, error: "ticket_expired" }]);

    // Unknown and malformed tickets.
    for (const bad of [`eit_${randomBytes(24).toString("base64url")}`, "eit_short", "", 42, null, `eva_${randomBytes(32).toString("base64url")}`]) {
      const r = await w.redeem(a, bad);
      assert.deepEqual([r.status, r.json], [404, { ok: false, error: "ticket_not_found" }]);
    }

    // Revoked injector: its token is dead, so its outstanding ticket can never be redeemed.
    const t5 = await w.inject(who, withA);
    assert.equal((await w.call(LOCAL, "admin_revoke_injector", { injector_id: a.id })).ok, true);
    const dead = await w.redeem(a, t5.ticket);
    assert.deepEqual([dead.status, dead.json], [401, { ok: false, error: "invalid_injector" }]);
    assert.equal((await w.tickets.get(sha256hex(String(t5.ticket))))?.redeemed_at, null);
    failed(await w.call(who, "entry_inject", withA), "injector_not_found");
    // With one active injector left it is implied.
    const implied = await w.inject(who, FIELD);
    assert.equal(implied.injector_id, b.id);
    await w.finish();
  });

  it("an entry that stopped being usable after the mint burns the ticket and releases nothing", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_flagged");
    const entryId = await w.seed(who, "carol@example.com", "password", FLAGGED);
    const inj = await w.enroll();
    const args = { ...FIELD, account: "carol@example.com" };
    const minted = await w.inject(who, args);
    await flagForReentry(entryId, "site said 401", w.cards);
    const res = await w.redeem(inj, minted.ticket);
    assert.deepEqual([res.status, res.json], [503, { ok: false, error: "unavailable" }]);
    assert.equal((await w.redeem(inj, minted.ticket)).json.error, "ticket_used", "burned by the first attempt, success or not");
    // And a flagged entry is refused at planning time, before the owner is asked.
    const before = w.prompts().length;
    failed(await w.call(who, "entry_inject", args), "entry_not_active");
    assert.equal(w.prompts().length, before);
    const row = (await w.rows()).filter((r) => r.capability === "vault.entry.inject.redeem").at(-2);
    assert.deepEqual([row?.result, row?.error], ["error", "entry_needs_reentry"]);
    await w.finish();
  });
});

describe("injector channel: approval on every call", () => {
  it("a second call does not reuse the first approval, and no standing grant is created", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_approvals");
    await w.seed(who, "alice@example.com", "password", PASSWORD);
    const inj = await w.enroll();

    const first = failed(await w.call(who, "entry_inject", FIELD), "approval_required");
    assert.equal(first.tier, 2);
    assert.equal(w.prompts().length, 1);
    const text = String(w.prompts()[0].payload.text);
    assert.ok(text.includes(`https://${SITE}`) && text.includes(inj.id) && text.includes("vault.entry.inject"), "the owner sees the origin, the injector and the action");
    // Not approved yet: nothing is minted.
    failed(await w.call(who, "entry_inject", { ...FIELD, approval_id: first.approval_id }), "approval_pending");
    await w.tap(String(first.approval_id));
    const minted = await w.call(who, "entry_inject", { ...FIELD, approval_id: first.approval_id });
    assert.equal(minted.ok, true, JSON.stringify(minted));
    rawTickets.add(String((minted as { data: { ticket: string } }).data.ticket));

    // The same approval again: consumed. One approval, one ticket.
    failed(await w.call(who, "entry_inject", { ...FIELD, approval_id: first.approval_id }), "approval_already_consumed");
    assert.equal((await (w.tickets as MemoryInjectTicketStore).dumpForTests()).length, 1);
    // The same request again, without an approval: the owner is asked again, with a NEW approval.
    const second = failed(await w.call(who, "entry_inject", FIELD), "approval_required");
    assert.notEqual(second.approval_id, first.approval_id);
    assert.equal(w.prompts().length, 2);
    // An approval for one request does not cover another (other origin, other task, other injector binding).
    await w.tap(String(second.approval_id));
    failed(await w.call(who, "entry_inject", { ...FIELD, target_origin: `https://app.${SITE}`, approval_id: second.approval_id }), "approval_digest_mismatch");
    failed(await w.call(who, "entry_inject", { ...FIELD, task: "something else", approval_id: second.approval_id }), "approval_digest_mismatch");
    // Another client cannot spend it either.
    failed(await w.call(agent("oc_inject_other"), "entry_inject", { ...FIELD, approval_id: second.approval_id }), "approval_digest_mismatch");
    // A denied approval mints nothing.
    const third = failed(await w.call(who, "entry_inject", { ...FIELD, task: "a third try" }), "approval_required");
    await w.tap(String(third.approval_id), "Deny");
    failed(await w.call(who, "entry_inject", { ...FIELD, task: "a third try", approval_id: third.approval_id }), "approval_denied");

    assert.deepEqual(await w.grants.list(), [], "injection never creates a consent grant");
    assert.equal((await (w.tickets as MemoryInjectTicketStore).dumpForTests()).length, 1);
    // Without vault.write the owner is never paged and nothing about the entry is confirmed.
    const readOnly = agent("oc_inject_readonly", ["vault.read"]);
    const promptsBefore = w.prompts().length;
    failed(await w.call(readOnly, "entry_inject", FIELD), "missing_scope");
    failed(await w.call(readOnly, "entry_inject", { ...FIELD, site: "no-such-site.example" }), "missing_scope");
    assert.equal(w.prompts().length, promptsBefore);
    await w.finish();
  });

  it("refuses a target origin outside the entry's site, a bad origin, and a mode/kind mismatch — before any approval is requested", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_origin");
    await w.seed(who, "alice@example.com", "cookie", JAR);
    await w.seed(who, "bob@example.com", "password", PASSWORD);
    await w.enroll();
    const start = w.prompts().length;

    const outside = ["https://example.com", "https://evil.example.net", `https://${SITE}.evil.net`, `https://not${SITE}`, "https://com", "https://localhost", "https://169.254.169.254"];
    for (const target_origin of outside) failed(await w.call(who, "entry_inject", { ...COOKIES, target_origin }), "target_origin_not_allowed");
    const malformed = [`http://${SITE}`, `https://${SITE}/`, `https://${SITE}/login`, `https://${SITE}:8443`, `https://user:pw@${SITE}`, `https://${SITE}?x=1`, `https://${SITE.toUpperCase()}`, `//${SITE}`, SITE, `https://*.${SITE}`, "javascript:alert(1)", `chrome-extension://${"a".repeat(32)}`];
    for (const target_origin of malformed) failed(await w.call(who, "entry_inject", { ...COOKIES, target_origin }), "invalid_target_origin");

    // cookies ↔ cookie entry, field ↔ password entry.
    failed(await w.call(who, "entry_inject", { ...COOKIES, account: "bob@example.com" }), "mode_kind_mismatch");
    failed(await w.call(who, "entry_inject", { ...FIELD, account: "alice@example.com" }), "mode_kind_mismatch");
    failed(await w.call(who, "entry_inject", { ...COOKIES, account: "nobody@example.com" }), "entry_not_found");
    failed(await w.call(who, "entry_inject", { ...COOKIES, mode: "header" }), "invalid_arguments");
    failed(await w.call(who, "entry_inject", { ...COOKIES, task: "" }), "invalid_arguments");
    failed(await w.call(who, "entry_inject", { ...COOKIES, kind: "cookie" }), "invalid_arguments");

    assert.equal(w.prompts().length, start, "no Telegram prompt was sent for any refused request");
    assert.equal((await (w.tickets as MemoryInjectTicketStore).dumpForTests()).length, 0);
    assert.ok((await w.rows()).filter((r) => r.capability === "tool.entry_inject").every((r) => r.result === "error" && r.decision === "deny"));
    await w.finish();
  });

  it("no injector enrolled: refused before any approval", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_none");
    await w.seed(who, "alice@example.com", "password", PASSWORD);
    failed(await w.call(who, "entry_inject", FIELD), "no_injector_enrolled");
    assert.equal(w.prompts().length, 0);
    await w.finish();
  });
});

describe("injector channel: cookie selection", () => {
  it("cookiesForOrigin never returns a cookie of another registrable domain, a public suffix, another host or an expired one", () => {
    const now = Date.parse("2026-11-14T12:00:00Z");
    const c = (name: string, domain: string, hostOnly: boolean, expires: number | null = null) => ({ name, value: `value-of-${name}`, domain, path: "/", secure: true, httpOnly: false, hostOnly, expires });
    const jar = {
      v: 1 as const,
      cookies: [
        c("site_host", SITE, true),
        c("site_domain", SITE, false),
        c("bound", "", true), // stored with domain "": host-only for the entry's site
        c("parent", "example.com", false),
        c("parent_hostonly", "example.com", true),
        c("sub", `app.${SITE}`, false),
        c("evil", "evil.example.net", false),
        c("suffix", "com", false),
        c("lookalike", `not${SITE}`, false),
        c("expired", SITE, true, Math.floor(now / 1000) - 1),
      ],
    };
    const names = (host: string) => cookiesForOrigin(jar, host, SITE, now).map((x) => x.name).sort();
    assert.deepEqual(names(SITE), ["bound", "parent", "site_domain", "site_host"]);
    assert.deepEqual(names(`app.${SITE}`), ["parent", "site_domain", "sub"]);
    assert.deepEqual(names(`deep.app.${SITE}`), ["parent", "site_domain", "sub"]);
    assert.deepEqual(names("evil.example.net"), ["evil"], "the function is a pure domain match; the origin rule keeps such a host from ever being asked for");
    for (const host of [SITE, `app.${SITE}`]) {
      for (const x of cookiesForOrigin(jar, host, SITE, now)) assert.ok(host === x.domain || host.endsWith(`.${x.domain}`), `${x.name} matches ${host}`);
    }
    assert.equal(cookiesForOrigin(jar, SITE, SITE, now).find((x) => x.name === "bound")?.domain, SITE);
  });

  it("no stored cookie matches the origin: 503, ticket burned, nothing sealed", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_nocookie");
    await w.seed(who, "dave@example.com", "cookie", { cookies: [{ name: "apponly", value: APP_ONLY, domain: `app.${SITE}`, hostOnly: true, path: "/" }] });
    const inj = await w.enroll();
    const minted = await w.inject(who, { ...COOKIES, account: "dave@example.com" });
    const res = await w.redeem(inj, minted.ticket);
    assert.deepEqual([res.status, res.json], [503, { ok: false, error: "unavailable" }]);
    const row = (await w.rows()).filter((r) => r.capability === "vault.entry.inject.redeem").at(-1);
    assert.deepEqual([row?.result, row?.error], ["error", "no_cookie_for_origin"]);
    await w.finish();
  });
});

describe("injector endpoints: authentication, limits, shape", () => {
  it("only an ein_ token of an active injector authenticates; method, body and size are checked", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_http");
    await w.seed(who, "alice@example.com", "password", PASSWORD);
    const inj = await w.enroll();
    const minted = await w.inject(who, FIELD);
    const body = { ticket: minted.ticket };

    const noAuth = await w.http(handleInjectorRedeem, "/api/injector/redeem", null, body);
    assert.deepEqual([noAuth.status, noAuth.json], [401, { ok: false, error: "invalid_injector" }]);
    for (const token of [`ein_${randomBytes(32).toString("base64url")}`, `eva_${randomBytes(32).toString("base64url")}`, `ewk_${randomBytes(32).toString("base64url")}`, inj.token.slice(0, -1), `${inj.token}x`, inj.id, String(minted.ticket)]) {
      for (const [handler, path] of [[handleInjectorRedeem, "/api/injector/redeem"], [handleInjectorReport, "/api/injector/report"]] as const) {
        const r = await w.http(handler, path, token, body);
        assert.deepEqual([r.status, r.json], [401, { ok: false, error: "invalid_injector" }], token.slice(0, 4));
        assert.equal(r.headers.get("cache-control"), "no-store");
      }
    }
    // The token in another header, a query string or the body authenticates nothing.
    const elsewhere = await w.http(handleInjectorRedeem, `/api/injector/redeem?token=${inj.token}`, null, { ...body, token: inj.token }, { headers: { "x-injector-token": inj.token } });
    assert.equal(elsewhere.status, 401);
    injectorTokens.delete(inj.token); // it was deliberately put into a request above; responses are still scanned for it below
    assert.equal(everyHttp.at(-1)?.includes(inj.token), false);
    injectorTokens.add(inj.token);

    const get = await w.http(handleInjectorRedeem, "/api/injector/redeem", inj.token, null, { method: "GET" });
    assert.deepEqual([get.status, get.json.error, get.headers.get("allow")], [405, "method_not_allowed", "POST"]);
    for (const raw of ["", "not json", "[1]", '"eit"', "null"]) {
      const r = await w.redeem(inj, null, { raw });
      assert.deepEqual([r.status, r.json], [400, { ok: false, error: "invalid_request" }], raw);
    }
    const big = await w.redeem(inj, null, { raw: JSON.stringify({ ticket: minted.ticket, pad: "x".repeat(MAX_INJECTOR_BODY_BYTES) }) });
    assert.deepEqual([big.status, big.json], [413, { ok: false, error: "request_too_large" }]);

    // None of that burned the ticket.
    const ok = await w.redeem(inj, minted.ticket);
    assert.equal(ok.status, 200, ok.text);
    await inj.open(ok.json.sealed as Sealed, { ticket: String(minted.ticket), target_origin: `https://${SITE}`, mode: "field" });
    // Every error body is exactly {ok:false,error:<short code>}.
    for (const r of everyHttp.map((x) => x.slice(x.indexOf("\n") + 1)).filter((t) => t.includes('"ok":false'))) {
      const o = JSON.parse(r) as Record<string, unknown>;
      assert.deepEqual(Object.keys(o).sort(), ["error", "ok"]);
      assert.match(String(o.error), /^[a-z_]{1,40}$/);
    }
    await w.finish();
  });

  it("redeem is rate-limited per injector through the shared store, and fails closed when the store is down", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_rate");
    await w.seed(who, "alice@example.com", "password", PASSWORD);
    const a = await w.enroll("a");
    const b = await w.enroll("b");
    const mine = await w.inject(who, { ...FIELD, injector_id: a.id });
    const bogus = `eit_${randomBytes(24).toString("base64url")}`;
    for (let i = 0; i < REDEEM_MAX_PER_WINDOW; i += 1) assert.equal((await w.redeem(a, bogus)).status, 404);
    const limited = await w.redeem(a, mine.ticket);
    assert.deepEqual([limited.status, limited.json], [429, { ok: false, error: "rate_limited" }]);
    // Per injector: b is unaffected.
    assert.equal((await w.redeem(b, bogus)).status, 404);
    // Keys in the store are hashes of the injector id, never the id or a token.
    const keys = (w.injector.rateLimit as MemoryRateLimitStore).keys();
    assert.ok(keys.length >= 2 && keys.every((k) => /^injector\.redeem:[0-9a-f]{64}$/.test(k)), keys.join(","));
    // The limited attempt did not burn the ticket: after the window it redeems (the ticket is still inside its 120 s).
    w.advance(60_001);
    assert.equal((await w.redeem(a, mine.ticket)).status, 200);

    // Store unreachable → 503, ticket untouched.
    const down: RateLimitStore = {
      kind: "memory",
      hit: async () => {
        throw new Error("db down");
      },
      count: async () => {
        throw new Error("db down");
      },
      reset: async () => undefined,
      prune: async () => 0,
    };
    const next = await w.inject(who, { ...FIELD, injector_id: a.id });
    const res = await handleInjectorRedeem(
      new Request(`${ORIGIN}/api/injector/redeem`, { method: "POST", headers: { authorization: `Bearer ${a.token}`, "content-type": "application/json" }, body: JSON.stringify({ ticket: next.ticket }) }),
      { ...w.injector, rateLimit: down },
    );
    assert.deepEqual([res.status, await res.json()], [503, { ok: false, error: "unavailable" }]);
    assert.equal((await w.tickets.get(sha256hex(String(next.ticket))))?.redeemed_at, null);
    await w.finish();
  });

  it("report: once per redeemed ticket, by the injector that redeemed it", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_report");
    await w.seed(who, "alice@example.com", "password", PASSWORD);
    const a = await w.enroll("a");
    const b = await w.enroll("b");
    const t1 = await w.inject(who, { ...FIELD, injector_id: a.id });
    const sha = sha256hex(String(t1.ticket));

    const early = await w.report(a, { ticket_sha256: sha, result: "injected" });
    assert.deepEqual([early.status, early.json], [409, { ok: false, error: "ticket_not_redeemed" }]);
    assert.equal((await w.redeem(a, t1.ticket)).status, 200);
    assert.deepEqual((await w.report(b, { ticket_sha256: sha, result: "injected" })).json, { ok: false, error: "ticket_wrong_injector" });
    for (const bad of [{ ticket_sha256: sha, result: "done" }, { ticket_sha256: String(t1.ticket), result: "injected" }, { ticket_sha256: sha, result: "failed", detail_code: "Has Spaces And A Value" }, { result: "injected" }]) {
      assert.deepEqual((await w.report(a, bad)).json, { ok: false, error: "invalid_request" });
    }
    assert.deepEqual((await w.report(a, { ticket_sha256: "0".repeat(64), result: "injected" })).json, { ok: false, error: "ticket_not_found" });
    const done = await w.report(a, { ticket_sha256: sha, result: "injected" });
    assert.deepEqual([done.status, done.json, done.headers.get("cache-control")], [200, { ok: true }, "no-store"]);
    assert.deepEqual((await w.report(a, { ticket_sha256: sha, result: "failed" })).json, { ok: false, error: "result_already_reported" });
    assert.equal((await w.tickets.get(sha))?.result, "injected");

    const t2 = await w.inject(who, { ...FIELD, injector_id: a.id });
    await w.redeem(a, t2.ticket);
    assert.equal((await w.report(a, { ticket_sha256: sha256hex(String(t2.ticket)), result: "failed", detail_code: "field_not_found" })).status, 200);
    const results = (await w.rows()).filter((r) => r.capability === "vault.entry.inject.result");
    assert.deepEqual(results.map((r) => [r.client_id, r.result, r.error ?? null, r.approval_id]), [
      [`injector:${a.id}`, "ok", null, t1.approval_id],
      [`injector:${a.id}`, "error", "field_not_found", t2.approval_id],
    ]);
    assert.ok(results.every((r) => /^vault:\/\/entry\/ve_[0-9a-f]{32}$/.test(String(r.credential_ref)) && String(r.resource).endsWith(`#${a.id}`)));
    await w.finish();
  });
});

describe("injector channel: ledger", () => {
  it("writes pending → decide → ok for the mint, then redeem and result, each with entry ref, injector id and approval id", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_ledger");
    const entryId = await w.seed(who, "alice@example.com", "password", PASSWORD);
    const inj = await w.enroll();
    const start = (await w.rows()).length;
    const minted = await w.inject(who, FIELD);
    assert.equal((await w.redeem(inj, minted.ticket)).status, 200);
    assert.equal((await w.report(inj, { ticket_sha256: sha256hex(String(minted.ticket)), result: "injected" })).status, 200);
    const rows = (await w.rows()).slice(start);
    const resource = `entry:${SITE}/alice@example.com#${inj.id}`;
    assert.deepEqual(
      rows.map((r) => [r.client_id, r.capability, r.decision, r.tier, r.result, r.resource]),
      [
        ["oc_inject_ledger", "vault.entry.inject", "escalate", 2, "pending_approval", resource],
        ["owner:telegram", "vault.approval.decide", "allow", 3, "ok", `vault.entry.inject ${resource}`],
        ["oc_inject_ledger", "vault.entry.inject", "escalate", 2, "committing", resource],
        ["oc_inject_ledger", "vault.entry.inject", "escalate", 2, "ok", resource],
        [`injector:${inj.id}`, "vault.entry.inject.redeem", "escalate", 2, "ok", resource],
        [`injector:${inj.id}`, "vault.entry.inject.result", "allow", 2, "ok", resource],
      ],
    );
    assert.ok(rows.every((r) => r.approval_id === minted.approval_id), "every row carries the approval id");
    for (const r of [rows[3], rows[4], rows[5]]) assert.equal(r.credential_ref, `vault://entry/${entryId}`);
    assert.equal(rows[3].task, FIELD.task);

    // Refusals at the endpoint are on the chain too.
    await w.redeem(inj, minted.ticket);
    const refusal = (await w.rows()).at(-1);
    assert.deepEqual([refusal?.capability, refusal?.result, refusal?.error, refusal?.approval_id], ["vault.entry.inject.redeem", "error", "ticket_used", minted.approval_id]);
    await w.finish();
  });

  it("fails closed: no ticket without its mint row, and no ciphertext when the redeem row cannot be written", async () => {
    const w = makeWorld();
    const who = agent("oc_inject_failclosed");
    await w.seed(who, "alice@example.com", "password", PASSWORD);
    const inj = await w.enroll();

    // Mint: the ok row cannot be written → no ticket, in the result or in the store.
    const first = failed(await w.call(who, "entry_inject", FIELD), "approval_required");
    await w.tap(String(first.approval_id));
    w.setLedgerDown((row) => row.capability === "vault.entry.inject" && row.result === "ok");
    const refused = failed(await w.call(who, "entry_inject", { ...FIELD, approval_id: first.approval_id }), "ledger_unavailable");
    assert.equal(refused.action_performed, false);
    assert.equal(JSON.stringify(refused).includes("eit_"), false);
    assert.equal((await (w.tickets as MemoryInjectTicketStore).dumpForTests()).length, 0);
    // The intent row cannot be written either → refused before the mint is even attempted.
    w.setLedgerDown(null);
    const again = failed(await w.call(who, "entry_inject", { ...FIELD, task: "second try" }), "approval_required");
    await w.tap(String(again.approval_id));
    w.setLedgerDown((row) => row.capability === "vault.entry.inject" && row.result === "committing");
    failed(await w.call(who, "entry_inject", { ...FIELD, task: "second try", approval_id: again.approval_id }), "ledger_unavailable");
    assert.equal((await (w.tickets as MemoryInjectTicketStore).dumpForTests()).length, 0);
    w.setLedgerDown(null);

    // Redeem: the row cannot be written → 503, no sealed blob, and the ticket is spent.
    const minted = await w.inject(who, { ...FIELD, task: "third try" });
    w.setLedgerDown((row) => row.capability === "vault.entry.inject.redeem");
    const res = await w.redeem(inj, minted.ticket);
    assert.deepEqual([res.status, res.json], [503, { ok: false, error: "unavailable" }]);
    assert.equal(res.text.includes("sealed"), false);
    w.setLedgerDown(null);
    assert.equal((await w.redeem(inj, minted.ticket)).json.error, "ticket_used");
    await w.finish();
  });
});

describe("injector enrollment (owner only)", () => {
  it("remote identities are refused on every injector admin tool; the local identity enrolls, lists and revokes", async () => {
    const w = makeWorld();
    const inj = await TestInjector.create();
    const calls: Array<[string, Record<string, unknown>]> = [
      ["admin_enroll_injector", { name: "x", public_key_jwk: inj.publicJwk }],
      ["admin_list_injectors", {}],
      ["admin_revoke_injector", { injector_id: "inj_0000000000000000" }],
    ];
    const remotes: ClientIdentity[] = [
      agent("oc_remote_admin", ["vault.read", "vault.write", "audit.read"]),
      { client_id: "workload:sdk-gate", name: "gate", kind: "workload", scopes: ["vault.read", "vault.write"] },
      { client_id: "owner:abcdefabcdef", name: "forged", kind: "owner", scopes: [] }, // not minted by the console
    ];
    for (const who of remotes) {
      for (const [name, args] of calls) {
        const r = await w.call(who, name, args);
        assert.equal(r.ok, false);
        assert.ok(["tier3_human_only", "unauthenticated"].includes((r as { error: string }).error), `${who.client_id} ${name}: ${(r as { error: string }).error}`);
      }
    }
    assert.equal((await w.injectors.list()).length, 0);
    assert.equal(w.prompts().length, 0, "refused admin calls page nobody");

    const enrolled = await w.enroll("desk");
    const listed = await w.call(LOCAL, "admin_list_injectors");
    const list = (listed as { data: { injectors: Array<Record<string, unknown>> } }).data.injectors;
    assert.deepEqual(list.map((i) => [i.injector_id, i.name, i.status]), [[enrolled.id, "desk", "active"]]);
    assert.deepEqual(Object.keys(list[0]).sort(), ["created_at", "injector_id", "key_thumbprint", "last_used_at", "name", "revoked_at", "status"]);
    const [stored] = await (w.injectors as MemoryInjectorStore).dumpForTests();
    assert.equal(stored.token_sha256, sha256hex(enrolled.token), "only the sha256 of the token is stored");
    assert.equal(stored.public_key_jwk, `{"crv":"P-256","kty":"EC","x":"${enrolled.publicJwk.x}","y":"${enrolled.publicJwk.y}"}`);
    assert.equal(JSON.stringify(await w.rows()).includes(enrolled.token), false);

    // Key validation: anything but a P-256 public point is refused, a private key above all.
    const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const priv = p256.privateKey.export({ format: "jwk" });
    const pub = p256.publicKey.export({ format: "jwk" });
    const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" }).publicKey.export({ format: "jwk" });
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" });
    const offCurve = { ...pub, y: Buffer.alloc(32, 7).toString("base64url") };
    const cases: Array<[unknown, string]> = [
      [priv, "private_key_not_allowed"],
      [JSON.stringify(priv), "private_key_not_allowed"],
      [p384, "invalid_public_key"],
      [rsa, "invalid_public_key"],
      [offCurve, "invalid_public_key"],
      [{ ...pub, crv: "P-384" }, "invalid_public_key"],
      [{ ...pub, extra: "member" }, "invalid_public_key"],
      [{ kty: "EC", crv: "P-256", x: pub.x }, "invalid_public_key"],
      ["{not json", "invalid_public_key"],
      [[pub], "invalid_public_key"],
      [42, "invalid_public_key"],
    ];
    for (const [jwk, code] of cases) {
      const r = await w.call(LOCAL, "admin_enroll_injector", { name: "bad", public_key_jwk: jwk });
      failed(r, code);
      assert.equal(JSON.stringify(r).includes(String(priv.d)), false);
    }
    failed(await w.call(LOCAL, "admin_enroll_injector", { name: "dup", public_key_jwk: enrolled.publicJwk }), "key_already_enrolled");
    failed(await w.call(LOCAL, "admin_enroll_injector", { name: "   ", public_key_jwk: pub }), "invalid_name");
    // What a browser exports (ext, key_ops) is accepted, as an object or as JSON text.
    assert.deepEqual(await validatePublicJwk(JSON.stringify({ ...pub, ext: true, key_ops: [] })), { kty: "EC", crv: "P-256", x: pub.x, y: pub.y });
    assert.equal((await w.injectors.list()).length, 1);

    const revoked = await w.call(LOCAL, "admin_revoke_injector", { injector_id: enrolled.id });
    assert.deepEqual((revoked as { data: unknown }).data, { injector_id: enrolled.id, revoked: true });
    assert.deepEqual(((await w.call(LOCAL, "admin_revoke_injector", { injector_id: enrolled.id })) as { data: unknown }).data, { injector_id: enrolled.id, revoked: false });
    failed(await w.call(LOCAL, "admin_revoke_injector", { injector_id: "inj_ffffffffffffffff" }), "injector_not_found");
    await w.finish();
  });
});

// ---------------------------------------------------------------------------

describe("migration 0013 on PGlite", () => {
  it("applies twice; hashes only; the SQL stores run the whole channel, with an atomic single-use redeem", async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const pg = new PGlite();
    try {
      const migration = (f: string) => readFileSync(new URL(`../../../../migrations/${f}`, import.meta.url), "utf8");
      for (const f of ["0005_vault_entries.sql", "0007_vault_entry_rotation.sql", "0012_vault_cookie_entries.sql", "0013_vault_injectors.sql"]) await pg.exec(migration(f));
      await pg.exec(migration("0013_vault_injectors.sql")); // idempotent
      const sql = { query: async (text: string, params: unknown[] = []) => (await pg.query(text, params)).rows } as unknown as Sql;
      const provider = async () => sql;
      const w = makeWorld({
        injectors: new SqlInjectorStore(provider),
        tickets: new SqlInjectTicketStore(provider),
        cards: { entries: new SqlEntryStore(provider), cards: new SqlCardStore(provider) },
      });
      const who = agent("oc_inject_sql");
      await w.seed(who, "alice@example.com", "cookie", `sid=${SQL_SID}`);
      await w.seed(who, "alice@example.com", "password", SQL_PASSWORD);
      const a = await w.enroll("sql a");
      const b = await w.enroll("sql b");

      const t1 = await w.inject(who, { ...COOKIES, injector_id: a.id });
      assert.equal((await w.redeem(b, t1.ticket)).json.error, "ticket_wrong_injector");
      // Atomic burn: many parallel redeems, exactly one success.
      const race = await Promise.all(Array.from({ length: 6 }, () => w.redeem(a, t1.ticket)));
      assert.deepEqual(race.map((r) => r.status).sort(), [200, 409, 409, 409, 409, 409]);
      const won = race.find((r) => r.status === 200) as HttpAnswer;
      const plain = await a.open(won.json.sealed as Sealed, { ticket: String(t1.ticket), target_origin: `https://${SITE}`, mode: "cookies" });
      assert.deepEqual((plain.cookies as Array<Record<string, unknown>>).map((c) => [c.name, c.value, c.domain, c.hostOnly]), [["sid", SQL_SID, SITE, true]]);
      assert.equal((await w.report(a, { ticket_sha256: sha256hex(String(t1.ticket)), result: "injected" })).status, 200);
      assert.equal((await w.report(a, { ticket_sha256: sha256hex(String(t1.ticket)), result: "injected" })).json.error, "result_already_reported");

      const t2 = await w.inject(who, { ...FIELD, injector_id: b.id });
      const r2 = await w.redeem(b, t2.ticket);
      assert.deepEqual(await b.open(r2.json.sealed as Sealed, { ticket: String(t2.ticket), target_origin: `https://${SITE}`, mode: "field" }), { v: 1, username: "alice@example.com", secret: SQL_PASSWORD });

      const t3 = await w.inject(who, { ...FIELD, injector_id: b.id });
      w.advance(TICKET_TTL_MS);
      assert.equal((await w.redeem(b, t3.ticket)).json.error, "ticket_expired");
      assert.equal((await w.call(LOCAL, "admin_revoke_injector", { injector_id: b.id })).ok, true);
      assert.equal((await w.redeem(b, t3.ticket)).status, 401);
      const listed = (await w.call(LOCAL, "admin_list_injectors")) as { data: { injectors: Array<Record<string, unknown>> } };
      assert.deepEqual(listed.data.injectors.map((i) => [i.injector_id, i.status, i.last_used_at !== null]), [[a.id, "active", true], [b.id, "revoked", true]]);

      // Rows: hashes and bindings only.
      const injectorRows = (await pg.query("select * from vault_injectors order by created_at, id")).rows as Array<Record<string, unknown>>;
      const ticketRows = (await pg.query("select * from vault_inject_tickets order by created_at")).rows as Array<Record<string, unknown>>;
      const dump = JSON.parse(JSON.stringify([injectorRows, ticketRows, (await pg.query("select * from vault_entries")).rows], (_k, v) => (typeof v === "bigint" ? Number(v) : v)));
      everyRow.push(dump);
      assert.deepEqual(Object.keys(injectorRows[0]).sort(), ["created_at", "id", "last_used_at", "name", "public_key_jwk", "revoked_at", "token_sha256"]);
      assert.deepEqual(Object.keys(ticketRows[0]).sort(), ["approval_id", "client_id", "created_at", "entry_id", "expires_at", "injector_id", "mode", "redeemed_at", "result", "sha256", "target_origin"]);
      assert.equal(injectorRows[0].token_sha256, sha256hex(a.token));
      assert.deepEqual(ticketRows.map((t) => [t.sha256, t.mode, t.injector_id, t.result]), [
        [sha256hex(String(t1.ticket)), "cookies", a.id, "injected"],
        [sha256hex(String(t2.ticket)), "field", b.id, null],
        [sha256hex(String(t3.ticket)), "field", b.id, null],
      ]);
      assert.ok(ticketRows.every((t) => t.approval_id && t.client_id === "oc_inject_sql" && t.target_origin === `https://${SITE}`));

      // CHECK constraints: a raw token, a raw ticket, a private JWK, a non-https origin, a reused approval are unstorable.
      const pubJwk = `{"crv":"P-256","kty":"EC","x":"${a.publicJwk.x}","y":"${a.publicJwk.y}"}`;
      const insInjector = (id: string, jwk: string, tokenHash: string) =>
        pg.query("insert into vault_injectors (id, name, public_key_jwk, token_sha256, created_at) values ($1, 'n', $2, $3, 1)", [id, jwk, tokenHash]);
      await assert.rejects(insInjector("inj_1111111111111111", pubJwk, a.token), "a raw token is not a sha256");
      await assert.rejects(insInjector("inj_1111111111111111", pubJwk.replace("}", `,"d":"${"A".repeat(43)}"}`), sha256hex("t1")), "a private JWK cannot be stored");
      await assert.rejects(insInjector("not-an-id", pubJwk, sha256hex("t2")));
      await assert.rejects(insInjector("inj_1111111111111111", pubJwk, sha256hex(a.token)), "token hash is unique");
      const insTicket = (sha: string, origin: string, mode: string, approval: string, injector = a.id) =>
        pg.query(
          "insert into vault_inject_tickets (sha256, entry_id, mode, target_origin, injector_id, approval_id, client_id, created_at, expires_at) values ($1, $2, $3, $4, $5, $6, 'oc_x', 1, 2)",
          [sha, `ve_${"a".repeat(32)}`, mode, origin, injector, approval],
        );
      await assert.rejects(insTicket(String(t1.ticket), `https://${SITE}`, "field", "ap1"), "a raw ticket is not a sha256");
      await assert.rejects(insTicket(sha256hex("x1"), `http://${SITE}`, "field", "ap2"));
      await assert.rejects(insTicket(sha256hex("x2"), `https://${SITE}/path`, "field", "ap3"));
      await assert.rejects(insTicket(sha256hex("x3"), `https://${SITE}`, "header", "ap4"));
      await assert.rejects(insTicket(sha256hex("x4"), `https://${SITE}`, "field", String(t1.approval_id)), "one approval, one ticket");
      await assert.rejects(insTicket(sha256hex("x5"), `https://${SITE}`, "field", "ap5", "inj_9999999999999999"), "the injector must exist");
      await assert.rejects(pg.query("update vault_inject_tickets set result = 'injected' where sha256 = $1", [sha256hex(String(t3.ticket))]), "no result without a redeem");
      await assert.rejects(pg.query("update vault_inject_tickets set result = 'leaked-value' where sha256 = $1", [sha256hex(String(t1.ticket))]));
      await insTicket(sha256hex("x6"), `https://app.${SITE}`, "cookies", "ap6");
      await w.finish();
    } finally {
      await pg.close();
    }
  });

  it("the full migration set applies in order with 0013 last", async () => {
    const { readdirSync } = await import("node:fs");
    const dir = new URL("../../../../migrations/", import.meta.url);
    const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
    assert.equal(files.at(-1), "0013_vault_injectors.sql");
    assert.equal(files.filter((f) => f.startsWith("0013_")).length, 1);
  });
});
