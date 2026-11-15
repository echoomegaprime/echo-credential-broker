// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Owner console tests. WebAuthn ceremonies are REAL: a software authenticator
 * written here (P-256 key from node:crypto, hand-built clientDataJSON,
 * authenticatorData and a "none" attestation object, ECDSA-signed assertions)
 * talks to the console's HTTP handler, and @simplewebauthn/server verifies the
 * responses unmocked. There is no browser and no hardware authenticator in
 * this file. Stores are in memory, plus the SQL store on PGlite with the real
 * migration. No network, no real vault.
 */
import assert from "node:assert/strict";
import { createHash, createSign, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { FakeVaultBackend } from "../backend.ts";
import { CredentialStore } from "../store.ts";
import { MemoryApprovalStore } from "./approvals.ts";
import { ensureV2Configured } from "./bootstrap.ts";
import { escapeHtml, handleCardRequest } from "./card-pages.ts";
import { MemoryCardStore, MemoryEntryStore, type CardsDeps } from "./cards.ts";
import type { ClientIdentity } from "./contracts.ts";
import { MemoryDigestStateStore } from "./digest.ts";
import { MemoryEntryGrantStore } from "./entry-grants.ts";
import { dispatchTool, TOOL_DEFINITIONS, type GatewayDeps, type GatewayResult } from "./gateway.ts";
import { authenticateHttp, handleMcpPost, handleRestTool } from "./http-transport.ts";
import { authenticateRequest, localIdentity } from "./identity.ts";
import { Ledger, MemoryLedgerStore } from "./ledger.ts";
import { MemoryAnchorStore } from "./ledger-anchor.ts";
import {
  configureOAuth,
  handleAuthorize,
  handleRegister,
  handleToken,
  resetOAuth,
  s256Challenge,
  SUPPORTED_SCOPES,
  type OwnerApprover,
} from "./oauth-server.ts";
import { MemoryOAuthStore } from "./oauth-store.ts";
import {
  authenticateSession,
  CHALLENGE_TTL_MS,
  consoleConfig,
  CONSOLE_TOOLS,
  csrfTokenFor,
  MAX_FAILED_ASSERTIONS,
  MAX_FAILED_BOOTSTRAP,
  runOwnerTool,
  SESSION_ABSOLUTE_MS,
  SESSION_IDLE_MS,
  STEP_UP_MS,
  toolNeedsStepUp,
  type ConsoleDeps,
} from "./owner-console.ts";
import { CONSOLE_COOKIE, CONSOLE_ROUTES, handleConsoleRequest } from "./owner-console-pages.ts";
import {
  MemoryOwnerConsoleStore,
  sha256Hex,
  SqlOwnerConsoleStore,
  type OwnerConsoleStore,
  type PasskeyRecord,
  type SessionRecord,
} from "./owner-console-store.ts";
import { WEBAUTHN_BROWSER_BUNDLE, WEBAUTHN_BROWSER_SHA256 } from "./owner-console-webauthn-bundle.ts";
import { BOOTSTRAP_TTL_MS, isMintedOwnerIdentity, mintOwnerIdentity, ownerClientId } from "./owner-identity.ts";
import { MemoryRateLimitStore, setDefaultRateLimitStore, type RateLimitStore } from "./rate-limit-store.ts";
import { authenticateWorkload, resetWorkloadCacheForTests } from "./workload.ts";

setDefaultRateLimitStore(new MemoryRateLimitStore());

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ORIGIN = "https://vault.example.test";
const RP_ID = "vault.example.test";
/** What the server "sees" as the request URL: a different host on purpose — the console must never use it. */
const INTERNAL = "http://10.9.8.7:8080";
const T0 = Date.parse("2026-11-14T10:00:00.000Z");
const APPROVER_ID = 424242;
const ENV: NodeJS.ProcessEnv = {
  ECHO_VAULT_CONSOLE_ORIGIN: ORIGIN,
  TELEGRAM_BOT_TOKEN: "123456789:AAH_TESTONLY_bot_token_do_not_use_0123456789",
  ECHO_VAULT_APPROVER_TELEGRAM_ID: String(APPROVER_ID),
  ECHO_VAULT_PUBLIC_URL: ORIGIN,
  ECHO_VAULT_APPROVAL_HMAC_KEY: "test-only-approval-hmac-key-0123456789abcdef",
};

const SECRETS = ["Leak/Scan+Passw0rd&=?#%! 01", "leakscan_api_key_A1b2C3d4E5f6G7h8", "leak<scan>\"quote'&amp;-secret-03"];
const secretsToScan = new Set<string>(SECRETS);

function variants(secret: string): string[] {
  const buf = Buffer.from(secret, "utf8");
  return [
    secret,
    buf.toString("base64"),
    buf.toString("base64").replace(/=+$/, ""),
    buf.toString("base64url"),
    buf.toString("hex"),
    encodeURIComponent(secret),
    new URLSearchParams({ s: secret }).toString().slice(2),
    escapeHtml(secret),
    JSON.stringify(secret).slice(1, -1),
  ];
}

function scan(label: string, value: unknown): void {
  const blob = typeof value === "string" ? value : JSON.stringify(value);
  for (const secret of secretsToScan) {
    for (const v of variants(secret)) assert.equal(blob.includes(v), false, `${label} leaks a secret (${v.length} chars form)`);
  }
}

// Process output (logs) is captured for the whole file and scanned at the end.
const captured: string[] = [];
const restores: Array<() => void> = [];
const everyResponse: string[] = [];

before(() => {
  for (const stream of [process.stdout, process.stderr]) {
    const orig = stream.write.bind(stream);
    const isErr = stream === process.stderr;
    stream.write = ((chunk: unknown, enc?: unknown, cb?: unknown) => {
      captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("latin1"));
      return isErr ? true : orig(chunk as never, enc as never, cb as never);
    }) as typeof stream.write;
    restores.push(() => {
      stream.write = orig as typeof stream.write;
    });
  }
});

after(() => {
  for (const restore of restores) restore();
  scan("captured process output", captured.join("\n"));
  scan("every console response", everyResponse.join("\n"));
});

// ---------------------------------------------------------------------------
// Software authenticator
// ---------------------------------------------------------------------------

const b64u = (b: Uint8Array | string): string => Buffer.from(b).toString("base64url");
const sha256 = (b: Uint8Array | string): Buffer => createHash("sha256").update(b).digest();

function cborBytes(b: Buffer): Buffer {
  if (b.length < 24) return Buffer.concat([Buffer.from([0x40 + b.length]), b]);
  if (b.length < 256) return Buffer.concat([Buffer.from([0x58, b.length]), b]);
  return Buffer.concat([Buffer.from([0x59, b.length >> 8, b.length & 0xff]), b]);
}
function cborText(s: string): Buffer {
  const b = Buffer.from(s, "utf8");
  assert.ok(b.length < 24);
  return Buffer.concat([Buffer.from([0x60 + b.length]), b]);
}

interface CeremonyOverrides {
  origin?: string;
  rpId?: string;
  /** Set the UV flag. Default true. */
  uv?: boolean;
  /** Force a specific signature counter instead of incrementing. */
  counter?: number;
  /** Sign with a different key (a forged assertion). */
  signWith?: KeyObject;
}

interface Options {
  challenge: string;
  rpId?: string;
  rp?: { id?: string };
  authenticatorSelection?: { userVerification?: string; residentKey?: string };
  userVerification?: string;
  attestation?: string;
  allowCredentials?: unknown[];
  excludeCredentials?: Array<{ id: string }>;
}

class SoftAuthenticator {
  readonly credentialId = randomBytes(32);
  readonly keys = generateKeyPairSync("ec", { namedCurve: "P-256" });
  counter = 0;

  get id(): string {
    return b64u(this.credentialId);
  }

  private coseKey(): Buffer {
    const jwk = this.keys.publicKey.export({ format: "jwk" }) as { x: string; y: string };
    // {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
    return Buffer.concat([
      Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]),
      cborBytes(Buffer.from(jwk.x, "base64url")),
      Buffer.from([0x22]),
      cborBytes(Buffer.from(jwk.y, "base64url")),
    ]);
  }

  private nextCounter(o: CeremonyOverrides): Buffer {
    this.counter = o.counter ?? this.counter + 1;
    const out = Buffer.alloc(4);
    out.writeUInt32BE(this.counter);
    return out;
  }

  private clientData(type: string, challenge: string, o: CeremonyOverrides): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin: o.origin ?? ORIGIN, crossOrigin: false }), "utf8");
  }

  /** navigator.credentials.create() */
  register(options: Options, o: CeremonyOverrides = {}): Record<string, unknown> {
    const flags = 0x01 | 0x40 | (o.uv === false ? 0 : 0x04); // UP | AT | UV
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credentialId.length);
    const authData = Buffer.concat([
      sha256(o.rpId ?? RP_ID),
      Buffer.from([flags]),
      this.nextCounter(o),
      Buffer.alloc(16), // aaguid
      idLen,
      this.credentialId,
      this.coseKey(),
    ]);
    const attestationObject = Buffer.concat([
      Buffer.from([0xa3]),
      cborText("fmt"),
      cborText("none"),
      cborText("attStmt"),
      Buffer.from([0xa0]),
      cborText("authData"),
      cborBytes(authData),
    ]);
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(this.clientData("webauthn.create", options.challenge, o)),
        attestationObject: b64u(attestationObject),
        transports: ["internal", "hybrid"],
      },
    };
  }

  /** navigator.credentials.get() */
  assert(options: Options, o: CeremonyOverrides = {}): Record<string, unknown> {
    const flags = 0x01 | (o.uv === false ? 0 : 0x04);
    const authData = Buffer.concat([sha256(o.rpId ?? RP_ID), Buffer.from([flags]), this.nextCounter(o)]);
    const clientDataJSON = this.clientData("webauthn.get", options.challenge, o);
    const signature = createSign("sha256")
      .update(Buffer.concat([authData, sha256(clientDataJSON)]))
      .sign(o.signWith ?? this.keys.privateKey);
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
        userHandle: b64u("echo-vault-owner"),
      },
    };
  }
}

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

const LOCAL: ClientIdentity = { client_id: "local:owner", name: "owner", kind: "local", scopes: [] };
const AGENT: ClientIdentity = { client_id: "oc_agent", name: "Agent", kind: "oauth", scopes: [...SUPPORTED_SCOPES] };
const WORKLOAD: ClientIdentity = { client_id: "workload:svc", name: "svc", kind: "workload", scopes: [...SUPPORTED_SCOPES] };

interface Sent {
  status: number;
  headers: Headers;
  text: string;
  json: Record<string, unknown>;
}

interface Login {
  token: string;
  cookie: string;
  csrf: string;
}

function makeWorld(opts: { store?: OwnerConsoleStore; rateLimits?: RateLimitStore; env?: NodeJS.ProcessEnv } = {}) {
  let clock = T0;
  const telegram: Array<Record<string, unknown>> = [];
  const telegramFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    assert.ok(String(input).startsWith("https://api.telegram.org/bot"));
    telegram.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
    return new Response(JSON.stringify({ ok: true, result: { message_id: telegram.length } }), { status: 200 });
  }) as typeof fetch;

  const backend = new FakeVaultBackend();
  const ledgerStore = new MemoryLedgerStore();
  const ledger = new Ledger({ store: ledgerStore });
  const grants = new MemoryEntryGrantStore();
  const entries = new MemoryEntryStore();
  const env = opts.env ?? ENV;
  const cards: CardsDeps = { entries, cards: new MemoryCardStore(), backend, ledger: (i) => ledger.append(i), fetch: telegramFetch, env };
  const store = opts.store ?? new MemoryOwnerConsoleStore();
  const rateLimits = opts.rateLimits ?? new MemoryRateLimitStore();
  const gateway: GatewayDeps = {
    ledger: (i) => ledger.append(i),
    listLedger: (o) => ledger.list(o),
    verifyLedger: () => ledger.verify(),
    ledgerHead: () => ledger.head(),
    anchor: { ledger, anchors: new MemoryAnchorStore(), fetch: telegramFetch, env },
    approvals: { store: new MemoryApprovalStore(), fetch: telegramFetch, env },
    rules: [],
    store: new CredentialStore(backend),
    cards,
    grants,
    fetch: (async () => new Response("{}", { status: 404 })) as typeof fetch,
    resolveHost: async () => ["140.82.112.5"],
    digest: { ledger, state: new MemoryDigestStateStore(), fetch: telegramFetch, env },
    console: { store, now: () => clock },
  };
  const deps: ConsoleDeps = { env, now: () => clock, store, rateLimits, gateway };

  const rows = () => ledgerStore.scanAscending(0, 100_000);

  async function send(
    method: string,
    path: string,
    o: { cookie?: string; form?: Record<string, string | string[]>; json?: unknown; headers?: Record<string, string>; rawBody?: string } = {},
  ): Promise<Sent> {
    const headers: Record<string, string> = {};
    if (o.cookie) headers.cookie = o.cookie;
    let body: string | undefined;
    if (method === "POST") {
      headers.origin = ORIGIN;
      headers["sec-fetch-site"] = "same-origin";
      if (o.form) {
        const p = new URLSearchParams();
        for (const [k, v] of Object.entries(o.form)) for (const x of Array.isArray(v) ? v : [v]) p.append(k, x);
        body = p.toString();
        headers["content-type"] = "application/x-www-form-urlencoded";
        headers.origin = "null"; // what browsers send for a same-origin form POST under Referrer-Policy: no-referrer
      } else {
        body = o.rawBody ?? JSON.stringify(o.json ?? {});
        headers["content-type"] = "application/json";
      }
    }
    for (const [k, v] of Object.entries(o.headers ?? {})) {
      if (v === "") delete headers[k];
      else headers[k] = v;
    }
    const res = await handleConsoleRequest(new Request(`${INTERNAL}${path}`, { method, headers, body }), deps);
    const text = await res.text();
    everyResponse.push(`${res.status} ${JSON.stringify([...res.headers])}\n${text}`);
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      // an HTML page
    }
    return { status: res.status, headers: res.headers, text, json };
  }

  async function mintCode(): Promise<string> {
    const result = await dispatchTool(LOCAL, "admin_console_bootstrap", {}, gateway);
    assert.equal(result.ok, true, JSON.stringify(result));
    return String(((result as { data: Record<string, unknown> }).data).bootstrap_code);
  }

  async function enroll(auth: SoftAuthenticator, label = "Test key"): Promise<Sent> {
    const code = await mintCode();
    const opt = await send("POST", "/console/enroll/options", { json: { code } });
    assert.equal(opt.status, 200, opt.text);
    return send("POST", "/console/enroll/verify", { json: { code, label, response: auth.register(opt.json.options as Options) } });
  }

  async function login(auth: SoftAuthenticator, o: CeremonyOverrides = {}): Promise<Login> {
    const opt = await send("POST", "/console/login/options");
    assert.equal(opt.status, 200, opt.text);
    const done = await send("POST", "/console/login/verify", { json: { response: auth.assert(opt.json.options as Options, o) } });
    assert.equal(done.status, 200, done.text);
    const setCookie = done.headers.get("set-cookie") ?? "";
    const token = new RegExp(`${CONSOLE_COOKIE}=([A-Za-z0-9_-]{43});`).exec(setCookie)?.[1] ?? "";
    assert.ok(token, "login sets the session cookie");
    return { token, cookie: `${CONSOLE_COOKIE}=${token}`, csrf: csrfTokenFor(token) };
  }

  async function stepUp(l: Login, auth: SoftAuthenticator): Promise<Sent> {
    const opt = await send("POST", "/console/stepup/options", { cookie: l.cookie, headers: { "x-csrf-token": l.csrf } });
    assert.equal(opt.status, 200, opt.text);
    return send("POST", "/console/stepup/verify", {
      cookie: l.cookie,
      headers: { "x-csrf-token": l.csrf },
      json: { response: auth.assert(opt.json.options as Options) },
    });
  }

  const post = (l: Login, path: string, form: Record<string, string | string[]> = {}): Promise<Sent> =>
    send("POST", path, { cookie: l.cookie, form: { csrf: l.csrf, ...form } });

  /** Create an entry the way production does: an agent requests a card, the owner types the secret. */
  async function seedEntry(site: string, account: string, kind: string, secret: string): Promise<string> {
    const asked = await dispatchTool(AGENT, "entry_request_card", { site, account, kind, reason: "seed" }, gateway);
    assert.equal(asked.ok, true, JSON.stringify(asked));
    const text = [...telegram].reverse().find((c) => typeof c.text === "string" && /\/card\//.test(c.text as string));
    const token = /\/card\/([A-Za-z0-9_-]{43})/.exec(String(text?.text))?.[1] ?? "";
    const res = await handleCardRequest(
      new Request(`${ORIGIN}/card/${token}`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", origin: "null", "sec-fetch-site": "same-origin" },
        body: new URLSearchParams({ secret }).toString(),
      }),
      token,
      cards,
    );
    assert.equal(res.status, 200);
    const listed = await dispatchTool(LOCAL, "admin_list_entries", { site }, gateway);
    const found = ((listed as { data: { entries: Array<{ id: string; account: string }> } }).data.entries).find((x) => x.account === account);
    assert.ok(found);
    return found.id;
  }

  return {
    deps,
    gateway,
    store,
    rateLimits,
    ledger,
    rows,
    telegram,
    grants,
    entries,
    send,
    mintCode,
    enroll,
    login,
    stepUp,
    post,
    seedEntry,
    advance: (ms: number) => {
      clock += ms;
    },
    now: () => clock,
  };
}

type World = ReturnType<typeof makeWorld>;

async function ready(w: World = makeWorld()): Promise<{ w: World; auth: SoftAuthenticator; l: Login }> {
  const auth = new SoftAuthenticator();
  assert.equal((await w.enroll(auth)).status, 200);
  return { w, auth, l: await w.login(auth) };
}

/** True when a real element (not escaped text, not a quoted attribute value) carries an on* attribute. */
function hasInlineHandler(markup: string): boolean {
  for (const tag of markup.matchAll(/<[a-zA-Z][^<>]*>/g)) {
    if (/\son[a-z]+\s*=/i.test(tag[0].replace(/"[^"]*"/g, '""'))) return true;
  }
  return false;
}

function expectFail(result: GatewayResult, error: string): void {
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal((result as { error: string }).error, error, JSON.stringify(result));
}

const ENTRY0 = `ve_${"0".repeat(32)}`;

// ---------------------------------------------------------------------------
// Configuration gate
// ---------------------------------------------------------------------------

describe("console configuration comes from the environment only", () => {
  it("parses origins strictly", () => {
    assert.deepEqual(consoleConfig({ ECHO_VAULT_CONSOLE_ORIGIN: "https://vault.example.com" }), { ok: true, origin: "https://vault.example.com", rpId: "vault.example.com" });
    assert.deepEqual(consoleConfig({ ECHO_VAULT_CONSOLE_ORIGIN: "https://vault.example.com:8443/" }), { ok: true, origin: "https://vault.example.com:8443", rpId: "vault.example.com" });
    assert.deepEqual(consoleConfig({}), { ok: false, reason: "unset" });
    assert.deepEqual(consoleConfig({ ECHO_VAULT_CONSOLE_ORIGIN: "  " }), { ok: false, reason: "unset" });
    for (const bad of [
      "http://vault.example.com",
      "https://vault.example.com/console",
      "https://vault.example.com?x=1",
      "https://user:pw@vault.example.com",
      "https://10.0.0.1",
      "https://[::1]",
      "vault.example.com",
      "ftp://vault.example.com",
      "https://Vault.Example.com",
      "http://127.0.0.1:8080",
    ]) {
      assert.deepEqual(consoleConfig({ ECHO_VAULT_CONSOLE_ORIGIN: bad, ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST: "1" }), { ok: false, reason: "invalid" }, bad);
    }
    assert.deepEqual(consoleConfig({ ECHO_VAULT_CONSOLE_ORIGIN: "http://localhost:8080" }), { ok: false, reason: "localhost_not_allowed" });
    assert.deepEqual(consoleConfig({ ECHO_VAULT_CONSOLE_ORIGIN: "http://localhost:8080", ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST: "true" }), { ok: false, reason: "localhost_not_allowed" });
    assert.deepEqual(consoleConfig({ ECHO_VAULT_CONSOLE_ORIGIN: "http://localhost:8080", ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST: "1" }), { ok: true, origin: "http://localhost:8080", rpId: "localhost" });
  });

  it("every console path answers 503 while ECHO_VAULT_CONSOLE_ORIGIN is unset or unusable", async () => {
    for (const env of [{}, { ECHO_VAULT_CONSOLE_ORIGIN: "http://vault.example.com" }, { ECHO_VAULT_CONSOLE_ORIGIN: "http://localhost:8080" }]) {
      const w = makeWorld({ env });
      for (const [method, path] of [
        ["GET", "/console"],
        ["GET", "/console/login"],
        ["GET", "/console/enroll"],
        ["GET", "/console/entries"],
        ["POST", "/console/login/options"],
        ["POST", "/console/enroll/options"],
        ["POST", "/console/logout"],
      ]) {
        const res = await w.send(method, path, { json: {} });
        assert.equal(res.status, 503, `${method} ${path}`);
        assert.match(res.text, /Owner console disabled/);
        assert.equal(res.headers.get("cache-control"), "no-store");
      }
      assert.equal((await w.rows()).length, 0);
    }
  });

  it("http://localhost works only with the explicit opt-in, and the request's own host is irrelevant", async () => {
    const env = { ...ENV, ECHO_VAULT_CONSOLE_ORIGIN: "http://localhost:8080", ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST: "1" };
    const w = makeWorld({ env });
    assert.equal((await w.send("GET", "/console/login")).status, 200);
    // A request whose URL host is the production-looking origin gains nothing when the env says otherwise.
    const off = makeWorld({ env: {} });
    const res = await handleConsoleRequest(new Request(`${ORIGIN}/console/login`, { headers: { host: RP_ID } }), off.deps);
    assert.equal(res.status, 503);
  });
});

// ---------------------------------------------------------------------------
// Bootstrap + enrollment
// ---------------------------------------------------------------------------

describe("enrollment bootstrap", () => {
  it("only the local stdio identity can mint the code; the code is never ledgered or stored raw", async () => {
    const w = makeWorld();
    for (const who of [AGENT, WORKLOAD]) expectFail(await dispatchTool(who, "admin_console_bootstrap", {}, w.gateway), "tier3_human_only");
    const code = await w.mintCode();
    assert.match(code, /^evb_[A-Za-z0-9_-]{32}$/);
    const memory = w.store as MemoryOwnerConsoleStore;
    assert.match(memory.bootstrap?.code_hash ?? "", /^[0-9a-f]{64}$/);
    assert.equal(JSON.stringify(memory.bootstrap).includes(code), false);
    assert.equal(JSON.stringify((await w.rows())).includes(code), false, "the code is not in the ledger");
    const row = (await w.rows()).at(-1);
    assert.deepEqual([row?.client_id, row?.capability, row?.result], ["local:owner", "vault.admin.console.bootstrap", "ok"]);
    assert.equal(captured.join("").includes(code), false, "the code is not logged");

    // An owner console session cannot mint it either — neither through the console path nor the gateway.
    const { l } = await ready(w);
    const session = await authenticateSession(l.token, w.deps);
    assert.ok(session);
    expectFail(await runOwnerTool(session, "admin_console_bootstrap", {}, w.deps), "tool_not_available");
    expectFail(await dispatchTool(session.identity, "admin_console_bootstrap", {}, w.gateway), "tier3_human_only");
  });

  it("enroll → login → session; the code is single use and a new mint replaces the old one", async () => {
    const w = makeWorld();
    const auth = new SoftAuthenticator();
    const code = await w.mintCode();
    const opt = await w.send("POST", "/console/enroll/options", { json: { code } });
    const options = opt.json.options as Options;
    assert.equal(options.rp?.id, RP_ID);
    assert.equal(options.authenticatorSelection?.userVerification, "required");
    assert.equal(options.authenticatorSelection?.residentKey, "required");
    assert.equal(options.attestation, "none");
    const done = await w.send("POST", "/console/enroll/verify", { json: { code, label: "MacBook", response: auth.register(options) } });
    assert.equal(done.status, 200, done.text);
    assert.deepEqual(done.json, { ok: true });

    const stored = (await w.store.listPasskeys())[0];
    assert.equal(stored.credential_id, auth.id);
    assert.equal(stored.label, "MacBook");
    assert.deepEqual(stored.transports, ["internal", "hybrid"]);
    assert.deepEqual(Object.keys(stored).sort(), ["counter", "created_at", "credential_id", "flag_reason", "flagged_at", "label", "last_used_at", "public_key", "transports"]);

    // Same code again: refused at both steps.
    const second = new SoftAuthenticator();
    const again = await w.send("POST", "/console/enroll/options", { json: { code } });
    assert.deepEqual([again.status, again.json.error], [400, "bootstrap_code_invalid"]);
    assert.equal((await w.store.listPasskeys()).length, 1);

    // A new mint replaces the previous (unused) code.
    const first = await w.mintCode();
    const replacement = await w.mintCode();
    assert.equal((await w.send("POST", "/console/enroll/options", { json: { code: first } })).json.error, "bootstrap_code_invalid");
    const opt2 = await w.send("POST", "/console/enroll/options", { json: { code: replacement } });
    assert.equal(opt2.status, 200);
    assert.equal((opt2.json.options as Options).excludeCredentials?.[0]?.id, auth.id, "already enrolled credentials are excluded");
    assert.equal((await w.send("POST", "/console/enroll/verify", { json: { code: replacement, response: second.register(opt2.json.options as Options) } })).status, 200);

    const l = await w.login(auth);
    const home = await w.send("GET", "/console", { cookie: l.cookie });
    assert.equal(home.status, 200);
    assert.match(home.text, /Overview/);
    assert.ok(home.text.includes(ownerClientId(auth.id)));
    const rows = (await w.rows());
    assert.ok(rows.some((r) => r.capability === "vault.console.enroll" && r.result === "ok" && r.client_id === ownerClientId(auth.id)));
    assert.ok(rows.some((r) => r.capability === "vault.console.enroll" && r.result === "denied" && r.error === "bootstrap_code_invalid"));
    assert.ok(rows.some((r) => r.capability === "vault.console.login" && r.result === "ok" && r.client_id === ownerClientId(auth.id)));
  });

  it("two parallel enrollments with one code: exactly one passkey is created", async () => {
    const w = makeWorld();
    const code = await w.mintCode();
    const a = new SoftAuthenticator();
    const b = new SoftAuthenticator();
    const oa = await w.send("POST", "/console/enroll/options", { json: { code } });
    const ob = await w.send("POST", "/console/enroll/options", { json: { code } });
    const results = await Promise.all([
      w.send("POST", "/console/enroll/verify", { json: { code, response: a.register(oa.json.options as Options) } }),
      w.send("POST", "/console/enroll/verify", { json: { code, response: b.register(ob.json.options as Options) } }),
    ]);
    assert.deepEqual(results.map((r) => r.status).sort(), [200, 400]);
    assert.equal((await w.store.listPasskeys()).length, 1);
  });

  it("the code expires after 15 minutes", async () => {
    const w = makeWorld();
    const code = await w.mintCode();
    w.advance(BOOTSTRAP_TTL_MS - 1000);
    assert.equal((await w.send("POST", "/console/enroll/options", { json: { code } })).status, 200);
    w.advance(1001);
    const late = await w.send("POST", "/console/enroll/options", { json: { code } });
    assert.deepEqual([late.status, late.json.error], [400, "bootstrap_code_invalid"]);
  });

  it("wrong codes are rate-limited through the DB store, and the limiter fails closed", async () => {
    const w = makeWorld();
    const code = await w.mintCode();
    for (let i = 0; i < MAX_FAILED_BOOTSTRAP; i++) {
      const res = await w.send("POST", "/console/enroll/options", { json: { code: `evb_${randomBytes(24).toString("base64url")}` } });
      assert.deepEqual([res.status, res.json.error], [400, "bootstrap_code_invalid"]);
    }
    // Over the limit: even the right code is refused, nothing is compared.
    const blocked = await w.send("POST", "/console/enroll/options", { json: { code } });
    assert.deepEqual([blocked.status, blocked.json.error], [429, "rate_limited"]);
    const keys = (w.rateLimits as MemoryRateLimitStore).keys();
    assert.ok(keys.every((k) => /^[a-z0-9_.-]+:[0-9a-f]{64}$/.test(k)), "keys are namespace:sha256 only");
    assert.ok(keys.some((k) => k.startsWith("console.bootstrap:")));
    w.advance(15 * 60 * 1000 + 1);
    const fresh = await w.mintCode();
    assert.equal((await w.send("POST", "/console/enroll/options", { json: { code: fresh } })).status, 200);

    const down: RateLimitStore = {
      kind: "memory",
      hit: async () => Promise.reject(new Error("db down")),
      count: async () => Promise.reject(new Error("db down")),
      reset: async () => Promise.reject(new Error("db down")),
      prune: async () => Promise.reject(new Error("db down")),
    };
    const closed = makeWorld({ rateLimits: down });
    const c2 = await closed.mintCode();
    const refused = await closed.send("POST", "/console/enroll/options", { json: { code: c2 } });
    assert.deepEqual([refused.status, refused.json.error], [503, "rate_limit_unavailable"]);
    assert.equal((await closed.send("POST", "/console/login/options")).status, 503);
    assert.equal((await closed.store.listPasskeys()).length, 0);
  });

  it("a bad registration (wrong origin, wrong RP ID, no UV, replay, expired) is refused and does not burn the code", async () => {
    const w = makeWorld();
    const code = await w.mintCode();
    const attempt = async (o: CeremonyOverrides, expected: string, mutate?: (w: World) => void): Promise<void> => {
      const auth = new SoftAuthenticator();
      const opt = await w.send("POST", "/console/enroll/options", { json: { code } });
      mutate?.(w);
      const res = await w.send("POST", "/console/enroll/verify", { json: { code, response: auth.register(opt.json.options as Options, o) } });
      assert.deepEqual([res.status, res.json.error], [400, expected], JSON.stringify(o));
    };
    await attempt({ origin: "https://evil.example" }, "registration_invalid");
    await attempt({ origin: `${ORIGIN}.evil.example` }, "registration_invalid");
    await attempt({ origin: INTERNAL }, "registration_invalid"); // the request's own host is not an accepted origin
    await attempt({ rpId: "evil.example" }, "registration_invalid");
    await attempt({ uv: false }, "registration_invalid");
    await attempt({}, "challenge_expired", (x) => x.advance(CHALLENGE_TTL_MS + 1));
    assert.equal((await w.store.listPasskeys()).length, 0);

    // Replay of a registration response: the first use wins, the second finds no challenge.
    const auth = new SoftAuthenticator();
    const code2 = await w.mintCode();
    const opt = await w.send("POST", "/console/enroll/options", { json: { code: code2 } });
    const response = auth.register(opt.json.options as Options);
    assert.equal((await w.send("POST", "/console/enroll/verify", { json: { code: code2, response } })).status, 200);
    const code3 = await w.mintCode();
    const replay = await w.send("POST", "/console/enroll/verify", { json: { code: code3, response } });
    assert.deepEqual([replay.status, replay.json.error], [400, "challenge_invalid"]);
    assert.equal((await w.store.listPasskeys()).length, 1);
  });

  it("there is no other enrollment path: adding a passkey needs a session, CSRF and a fresh step-up", async () => {
    const { w, auth, l } = await ready();
    const anon = await w.send("POST", "/console/security/passkeys/options");
    assert.deepEqual([anon.status, anon.json.error], [401, "unauthenticated"]);
    const noCsrf = await w.send("POST", "/console/security/passkeys/options", { cookie: l.cookie });
    assert.deepEqual([noCsrf.status, noCsrf.json.error], [403, "csrf"]);

    const second = new SoftAuthenticator();
    const h = { "x-csrf-token": l.csrf };
    const opt = await w.send("POST", "/console/security/passkeys/options", { cookie: l.cookie, headers: h });
    assert.equal(opt.status, 200, "login counts as a fresh assertion for five minutes");
    w.advance(STEP_UP_MS + 1);
    const stale = await w.send("POST", "/console/security/passkeys/verify", { cookie: l.cookie, headers: h, json: { response: second.register(opt.json.options as Options) } });
    assert.deepEqual([stale.status, stale.json.error], [403, "step_up_required"]);
    assert.equal((await w.send("POST", "/console/security/passkeys/options", { cookie: l.cookie, headers: h })).status, 403);

    assert.equal((await w.stepUp(l, auth)).status, 200);
    const opt2 = await w.send("POST", "/console/security/passkeys/options", { cookie: l.cookie, headers: h });
    const added = await w.send("POST", "/console/security/passkeys/verify", { cookie: l.cookie, headers: h, json: { label: "Phone", response: second.register(opt2.json.options as Options) } });
    assert.equal(added.status, 200, added.text);
    assert.equal((await w.store.listPasskeys()).length, 2);
    // A challenge issued to one session cannot complete an enrollment or a different session's ceremony.
    const other = await w.login(second);
    const opt3 = await w.send("POST", "/console/security/passkeys/options", { cookie: l.cookie, headers: h });
    const third = new SoftAuthenticator();
    const cross = await w.send("POST", "/console/security/passkeys/verify", {
      cookie: other.cookie,
      headers: { "x-csrf-token": other.csrf },
      json: { response: third.register(opt3.json.options as Options) },
    });
    assert.deepEqual([cross.status, cross.json.error], [400, "challenge_invalid"]);
    const rows = (await w.rows());
    assert.ok(rows.some((r) => r.capability === "vault.console.passkey.add" && r.result === "ok"));
    assert.ok(rows.some((r) => r.capability === "vault.console.passkey.add" && r.error === "step_up_required"));
    assert.ok(rows.some((r) => r.capability === "vault.console.stepup" && r.result === "ok"));
  });
});

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

describe("login assertions", () => {
  async function tryLogin(w: World, auth: SoftAuthenticator, o: CeremonyOverrides = {}, between?: () => void): Promise<Sent> {
    const opt = await w.send("POST", "/console/login/options");
    between?.();
    return w.send("POST", "/console/login/verify", { json: { response: auth.assert(opt.json.options as Options, o) } });
  }

  it("login options require UV, name the env RP ID and disclose no credential ids", async () => {
    const { w } = await ready();
    const opt = (await w.send("POST", "/console/login/options")).json.options as Options;
    assert.equal(opt.rpId, RP_ID);
    assert.equal(opt.userVerification, "required");
    assert.equal(opt.allowCredentials === undefined || opt.allowCredentials.length === 0, true);
    const memory = w.store as MemoryOwnerConsoleStore;
    assert.equal(JSON.stringify([...memory.challenges.values()]).includes(opt.challenge), false, "challenges are stored hashed");
    assert.ok([...memory.challenges.keys()].every((k) => /^[0-9a-f]{64}$/.test(k)));
  });

  it("wrong origin, wrong RP ID, missing UV, forged signature, unknown credential → all rejected, no session", async () => {
    const { w, auth } = await ready();
    const cases: Array<[CeremonyOverrides, string]> = [
      [{ origin: "https://evil.example" }, "assertion_invalid"],
      [{ origin: INTERNAL }, "assertion_invalid"],
      [{ rpId: "evil.example" }, "assertion_invalid"],
      [{ uv: false }, "assertion_invalid"],
      [{ signWith: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey }, "assertion_invalid"],
    ];
    for (const [o, expected] of cases.slice(0, MAX_FAILED_ASSERTIONS - 1)) {
      const res = await tryLogin(w, auth, o);
      assert.deepEqual([res.status, res.json.error], [400, expected], JSON.stringify(Object.keys(o)));
      assert.equal(res.headers.get("set-cookie"), null);
    }
    // A good login clears the failure count for this passkey…
    await w.login(auth);
    const forged = await tryLogin(w, auth, cases[4][0]);
    assert.deepEqual([forged.status, forged.json.error], [400, "assertion_invalid"]);

    const stranger = new SoftAuthenticator();
    const unknown = await tryLogin(w, stranger);
    assert.deepEqual([unknown.status, unknown.json.error], [400, "unknown_credential"]);
    assert.equal((await w.store.listSessions(w.now(), SESSION_IDLE_MS)).length, 2, "only the two good logins opened sessions");
    const denied = (await w.rows()).filter((r) => r.capability === "vault.console.login" && r.result === "denied");
    assert.ok(denied.some((r) => r.error === "assertion_invalid" && r.client_id === ownerClientId(auth.id)));
    assert.ok(denied.some((r) => r.error === "unknown_credential" && r.client_id === "console:anonymous"));
  });

  it("a challenge is single use and expires", async () => {
    const { w, auth } = await ready();
    const opt = await w.send("POST", "/console/login/options");
    const response = auth.assert(opt.json.options as Options);
    assert.equal((await w.send("POST", "/console/login/verify", { json: { response } })).status, 200);
    const replay = await w.send("POST", "/console/login/verify", { json: { response } });
    assert.deepEqual([replay.status, replay.json.error], [400, "challenge_invalid"]);

    const expired = await tryLogin(w, auth, {}, () => w.advance(CHALLENGE_TTL_MS + 1));
    assert.deepEqual([expired.status, expired.json.error], [400, "challenge_expired"]);
    // A challenge the server never issued.
    const invented = await w.send("POST", "/console/login/verify", { json: { response: auth.assert({ challenge: b64u(randomBytes(32)) }) } });
    assert.deepEqual([invented.status, invented.json.error], [400, "challenge_invalid"]);
    // A login challenge cannot be spent as a step-up, nor a step-up challenge as a login.
    const l = await w.login(auth);
    const loginOpt = await w.send("POST", "/console/login/options");
    const asStepUp = await w.send("POST", "/console/stepup/verify", { cookie: l.cookie, headers: { "x-csrf-token": l.csrf }, json: { response: auth.assert(loginOpt.json.options as Options) } });
    assert.deepEqual([asStepUp.status, asStepUp.json.error], [400, "challenge_invalid"]);
    const stepOpt = await w.send("POST", "/console/stepup/options", { cookie: l.cookie, headers: { "x-csrf-token": l.csrf } });
    const asLogin = await w.send("POST", "/console/login/verify", { json: { response: auth.assert(stepOpt.json.options as Options) } });
    assert.deepEqual([asLogin.status, asLogin.json.error], [400, "challenge_invalid"]);
  });

  it("a signature counter that does not advance is rejected and the passkey is flagged", async () => {
    const { w, auth } = await ready();
    await w.login(auth);
    const before = (await w.store.getPasskey(auth.id)) as PasskeyRecord;
    assert.ok(before.counter >= 2);
    for (const counter of [before.counter, 1]) {
      const res = await tryLogin(w, auth, { counter });
      assert.deepEqual([res.status, res.json.error], [400, "counter_regression"]);
    }
    const flagged = (await w.store.getPasskey(auth.id)) as PasskeyRecord;
    assert.equal(flagged.flag_reason, "counter_regression");
    assert.equal(flagged.counter, before.counter, "the stored counter is not lowered");
    assert.ok((await w.rows()).some((r) => r.capability === "vault.console.login" && r.error === "counter_regression"));
    // A forged response with a low counter is NOT a regression signal: it flags nothing new and reads as invalid.
    const forged = await tryLogin(w, auth, { counter: 1, signWith: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey });
    assert.equal(forged.json.error, "assertion_invalid");
    // The flag is shown to the owner; a later valid assertion still works so they can remove the passkey.
    auth.counter = before.counter;
    const l = await w.login(auth);
    assert.match((await w.send("GET", "/console/security", { cookie: l.cookie })).text, /counter_regression/);
  });

  it("failed assertions are rate-limited per passkey; unknown credentials share one bucket and cannot lock a real passkey", async () => {
    const { w, auth } = await ready();
    const stranger = new SoftAuthenticator();
    for (let i = 0; i < MAX_FAILED_ASSERTIONS; i++) assert.equal((await tryLogin(w, stranger)).json.error, "unknown_credential");
    const blockedStranger = await tryLogin(w, stranger);
    assert.deepEqual([blockedStranger.status, blockedStranger.json.error], [429, "rate_limited"]);
    await w.login(auth); // the enrolled passkey is unaffected

    for (let i = 0; i < MAX_FAILED_ASSERTIONS; i++) assert.equal((await tryLogin(w, auth, { uv: false })).json.error, "assertion_invalid");
    const blocked = await tryLogin(w, auth);
    assert.deepEqual([blocked.status, blocked.json.error], [429, "rate_limited"]);
    const ledgered = (await w.rows()).filter((r) => r.capability === "vault.console.login" && r.result === "denied").length;
    assert.equal(ledgered, 2 * MAX_FAILED_ASSERTIONS, "limiter refusals are not ledgered");
    w.advance(15 * 60 * 1000 + 1);
    await w.login(auth);
  });
});

// ---------------------------------------------------------------------------
// Sessions, CSRF, step-up
// ---------------------------------------------------------------------------

describe("sessions", () => {
  it("cookie attributes; the token is stored hashed; idle and absolute expiry; logout revokes", async () => {
    const { w, auth } = await ready();
    const opt = await w.send("POST", "/console/login/options");
    const done = await w.send("POST", "/console/login/verify", { json: { response: auth.assert(opt.json.options as Options) } });
    const setCookie = done.headers.get("set-cookie") ?? "";
    assert.match(setCookie, /^__Secure-echo_vault_console=[A-Za-z0-9_-]{43}; Path=\/console; HttpOnly; Secure; SameSite=Strict; Max-Age=28800$/);
    const token = /=([A-Za-z0-9_-]{43});/.exec(setCookie)?.[1] ?? "";
    assert.equal(Buffer.from(token, "base64url").length, 32, "256-bit token");
    assert.equal(done.text.includes(token), false, "the token is only in the cookie");
    const memory = w.store as MemoryOwnerConsoleStore;
    const dump = JSON.stringify([...memory.sessions.values()]);
    assert.equal(dump.includes(token), false);
    assert.equal(JSON.stringify((await w.rows())).includes(token), false);
    const cookie = `${CONSOLE_COOKIE}=${token}`;

    // Idle: activity inside 15 minutes keeps it alive; 15 idle minutes end it.
    for (let i = 0; i < 3; i++) {
      w.advance(SESSION_IDLE_MS - 1000);
      assert.equal((await w.send("GET", "/console/security", { cookie })).status, 200);
    }
    w.advance(SESSION_IDLE_MS + 1);
    const idle = await w.send("GET", "/console/security", { cookie });
    assert.deepEqual([idle.status, idle.headers.get("location")], [303, "/console/login"]);
    assert.match(idle.headers.get("set-cookie") ?? "", /Max-Age=0/);

    // Absolute: constant activity does not extend past 8 hours.
    const l = await w.login(auth);
    const start = w.now();
    while (w.now() + 10 * 60 * 1000 < start + SESSION_ABSOLUTE_MS) {
      w.advance(10 * 60 * 1000);
      assert.equal((await w.send("GET", "/console/security", { cookie: l.cookie })).status, 200);
    }
    w.advance(10 * 60 * 1000);
    assert.equal((await w.send("GET", "/console/security", { cookie: l.cookie })).status, 303);

    // Logout revokes server-side: the old cookie is dead even if replayed.
    const l2 = await w.login(auth);
    const out = await w.post(l2, "/console/logout");
    assert.deepEqual([out.status, out.headers.get("location")], [303, "/console/login"]);
    assert.equal((await w.send("GET", "/console", { cookie: l2.cookie })).status, 303);
    assert.equal(await authenticateSession(l2.token, w.deps), null);
    assert.ok((await w.rows()).some((r) => r.capability === "vault.console.logout" && r.result === "ok"));
  });

  it("sessions can be listed and revoked from the console", async () => {
    const { w, auth, l } = await ready();
    const other = await w.login(auth);
    const page = await w.send("GET", "/console/security", { cookie: l.cookie });
    assert.match(page.text, /\(this session\)/);
    const sessions = await w.store.listSessions(w.now(), SESSION_IDLE_MS);
    assert.equal(sessions.length, 2);
    const otherId = (sessions.find((s) => s.token_hash !== (sessions.find((x) => page.text.includes(`${x.id.slice(0, 8)} (this session)`)) as SessionRecord).token_hash) as SessionRecord).id;
    const revoked = await w.post(l, "/console/security/sessions/revoke", { session_id: otherId });
    assert.equal(revoked.status, 200);
    assert.match(revoked.text, /Session revoked/);
    assert.equal((await w.send("GET", "/console", { cookie: other.cookie })).status, 303);
    assert.equal((await w.post(l, "/console/security/sessions/revoke", { session_id: "f".repeat(32) })).status, 400);
    assert.ok((await w.rows()).some((r) => r.capability === "vault.console.session.revoke" && r.result === "ok"));
    // Garbage and foreign cookies are not sessions.
    for (const cookie of [`${CONSOLE_COOKIE}=${"A".repeat(43)}`, `${CONSOLE_COOKIE}=x`, `echo_vault_console=${l.token}`, `other=${l.token}`]) {
      assert.equal((await w.send("GET", "/console", { cookie })).status, 303, cookie);
    }
  });

  it("CSRF: missing or wrong token, wrong Origin, cross-site or missing Sec-Fetch-Site are all rejected", async () => {
    const { w, l } = await ready();
    const id = await w.seedEntry("csrf.example.com", "a", "api_key", "csrf-test-secret-000001");
    secretsToScan.add("csrf-test-secret-000001");
    const form = { entry_id: id, mode: "manual", interval_days: "30" };
    const attempts: Array<[string, Parameters<World["send"]>[2]]> = [
      ["no csrf token", { cookie: l.cookie, form }],
      ["wrong csrf token", { cookie: l.cookie, form: { ...form, csrf: csrfTokenFor("B".repeat(43)) } }],
      ["foreign Origin", { cookie: l.cookie, form: { ...form, csrf: l.csrf }, headers: { origin: "https://evil.example" } }],
      ["the request's own host as Origin", { cookie: l.cookie, form: { ...form, csrf: l.csrf }, headers: { origin: INTERNAL } }],
      ["no Origin", { cookie: l.cookie, form: { ...form, csrf: l.csrf }, headers: { origin: "" } }],
      ["cross-site", { cookie: l.cookie, form: { ...form, csrf: l.csrf }, headers: { "sec-fetch-site": "cross-site" } }],
      ["same-site", { cookie: l.cookie, form: { ...form, csrf: l.csrf }, headers: { "sec-fetch-site": "same-site" } }],
      ["no Sec-Fetch-Site", { cookie: l.cookie, form: { ...form, csrf: l.csrf }, headers: { "sec-fetch-site": "" } }],
      ["null Origin without Sec-Fetch-Site", { cookie: l.cookie, form: { ...form, csrf: l.csrf }, headers: { origin: "null", "sec-fetch-site": "" } }],
    ];
    const before = (await w.rows()).length;
    for (const [label, o] of attempts) {
      const res = await w.send("POST", "/console/entries/rotation", o);
      assert.equal(res.status, 403, label);
    }
    const untouched = (await w.entries.get(id)) as { rotate_interval_days: number | null };
    assert.equal(untouched.rotate_interval_days, null);
    assert.equal((await w.rows()).length, before, "a rejected request runs nothing");

    // JSON endpoints: the token travels in x-csrf-token; logout and anonymous endpoints get the origin check too.
    assert.equal((await w.send("POST", "/console/stepup/options", { cookie: l.cookie })).status, 403);
    assert.equal((await w.send("POST", "/console/stepup/options", { cookie: l.cookie, headers: { "x-csrf-token": l.csrf, origin: "https://evil.example" } })).status, 403);
    assert.equal((await w.send("POST", "/console/logout", { cookie: l.cookie, form: {} })).status, 403);
    assert.equal((await w.send("POST", "/console/login/options", { headers: { origin: "https://evil.example" } })).status, 403);
    assert.equal((await w.send("POST", "/console/enroll/options", { headers: { "sec-fetch-site": "cross-site" }, json: { code: "x" } })).status, 403);
    assert.equal((await w.send("GET", "/console", { cookie: l.cookie })).status, 200, "the session survived all of it");

    // The same form with everything in place works.
    const ok = await w.post(l, "/console/entries/rotation", form);
    assert.equal(ok.status, 200, ok.text);
    assert.equal(((await w.entries.get(id)) as { rotate_interval_days: number | null }).rotate_interval_days, 30);
    // Body limits and encodings.
    assert.equal((await w.send("POST", "/console/login/verify", { rawBody: `{"x":"${"a".repeat(70_000)}"}` })).status, 413);
    assert.equal((await w.send("POST", "/console/login/verify", { rawBody: "{not json" })).status, 400);
    assert.equal((await w.send("POST", "/console/login/verify", { headers: { "content-type": "text/plain" } })).status, 415);
    assert.equal((await w.send("PUT", "/console")).status, 405);
    assert.equal((await w.send("GET", "/console/nope", { cookie: l.cookie })).status, 404);
    assert.equal((await w.send("POST", "/console/nope", { cookie: l.cookie, form: { csrf: l.csrf } })).status, 404);
  });
});

describe("step-up", () => {
  it("classifies destructive tools", () => {
    for (const tool of ["admin_purge_entry", "admin_delete_entry", "admin_revoke_client", "admin_set_client_scopes", "admin_rotate_entry"]) {
      assert.equal(toolNeedsStepUp(tool, {}), true, tool);
    }
    assert.equal(toolNeedsStepUp("admin_set_rotation", { mode: "auto" }), true);
    assert.equal(toolNeedsStepUp("admin_set_rotation", { mode: "AUTO" }), true);
    assert.equal(toolNeedsStepUp("admin_set_rotation", {}), true);
    assert.equal(toolNeedsStepUp("admin_set_rotation", { mode: "manual" }), false);
    assert.equal(toolNeedsStepUp("admin_revoke_grant", { client_id: "c", entry_id: "e" }), true);
    assert.equal(toolNeedsStepUp("admin_revoke_grant", { client_id: "c", entry_id: "e", host: "h", path_prefix: "/" }), false);
    for (const tool of ["audit_list", "audit_verify", "admin_list_entries", "admin_list_clients", "admin_digest_now", "admin_anchor_now", "admin_request_reentry"]) {
      assert.equal(toolNeedsStepUp(tool, {}), false, tool);
    }
  });

  it("every destructive action needs an assertion from the last 5 minutes for THIS session", async () => {
    const oauth = new MemoryOAuthStore();
    resetOAuth();
    configureOAuth({ store: oauth, env: { ECHO_VAULT_PUBLIC_URL: ORIGIN } });
    try {
      const { w, auth, l } = await ready();
      await oauth.createClient({
        client_id: "oc_managed", client_name: "Managed", redirect_uris: ["http://127.0.0.1:1/cb"], requested_scopes: ["github.read"],
        granted_scopes: ["github.read"], status: "approved", created_at: T0, approved_at: T0, revoked_at: null,
      });
      const id = await w.seedEntry("stepup.example.com", "a", "api_key", "stepup-test-secret-000001");
      secretsToScan.add("stepup-test-secret-000001");
      const grant = (path: string) => w.grants.add({
        client_id: "oc_managed", entry_id: id, host: "stepup.example.com", path_prefix: path, approval_id: "A".repeat(24),
        granted_at: new Date(w.now()).toISOString(), expires_at: new Date(w.now() + 86_400_000).toISOString(), max_uses: 5, uses_remaining: 5,
      });
      await grant("/a");
      await grant("/b");
      const second = new SoftAuthenticator();
      assert.equal((await w.enroll(second)).status, 200);

      const destructive: Array<[string, Record<string, string | string[]>]> = [
        ["/console/entries/purge", { entry_id: id, confirm: `PURGE ${id}` }],
        ["/console/entries/delete", { entry_id: id }],
        ["/console/entries/rotate", { entry_id: id }],
        ["/console/entries/rotation", { entry_id: id, mode: "auto", interval_days: "30" }],
        ["/console/clients/revoke", { client_id: "oc_managed" }],
        ["/console/clients/scopes", { client_id: "oc_managed", scope: ["github.read", "github.write"] }],
        ["/console/grants/revoke", { client_id: "oc_managed", entry_id: id, all: "1" }],
        ["/console/security/passkeys/remove", { credential_id: second.id }],
      ];
      const state = async () =>
        JSON.stringify([await w.entries.get(id), await oauth.getClient("oc_managed"), await w.grants.list({}), (await w.store.listPasskeys()).length]);

      // Fresh from login: allowed (shown by one harmless member of the set)…
      assert.notEqual((await w.post(l, "/console/entries/rotation", { entry_id: id, mode: "auto", interval_days: "30" })).status, 403);
      // …and stale five minutes later, for every one of them.
      w.advance(STEP_UP_MS + 1);
      const snapshot = await state();
      for (const [path, form] of destructive) {
        const res = await w.post(l, path, form);
        assert.equal(res.status, 403, path);
        assert.match(res.text, /Confirm with your passkey first/, path);
      }
      assert.equal(await state(), snapshot, "nothing changed while step-up was stale");
      const refusals = (await w.rows()).filter((r) => r.error === "step_up_required");
      assert.equal(refusals.length, destructive.length, "each refusal is ledgered");
      assert.ok(refusals.every((r) => r.result === "denied" && r.client_id === ownerClientId(auth.id)));

      // Non-destructive actions do not need it.
      assert.equal((await w.post(l, "/console/entries/rotation", { entry_id: id, mode: "manual", interval_days: "45" })).status, 200);
      assert.equal((await w.post(l, "/console/grants/revoke", { client_id: "oc_managed", entry_id: id, host: "stepup.example.com", path_prefix: "/a" })).status, 200);
      assert.equal((await w.grants.list({})).length, 1);
      assert.equal((await w.post(l, "/console/entries/reentry", { entry_id: id })).status, 200);

      // Step-up on ANOTHER session does not help this one.
      const other = await w.login(auth);
      w.advance(STEP_UP_MS + 1);
      assert.equal((await w.stepUp(other, auth)).status, 200);
      assert.equal((await w.post(l, "/console/clients/scopes", { client_id: "oc_managed", scope: ["github.read"] })).status, 403);

      // Step-up on this session: a wrong assertion does not count, a right one does — for five minutes.
      const opt = await w.send("POST", "/console/stepup/options", { cookie: l.cookie, headers: { "x-csrf-token": l.csrf } });
      const bad = await w.send("POST", "/console/stepup/verify", { cookie: l.cookie, headers: { "x-csrf-token": l.csrf }, json: { response: auth.assert(opt.json.options as Options, { uv: false }) } });
      assert.deepEqual([bad.status, bad.json.error], [400, "assertion_invalid"]);
      assert.equal((await w.post(l, "/console/clients/scopes", { client_id: "oc_managed", scope: ["github.read"] })).status, 403);
      assert.equal((await w.stepUp(l, auth)).status, 200);
      w.advance(STEP_UP_MS - 1000);
      const scoped = await w.post(l, "/console/clients/scopes", { client_id: "oc_managed", scope: ["github.read", "github.write"] });
      assert.equal(scoped.status, 200, scoped.text);
      assert.deepEqual([...((await oauth.getClient("oc_managed"))?.granted_scopes ?? [])].sort(), ["github.read", "github.write"]);
      w.advance(1001);
      assert.equal((await w.post(l, "/console/clients/revoke", { client_id: "oc_managed" })).status, 403);

      // With a fresh step-up the whole destructive set goes through (in an order that leaves something to act on).
      assert.equal((await w.stepUp(l, auth)).status, 200);
      assert.equal((await w.post(l, "/console/grants/revoke", { client_id: "oc_managed", entry_id: id, all: "1" })).status, 200);
      assert.equal((await w.grants.list({})).length, 0);
      assert.equal((await w.post(l, "/console/clients/revoke", { client_id: "oc_managed" })).status, 200);
      assert.equal((await oauth.getClient("oc_managed"))?.status, "revoked");
      assert.equal((await w.post(l, "/console/entries/rotate", { entry_id: id })).status, 400, "no rotator for this site: refused by the tool, not by step-up");
      assert.equal((await w.post(l, "/console/entries/delete", { entry_id: id })).status, 200);
      assert.equal((await w.entries.get(id))?.status, "deleted");
      assert.equal((await w.post(l, "/console/entries/purge", { entry_id: id, confirm: "PURGE" })).status, 400, "typed confirmation must match");
      assert.ok(await w.entries.get(id));
      assert.equal((await w.post(l, "/console/entries/purge", { entry_id: id, confirm: `PURGE ${id}` })).status, 200);
      assert.equal(await w.entries.get(id), null);
      assert.equal((await w.post(l, "/console/security/passkeys/remove", { credential_id: second.id })).status, 200);
      assert.equal((await w.store.listPasskeys()).length, 1);
      assert.equal((await w.ledger.verify()).ok, true);
    } finally {
      resetOAuth();
    }
  });

  it("the last passkey cannot be removed; removing a passkey ends its sessions", async () => {
    const { w, auth, l } = await ready();
    const last = await w.post(l, "/console/security/passkeys/remove", { credential_id: auth.id });
    assert.equal(last.status, 400);
    assert.match(last.text, /last passkey cannot be removed/);
    assert.equal((await w.store.listPasskeys()).length, 1);
    assert.equal(await w.store.deletePasskeyUnlessLast(auth.id), "last", "the store refuses too");
    assert.ok((await w.rows()).some((r) => r.capability === "vault.console.passkey.remove" && r.error === "last_passkey"));
    assert.equal((await w.post(l, "/console/security/passkeys/remove", { credential_id: b64u(randomBytes(32)) })).status, 400);

    const second = new SoftAuthenticator();
    assert.equal((await w.enroll(second)).status, 200);
    const l2 = await w.login(second);
    // Session 1 removes its OWN passkey: allowed (another remains), and session 1 ends with it.
    const gone = await w.post(l, "/console/security/passkeys/remove", { credential_id: auth.id });
    assert.deepEqual([gone.status, gone.headers.get("location")], [303, "/console/login"]);
    assert.equal((await w.send("GET", "/console", { cookie: l.cookie })).status, 303);
    assert.equal((await w.send("GET", "/console", { cookie: l2.cookie })).status, 200);
    const opt = await w.send("POST", "/console/login/options");
    const removed = await w.send("POST", "/console/login/verify", { json: { response: auth.assert(opt.json.options as Options) } });
    assert.equal(removed.json.error, "unknown_credential");
    assert.ok((await w.rows()).some((r) => r.capability === "vault.console.passkey.remove" && r.result === "ok"));
  });
});

// ---------------------------------------------------------------------------
// Identity + authorization
// ---------------------------------------------------------------------------

describe("the owner identity", () => {
  const ADMIN_CALLS: Array<[string, Record<string, unknown>]> = [
    ["admin_list_clients", {}],
    ["admin_set_client_scopes", { client_id: "oc_x", scopes: ["github.read"] }],
    ["admin_revoke_client", { client_id: "oc_x" }],
    ["admin_list_grants", {}],
    ["admin_revoke_grant", { client_id: "oc_x", entry_id: ENTRY0 }],
    ["admin_list_entries", {}],
    ["admin_set_rotation", { entry_id: ENTRY0, mode: "manual", interval_days: 30 }],
    ["admin_rotate_entry", { entry_id: ENTRY0 }],
    ["admin_rotation_due", {}],
    ["admin_purge_entry", { entry_id: ENTRY0, confirm: `PURGE ${ENTRY0}` }],
    ["admin_delete_entry", { entry_id: ENTRY0 }],
    ["admin_request_reentry", { entry_id: ENTRY0 }],
    ["admin_anchor_now", {}],
    ["admin_verify_anchor", { line: `ECHO-VAULT-ANCHOR v1 seq=1 hash=${"0".repeat(64)} rows=1 at=2026-11-14T10:00:00.000Z unsigned` }],
    ["admin_digest_now", {}],
    ["admin_console_bootstrap", {}],
  ];

  it("covers every admin_* tool the gateway defines", () => {
    const defined = TOOL_DEFINITIONS.map((t) => t.name).filter((n) => n.startsWith("admin_")).sort();
    assert.deepEqual([...new Set(ADMIN_CALLS.map(([n]) => n))].sort(), defined);
    assert.deepEqual([...CONSOLE_TOOLS].filter((n) => n.startsWith("admin_")).sort(), defined.filter((n) => n !== "admin_console_bootstrap"));
  });

  it("runs every admin tool through the console path, while oauth and workload identities stay tier3_human_only", async () => {
    const oauth = new MemoryOAuthStore();
    resetOAuth();
    configureOAuth({ store: oauth, env: { ECHO_VAULT_PUBLIC_URL: ORIGIN } });
    try {
      const { w, auth, l } = await ready();
      const session = await authenticateSession(l.token, w.deps);
      assert.ok(session);
      assert.equal(session.identity.kind, "owner");
      assert.equal(session.identity.client_id, `owner:${sha256Hex(Buffer.from(auth.id, "base64url")).slice(0, 12)}`);
      assert.match(session.identity.client_id, /^owner:[0-9a-f]{12}$/);

      for (const who of [AGENT, WORKLOAD]) {
        for (const [name, args] of ADMIN_CALLS) expectFail(await dispatchTool(who, name, args, w.gateway), "tier3_human_only");
      }
      assert.equal(w.telegram.length, 0, "refused admin calls send nothing");

      for (const [name, args] of ADMIN_CALLS) {
        if (name === "admin_console_bootstrap") continue; // local stdio only, by design (tested above)
        const before = (await w.rows()).length;
        const result = await runOwnerTool(session, name, args, w.deps);
        const error = result.ok ? "" : result.error;
        assert.ok(!["tier3_human_only", "unauthenticated", "missing_scope", "step_up_required", "tool_not_available"].includes(error), `${name}: ${error}`);
        const added = (await w.rows()).slice(before);
        const row = added.find((r) => r.capability.startsWith("vault.admin."));
        assert.ok(row, `${name} writes a vault.admin.* ledger row`);
        assert.deepEqual([row.client_id, row.decision, row.tier], [session.identity.client_id, "allow", 3], name);
        assert.ok(added.every((r) => r.client_id === session.identity.client_id), `${name}: every row is attributed to the owner`);
      }
      // The two read tools the console uses run on the owner's read scopes.
      assert.equal((await runOwnerTool(session, "audit_list", { limit: 5 }, w.deps)).ok, true);
      assert.equal((await runOwnerTool(session, "audit_verify", {}, w.deps)).ok, true);
      // Anything outside the console's allowlist is refused before the gateway; agent-tier rules still apply inside it.
      expectFail(await runOwnerTool(session, "entry_use", { site: "x.com", method: "GET", url_path: "/", task: "t" }, w.deps), "tool_not_available");
      expectFail(await runOwnerTool(session, "get_secret", {}, w.deps), "tool_not_available");
      expectFail(await dispatchTool(session.identity, "get_secret", {}, w.gateway), "tool_forbidden");
      expectFail(await dispatchTool(session.identity, "credential_rotate", {}, w.gateway), "tier3_human_only");
      expectFail(await dispatchTool(session.identity, "github_get_user", {}, w.gateway), "missing_scope");
    } finally {
      resetOAuth();
    }
  });

  it("is accepted only when the console minted that very object", async () => {
    const { w, l } = await ready();
    const session = await authenticateSession(l.token, w.deps);
    assert.ok(session);
    const real = session.identity;
    assert.equal(isMintedOwnerIdentity(real), true);
    assert.equal(Object.isFrozen(real), true);
    const fakes: unknown[] = [
      { client_id: "owner:abcdefabcdef", name: "Owner", kind: "owner", scopes: ["audit.read", "vault.read"] },
      { ...real },
      JSON.parse(JSON.stringify(real)),
      Object.create(real as object),
      { ...real, kind: "local" }, // an "owner:" id under another kind
      { ...real, kind: "oauth" },
      { ...real, kind: "workload" },
    ];
    for (const fake of fakes) {
      assert.equal(isMintedOwnerIdentity(fake), false);
      const before = (await w.rows()).length;
      expectFail(await dispatchTool(fake as ClientIdentity, "admin_list_entries", {}, w.gateway), "unauthenticated");
      assert.equal((await w.rows()).length, before);
    }
    assert.equal((await dispatchTool(real, "admin_list_entries", {}, w.gateway)).ok, true);
    // A minted identity whose id is not the owner pattern is refused as well.
    assert.throws(() => localIdentity("owner:abcdefabcdef"));
  });

  describe("cannot be produced by the MCP, REST, OAuth or workload paths", () => {
    const BASE = "http://localhost:8080";
    const REDIRECT = "http://127.0.0.1:33418/callback";
    const approver: OwnerApprover = {
      requestClientApproval: async () => ({ approval_id: "ap_auto" }),
      checkClientApproval: async () => "approved",
    };
    const workloadToken = `ewk_${randomBytes(32).toString("base64url")}`;
    const ownerishToken = `ewk_${randomBytes(32).toString("base64url")}`;
    const savedEnv = process.env.ECHO_VAULT_WORKLOAD_TOKENS_FILE;
    let dir: string;

    before(() => {
      ensureV2Configured();
      resetOAuth();
      configureOAuth({ store: new MemoryOAuthStore(), approver, env: { ECHO_VAULT_PUBLIC_URL: BASE } });
      dir = mkdtempSync(join(tmpdir(), "vault-console-workload-"));
      secretsToScan.add(workloadToken).add(ownerishToken);
    });
    after(() => {
      if (savedEnv === undefined) delete process.env.ECHO_VAULT_WORKLOAD_TOKENS_FILE;
      else process.env.ECHO_VAULT_WORKLOAD_TOKENS_FILE = savedEnv;
      resetWorkloadCacheForTests();
      resetOAuth();
      rmSync(dir, { recursive: true, force: true });
    });

    function workloads(entries: unknown[]): void {
      const file = join(dir, `w-${randomBytes(4).toString("hex")}.json`);
      writeFileSync(file, JSON.stringify(entries));
      process.env.ECHO_VAULT_WORKLOAD_TOKENS_FILE = file;
      resetWorkloadCacheForTests();
    }

    async function oauthToken(): Promise<string> {
      const reg = await handleRegister(
        new Request(`${BASE}/api/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "owner", redirect_uris: [REDIRECT] }) }),
      );
      const clientId = ((await reg.json()) as { client_id: string }).client_id;
      const verifier = randomBytes(32).toString("base64url");
      const q = new URLSearchParams({
        response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: s256Challenge(verifier),
        code_challenge_method: "S256", scope: SUPPORTED_SCOPES.join(" "), resource: `${BASE}/api/mcp`,
      });
      const page = await (await handleAuthorize(new Request(`${BASE}/api/oauth/authorize?${q}`))).text();
      const pollUrl = (/content="\d+;url=([^"]+)"/.exec(page)?.[1] ?? "").replace(/&amp;/g, "&");
      const redirect = await handleAuthorize(new Request(pollUrl));
      const code = new URL(redirect.headers.get("location") ?? "").searchParams.get("code") ?? "";
      const res = await handleToken(
        new Request(`${BASE}/api/oauth/token`, {
          method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId }).toString(),
        }),
      );
      const token = ((await res.json()) as { access_token: string }).access_token;
      secretsToScan.add(token);
      return token;
    }

    it("no header, cookie or token turns an HTTP caller into the owner", async () => {
      const { w, l } = await ready();
      workloads([{ sha256: createHash("sha256").update(workloadToken).digest("hex"), client_id: "workload:svc", name: "svc", scopes: [...SUPPORTED_SCOPES] }]);
      const access = await oauthToken();

      const oauthIdentity = await authenticateHttp(new Headers({ authorization: `Bearer ${access}` }));
      assert.equal(oauthIdentity?.kind, "oauth");
      assert.match(oauthIdentity?.client_id ?? "", /^oc_/);
      assert.equal(isMintedOwnerIdentity(oauthIdentity), false);
      const workloadIdentity = await authenticateHttp(new Headers({ authorization: `Bearer ${workloadToken}` }));
      assert.equal(workloadIdentity?.kind, "workload");
      assert.equal(isMintedOwnerIdentity(workloadIdentity), false);

      // The console session cookie / token means nothing to the bearer transports.
      const spoofs: Array<Record<string, string>> = [
        { cookie: l.cookie },
        { cookie: l.cookie, "x-csrf-token": l.csrf },
        { authorization: `Bearer ${l.token}` },
        { authorization: `Bearer eva_${l.token}` },
        { authorization: `Bearer ewk_${l.token}` },
        { "x-echo-agent": "owner", "x-echo-kind": "owner", "x-client-kind": "owner", "x-echo-caller": "owner:abcdefabcdef" },
      ];
      const call = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "admin_list_entries", arguments: {} } };
      for (const headers of spoofs) {
        assert.equal(await authenticateHttp(new Headers(headers)), null, JSON.stringify(Object.keys(headers)));
        assert.equal(await authenticateRequest(new Headers(headers)), null);
        assert.equal(authenticateWorkload(new Headers(headers)), null);
        const mcp = await handleMcpPost(new Request(`${BASE}/api/mcp`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(call) }), w.gateway);
        assert.equal(mcp.status, 401);
        const rest = await handleRestTool(new Request(`${BASE}/api/rest/tool`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ tool: "admin_list_entries", arguments: {} }) }), w.gateway);
        assert.equal(rest.status, 401);
      }

      // Authenticated bearer callers asking for owner powers — also via smuggled identity fields — get tier 3.
      for (const token of [access, workloadToken]) {
        for (const body of [
          { tool: "admin_list_entries", arguments: {} },
          { tool: "admin_console_bootstrap", arguments: {} },
          { tool: "admin_list_entries", arguments: {}, identity: { kind: "owner", client_id: "owner:abcdefabcdef" }, kind: "owner" },
        ]) {
          const res = await handleRestTool(new Request(`${BASE}/api/rest/tool`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}`, cookie: l.cookie }, body: JSON.stringify(body) }), w.gateway);
          const out = (await res.json()) as { result: { ok: boolean; error: string } };
          assert.deepEqual([out.result.ok, out.result.error], [false, "tier3_human_only"]);
        }
        const mcp = await handleMcpPost(new Request(`${BASE}/api/mcp`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(call) }), w.gateway);
        assert.match(await mcp.text(), /tier3_human_only/);
      }

      // A workload file that claims an owner id or kind does not yield an owner.
      workloads([{ sha256: createHash("sha256").update(ownerishToken).digest("hex"), client_id: "owner:abcdefabcdef", name: "x", kind: "owner", scopes: [] }]);
      const claimed = await authenticateHttp(new Headers({ authorization: `Bearer ${ownerishToken}` }));
      assert.notEqual(claimed?.kind, "owner");
      if (claimed) expectFail(await dispatchTool(claimed, "admin_list_entries", {}, w.gateway), "unauthenticated");
      workloads([{ sha256: createHash("sha256").update(ownerishToken).digest("hex"), client_id: "workload:x", name: "x", kind: "owner", scopes: [] }]);
      const kinded = await authenticateHttp(new Headers({ authorization: `Bearer ${ownerishToken}` }));
      assert.equal(kinded?.kind, "workload");
      expectFail(await dispatchTool(kinded as ClientIdentity, "admin_list_entries", {}, w.gateway), "tier3_human_only");
      assert.equal((await w.rows()).some((r) => r.client_id.startsWith("owner:") && r.capability.startsWith("vault.admin.") && r.result === "ok"), false);
    });

    it("in the source tree, only the console session path mints an owner and no web RPC claims to be local", () => {
      const root = new URL("../../../../", import.meta.url);
      const files: string[] = [];
      const walk = (rel: string): void => {
        for (const entry of readdirSync(new URL(rel, root), { withFileTypes: true })) {
          if (entry.isDirectory()) walk(`${rel}${entry.name}/`);
          else if (/\.(ts|tsx|mjs)$/.test(entry.name) && !/\.test\.(ts|mjs)$/.test(entry.name) && entry.name !== "routeTree.gen.ts") files.push(`${rel}${entry.name}`);
        }
      };
      walk("src/");
      walk("scripts/");
      const read = (f: string): string => readFileSync(new URL(f, root), "utf8");
      const containing = (re: RegExp): string[] => files.filter((f) => re.test(read(f))).sort();
      assert.deepEqual(containing(/kind:\s*"owner"/), ["src/lib/vault/v2/owner-identity.ts"]);
      assert.deepEqual(containing(/mintOwnerIdentity\(/), ["src/lib/vault/v2/owner-console.ts", "src/lib/vault/v2/owner-identity.ts"]);
      assert.equal((read("src/lib/vault/v2/owner-console.ts").match(/mintOwnerIdentity\(/g) ?? []).length, 1, "one call site: authenticateSession");
      for (const f of ["src/lib/vault/v2/http-transport.ts", "src/lib/vault/v2/identity.ts", "src/lib/vault/v2/oauth-server.ts", "src/lib/vault/v2/workload.ts", "src/lib/vault/mcp.ts"]) {
        assert.equal(/owner-identity|owner-console/.test(read(f)), false, `${f} must not import the owner modules`);
      }
      // kind "local" belongs to the stdio transport alone (the legacy web console RPC used to claim it).
      assert.deepEqual(containing(/kind:\s*"local"/), ["src/lib/vault/v2/identity.ts"]);
      assert.equal(/localIdentity\(/.test(read("src/lib/vault-rpc.ts")), false);
      // Reveal stays disabled in the legacy console RPC.
      assert.match(read("src/lib/vault-rpc.ts"), /error: "reveal_disabled"/);
    });
  });
});

// ---------------------------------------------------------------------------
// Pages: headers, escaping, ledger coverage, leak scan
// ---------------------------------------------------------------------------

const GET_PAGES = ["/console", "/console/clients", "/console/grants", "/console/entries", "/console/audit", "/console/digest", "/console/security"];

describe("console pages", () => {
  it("serve strict security headers with a per-response nonce and no inline handlers or external references", async () => {
    const { w, l } = await ready();
    const nonces = new Set<string>();
    const pages: Sent[] = [await w.send("GET", "/console/login"), await w.send("GET", "/console/enroll")];
    for (const path of GET_PAGES) pages.push(await w.send("GET", path, { cookie: l.cookie }));
    for (const res of pages) {
      assert.equal(res.status, 200);
      const csp = res.headers.get("content-security-policy") ?? "";
      const nonce = /style-src 'nonce-([A-Za-z0-9+/=]+)'/.exec(csp)?.[1] ?? "";
      assert.ok(nonce.length >= 24);
      nonces.add(nonce);
      assert.match(csp, /^default-src 'none';/);
      assert.match(csp, /frame-ancestors 'none'/);
      assert.match(csp, /base-uri 'none'/);
      assert.match(csp, /form-action 'self'/);
      assert.equal(/unsafe-inline|unsafe-eval|https?:|\*/.test(csp), false, csp);
      assert.equal(res.headers.get("referrer-policy"), "no-referrer");
      assert.equal(res.headers.get("cache-control"), "no-store");
      assert.equal(res.headers.get("x-frame-options"), "DENY");
      assert.equal(res.headers.get("x-content-type-options"), "nosniff");
      // Markup outside the one nonce'd script: no handlers, no external resources.
      const markup = res.text.replace(/<script nonce="[^"]+">[\s\S]*?<\/script>/g, "");
      assert.equal(/<script/i.test(markup), false);
      assert.equal(hasInlineHandler(markup), false, "no inline event handlers");
      assert.equal(/javascript:/i.test(markup), false);
      assert.equal(/(src|href|action)="(https?:)?\/\//i.test(markup), false, "no absolute or third-party URLs");
      assert.equal(/<(img|iframe|object|embed|link)\b/i.test(markup), false);
      for (const m of res.text.matchAll(/<(?:script|style) nonce="([^"]+)"/g)) assert.equal(m[1], nonce);
      const scripted = /<script/.test(res.text);
      assert.equal(csp.includes(scripted ? `script-src 'nonce-${nonce}'` : "script-src 'none'"), true);
      // Accessibility basics: language, one h1, every visible input labelled.
      assert.match(res.text, /<html lang="en">/);
      assert.equal((res.text.match(/<h1>/g) ?? []).length, 1);
      for (const m of markup.matchAll(/<input\b[^>]*>/g)) {
        if (/type="hidden"/.test(m[0])) continue;
        const id = /\bid="([^"]+)"/.exec(m[0])?.[1];
        const wrapped = new RegExp(`<label class="inline">${m[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`).test(markup);
        assert.ok(wrapped || (id && markup.includes(`<label for="${id}">`)), `unlabelled input: ${m[0]}`);
      }
    }
    assert.equal(nonces.size, pages.length, "a new nonce per response");
    const jsonRes = await w.send("POST", "/console/login/options");
    assert.match(jsonRes.headers.get("content-security-policy") ?? "", /default-src 'none'/);
    assert.equal(jsonRes.headers.get("cache-control"), "no-store");
    // Session pages redirect anonymous visitors; login redirects a signed-in owner.
    for (const path of GET_PAGES) assert.equal((await w.send("GET", path)).status, 303, path);
    assert.equal((await w.send("GET", "/console/login", { cookie: l.cookie })).status, 303);
  });

  it("the platform head injector leaves /console and /card pages alone", async () => {
    const { isDocumentPath } = await import("../../../../scripts/grok-pwa-shared.mjs");
    for (const path of ["/console", "/console/login", "/console/entries", "/card/abc"]) assert.equal(isDocumentPath(path), false, path);
    assert.equal(isDocumentPath("/"), true);
  });

  it("ships the installed @simplewebauthn/browser bundle verbatim", () => {
    const installed = readFileSync(new URL("../../../../node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js", import.meta.url), "utf8").trim();
    assert.equal(WEBAUTHN_BROWSER_BUNDLE, installed, "run: node scripts/vendor-webauthn-browser.mjs");
    assert.equal(sha256Hex(WEBAUTHN_BROWSER_BUNDLE), WEBAUTHN_BROWSER_SHA256);
    assert.equal(/<\/script|<!--/i.test(WEBAUTHN_BROWSER_BUNDLE), false);
  });

  it("escapes every dynamic value", async () => {
    const oauth = new MemoryOAuthStore();
    resetOAuth();
    configureOAuth({ store: oauth, env: { ECHO_VAULT_PUBLIC_URL: ORIGIN } });
    try {
      const w = makeWorld();
      const auth = new SoftAuthenticator();
      const evil = `<script>alert(1)</script>"'><img src=x onerror=alert(2)>`;
      assert.equal((await w.enroll(auth, `<b>key</b>"onfocus="x`)).status, 200);
      const opt = await w.send("POST", "/console/login/options");
      const done = await w.send("POST", "/console/login/verify", { json: { response: auth.assert(opt.json.options as Options) }, headers: { "user-agent": evil } });
      const token = /=([A-Za-z0-9_-]{43});/.exec(done.headers.get("set-cookie") ?? "")?.[1] ?? "";
      const l: Login = { token, cookie: `${CONSOLE_COOKIE}=${token}`, csrf: csrfTokenFor(token) };
      await oauth.createClient({
        client_id: "oc_evil", client_name: evil, redirect_uris: ["http://127.0.0.1:1/cb"], requested_scopes: [], granted_scopes: ["github.read"],
        status: "approved", created_at: T0, approved_at: T0, revoked_at: null,
      });
      // Hostile text reaches the ledger through a refused call, and the filters echo query values.
      await dispatchTool({ client_id: "oc_evil", name: evil, kind: "oauth", scopes: [] }, `<svg onload=alert(3)>`, {}, w.gateway);
      const pages = [
        await w.send("GET", "/console/clients", { cookie: l.cookie }),
        await w.send("GET", "/console/security", { cookie: l.cookie }),
        await w.send("GET", `/console/audit?client_id=${encodeURIComponent(evil)}&capability=${encodeURIComponent(evil)}&limit=5`, { cookie: l.cookie }),
        await w.send("GET", "/console/audit", { cookie: l.cookie }),
        await w.send("GET", `/console/digest?from=${encodeURIComponent(evil)}`, { cookie: l.cookie }),
        await w.post(l, "/console/audit/verify-anchor", { line: evil }),
        await w.post(l, "/console/entries/purge", { entry_id: evil, confirm: evil }),
      ];
      for (const res of pages) {
        const markup = res.text.replace(/<script nonce="[^"]+">[\s\S]*?<\/script>/g, "");
        assert.equal(/<script>alert|<img src=x|<svg onload|<b>key/.test(markup), false, "raw markup from data reached a page");
        assert.equal(hasInlineHandler(markup), false);
      }
      assert.ok(pages[0].text.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
      assert.ok(pages[1].text.includes("&lt;b&gt;key&lt;/b&gt;"));
    } finally {
      resetOAuth();
    }
  });

  it("every console action writes a ledger row", async () => {
    const { w, auth, l } = await ready();
    const id = await w.seedEntry("rows.example.com", "a", "api_key", "rows-test-secret-0000001");
    secretsToScan.add("rows-test-secret-0000001");
    const expectRow = async (label: string, run: () => Promise<Sent>, capability: RegExp): Promise<void> => {
      const before = (await w.rows()).length;
      const res = await run();
      const added = (await w.rows()).slice(before);
      assert.ok(added.length >= 1, `${label}: no ledger row (status ${res.status})`);
      assert.ok(added.some((r) => capability.test(r.capability) && r.client_id === ownerClientId(auth.id)), `${label}: ${added.map((r) => r.capability).join(",")}`);
    };
    for (const path of GET_PAGES) await expectRow(`GET ${path}`, () => w.send("GET", path, { cookie: l.cookie }), /^(vault\.admin\.|audit\.|vault\.console\.)/);
    const actions: Array<[string, Record<string, string>, RegExp]> = [
      ["/console/entries/rotation", { entry_id: id, mode: "manual", interval_days: "30" }, /^vault\.admin\.entries\.rotation\.set$/],
      ["/console/entries/rotate", { entry_id: id }, /^vault\.admin\.entries\.rotate$/],
      ["/console/entries/reentry", { entry_id: id }, /^vault\.admin\.entries\.reentry$/],
      ["/console/clients/scopes", { client_id: "oc_none", scope: "github.read" }, /^vault\.admin\.clients\.scopes$/],
      ["/console/clients/revoke", { client_id: "oc_none" }, /^vault\.admin\.clients\.revoke$/],
      ["/console/grants/revoke", { client_id: "oc_none", entry_id: id, host: "rows.example.com", path_prefix: "/" }, /^vault\.admin\.grants\.revoke$/],
      ["/console/grants/revoke", { client_id: "oc_none", entry_id: id, all: "1" }, /^vault\.admin\.grants\.revoke$/],
      ["/console/audit/verify", {}, /^audit\.verify$/],
      ["/console/audit/anchor", {}, /^vault\.admin\.ledger\.anchor$/],
      ["/console/audit/verify-anchor", { line: "ECHO-VAULT-ANCHOR v1 nonsense" }, /^vault\.admin\.ledger\.verify_anchor$/],
      ["/console/digest/send", { from: "2026-11-13" }, /^vault\.admin\.digest$/],
      ["/console/security/sessions/revoke", { session_id: "e".repeat(32) }, /^vault\.console\.session\.revoke$/],
      ["/console/security/passkeys/remove", { credential_id: auth.id }, /^vault\.console\.passkey\.remove$/],
      ["/console/entries/delete", { entry_id: id }, /^vault\.admin\.entries\.delete$/],
      ["/console/entries/purge", { entry_id: id, confirm: `PURGE ${id}` }, /^vault\.admin\.entries\.purge$/],
    ];
    for (const [path, form, capability] of actions) await expectRow(`POST ${path}`, () => w.post(l, path, form), capability);
    await expectRow("step-up", () => w.stepUp(l, auth), /^vault\.console\.stepup$/);
    await expectRow("logout", () => w.post(l, "/console/logout"), /^vault\.console\.logout$/);
    assert.equal((await w.ledger.verify()).ok, true);
    // The route table matches what the handler serves.
    assert.equal(new Set(CONSOLE_ROUTES).size, CONSOLE_ROUTES.length);
    for (const [path] of actions) assert.ok(CONSOLE_ROUTES.includes(`POST ${path}`), path);
    for (const path of GET_PAGES) assert.ok(CONSOLE_ROUTES.includes(`GET ${path}`), path);
  });

  it("LEAK SCAN: no page, JSON response, header, ledger row or log line contains a stored secret in any encoding", async () => {
    const oauth = new MemoryOAuthStore();
    resetOAuth();
    configureOAuth({ store: oauth, env: { ECHO_VAULT_PUBLIC_URL: ORIGIN } });
    try {
      const { w, auth, l } = await ready();
      const ids = [
        await w.seedEntry("leak-one.example.com", "alice@example.com", "password", SECRETS[0]),
        await w.seedEntry("leak-two.example.com", "svc", "api_key", SECRETS[1]),
        await w.seedEntry("leak-three.example.com", "bot", "oauth_token", SECRETS[2]),
      ];
      await oauth.createClient({
        client_id: "oc_leak", client_name: "Leak client", redirect_uris: ["http://127.0.0.1:1/cb"], requested_scopes: ["vault.read"],
        granted_scopes: ["vault.read"], status: "approved", created_at: T0, approved_at: T0, revoked_at: null,
      });
      await w.grants.add({
        client_id: "oc_leak", entry_id: ids[0], host: "leak-one.example.com", path_prefix: "/", approval_id: "A".repeat(24),
        granted_at: new Date(w.now()).toISOString(), expires_at: new Date(w.now() + 86_400_000).toISOString(), max_uses: 5, uses_remaining: 5,
      });
      const start = everyResponse.length;
      // The scanner itself: it must trip on each encoding it claims to cover.
      for (const v of variants(SECRETS[0])) assert.throws(() => scan("self-test", `<td>${v}</td>`));

      const getAll = async (): Promise<void> => {
        for (const path of ["/console/login", "/console/enroll"]) await w.send("GET", path);
        for (const path of GET_PAGES) assert.equal((await w.send("GET", path, { cookie: l.cookie })).status, 200, path);
        await w.send("GET", "/console/audit?limit=1000", { cookie: l.cookie });
        await w.send("GET", `/console/audit?capability=vault.card.request&client_id=${AGENT.client_id}`, { cookie: l.cookie });
        await w.send("GET", `/console/digest?from=${new Date(T0).toISOString().slice(0, 10)}`, { cookie: l.cookie });
      };
      await getAll();
      // The entries page shows exactly the metadata the spec lists — and it is not the secret.
      const entriesPage = await w.send("GET", "/console/entries", { cookie: l.cookie });
      for (const secret of SECRETS) {
        assert.ok(entriesPage.text.includes(sha256Hex(secret).slice(0, 8)), "fingerprint is shown");
        assert.ok(entriesPage.text.includes(`${secret.length} characters`), "length is shown");
      }
      const entriesMarkup = entriesPage.text.replace(/<script nonce="[^"]+">[\s\S]*?<\/script>/g, "").replace("cannot show, copy or export", "");
      assert.equal(/reveal|show secret|copy|export|download/i.test(entriesMarkup), false, "no reveal/copy/export control");

      // Every POST action, successful or refused, including hostile attempts to make a secret echo back.
      const h = { "x-csrf-token": l.csrf };
      const posts: Array<[string, Record<string, string | string[]>]> = [
        ["/console/entries/rotation", { entry_id: ids[0], mode: "manual", interval_days: "30" }],
        ["/console/entries/rotation", { entry_id: ids[1], mode: "auto", interval_days: "30", provider_token_id: "0123456789abcdef0123456789abcdef" }],
        ["/console/entries/rotation", { entry_id: ids[1], mode: "manual", provider_token_id: SECRETS[1] }],
        ["/console/entries/rotate", { entry_id: ids[0] }],
        ["/console/entries/reentry", { entry_id: ids[2] }],
        ["/console/clients/scopes", { client_id: "oc_leak", scope: ["vault.read", "audit.read"] }],
        ["/console/grants/revoke", { client_id: "oc_leak", entry_id: ids[0], host: "leak-one.example.com", path_prefix: "/" }],
        ["/console/grants/revoke", { client_id: "oc_leak", entry_id: ids[0], all: "1" }],
        ["/console/audit/verify", {}],
        ["/console/audit/anchor", {}],
        ["/console/audit/verify-anchor", { line: `ECHO-VAULT-ANCHOR v1 seq=1 hash=${"0".repeat(64)} rows=1 at=2026-11-14T10:00:00.000Z unsigned` }],
        ["/console/digest/send", { from: new Date(T0).toISOString().slice(0, 10) }],
        ["/console/security/sessions/revoke", { session_id: "d".repeat(32) }],
        ["/console/security/passkeys/remove", { credential_id: auth.id }],
        ["/console/entries/delete", { entry_id: ids[1] }],
        ["/console/entries/purge", { entry_id: ids[1], confirm: "nope" }],
        ["/console/entries/purge", { entry_id: ids[1], confirm: `PURGE ${ids[1]}` }],
        ["/console/clients/revoke", { client_id: "oc_leak" }],
      ];
      for (const [path, form] of posts) {
        const res = await w.post(l, path, form);
        assert.ok([200, 400].includes(res.status), `${path}: ${res.status}`);
      }
      await w.send("POST", "/console/stepup/options", { cookie: l.cookie, headers: h });
      await w.stepUp(l, auth);
      const second = new SoftAuthenticator();
      const addOpt = await w.send("POST", "/console/security/passkeys/options", { cookie: l.cookie, headers: h });
      await w.send("POST", "/console/security/passkeys/verify", { cookie: l.cookie, headers: h, json: { response: second.register(addOpt.json.options as Options) } });
      await w.send("POST", "/console/login/options");
      await w.send("POST", "/console/login/verify", { json: { response: { id: "x" } } });
      await w.send("POST", "/console/enroll/options", { json: { code: SECRETS[0] } });
      await w.send("POST", "/console/enroll/verify", { json: { code: SECRETS[1], response: {} } });
      // After a rotation of the stored value through a re-entry card, the NEW secret must not appear either.
      const rotated = "leak-scan-re-entered-secret-04";
      secretsToScan.add(rotated);
      const card = [...w.telegram].reverse().find((c) => typeof c.text === "string" && /\/card\//.test(c.text as string));
      const cardToken = /\/card\/([A-Za-z0-9_-]{43})/.exec(String(card?.text))?.[1] ?? "";
      const filled = await handleCardRequest(
        new Request(`${ORIGIN}/card/${cardToken}`, {
          method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: "null", "sec-fetch-site": "same-origin" },
          body: new URLSearchParams({ secret: rotated }).toString(),
        }),
        cardToken,
        { ...(w.gateway.cards as CardsDeps) },
      );
      assert.equal(filled.status, 200);
      await getAll();

      const responses = everyResponse.slice(start);
      assert.ok(responses.length > 50, `scanned ${responses.length} responses`);
      scan("console responses", responses.join("\n"));
      scan("ledger rows", (await w.rows()));
      scan("console store", [...(w.store as MemoryOwnerConsoleStore).passkeys.values(), ...(w.store as MemoryOwnerConsoleStore).sessions.values()]);
      scan("rate-limit keys", (w.rateLimits as MemoryRateLimitStore).keys());
      // Session token, CSRF-less: the token itself is never rendered into a page either.
      assert.equal(responses.filter((r) => r.includes(l.token)).length, 0, "the session token appears in no response body or header after login");
      assert.equal((await w.ledger.verify()).ok, true);
    } finally {
      resetOAuth();
    }
  });
});

// ---------------------------------------------------------------------------
// Storage: both stores, and the migration on PGlite
// ---------------------------------------------------------------------------

type StoreFixture = () => Promise<OwnerConsoleStore>;

function runStoreSuite(name: string, fixture: StoreFixture): void {
  describe(`owner console store — ${name}`, () => {
    const passkey = (id: string, at = T0): PasskeyRecord => ({
      credential_id: id, public_key: b64u(randomBytes(77)), counter: 1, transports: ["internal"], label: "k", created_at: at,
      last_used_at: null, flagged_at: null, flag_reason: null,
    });
    const session = (id: string, cred: string, at = T0): SessionRecord => ({
      id, token_hash: sha256Hex(`t-${id}`), credential_id: cred, created_at: at, last_seen_at: at, absolute_expires_at: at + SESSION_ABSOLUTE_MS,
      step_up_at: at, revoked_at: null, user_agent: "ua",
    });
    const A = b64u(randomBytes(32));
    const B = b64u(randomBytes(32));

    it("passkeys: insert once, update, flag, never delete the last one, cascade sessions", async () => {
      const s = await fixture();
      assert.equal(await s.insertPasskey(passkey(A)), true);
      assert.equal(await s.insertPasskey(passkey(A)), false);
      await s.updatePasskeyUse(A, 7, T0 + 5);
      await s.flagPasskey(A, "counter_regression", T0 + 6);
      const got = (await s.getPasskey(A)) as PasskeyRecord;
      assert.deepEqual([got.counter, got.last_used_at, got.flagged_at, got.flag_reason, got.transports], [7, T0 + 5, T0 + 6, "counter_regression", ["internal"]]);
      assert.equal(await s.deletePasskeyUnlessLast(A), "last");
      assert.equal(await s.deletePasskeyUnlessLast(B), "not_found");
      assert.equal(await s.insertPasskey(passkey(B, T0 + 1)), true);
      await s.insertSession(session("a".repeat(32), A));
      await s.insertSession(session("b".repeat(32), B));
      assert.equal(await s.deletePasskeyUnlessLast(A), "deleted");
      assert.deepEqual((await s.listPasskeys()).map((p) => p.credential_id), [B]);
      assert.deepEqual((await s.listSessions(T0, SESSION_IDLE_MS)).map((x) => x.id), ["b".repeat(32)]);
      assert.equal(await s.deletePasskeyUnlessLast(B), "last");
      await assert.rejects(s.insertSession(session("c".repeat(32), A)), "a session needs an existing passkey");
      await assert.rejects(s.insertPasskey({ ...passkey(b64u(randomBytes(32))), public_key: "not base64url!" }));
      await assert.rejects(s.insertPasskey({ ...passkey(b64u(randomBytes(32))), counter: -1 }));
    });

    it("challenges are single use and prunable", async () => {
      const s = await fixture();
      const hash = sha256Hex("c1");
      await s.putChallenge({ challenge_hash: hash, purpose: "login", session_id: null, created_at: T0, expires_at: T0 + 1000 });
      const [first, second] = await Promise.all([s.takeChallenge(hash), s.takeChallenge(hash)]);
      assert.equal([first, second].filter(Boolean).length, 1, "exactly one taker");
      assert.deepEqual((first ?? second)?.purpose, "login");
      await s.putChallenge({ challenge_hash: sha256Hex("c2"), purpose: "stepup", session_id: "a".repeat(32), created_at: T0, expires_at: T0 + 1000 });
      assert.equal(await s.pruneChallenges(T0 + 999), 0);
      assert.equal(await s.pruneChallenges(T0 + 1000), 1);
      assert.equal(await s.takeChallenge(sha256Hex("c2")), null);
      await assert.rejects(s.putChallenge({ challenge_hash: "raw-challenge-value", purpose: "login", session_id: null, created_at: T0, expires_at: T0 + 1 }));
      await assert.rejects(s.putChallenge({ challenge_hash: sha256Hex("c3"), purpose: "stepup", session_id: null, created_at: T0, expires_at: T0 + 1 }));
    });

    it("sessions: touch enforces idle and absolute limits and revocation", async () => {
      const s = await fixture();
      await s.insertPasskey(passkey(A));
      const rec = session("a".repeat(32), A);
      await s.insertSession(rec);
      assert.equal((await s.touchSession(rec.token_hash, T0 + SESSION_IDLE_MS - 1, SESSION_IDLE_MS))?.last_seen_at, T0 + SESSION_IDLE_MS - 1);
      assert.equal(await s.touchSession(rec.token_hash, T0 + 2 * SESSION_IDLE_MS, SESSION_IDLE_MS), null, "idle");
      assert.equal(await s.touchSession(sha256Hex("nope"), T0, SESSION_IDLE_MS), null);
      const long = session("b".repeat(32), A);
      await s.insertSession(long);
      let t = T0;
      while (t + 600_000 < T0 + SESSION_ABSOLUTE_MS) {
        t += 600_000;
        assert.ok(await s.touchSession(long.token_hash, t, SESSION_IDLE_MS));
      }
      assert.equal(await s.touchSession(long.token_hash, T0 + SESSION_ABSOLUTE_MS, SESSION_IDLE_MS), null, "absolute");
      const live = session("c".repeat(32), A, t);
      await s.insertSession(live);
      await s.markStepUp(live.id, t + 5);
      assert.equal((await s.touchSession(live.token_hash, t + 6, SESSION_IDLE_MS))?.step_up_at, t + 5);
      assert.equal(await s.revokeSession(live.id, t + 7), true);
      assert.equal(await s.revokeSession(live.id, t + 8), false);
      assert.equal(await s.touchSession(live.token_hash, t + 9, SESSION_IDLE_MS), null, "revoked");
      assert.equal(await s.pruneSessions(T0 + SESSION_ABSOLUTE_MS, SESSION_IDLE_MS), 3);
      await assert.rejects(s.insertSession({ ...session("d".repeat(32), A), token_hash: "raw-session-token" }));
    });

    it("bootstrap code: one row, single use, expiry, hash only", async () => {
      const s = await fixture();
      const h1 = sha256Hex("code-1");
      const h2 = sha256Hex("code-2");
      assert.equal(await s.checkBootstrapCode(h1, T0), false);
      await s.setBootstrapCode({ code_hash: h1, minted_by: "local:owner", created_at: T0, expires_at: T0 + 1000, consumed_at: null });
      await s.setBootstrapCode({ code_hash: h2, minted_by: "local:owner", created_at: T0, expires_at: T0 + 1000, consumed_at: null });
      assert.equal(await s.checkBootstrapCode(h1, T0), false, "replaced");
      assert.equal(await s.checkBootstrapCode(h2, T0 + 999), true);
      assert.equal(await s.consumeBootstrapCode(h2, T0 + 1000), false, "expired");
      const results = await Promise.all([s.consumeBootstrapCode(h2, T0 + 1), s.consumeBootstrapCode(h2, T0 + 1)]);
      assert.deepEqual(results.sort(), [false, true]);
      assert.equal(await s.checkBootstrapCode(h2, T0 + 2), false, "consumed");
      await assert.rejects(s.setBootstrapCode({ code_hash: "evb_raw_code_value", minted_by: "local:owner", created_at: T0, expires_at: T0 + 1, consumed_at: null }));
      await assert.rejects(s.setBootstrapCode({ code_hash: h1, minted_by: "oc_remote", created_at: T0, expires_at: T0 + 1, consumed_at: null }));
    });
  });
}

runStoreSuite("memory", async () => new MemoryOwnerConsoleStore());

let pglite: Promise<import("@electric-sql/pglite").PGlite> | null = null;
const TABLES = ["vault_console_sessions", "vault_console_challenges", "vault_console_bootstrap", "vault_console_passkeys"];
async function sqlStore(): Promise<SqlOwnerConsoleStore> {
  pglite ??= (async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const pg = new PGlite();
    await pg.exec(readFileSync(new URL("../../../../migrations/0011_vault_owner_console.sql", import.meta.url), "utf8"));
    return pg;
  })();
  const pg = await pglite;
  for (const t of TABLES) await pg.exec(`delete from ${t}`);
  return new SqlOwnerConsoleStore(async () => ({
    query: async <T>(text: string, params?: unknown[]) => (await pg.query(text, params)).rows as T[],
  }));
}

runStoreSuite("sql on PGlite (migrations/0011_vault_owner_console.sql)", sqlStore);

describe("migration 0011 on PGlite", () => {
  after(async () => {
    if (pglite) await (await pglite).close();
  });

  it("applies twice, creates the four tables with hashed-token CHECK constraints and no secret-bearing column", async () => {
    await sqlStore();
    const pg = await (pglite as Promise<import("@electric-sql/pglite").PGlite>);
    await pg.exec(readFileSync(new URL("../../../../migrations/0011_vault_owner_console.sql", import.meta.url), "utf8"));
    const cols = (await pg.query<{ table_name: string; column_name: string }>(
      "select table_name, column_name from information_schema.columns where table_name like 'vault_console_%' order by 1, 2",
    )).rows;
    assert.deepEqual([...new Set(cols.map((c) => c.table_name))], [...TABLES].sort());
    const names = cols.map((c) => c.column_name);
    for (const banned of ["private_key", "secret", "token", "code", "challenge", "password"]) assert.equal(names.includes(banned), false, banned);
    const raw = "A".repeat(43);
    await assert.rejects(pg.query("insert into vault_console_challenges (challenge_hash, purpose, created_at, expires_at) values ($1, 'login', 1, 2)", [raw]));
    await assert.rejects(pg.query("insert into vault_console_bootstrap (id, code_hash, minted_by, created_at, expires_at) values (1, $1, 'local:owner', 1, 2)", ["evb_" + "a".repeat(32)]));
    await assert.rejects(pg.query("insert into vault_console_bootstrap (id, code_hash, minted_by, created_at, expires_at) values (2, $1, 'local:owner', 1, 2)", [sha256Hex("x")]), "singleton");
    await assert.rejects(pg.query("insert into vault_console_passkeys (credential_id, public_key, counter, label, created_at) values ($1, $2, 0, 'k', 1)", ["short", b64u(randomBytes(64))]));
    await assert.rejects(pg.query("insert into vault_console_challenges (challenge_hash, purpose, created_at, expires_at) values ($1, 'recovery', 1, 2)", [sha256Hex("y")]));
    // It also applies as part of the full migration set, in order.
    const dir = new URL("../../../../migrations/", import.meta.url);
    const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
    assert.equal(files.at(-1), "0011_vault_owner_console.sql");
    assert.equal(files.filter((f) => f.startsWith("0011_")).length, 1);
    const { PGlite } = await import("@electric-sql/pglite");
    const all = new PGlite();
    for (const f of files) await all.exec(readFileSync(new URL(f, dir), "utf8"));
    assert.equal((await all.query("select count(*) as n from vault_console_passkeys")).rows.length, 1);
    await all.close();
  });

  it("the full ceremony runs on the SQL store: bootstrap → enroll → login → step-up → admin tool → logout", async () => {
    const w = makeWorld({ store: await sqlStore() });
    const auth = new SoftAuthenticator();
    assert.equal((await w.enroll(auth, "SQL key")).status, 200);
    const l = await w.login(auth);
    assert.equal((await w.send("GET", "/console/security", { cookie: l.cookie })).status, 200);
    w.advance(STEP_UP_MS + 1);
    assert.equal((await w.post(l, "/console/clients/revoke", { client_id: "oc_none" })).status, 403);
    assert.equal((await w.stepUp(l, auth)).status, 200);
    assert.notEqual((await w.post(l, "/console/clients/revoke", { client_id: "oc_none" })).status, 403);
    const pg = await (pglite as Promise<import("@electric-sql/pglite").PGlite>);
    const dump = JSON.stringify([
      (await pg.query("select * from vault_console_sessions")).rows,
      (await pg.query("select * from vault_console_bootstrap")).rows,
      (await pg.query("select * from vault_console_passkeys")).rows,
    ], (_k, v) => (typeof v === "bigint" ? Number(v) : v));
    assert.equal(dump.includes(l.token), false, "SQL rows hold the session token only as a hash");
    assert.equal(/evb_/.test(dump), false, "SQL rows hold the bootstrap code only as a hash");
    const replay = await w.send("POST", "/console/login/verify", { json: { response: auth.assert({ challenge: b64u(randomBytes(32)) }, { counter: 1 }) } });
    assert.equal(replay.status, 400);
    assert.equal((await w.post(l, "/console/logout")).status, 303);
    assert.equal((await w.send("GET", "/console", { cookie: l.cookie })).status, 303);
    assert.equal(mintOwnerIdentity(auth.id).client_id, ownerClientId(auth.id));
  });
});
