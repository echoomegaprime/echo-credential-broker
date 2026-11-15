#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * ECHO Vault v2 rehearsal: the whole proof against the real, unmodified server.
 *
 * What is real:   the server (`npm run dev`, everything under src/), its PGlite
 *                 database, OAuth, approvals, cards, the ledger, redaction, the
 *                 DNS-pinned request to the target site, and proof-client.mjs.
 * What is a fake: the canonical vault (fake-gate.mjs, via ECHO_SDK_GATE_URL),
 *                 Telegram (fake-telegram.mjs, via telegram-preload.mjs) and the
 *                 owner (this script, acting only through public surfaces: the
 *                 Telegram webhook and the card page).
 *
 * Every key and the throwaway "credential" are generated here, live in memory
 * and in the child processes' environment only, and are never printed or
 * written to disk. At the end the script searches every artifact for them.
 *
 *   node scripts/e2e/rehearsal.mjs            # exit 0 only when every row passes
 *   node scripts/e2e/rehearsal.mjs --keep     # keep the temp dir (server log, transcript)
 *   node scripts/e2e/rehearsal.mjs --cookie   # the same proof with a `cookie` entry (docs/ops/cookie-entries.md):
 *                                             # the owner pastes a Cookie header on the card page, entry_use sends it
 *                                             # to https://httpbin.org/cookies, which echoes the cookies it received —
 *                                             # the client must see them REDACTED. Same fail-closed rule when the
 *                                             # site is unreachable.
 *   node scripts/e2e/rehearsal.mjs --inject   # the --cookie proof, plus the browser injector channel
 *                                             # (docs/ops/injector-contract.md): a SCRIPTED injector (a P-256 key
 *                                             # pair generated here; no extension, no browser) is enrolled over the
 *                                             # local stdio path before the server starts, the client calls
 *                                             # entry_inject, the owner stand-in approves that one request, and this
 *                                             # script redeems the ticket over HTTP, opens the sealed blob and
 *                                             # compares the cookie with what the owner typed on the card.
 */
import { spawn } from "node:child_process";
import { createHash, randomBytes, randomInt, webcrypto } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { startFakeGate } from "./fake-gate.mjs";
import { approvalButtons, cardLink, startFakeTelegram } from "./fake-telegram.mjs";

const { values: flags } = parseArgs({
  options: {
    keep: { type: "boolean", default: false },
    verbose: { type: "boolean", default: false },
    cookie: { type: "boolean", default: false },
    inject: { type: "boolean", default: false },
    help: { type: "boolean", default: false },
  },
});
if (flags.help) {
  process.stdout.write("usage: node scripts/e2e/rehearsal.mjs [--cookie | --inject] [--keep] [--verbose]\n");
  process.exit(0);
}

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const SITE = "httpbin.org";
/** --cookie: a `cookie` entry against /cookies (echoes received cookies). Default: an api_key entry against /bearer. */
const COOKIE_MODE = flags.cookie || flags.inject;
/** --inject: the cookie proof plus the injector channel (ticket → sealed blob → scripted injector). */
const INJECT_MODE = flags.inject;
const INJECT_ORIGIN = `https://${SITE}`;
const KIND = COOKIE_MODE ? "cookie" : "api_key";
const SITE_PATH = COOKIE_MODE ? "/cookies" : "/bearer";
const COOKIE_NAME = "rehearsal_session";
/** What the site answers to a request that carries no credential: /bearer refuses, /cookies shows an empty jar. */
const STATUS_WITHOUT_CREDENTIAL = COOKIE_MODE ? 200 : 401;
const ACCOUNT = "e2e-rehearsal";
const READY_TIMEOUT_MS = 120_000;
const CLIENT_TIMEOUT_MS = 240_000;

const out = (line = "") => process.stdout.write(`${line}\n`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64url = (n) => randomBytes(n).toString("base64url");

// ---------------------------------------------------------------- results table

const rows = [];
/** Set when the target site was unreachable and only the fail-closed path was exercised. */
let failClosedOnly = false;
function check(name, ok, detail = "") {
  rows.push({ name, ok: Boolean(ok), detail });
  if (flags.verbose) out(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  return Boolean(ok);
}

// ---------------------------------------------------------------- secrets (memory only)

/** Throwaway values. `+` and `/` make the URL-encoded and base64 forms differ from the raw one. */
const secrets = {
  credential: `rh/${b64url(24)}+${b64url(6)}`,
  gateApiKey: `fakegate_${b64url(24)}`,
  botToken: `${randomInt(10_000_000, 99_999_999)}:AA${b64url(26).slice(0, 33)}`,
  approvalHmacKey: b64url(36),
  webhookSecret: b64url(24),
  ledgerHmacKey: b64url(36),
  anchorKey: b64url(36),
};
const APPROVER_ID = 700_000_000 + randomInt(1, 9_999_999);
/** What the owner types on the card page. --cookie: a Cookie header whose one value is the throwaway credential. */
const typedSecret = COOKIE_MODE ? `${COOKIE_NAME}=${secrets.credential}` : secrets.credential;
/**
 * What the vault must hold under the entry key. For a cookie entry that is the canonical jar JSON
 * (docs/ops/cookie-entries.md), written out here independently of src/ so the fingerprint check means something.
 */
const storedSecret = COOKIE_MODE
  ? `{"v":1,"cookies":[{"name":${JSON.stringify(COOKIE_NAME)},"value":${JSON.stringify(secrets.credential)},"domain":"","path":"/","secure":false,"httpOnly":false,"hostOnly":true,"expires":null}]}`
  : secrets.credential;
const credentialFingerprint = createHash("sha256").update(storedSecret, "utf8").digest("hex").slice(0, 8);

/** Every encoding of a value that a leak could take. */
function encodings(value) {
  const set = new Set([
    value,
    encodeURIComponent(value),
    new URLSearchParams({ v: value }).toString().slice(2),
    Buffer.from(value, "utf8").toString("base64"),
    Buffer.from(value, "utf8").toString("base64url"),
    Buffer.from(value, "utf8").toString("hex"),
    JSON.stringify(value).slice(1, -1),
  ]);
  return [...set].filter((v) => v.length >= 8);
}
const credentialNeedles = encodings(secrets.credential);
const keyNeedles = Object.entries(secrets)
  .filter(([name]) => name !== "credential")
  .flatMap(([name, value]) => encodings(value).map((needle) => ({ name, needle })));

function holdsAny(haystack, needles) {
  const text = Buffer.isBuffer(haystack) ? haystack.toString("latin1") : String(haystack);
  return needles.some((n) => text.includes(n));
}
/** Names (never values) of server keys found in a text. */
function keysFoundIn(haystack) {
  const text = String(haystack);
  return [...new Set(keyNeedles.filter(({ needle }) => text.includes(needle)).map(({ name }) => name))];
}

// ---------------------------------------------------------------- process handling

const cleanups = [];
let cleaned = false;
async function cleanup() {
  if (cleaned) return;
  cleaned = true;
  for (const fn of cleanups.reverse()) {
    try {
      await fn();
    } catch {
      // best effort
    }
  }
}
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    cleanup().finally(() => process.exit(130));
  });
}
process.on("uncaughtException", (err) => {
  process.stderr.write(`rehearsal crashed: ${err?.name ?? "error"}\n`);
  cleanup().finally(() => process.exit(1));
});

/** Kill a detached child's whole process group; escalate to SIGKILL. */
async function stopGroup(child, graceMs = 5000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((r) => child.once("exit", r));
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    // already gone
  }
  const done = await Promise.race([exited.then(() => true), sleep(graceMs).then(() => false)]);
  if (!done) {
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      // already gone
    }
    await Promise.race([exited, sleep(2000)]);
  }
  // npm → sh → node → vite: make sure no grandchild of the group outlives it.
  await sleep(200);
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    // group is empty
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/**
 * A plain, direct HTTPS GET without any credential: is the target reachable, and what does it say to nobody?
 * Runs in a child with exactly the environment the server gets, so both see the same TLS trust store.
 */
function controlRequest() {
  const script =
    'const https=require("node:https");const done=(o)=>{console.log(JSON.stringify(o));process.exit(0)};' +
    `const req=https.get(${JSON.stringify(`https://${SITE}${SITE_PATH}`)},{timeout:10000,agent:false},(res)=>{res.resume();res.once("end",()=>done({reachable:true,status:res.statusCode}))});` +
    'req.once("timeout",()=>req.destroy(Object.assign(new Error("timeout"),{code:"ETIMEDOUT"})));req.once("error",(e)=>done({reachable:false,code:e&&e.code||"error"}));';
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["-e", script], { env: baseEnv(), stdio: ["ignore", "pipe", "ignore"] });
    let text = "";
    child.stdout.on("data", (d) => (text += d.toString("utf8")));
    child.once("error", () => resolve({ reachable: false, code: "probe_failed" }));
    child.once("exit", () => {
      try {
        resolve(JSON.parse(text));
      } catch {
        resolve({ reachable: false, code: "probe_failed" });
      }
    });
  });
}

/** Environment for a child: nothing from this shell except what a process needs to run. */
function baseEnv() {
  const env = {};
  for (const name of ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "SystemRoot", "APPDATA"]) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  // TLS trust anchors configured for this machine (e.g. a corporate or sandbox egress CA).
  // Verification itself is never relaxed.
  for (const name of ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR"]) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  return env;
}

// ---------------------------------------------------------------- scripted injector (--inject)

/** What the extension does, from docs/ops/injector-contract.md alone. Nothing under src/ is imported. */
const subtle = webcrypto.subtle;
const injector = {
  keys: null, // CryptoKeyPair; the private key is non-extractable
  publicJwk: null,
  id: null,
  token: null,
  /** Encodings of the token (and, later, of the derived key and shared secret) that must appear nowhere. */
  needles: [],
};

async function injectorKeygen() {
  injector.keys = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const jwk = await subtle.exportKey("jwk", injector.keys.publicKey);
  injector.publicJwk = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

/**
 * Enroll over the LOCAL STDIO path (`npm run mcp`, the owner's own machine): the only identities that may enroll
 * are local stdio and a passkey console session. Runs before the HTTP server starts, on the same data directory.
 */
function enrollOverStdio(env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", join(ROOT, "scripts", "mcp-stdio.ts")], {
      cwd: ROOT,
      env: { ...env, ECHO_AGENT: "owner", NODE_OPTIONS: "" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      resolve({ ...value, stderr });
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      done({ ok: false, error: "timeout" });
    }, 90_000);
    child.stderr.on("data", (d) => (stderr += d.toString("utf8")));
    let payload = null;
    let answered = false;
    child.stdout.on("data", (d) => {
      stdout += d.toString("utf8");
      const nl = stdout.indexOf("\n");
      if (nl === -1 || answered) return;
      answered = true;
      try {
        payload = JSON.parse(stdout.slice(0, nl))?.result?.structuredContent ?? null;
      } catch {
        payload = null;
      }
      child.stdin.end(); // lets the process flush the embedded database and exit
    });
    child.once("error", () => done({ ok: false, error: "spawn_failed" }));
    child.once("exit", (code) => {
      clearTimeout(timer);
      done(payload?.ok ? { ok: true, data: payload.data } : { ok: false, error: payload?.error ?? (answered ? "no_result" : `exited_${code}`) });
    });
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "admin_enroll_injector", arguments: { name: "rehearsal scripted injector", public_key_jwk: injector.publicJwk } } })}\n`,
    );
  });
}

/** ECDH → HKDF-SHA256(salt, "echo-vault-injector-v1") → AES-256-GCM(iv, aad). Throws on any mismatch. */
async function openSealed(sealed, expect) {
  const expectedAad = `eit:${createHash("sha256").update(expect.ticket, "utf8").digest("hex")}|${injector.id}|${expect.target_origin}|${expect.mode}`;
  if (Buffer.from(sealed.aad, "base64url").toString("utf8") !== expectedAad) throw new Error("aad_mismatch");
  const u8 = (s) => new Uint8Array(Buffer.from(s, "base64url"));
  const epk = await subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: sealed.epk.x, y: sealed.epk.y, ext: true }, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const z = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: epk }, injector.keys.privateKey, 256));
  const ikm = await subtle.importKey("raw", z, "HKDF", false, ["deriveKey", "deriveBits"]);
  const hkdf = { name: "HKDF", hash: "SHA-256", salt: u8(sealed.salt), info: new TextEncoder().encode("echo-vault-injector-v1") };
  const key = await subtle.deriveKey(hkdf, ikm, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plain = await subtle.decrypt({ name: "AES-GCM", iv: u8(sealed.iv), additionalData: u8(sealed.aad), tagLength: 128 }, key, u8(sealed.ct));
  // For the leak search only: the derived key and the shared secret as bytes.
  const k = Buffer.from(await subtle.deriveBits(hkdf, ikm, 256));
  for (const bytes of [k, Buffer.from(z)]) for (const enc of ["hex", "base64", "base64url"]) injector.needles.push(bytes.toString(enc));
  return JSON.parse(new TextDecoder().decode(plain));
}

// ---------------------------------------------------------------- main

async function main() {
  out("ECHO Vault v2 rehearsal — real server, fake canonical vault, fake Telegram, scripted owner");
  if (INJECT_MODE) out(`mode: --inject — the cookie proof below, then the injector channel: entry_inject → ticket → sealed blob → SCRIPTED injector (no extension, no browser)`);
  out(COOKIE_MODE ? `mode: cookie entry (--cookie) — the owner pastes a Cookie header; target GET https://${SITE}${SITE_PATH}` : `mode: api_key entry — target GET https://${SITE}${SITE_PATH}`);
  out("");

  const tmp = mkdtempSync(join(tmpdir(), "echo-vault-rehearsal-"));
  cleanups.push(() => {
    if (!flags.keep) rmSync(tmp, { recursive: true, force: true });
  });
  const dataDir = join(tmp, "data");
  const transcriptPath = join(tmp, "transcript.json");

  // -- reachability of the target site (decides which entry_use outcome is expected)
  const control = await controlRequest();
  const extraCa = ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR"].filter((n) => process.env[n] !== undefined);
  failClosedOnly = !control.reachable;
  if (control.reachable) {
    out(`target site: https://${SITE}${SITE_PATH} is reachable from here; without a credential it answers ${control.status}.`);
  } else {
    out("!!! ------------------------------------------------------------------------------");
    out(`!!! https://${SITE} is NOT reachable from this machine (${control.code}).`);
    out("!!! The rehearsal will assert that entry_use FAILS CLOSED (entry_use_failed).");
    out("!!! It will NOT prove a successful request with an injected credential.");
    out("!!! ------------------------------------------------------------------------------");
  }
  if (extraCa.length) out(`TLS trust: Node defaults plus ${extraCa.join(", ")} inherited from this environment (verification stays on).`);
  out("");

  // -- fakes
  const gate = await startFakeGate({ apiKey: secrets.gateApiKey });
  cleanups.push(() => gate.close());
  const telegram = await startFakeTelegram({ botToken: secrets.botToken });
  cleanups.push(() => telegram.close());

  // -- the real server
  const port = await freePort();
  const vault = `http://127.0.0.1:${port}`;
  const serverEnv = {
    ...baseEnv(),
    // docs/DEPLOY.md §1–3, with PGlite in the temp dir instead of DATABASE_URL.
    ECHO_VAULT_DATA_DIR: dataDir,
    ECHO_VAULT_PUBLIC_URL: vault,
    TELEGRAM_BOT_TOKEN: secrets.botToken,
    ECHO_VAULT_APPROVER_TELEGRAM_ID: String(APPROVER_ID),
    ECHO_VAULT_APPROVAL_HMAC_KEY: secrets.approvalHmacKey,
    ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET: secrets.webhookSecret,
    ECHO_SDK_API_KEY: secrets.gateApiKey,
    ECHO_SDK_GATE_URL: gate.url,
    ECHO_VAULT_LEDGER_HMAC_KEY: secrets.ledgerHmacKey,
    ECHO_VAULT_ANCHOR_KEY: secrets.anchorKey,
    // Rehearsal wiring, outside src/: reroute api.telegram.org to the fake.
    ECHO_E2E_FAKE_TELEGRAM_URL: telegram.url,
    NODE_OPTIONS: `--import=${pathToFileURL(join(HERE, "telegram-preload.mjs")).href}`,
  };
  // -- --inject: enroll the scripted injector over local stdio, before the HTTP server owns the database
  const inject = { enroll: null, redeem: null, plain: null, replay: null, mcpWithToken: null, restWithToken: null, report: null, tamper: null, redeemBodyText: "", error: null };
  if (INJECT_MODE) {
    await injectorKeygen();
    inject.enroll = await enrollOverStdio(serverEnv);
    if (inject.enroll.ok) {
      injector.id = inject.enroll.data.injector_id;
      injector.token = inject.enroll.data.injector_token;
      injector.needles.push(...encodings(String(injector.token)));
    }
    check(
      "injector: a scripted injector (P-256 key generated here, private key non-extractable) is enrolled over LOCAL STDIO; the token is returned once",
      inject.enroll.ok && /^inj_[0-9a-f]{16}$/.test(String(injector.id)) && /^ein_[A-Za-z0-9_-]{43}$/.test(String(injector.token)) && injector.keys.privateKey.extractable === false,
      inject.enroll.ok ? `${injector.id}` : `enroll failed: ${inject.enroll.error}`,
    );
    if (!inject.enroll.ok) return;
  }

  let serverLog = "";
  const server = spawn("npm", ["run", "dev", "--", "--host", "127.0.0.1", "--port", String(port)], {
    cwd: ROOT,
    env: serverEnv,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  cleanups.push(() => stopGroup(server));
  server.stdout.on("data", (d) => (serverLog += d.toString("utf8")));
  server.stderr.on("data", (d) => (serverLog += d.toString("utf8")));
  let serverExit = null;
  server.once("exit", (code, signal) => (serverExit = { code, signal }));

  const readyBy = Date.now() + READY_TIMEOUT_MS;
  let ready = false;
  while (Date.now() < readyBy && serverExit === null) {
    try {
      const res = await fetch(`${vault}/api/mcp`, { method: "POST", body: "{}", signal: AbortSignal.timeout(5000) });
      await res.arrayBuffer();
      if (res.status === 401 && (res.headers.get("www-authenticate") ?? "").includes("resource_metadata=")) {
        ready = true;
        break;
      }
    } catch {
      // not up yet
    }
    await sleep(500);
  }
  if (!check("real server boots (npm run dev, PGlite in a temp dir) and answers the 401 challenge", ready, ready ? vault : "server did not become ready")) {
    out("server did not start; last log lines (already searched for secrets):");
    const tail = serverLog.split("\n").slice(-15).join("\n");
    out(holdsAny(tail, [...credentialNeedles, ...keyNeedles.map((k) => k.needle)]) ? "(withheld: contains a generated key)" : tail);
    return;
  }

  // -- the owner, through public surfaces only
  const owner = {
    approvals: [], // { ref, action, resource, callbackStatus }
    ignored: [], // approval prompts the owner deliberately left undecided (--inject)
    strangerTap: null,
    badSecretStatus: null,
    card: null, // { getStatus, postStatus, fingerprintOk, replayStatus, postResponse }
    cardPostBody: null,
    errors: [],
  };
  let updateId = 1000;

  async function tap(message, data, fromId, secret) {
    updateId += 1;
    const res = await fetch(`${vault}/api/telegram/webhook`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-telegram-bot-api-secret-token": secret },
      body: JSON.stringify({
        update_id: updateId,
        callback_query: {
          id: `cq-${updateId}`,
          from: { id: fromId, is_bot: false, first_name: "Owner" },
          message: { message_id: message.message_id, date: Math.floor(Date.now() / 1000), chat: { id: message.payload.chat_id, type: "private" } },
          chat_instance: "rehearsal",
          data,
        },
      }),
      signal: AbortSignal.timeout(15_000),
    });
    await res.arrayBuffer();
    return { status: res.status, callbackId: `cq-${updateId}` };
  }

  async function ownerHandles(message) {
    const buttons = approvalButtons(message.payload);
    const text = String(message.payload.text ?? "");
    if (buttons) {
      const action = /^Action: (.*)$/m.exec(text)?.[1] ?? "?";
      const resource = /^Resource: (.*)$/m.exec(text)?.[1] ?? "?";
      const ref = /^Ref: ([A-Za-z0-9_-]{8})/m.exec(text)?.[1] ?? "?";
      if (String(message.payload.chat_id) !== String(APPROVER_ID)) owner.errors.push("approval sent to a chat that is not the approver");
      if (owner.badSecretStatus === null) {
        // Someone who does not know the webhook secret cannot decide anything.
        owner.badSecretStatus = (await tap(message, buttons.approve, APPROVER_ID, `wrong-${b64url(12)}`)).status;
        // Someone who is not the approver taps Approve: nothing may change.
        const stranger = await tap(message, buttons.approve, APPROVER_ID + 1, secrets.webhookSecret);
        await sleep(300);
        const answer = telegram.calls.find((c) => c.method === "answerCallbackQuery" && c.payload.callback_query_id === stranger.callbackId);
        owner.strangerTap = { status: stranger.status, answer: answer?.payload?.text ?? null };
      }
      if (action === "vault.entry.inject" && owner.approvals.some((a) => a.action === "vault.entry.inject")) {
        // --inject: the client's deliberate repeat. The owner leaves it undecided; it must stay pending and mint nothing.
        owner.ignored.push({ ref, action, resource });
        return;
      }
      const real = await tap(message, buttons.approve, APPROVER_ID, secrets.webhookSecret);
      owner.approvals.push({ ref, action, resource, callbackStatus: real.status });
      return;
    }
    const link = cardLink(message.payload);
    if (link) {
      if (!link.startsWith(`${vault}/card/`)) {
        owner.errors.push("card link does not point at the vault's public URL");
        return;
      }
      const page = await fetch(link, { signal: AbortSignal.timeout(15_000) });
      const html = await page.text();
      const form = new URLSearchParams();
      // Fill the form the way a browser would: every named input with its prefilled value.
      for (const m of html.matchAll(/<input\b[^>]*>/g)) {
        const name = /\bname="([^"]*)"/.exec(m[0])?.[1];
        if (!name) continue;
        const value = /\bvalue="([^"]*)"/.exec(m[0])?.[1] ?? "";
        form.set(name, value.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">"));
      }
      // A cookie card's secret field is a textarea (always empty); every other kind has an <input name="secret">.
      const hasSecretField = COOKIE_MODE ? /<textarea\b[^>]*\bname="secret"[^>]*><\/textarea>/.test(html) : form.has("secret");
      form.set("secret", typedSecret); // the owner types (or pastes) it
      owner.cardPostBody = form.toString();
      const post = await fetch(link, {
        method: "POST",
        // What a browser sends for a same-origin form POST from a no-referrer page.
        headers: { "content-type": "application/x-www-form-urlencoded", origin: "null", "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate" },
        body: owner.cardPostBody,
        signal: AbortSignal.timeout(20_000),
      });
      const postHtml = await post.text();
      const fp = /<dt>Fingerprint<\/dt><dd>([0-9a-f]{8}) \((\d+) characters\)<\/dd>/.exec(postHtml);
      const replay = await fetch(link, { signal: AbortSignal.timeout(15_000) });
      await replay.arrayBuffer();
      owner.card = {
        getStatus: page.status,
        hasSecretField,
        csp: page.headers.get("content-security-policy") ?? "",
        postStatus: post.status,
        stored: /Stored in vault/.test(postHtml),
        fingerprintOk: Boolean(fp) && fp[1] === credentialFingerprint && Number(fp[2]) === storedSecret.length,
        replayStatus: replay.status,
        postResponse: postHtml,
        formPage: html,
      };
    }
  }

  let ownerQueue = Promise.resolve();
  telegram.on("message", (message) => {
    ownerQueue = ownerQueue.then(() => ownerHandles(message)).catch((err) => owner.errors.push(`owner step failed: ${err?.name ?? "error"}`));
  });

  // -- the agent: proof-client.mjs as a separate process that knows no secret
  const clientArgs = [
    join(HERE, "proof-client.mjs"),
    "--vault", vault,
    "--site", SITE,
    "--account", ACCOUNT,
    "--kind", KIND,
    "--path", SITE_PATH,
    "--auto",
    "--poll-ms", "700",
    "--timeout-s", "90",
    "--out", transcriptPath,
    "--fingerprint", `${credentialFingerprint}:${storedSecret.length}`,
  ];
  if (!control.reachable) clientArgs.push("--expect-use-error", "entry_use_failed");
  if (INJECT_MODE) clientArgs.push("--inject-origin", INJECT_ORIGIN, "--inject-mode", "cookies");
  let clientOut = "";
  const client = spawn(process.execPath, clientArgs, { cwd: ROOT, env: baseEnv(), detached: true, stdio: ["ignore", "pipe", "pipe"] });
  cleanups.push(() => stopGroup(client, 1000));
  client.stdout.on("data", (d) => (clientOut += d.toString("utf8")));
  client.stderr.on("data", (d) => (clientOut += d.toString("utf8")));
  const clientCode = await Promise.race([
    new Promise((r) => client.once("exit", (code) => r(code))),
    sleep(CLIENT_TIMEOUT_MS).then(() => "timeout"),
  ]);
  await ownerQueue;
  await sleep(300);

  out("---------------- proof-client output ----------------");
  out(holdsAny(clientOut, credentialNeedles) || keysFoundIn(clientOut).length ? "(withheld: the client output contains a generated secret)" : clientOut.trimEnd());
  out("------------------------------------------------------");
  out("");

  // -- --inject: the scripted injector redeems the ticket the client was given, while the server is still up
  if (INJECT_MODE) {
    try {
      const minted = JSON.parse(readFileSync(transcriptPath, "utf8"))?.inject ?? null;
      inject.minted = minted;
      const post = async (path, token, body) => {
        const res = await fetch(`${vault}${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(20_000),
        });
        const text = await res.text();
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {
          json = null;
        }
        return { status: res.status, json, text, cacheControl: res.headers.get("cache-control"), cors: [...res.headers.keys()].filter((h) => h.startsWith("access-control-")) };
      };
      if (minted?.ticket) {
        // The injector token is no tool credential.
        inject.mcpWithToken = (await post("/api/mcp", injector.token, { jsonrpc: "2.0", id: 1, method: "tools/list" })).status;
        inject.restWithToken = (await post("/api/rest/tool", injector.token, { tool: "vault_status", arguments: {} })).status;
        inject.noToken = (await post("/api/injector/redeem", null, { ticket: minted.ticket })).status;
        inject.redeem = await post("/api/injector/redeem", injector.token, { ticket: minted.ticket });
        inject.redeemBodyText = inject.redeem.text;
        if (inject.redeem.status === 200 && inject.redeem.json?.sealed) {
          const want = { ticket: minted.ticket, target_origin: INJECT_ORIGIN, mode: "cookies" };
          inject.plain = await openSealed(inject.redeem.json.sealed, want);
          const sealed = inject.redeem.json.sealed;
          const flipped = Buffer.from(sealed.ct, "base64url");
          flipped[0] ^= 1;
          const refused = async (blob, expect = want) => openSealed(blob, expect).then(() => false, () => true);
          inject.tamper = {
            ct: await refused({ ...sealed, ct: flipped.toString("base64url") }),
            aad: await refused({ ...sealed, aad: Buffer.from("eit:x|y|https://evil.example|cookies").toString("base64url") }, { ...want, target_origin: "https://evil.example" }),
            origin: await refused(sealed, { ...want, target_origin: `https://other.${SITE}` }),
          };
        }
        inject.replay = await post("/api/injector/redeem", injector.token, { ticket: minted.ticket });
        inject.report = await post("/api/injector/report", injector.token, {
          ticket_sha256: createHash("sha256").update(minted.ticket, "utf8").digest("hex"),
          result: "injected",
        });
      }
    } catch (err) {
      inject.error = err?.name ?? "error";
    }
  }

  // -- stop the server, then read the database it left behind
  await stopGroup(server);
  await sleep(300);

  let transcript = null;
  let transcriptText = "";
  try {
    transcriptText = readFileSync(transcriptPath, "utf8");
    transcript = JSON.parse(transcriptText);
  } catch {
    transcript = null;
  }

  check(`proof-client exits 0 with verdict PASS (${INJECT_MODE ? "12 of 12" : "11 of 11"} steps)`, clientCode === 0 && transcript?.verdict?.passed === true, `exit ${clientCode}, steps ${transcript?.verdict?.steps_passed ?? "?"}/${transcript?.verdict?.steps_total ?? "?"}`);

  // -- owner surfaces
  check("Telegram stand-in received the vault's messages (preload active, src/ untouched)", telegram.calls.some((c) => c.method === "sendMessage"), `${telegram.calls.length} Bot API calls, ${telegram.rejected.length} rejected`);
  check("webhook refuses a wrong X-Telegram-Bot-Api-Secret-Token (401)", owner.badSecretStatus === 401, `status ${owner.badSecretStatus}`);
  check('a tap from a non-approver id changes nothing ("Not permitted")', owner.strangerTap?.status === 200 && owner.strangerTap?.answer === "Not permitted", `answer: ${owner.strangerTap?.answer ?? "none"}`);
  const connect = owner.approvals.find((a) => a.action === "vault.client.authorize");
  const firstUse = owner.approvals.find((a) => a.action === "vault.entry.use.read");
  check("owner approval 1: the connection (vault.client.authorize) via the webhook", connect?.callbackStatus === 200, connect ? `${connect.resource}, ref ${connect.ref}` : "no such approval message");
  check("owner approval 2: first use of the entry (vault.entry.use.read) via the webhook", firstUse?.callbackStatus === 200, firstUse ? `${firstUse.resource}, ref ${firstUse.ref}` : "no such approval message");
  if (INJECT_MODE) {
    const injectApproval = owner.approvals.find((a) => a.action === "vault.entry.inject");
    check("owner approval 3: this ONE injection (vault.entry.inject) via the webhook", injectApproval?.callbackStatus === 200, injectApproval ? `${injectApproval.resource}, ref ${injectApproval.ref}` : "no such approval message");
    check(
      "exactly three approvals were approved; the client's repeated injection request reached the owner as a NEW prompt and was left undecided",
      owner.approvals.length === 3 && owner.ignored.length === 1 && owner.ignored[0].action === "vault.entry.inject" && owner.ignored[0].ref !== injectApproval?.ref,
      `${owner.approvals.length} approved, ${owner.ignored.length} left pending`,
    );
  } else {
    check("exactly two approvals were requested and nothing else was approved", owner.approvals.length === 2, `${owner.approvals.length} approval message(s)`);
  }
  check("card page: form served, script-free CSP, secret field present", owner.card?.getStatus === 200 && owner.card.hasSecretField && /default-src 'none'/.test(owner.card.csp), `GET ${owner.card?.getStatus ?? "-"}`);
  check("card page: owner's POST stored the credential (fingerprint and length match)", owner.card?.postStatus === 200 && owner.card.stored && owner.card.fingerprintOk, `POST ${owner.card?.postStatus ?? "-"}`);
  check("card link is dead after one use", owner.card?.replayStatus === 410, `GET again → ${owner.card?.replayStatus ?? "-"}`);
  check("owner automation hit no error", owner.errors.length === 0, owner.errors.join("; "));

  // -- entry_use outcome
  const use = transcript?.use ?? null;
  if (control.reachable) {
    check(`entry_use reached the REAL site: GET https://${SITE}${SITE_PATH} → 200 (it answers ${control.status} without a credential)`, use?.ok === true && use.status === 200 && control.status === STATUS_WITHOUT_CREDENTIAL, `status ${use?.status ?? "-"}`);
    const body = JSON.stringify(use?.body_shape ?? null);
    const useExchange = (transcript?.exchanges ?? []).filter((e) => e.step === "entry_use").at(-1);
    const data = useExchange?.response?.body?.result?.structuredContent?.data;
    if (COOKIE_MODE) {
      // /cookies answers {"cookies": {<name>: <value>}} with exactly what it received in the Cookie header.
      const echoed = data?.body?.cookies?.[COOKIE_NAME];
      check("the site echoed the cookie it received; the client got its value REDACTED", data?.body?.cookies && Object.keys(data.body.cookies).length === 1 && typeof echoed === "string" && /^\[REDACTED/.test(echoed), `cookie "${COOKIE_NAME}" as the client saw it: ${typeof echoed === "string" && !holdsAny(echoed, credentialNeedles) ? echoed : "(withheld)"}; shape ${body}`);
    } else {
      check("the site echoed the token; the client got it REDACTED", data?.body?.authenticated === true && typeof data?.body?.token === "string" && /^\[REDACTED/.test(data.body.token), `token field as the client saw it: ${typeof data?.body?.token === "string" && !holdsAny(data.body.token, credentialNeedles) ? data.body.token : "(withheld)"}; shape ${body}`);
    }
  } else {
    check("!!! entry_use FAILED CLOSED (entry_use_failed) — NO successful injected request was proven", use?.expected_failure === true && use.error === "entry_use_failed", `error ${use?.error ?? "-"}`);
  }

  // -- --inject: what the scripted injector got, and what nobody else did
  if (INJECT_MODE) {
    const minted = inject.minted ?? null;
    check("injector pass ran without a script error", inject.error === null, inject.error ?? "");
    check(
      "entry_inject gave the client a ticket and metadata only (ticket, expiry, injector, entry label/kind, origin, mode)",
      minted && /^eit_[A-Za-z0-9_-]{32}$/.test(minted.ticket) && minted.injector_id === injector.id && minted.target_origin === INJECT_ORIGIN && minted.mode === "cookies" && minted.entry?.kind === "cookie",
      minted ? `injector ${minted.injector_id}, ${minted.mode} → ${minted.target_origin}` : "no inject result in the transcript",
    );
    check(
      "the injector token is not a tool credential (401 on /api/mcp and /api/rest/tool); redeem without a token is 401",
      inject.mcpWithToken === 401 && inject.restWithToken === 401 && inject.noToken === 401,
      `mcp ${inject.mcpWithToken}, rest ${inject.restWithToken}, redeem without token ${inject.noToken}`,
    );
    check(
      "redeem over HTTP as the injector: 200, Cache-Control: no-store, no CORS header, ciphertext only",
      inject.redeem?.status === 200 && inject.redeem.cacheControl === "no-store" && inject.redeem.cors.length === 0 && inject.redeem.json?.sealed?.alg === "ECDH-ES+HKDF-SHA256+A256GCM" && !holdsAny(inject.redeemBodyText, credentialNeedles),
      `status ${inject.redeem?.status ?? "-"}${inject.redeem?.json?.error ? ` (${inject.redeem.json.error})` : ""}`,
    );
    const cookies = Array.isArray(inject.plain?.cookies) ? inject.plain.cookies : [];
    check(
      "the scripted injector decrypted the blob with its private key: the cookie equals what the owner typed on the card",
      inject.plain?.v === 1 && cookies.length === 1 && cookies[0].name === COOKIE_NAME && cookies[0].value === secrets.credential && cookies[0].domain === SITE && cookies[0].hostOnly === true,
      cookies.length ? `${cookies.length} cookie, name "${cookies[0].name}", domain ${cookies[0].domain}, value matches: ${cookies[0].value === secrets.credential}` : "nothing decrypted",
    );
    check("a tampered ciphertext, a forged AAD and another origin are all refused by the injector's decryption", inject.tamper?.ct === true && inject.tamper?.aad === true && inject.tamper?.origin === true);
    check("the ticket is single use: a second redeem is 409 ticket_used", inject.replay?.status === 409 && inject.replay.json?.error === "ticket_used", `status ${inject.replay?.status ?? "-"}`);
    check("the injector reported the outcome (POST /api/injector/report → 200)", inject.report?.status === 200 && inject.report.json?.ok === true, `status ${inject.report?.status ?? "-"}`);
  }

  // -- what the server itself logged about the outbound request and about failures
  const logEvents = serverLog
    .split("\n")
    .map((line) => {
      try {
        return line.startsWith("{") ? JSON.parse(line) : null;
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  if (control.reachable) {
    const connected = logEvents.find((e) => e.event === "vault_entry_use_connected" && e.host === SITE);
    check("server log: one DNS-pinned connection to the target site, at a public address", Boolean(connected) && logEvents.filter((e) => e.event === "vault_entry_use_connected").length === 1, connected ? `${connected.host} at ${connected.address}` : "no vault_entry_use_connected event");
  }
  const errorEvents = logEvents.filter((e) => e.level === "error").map((e) => e.event);
  check("server log: no error-level event during the run", errorEvents.length === 0, [...new Set(errorEvents)].join(", "));
  const warnEvents = [...new Set(logEvents.filter((e) => e.level === "warn").map((e) => `${e.event}${e.reason ? `(${e.reason})` : ""}`))];
  const expectedWarnings = ["telegram_webhook_rejected(bad_secret)", "vault_approval_decision_rejected(unauthorized_user)"];
  // --inject: the replayed ticket this script sent on purpose.
  if (INJECT_MODE) expectedWarnings.push("vault_inject_redeem_refused");
  check(INJECT_MODE ? "server log: the only warnings are the two refused taps and the refused ticket replay this script provoked" : "server log: the only warnings are the two refused taps this script provoked", warnEvents.every((w) => expectedWarnings.includes(w)), warnEvents.join(", ") || "none");

  // -- where the credential is, and is not
  check("credential IS in the owner's card form POST (the one place it is typed)", holdsAny(owner.cardPostBody ?? "", credentialNeedles));
  check("credential IS in the fake canonical vault's store, under one entry key", gate.holds(storedSecret) && gate.count() === 1, `${gate.count()} stored value(s): ${gate.coordinates().map((c) => `${c.service.replace(/_[0-9a-f]{8,}$/, "_…")}/${c.username}`).join(", ")}`);
  const absent = (label, haystack) => check(`credential is NOT in ${label}`, haystack !== null && !holdsAny(haystack, credentialNeedles));
  absent("anything the client received or wrote (transcript)", transcript ? transcriptText : null);
  absent("the client's stdout/stderr", clientOut);
  absent("the server log (stdout + stderr)", serverLog);
  absent("any Telegram message (send/edit/answer payloads)", JSON.stringify(telegram.calls));
  absent("the fake gate's request log", JSON.stringify(gate.traffic));
  absent("the card page responses (form, success page)", owner.card ? `${owner.card.formPage}\n${owner.card.postResponse}` : null);

  // -- database, read independently after the server stopped
  let ledger = [];
  let dbDump = null;
  let dbError = null;
  let approvalRows = [];
  try {
    const { PGlite } = await import("@electric-sql/pglite");
    const db = new PGlite(join(dataDir, "pglite"));
    await db.waitReady;
    const tables = (await db.query("select tablename from pg_tables where schemaname = 'public' order by tablename")).rows.map((r) => r.tablename);
    const dump = {};
    for (const t of tables) dump[t] = (await db.query(`select * from "${t.replace(/"/g, "")}"`)).rows;
    dbDump = JSON.stringify(dump, (_k, v) => (typeof v === "bigint" ? Number(v) : v));
    approvalRows = dump.vault_approvals ?? [];
    ledger = (dump.vault_ledger ?? []).map((r) => ({ ...r, seq: Number(r.seq) })).sort((a, b) => a.seq - b.seq);
    await db.close();
  } catch (err) {
    dbError = err?.name ?? "error";
  }
  check("database opened independently after the server stopped", dbDump !== null, dbError ?? `${ledger.length} ledger rows`);
  absent("any database row (ledger, entries, cards, approvals, OAuth, grants)", dbDump);
  let filesScanned = 0;
  let fileHit = false;
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.size <= 64 * 1024 * 1024) {
        filesScanned += 1;
        if (holdsAny(readFileSync(p), credentialNeedles)) fileHit = true;
      }
    }
  };
  try {
    walk(tmp);
  } catch {
    fileHit = true;
  }
  check("credential is NOT in any file on disk (temp dir: database files, transcript)", !fileHit, `${filesScanned} files`);

  if (INJECT_MODE) {
    // The injector token, the derived AES key and the ECDH shared secret: nowhere but in this script's memory.
    const corpus = { "client transcript": transcriptText, "client output": clientOut, "server log": serverLog, "Telegram payloads": JSON.stringify(telegram.calls), "database rows": dbDump ?? "", "fake gate traffic": JSON.stringify(gate.traffic), "stdio enrollment stderr": inject.enroll?.stderr ?? "" };
    const hits = Object.entries(corpus).filter(([, text]) => holdsAny(text, injector.needles)).map(([name]) => name);
    check(
      "injector token, derived key and shared secret are NOT in the client transcript, client output, server log, Telegram payloads, database or gate traffic",
      injector.needles.length >= 9 && dbDump !== null && hits.length === 0,
      hits.length ? `found in: ${hits.join(", ")}` : `${injector.needles.length} encodings searched`,
    );
    check("the raw ticket is NOT in the server log, any Telegram payload or the database (stored as sha256)", Boolean(inject.minted?.ticket) && dbDump !== null && !holdsAny(`${serverLog}\n${JSON.stringify(telegram.calls)}\n${dbDump}`, [inject.minted?.ticket ?? "\u0000"]));
  }

  const leakedKeys = [...new Set([...keysFoundIn(serverLog), ...keysFoundIn(transcriptText), ...keysFoundIn(clientOut), ...keysFoundIn(JSON.stringify(telegram.calls)), ...keysFoundIn(dbDump ?? ""), ...keysFoundIn(JSON.stringify(gate.traffic))])];
  check("no server key (bot token, HMAC keys, webhook secret, gate API key) in log, transcript, Telegram payloads or database", leakedKeys.length === 0, leakedKeys.join(", "));

  // -- ledger, as stored
  const clientId = transcript?.client_id ?? null;
  const mine = ledger.filter((r) => r.client_id === clientId);
  let linked = ledger.length > 0 && ledger[0].prev_hash === "0".repeat(64);
  for (let i = 1; i < ledger.length && linked; i += 1) linked = ledger[i].prev_hash === ledger[i - 1].hash && ledger[i].seq === ledger[i - 1].seq + 1;
  check("ledger rows link into one chain from genesis (prev_hash = previous hash), every row has an HMAC", linked && ledger.every((r) => typeof r.hmac === "string" && r.hmac.length === 64), `${ledger.length} rows`);
  check("the vault's own audit_verify reported the chain intact", transcript?.chain?.ok === true, `count ${transcript?.chain?.count ?? "-"}`);
  const taps = ledger.filter((r) => r.capability === "vault.approval.decide" && r.client_id === "owner:telegram");
  check(
    INJECT_MODE ? "ledger: the owner's three decisions are on the chain (vault.approval.decide: the connection, the first use, the injection)" : "ledger: both owner decisions are on the chain (vault.approval.decide: the connection, then the first use)",
    taps.length === (INJECT_MODE ? 3 : 2) && (!INJECT_MODE || /^vault\.entry\.inject /.test(taps[2]?.resource ?? "")) && taps.every((r) => r.decision === "allow" && r.result === "ok" && r.approval_id) && /^vault\.client\.authorize /.test(taps[0]?.resource ?? "") && /^vault\.entry\.use\.read /.test(taps[1]?.resource ?? ""),
    taps.map((r) => `seq ${r.seq}`).join(", ") || "missing",
  );
  const cardRow = mine.find((r) => r.capability === "vault.card.request");
  const pendingUse = mine.find((r) => r.capability === "vault.entry.use.read" && r.result === "pending_approval");
  const doneUse = mine.find((r) => r.capability === "vault.entry.use.read" && r.approval_id && r.result !== "pending_approval");
  check("ledger: vault.card.request row for this client", Boolean(cardRow), cardRow ? `seq ${cardRow.seq}, ${cardRow.decision}/tier ${cardRow.tier}/${cardRow.result}` : "missing");
  check("ledger: entry use first recorded as pending_approval (escalate), with the approval the owner saw", Boolean(pendingUse) && pendingUse.approval_id?.slice(0, 8) === firstUse?.ref, pendingUse ? `seq ${pendingUse.seq}, approval ${pendingUse.approval_id.slice(0, 8)}…` : "missing");
  if (control.reachable) {
    check("ledger: the approved use is recorded ok with http 200, the same approval id and a vault:// reference", doneUse?.result === "ok" && Number(doneUse.http_status) === 200 && doneUse.approval_id === pendingUse?.approval_id && /^vault:\/\/entry\//.test(doneUse.credential_ref ?? ""), doneUse ? `seq ${doneUse.seq}, ${doneUse.credential_ref?.replace(/[0-9a-f]{20,}$/, "…")}` : "missing");
  } else {
    check("ledger: the approved use is recorded as an error (entry_use_failed), same approval id", doneUse?.result === "error" && doneUse.approval_id === pendingUse?.approval_id, doneUse ? `seq ${doneUse.seq}, error ${doneUse.error}` : "missing");
  }

  if (INJECT_MODE) {
    const injectRows = ledger.filter((r) => String(r.capability).startsWith("vault.entry.inject"));
    const shape = injectRows.map((r) => `${r.capability.replace("vault.entry.", "")}:${r.result}`).join(" ");
    const approved = injectRows.find((r) => r.capability === "vault.entry.inject" && r.result === "ok");
    const bound = injectRows.filter((r) => r.approval_id === approved?.approval_id);
    check(
      "ledger: inject pending → committing → ok (ticket minted), the consumed approval refused, a new pending request, then redeem ok, a refused replay, and the result — bound to the one approval, entry ref and injector id",
      shape === "inject:pending_approval inject:committing inject:ok inject:denied inject:pending_approval inject.redeem:ok inject.redeem:error inject.result:ok" &&
        bound.length === 7 &&
        bound.every((r) => String(r.resource).endsWith(`#${injector.id}`)) &&
        bound.filter((r) => r.result === "ok").every((r) => /^vault:\/\/entry\/ve_[0-9a-f]{32}$/.test(r.credential_ref ?? "")) &&
        bound.filter((r) => String(r.capability).includes("redeem") || String(r.capability).includes("result")).every((r) => r.client_id === `injector:${injector.id}`),
      shape,
    );
    const ticketRows = (() => {
      try {
        return JSON.parse(dbDump ?? "{}").vault_inject_tickets ?? [];
      } catch {
        return [];
      }
    })();
    const injectorRows = (() => {
      try {
        return JSON.parse(dbDump ?? "{}").vault_injectors ?? [];
      } catch {
        return [];
      }
    })();
    const ticketHash = inject.minted?.ticket ? createHash("sha256").update(inject.minted.ticket, "utf8").digest("hex") : null;
    check(
      "database: exactly one ticket row (sha256 only, redeemed, result injected) and one injector row (token sha256 only)",
      ticketRows.length === 1 && ticketRows[0].sha256 === ticketHash && ticketRows[0].redeemed_at !== null && ticketRows[0].result === "injected" && ticketRows[0].injector_id === injector.id &&
        injectorRows.length === 1 && injectorRows[0].token_sha256 === createHash("sha256").update(String(injector.token), "utf8").digest("hex"),
      `${ticketRows.length} ticket row(s), ${injectorRows.length} injector row(s)`,
    );
  }

  // The connection approval is not a ledger row (see docs/ops/e2e-proof.md); its record is the approvals table.
  const decided = approvalRows.filter((r) => String(r.decided_by ?? "") === String(APPROVER_ID) && ["approved", "consumed"].includes(r.status));
  if (INJECT_MODE) {
    const injectApprovals = approvalRows.filter((r) => r.capability === "vault.entry.inject");
    check(
      "approvals table: the injection approval is consumed (single use); the repeated request is a second, still-pending approval that minted nothing",
      approvalRows.length === 4 && decided.length === 3 && injectApprovals.length === 2 && injectApprovals.filter((r) => r.status === "consumed").length === 1 && injectApprovals.filter((r) => r.status === "pending").length === 1,
      approvalRows.map((r) => `${r.capability}:${r.status}`).join(", "),
    );
  }
  check(
    "approvals table: both approvals decided by the approver id, bound to their request digest",
    (INJECT_MODE || (approvalRows.length === 2 && decided.length === 2)) && decided.some((r) => r.capability === "vault.client.authorize") && decided.some((r) => r.capability === "vault.entry.use.read" && r.status === "consumed") && decided.every((r) => /^[0-9a-f]{64}$/.test(r.request_digest ?? "")),
    approvalRows.map((r) => `${r.capability}:${r.status}`).join(", "),
  );

  // -- ledger dump
  out("---------------- ledger rows of this run (read from the database after the server stopped) ----------------");
  out("  seq  client        capability               decision  tier  result            http  approval   credential_ref");
  for (const r of ledger) {
    const who = r.client_id === clientId ? "proof-client" : String(r.client_id).slice(0, 12);
    out(
      `  ${String(r.seq).padEnd(4)} ${who.padEnd(13)} ${String(r.capability).padEnd(24)} ${String(r.decision).padEnd(9)} ${String(r.tier).padEnd(5)} ${String(r.result).padEnd(17)} ${String(r.http_status ?? "-").padEnd(5)} ${(r.approval_id ? `${r.approval_id.slice(0, 8)}…` : "-").padEnd(10)} ${r.credential_ref ? "vault://entry/…" : "-"}`,
    );
  }
  out("");
  if (flags.keep) {
    const clean = !holdsAny(serverLog, credentialNeedles) && keysFoundIn(serverLog).length === 0;
    if (clean) writeFileSync(join(tmp, "server.log"), serverLog, { mode: 0o600 });
    out(`kept: ${tmp} (transcript.json, data/${clean ? ", server.log" : "; server.log withheld because it holds a generated secret"})`);
  }
}

let crashed = null;
try {
  await main();
} catch (err) {
  crashed = err?.name ?? "error";
  check("rehearsal ran to the end", false, `stopped by ${crashed}${err?.code ? ` (${err.code})` : ""}`);
} finally {
  await cleanup();
}

const width = Math.max(...rows.map((r) => r.name.length), 10);
out("======================== REHEARSAL RESULT ========================");
for (const r of rows) out(`${r.ok ? "PASS" : "FAIL"}  ${r.name.padEnd(width)}${r.detail ? `  ${r.detail}` : ""}`);
const failed = rows.filter((r) => !r.ok).length;
out("-------------------------------------------------------------------");
const pass = failed === 0 && rows.length > 0;
out(`${rows.length - failed} of ${rows.length} checks passed${INJECT_MODE ? " (cookie entry + injector channel, scripted injector)" : COOKIE_MODE ? " (cookie entry)" : ""} — ${pass ? (failClosedOnly ? "REHEARSAL PASS, FAIL-CLOSED PATH ONLY (the site was unreachable: no successful injected request was proven)" : "REHEARSAL PASS") : "REHEARSAL FAIL"}`);
out(`Not proven by a rehearsal: real Telegram delivery, the real canonical vault, a human owner${INJECT_MODE ? ", the real browser extension or any browser" : ""}. See docs/ops/e2e-proof.md.`);
process.exit(failed === 0 && rows.length > 0 ? 0 : 1);
