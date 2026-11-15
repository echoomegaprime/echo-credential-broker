// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  GENERATED_KEYS,
  deployChecks,
  generateKeys,
  registerWebhook,
  renderEnv,
  runSetup,
  validators,
  webhookPayload,
  writeEnvFile,
} from "./setup-env.mjs";

// Throwaway values with the shape of the real ones. None is a real credential.
const BOT_TOKEN = "123456789:AAtestonly_testonly_testonly_testonly";
const API_KEY = "testonly-sdk-key-0123456789";
const DB_URL = "postgres://user:p%40ss$word&x=1#frag@db.example:5432/vault?sslmode=require";
const ORIGIN = "https://vault.example.com";

function tmp(t) {
  const dir = mkdtempSync(join(tmpdir(), "setup-env-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Scripted terminal: answers by matching the question; records everything printed. */
function scriptedIo(answers, extra = {}) {
  const printed = [];
  const asked = [];
  const answer = (hidden) => async (question) => {
    asked.push({ question, hidden });
    const hit = answers.find(([re]) => re.test(question));
    if (!hit) throw new Error(`unexpected question: ${question}`);
    return hit[1];
  };
  return { io: { ask: answer(false), askHidden: answer(true), print: (line) => printed.push(line), ...extra }, printed, asked };
}

const HAPPY = [
  [/Public https origin/, `${ORIGIN}/`],
  [/numeric Telegram user id/, "424242"],
  [/TELEGRAM_BOT_TOKEN/, BOT_TOKEN],
  [/ECHO_SDK_API_KEY/, API_KEY],
  [/ECHO_SDK_GATE_URL/, ""],
  [/DATABASE_URL/, DB_URL],
  [/\[y\/N\]/, "n"],
];

test("generateKeys: four distinct keys that satisfy the server's own rules", () => {
  const keys = generateKeys();
  assert.deepEqual(Object.keys(keys), GENERATED_KEYS);
  for (const value of Object.values(keys)) assert.match(value, /^[A-Za-z0-9_-]{48}$/);
  assert.equal(new Set(Object.values(keys)).size, 4);
  // telegram.ts: 16–256 chars of A-Z a-z 0-9 _ -; approvals.ts / ledger.ts: 32+ bytes.
  assert.match(keys.ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET, /^[A-Za-z0-9_-]{16,256}$/);
  assert.ok(Buffer.byteLength(keys.ECHO_VAULT_APPROVAL_HMAC_KEY) >= 32);
  assert.ok(Buffer.byteLength(keys.ECHO_VAULT_LEDGER_HMAC_KEY) >= 32);
  assert.notDeepEqual(generateKeys(), keys);
});

test("validators accept real shapes and never echo the value", () => {
  assert.equal(validators.ECHO_VAULT_PUBLIC_URL(ORIGIN), null);
  assert.ok(validators.ECHO_VAULT_PUBLIC_URL("http://vault.example.com"));
  assert.ok(validators.ECHO_VAULT_PUBLIC_URL("https://vault.example.com/path"));
  assert.equal(validators.ECHO_VAULT_APPROVER_TELEGRAM_ID("424242"), null);
  assert.ok(validators.ECHO_VAULT_APPROVER_TELEGRAM_ID("@me"));
  assert.equal(validators.TELEGRAM_BOT_TOKEN(BOT_TOKEN), null);
  const complaint = validators.TELEGRAM_BOT_TOKEN("not-a-token-value");
  assert.ok(complaint);
  assert.ok(!complaint.includes("not-a-token-value"));
  assert.equal(validators.DATABASE_URL(DB_URL), null);
  assert.ok(validators.DATABASE_URL("mysql://x"));
});

test("renderEnv output is read back exactly by `node --env-file` and by a POSIX shell", (t) => {
  const dir = tmp(t);
  const values = { ECHO_VAULT_PUBLIC_URL: ORIGIN, DATABASE_URL: DB_URL, TELEGRAM_BOT_TOKEN: BOT_TOKEN, ...generateKeys() };
  const file = join(dir, ".env");
  writeEnvFile(file, renderEnv(values));
  const names = Object.keys(values);
  const viaNode = JSON.parse(
    execFileSync(process.execPath, [`--env-file=${file}`, "-e", `console.log(JSON.stringify(Object.fromEntries(${JSON.stringify(names)}.map(n=>[n,process.env[n]]))))`], {
      env: { PATH: process.env.PATH },
      encoding: "utf8",
    }),
  );
  assert.deepEqual(viaNode, values);
  const viaShell = execFileSync("sh", ["-c", `set -a; . "$1"; set +a; printf '%s' "$DATABASE_URL"`, "sh", file], { env: { PATH: process.env.PATH }, encoding: "utf8" });
  assert.equal(viaShell, DB_URL);
});

test("renderEnv refuses a value it cannot quote, naming the variable but not the value", () => {
  assert.throws(() => renderEnv({ DATABASE_URL: "postgres://u:it's@h/db" }), (err) => /DATABASE_URL/.test(err.message) && !err.message.includes("it's"));
});

test("writeEnvFile: mode 0600, refuses to overwrite, --force replaces and tightens the mode, never follows a symlink", (t) => {
  const dir = tmp(t);
  const file = join(dir, ".env");
  writeEnvFile(file, "A='1'\n");
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.throws(() => writeEnvFile(file, "A='2'\n"), /already exists/);
  assert.equal(readFileSync(file, "utf8"), "A='1'\n");

  const loose = join(dir, "loose.env");
  writeFileSync(loose, "old\n", { mode: 0o644 });
  writeEnvFile(loose, "A='3'\n", { force: true });
  assert.equal(readFileSync(loose, "utf8"), "A='3'\n");
  assert.equal(statSync(loose).mode & 0o777, 0o600);

  const outside = join(dir, "outside.txt");
  writeFileSync(outside, "untouched\n");
  const link = join(dir, "link.env");
  symlinkSync(outside, link);
  assert.throws(() => writeEnvFile(link, "A='4'\n", { force: true }), /symbolic link/);
  assert.equal(readFileSync(outside, "utf8"), "untouched\n");
});

test("runSetup writes the file and prints no value at all", async (t) => {
  const dir = tmp(t);
  const out = join(dir, ".env");
  const { io, printed, asked } = scriptedIo(HAPPY);
  const code = await runSetup({ out, force: false }, io);
  assert.equal(code, 0);

  const text = readFileSync(out, "utf8");
  assert.equal(statSync(out).mode & 0o777, 0o600);
  assert.ok(text.includes(`TELEGRAM_BOT_TOKEN='${BOT_TOKEN}'`));
  assert.ok(text.includes(`ECHO_SDK_API_KEY='${API_KEY}'`));
  assert.ok(text.includes(`DATABASE_URL='${DB_URL}'`));
  assert.ok(text.includes(`ECHO_VAULT_PUBLIC_URL='${ORIGIN}'`), "origin is normalized (no trailing slash)");
  assert.ok(!text.includes("ECHO_VAULT_DATA_DIR"), "no data dir when DATABASE_URL is given");
  assert.ok(!text.includes("ECHO_SDK_GATE_URL"), "blank optional value is left out");

  // Every value in the file — typed or generated — must be absent from everything printed.
  const written = [...text.matchAll(/^[A-Z_]+='([^']*)'$/gm)].map((m) => m[1]);
  assert.equal(written.length, 9);
  const stdout = printed.join("\n");
  for (const value of written) assert.ok(!stdout.includes(value), "a value was printed");
  for (const name of GENERATED_KEYS) assert.ok(stdout.includes(name), "variable names are listed");

  // Secrets are asked with the no-echo prompt.
  const hidden = asked.filter((a) => a.hidden).map((a) => a.question);
  assert.equal(hidden.length, 3);
  assert.ok(hidden.some((q) => /TELEGRAM_BOT_TOKEN/.test(q)) && hidden.some((q) => /ECHO_SDK_API_KEY/.test(q)) && hidden.some((q) => /DATABASE_URL/.test(q)));
});

test("runSetup without DATABASE_URL asks for a data directory", async (t) => {
  const dir = tmp(t);
  const out = join(dir, ".env");
  const answers = HAPPY.map((a) => (a[0].source === "DATABASE_URL" ? [a[0], ""] : a));
  answers.splice(-1, 0, [/Data directory/, ""]);
  const { io } = scriptedIo(answers);
  assert.equal(await runSetup({ out, force: false }, io), 0);
  const text = readFileSync(out, "utf8");
  assert.ok(text.includes("ECHO_VAULT_DATA_DIR='.vault-data'"));
  assert.ok(!text.includes("DATABASE_URL"));
});

test("runSetup refuses an existing file before asking anything; an invalid typed secret is never echoed", async (t) => {
  const dir = tmp(t);
  const out = join(dir, ".env");
  writeFileSync(out, "KEEP='me'\n");
  const first = scriptedIo([]);
  assert.equal(await runSetup({ out, force: false }, first.io), 1);
  assert.equal(first.asked.length, 0);
  assert.equal(readFileSync(out, "utf8"), "KEEP='me'\n");

  const bad = HAPPY.map((a) => (a[0].source === "TELEGRAM_BOT_TOKEN" ? [a[0], "typed-wrong-secret-value"] : a));
  const second = scriptedIo(bad);
  assert.equal(await runSetup({ out, force: true }, second.io), 1);
  assert.ok(!second.printed.join("\n").includes("typed-wrong-secret-value"));
  assert.equal(readFileSync(out, "utf8"), "KEEP='me'\n", "nothing is written when input is invalid");
});

test("webhook registration: the token is only in the request URL, and failures are a fixed code", async () => {
  assert.deepEqual(webhookPayload(ORIGIN, "s3cr3t-s3cr3t-s3cr3t"), {
    url: `${ORIGIN}/api/telegram/webhook`,
    secret_token: "s3cr3t-s3cr3t-s3cr3t",
    allowed_updates: ["callback_query"],
    drop_pending_updates: true,
  });
  const calls = [];
  const okFetch = async (url, init) => {
    calls.push({ url: String(url), body: init.body });
    const method = String(url).split("/").at(-1);
    const result = method === "getWebhookInfo" ? { url: `${ORIGIN}/api/telegram/webhook` } : true;
    return new Response(JSON.stringify({ ok: true, result }), { status: 200 });
  };
  assert.deepEqual(await registerWebhook({ botToken: BOT_TOKEN, origin: ORIGIN, secret: "s3cr3t-s3cr3t-s3cr3t", fetchImpl: okFetch }), { ok: true, code: "registered" });
  assert.equal(calls[0].url, `https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`);
  assert.ok(!calls[0].body.includes(BOT_TOKEN));

  const denied = async () => new Response(JSON.stringify({ ok: false, error_code: 401, description: `Unauthorized ${BOT_TOKEN}` }), { status: 401 });
  const res = await registerWebhook({ botToken: BOT_TOKEN, origin: ORIGIN, secret: "s3cr3t-s3cr3t-s3cr3t", fetchImpl: denied });
  assert.deepEqual(res, { ok: false, code: "telegram_http_401" });
  const thrown = async () => {
    throw new Error(`connect failed https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`);
  };
  assert.deepEqual(await registerWebhook({ botToken: BOT_TOKEN, origin: ORIGIN, secret: "x".repeat(20), fetchImpl: thrown }), { ok: false, code: "network_error" });
});

test("runSetup prints only PASS/FAIL for the webhook and the deploy checks", async (t) => {
  const dir = tmp(t);
  const out = join(dir, ".env");
  const answers = HAPPY.slice(0, -1).concat([[/migrations/, "y"], [/webhook/, "y"], [/checks/, "y"]]);
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(String(url));
    if (u.hostname === "api.telegram.org") {
      return new Response(JSON.stringify({ ok: true, result: u.pathname.endsWith("getWebhookInfo") ? { url: `${ORIGIN}/api/telegram/webhook` } : true }), { status: 200 });
    }
    if (u.pathname === "/api/mcp") {
      return new Response("{}", { status: 401, headers: { "www-authenticate": `Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource"` } });
    }
    if (u.pathname === "/.well-known/oauth-protected-resource") return new Response(JSON.stringify({ resource: `${ORIGIN}/api/mcp`, authorization_servers: [ORIGIN] }));
    if (u.pathname === "/.well-known/oauth-authorization-server") return new Response(JSON.stringify({ issuer: ORIGIN, code_challenge_methods_supported: ["S256"] }));
    if (u.pathname === "/api/telegram/webhook") return new Response("unauthorized", { status: init.headers?.["x-telegram-bot-api-secret-token"] ? 200 : 401 });
    return new Response("nope", { status: 404 });
  };
  let migrateEnv = null;
  const { io, printed } = scriptedIo(answers, { fetch: fetchImpl, runMigrate: async (env) => ((migrateEnv = env), 0) });
  assert.equal(await runSetup({ out, force: false }, io), 0);
  assert.equal(migrateEnv.DATABASE_URL, DB_URL);
  const stdout = printed.join("\n");
  assert.match(stdout, /migrations: PASS/);
  assert.match(stdout, /webhook: PASS/);
  assert.equal((stdout.match(/^ {2}PASS {2}/gm) ?? []).length, 5);
  for (const value of [BOT_TOKEN, API_KEY, DB_URL, ORIGIN]) assert.ok(!stdout.includes(value));
});

test("deployChecks reports a server whose public URL is not configured", async () => {
  const unconfigured = async (url) => {
    const u = new URL(String(url));
    if (u.pathname === "/api/mcp") return new Response("{}", { status: 401, headers: { "www-authenticate": 'Bearer realm="echo-vault"' } });
    return new Response(JSON.stringify({ error: "temporarily_unavailable" }), { status: 503 });
  };
  const results = await deployChecks(ORIGIN, unconfigured);
  assert.deepEqual(results.map((r) => r.ok), [false, false, false, true, false]);
});
