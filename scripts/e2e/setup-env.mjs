#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Owner-run setup helper for a real ECHO Vault v2 host.
 *
 *   node scripts/e2e/setup-env.mjs                 # interactive; writes ./.env (mode 0600)
 *   node scripts/e2e/setup-env.mjs --out /path/.env --force
 *   node scripts/e2e/setup-env.mjs --verify https://vault.example   # docs/DEPLOY.md §5 checks only
 *
 * It asks for the two values only the owner has (TELEGRAM_BOT_TOKEN and
 * ECHO_SDK_API_KEY, typed with no echo), generates the four keys locally with
 * node:crypto, and writes the env file. Then it offers to apply the database
 * migrations, register the Telegram webhook and run the deploy checks.
 *
 * It never prints a value — not a secret, not a key, not even the origin — and
 * writes exactly one file: the one named by --out (default `.env` in the
 * repository root). The bot token leaves this process only inside the request
 * to api.telegram.org when the owner agrees to register the webhook.
 *
 * How the file is used (verified against this repository):
 *   - `npm run dev`, `npm run build` (the `vite build` half) and `npm run preview`
 *     read `<repo>/.env` by themselves: TanStack Start's Vite plugin copies it
 *     into process.env. A variable already set in the shell wins.
 *   - Plain-node scripts do NOT read it: `npm run db:migrate` (also the second
 *     half of `npm run build`), `npm run mcp`, scripts/vault-*.ts. Run those as
 *     `node --env-file=.env …`, or export the file first:
 *     `set -a; . ./.env; set +a`.
 *   - A Vercel deployment reads the project's environment variables, not this
 *     file: add each name there (`vercel env add NAME production`).
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, lstatSync, openSync, realpathSync, writeSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export const GENERATED_KEYS = [
  "ECHO_VAULT_APPROVAL_HMAC_KEY",
  "ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET",
  "ECHO_VAULT_LEDGER_HMAC_KEY",
  "ECHO_VAULT_ANCHOR_KEY",
];

/** Order of the variables in the written file. */
const FILE_ORDER = [
  "ECHO_VAULT_PUBLIC_URL",
  "ECHO_VAULT_APPROVER_TELEGRAM_ID",
  "TELEGRAM_BOT_TOKEN",
  "ECHO_SDK_API_KEY",
  "ECHO_SDK_GATE_URL",
  "DATABASE_URL",
  "ECHO_VAULT_DATA_DIR",
  ...GENERATED_KEYS,
];

// ---------------------------------------------------------------- pure parts (unit-tested)

/** Four fresh keys: 48 characters of A-Z a-z 0-9 _ - (288 bits each). */
export function generateKeys(random = randomBytes) {
  const out = {};
  for (const name of GENERATED_KEYS) out[name] = random(36).toString("base64url");
  return out;
}

/** Null when acceptable, otherwise what is wrong (never echoing the value). */
export const validators = {
  ECHO_VAULT_PUBLIC_URL(value) {
    let url;
    try {
      url = new URL(value);
    } catch {
      return "not a URL";
    }
    if (url.protocol !== "https:") return "must start with https://";
    if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) return "must be an origin only: no path, query or credentials";
    if (/\s/.test(value)) return "must not contain whitespace";
    return null;
  },
  ECHO_VAULT_APPROVER_TELEGRAM_ID(value) {
    return /^[1-9][0-9]{0,19}$/.test(value) ? null : "must be your numeric Telegram user id (digits only)";
  },
  TELEGRAM_BOT_TOKEN(value) {
    return /^[0-9]{1,20}:[A-Za-z0-9_-]{20,200}$/.test(value) ? null : "does not look like a BotFather token (<digits>:<letters>)";
  },
  ECHO_SDK_API_KEY(value) {
    return value.length >= 8 && !/\s/.test(value) ? null : "must be at least 8 characters with no whitespace";
  },
  ECHO_SDK_GATE_URL(value) {
    if (value === "") return null;
    try {
      return new URL(value).protocol === "https:" ? null : "must start with https://";
    } catch {
      return "not a URL";
    }
  },
  DATABASE_URL(value) {
    if (value === "") return null;
    return /^postgres(ql)?:\/\/\S+$/.test(value) ? null : "must start with postgres:// or postgresql:// and contain no whitespace";
  },
  ECHO_VAULT_DATA_DIR(value) {
    return value.length > 0 && !/[\r\n]/.test(value) ? null : "must be a directory path";
  },
};

/** The public origin without a trailing slash, as the server will see it. */
export function normalizeOrigin(value) {
  return new URL(value).origin;
}

/**
 * Render the env file. Values are single-quoted, which both `node --env-file`
 * and a POSIX shell (`. ./.env`) read literally; a value containing a single
 * quote or a line break cannot be written safely and is refused by name.
 */
export function renderEnv(values) {
  const lines = [
    "# ECHO Vault v2 server environment. Written by scripts/e2e/setup-env.mjs.",
    "# Secrets: keep this file mode 0600, never commit it, never paste it anywhere.",
  ];
  for (const name of FILE_ORDER) {
    const value = values[name];
    if (value === undefined || value === "") continue;
    if (/['\r\n]/.test(value)) throw new Error(`${name} contains a single quote or a line break and cannot be written to an env file`);
    lines.push(`${name}='${value}'`);
  }
  return `${lines.join("\n")}\n`;
}

/**
 * Write the file with mode 0600. Refuses an existing file unless `force`, and
 * refuses a symlink always (it would write somewhere other than the chosen path).
 */
export function writeEnvFile(path, text, { force = false } = {}) {
  const target = resolve(path);
  let existing = null;
  try {
    existing = lstatSync(target);
  } catch (err) {
    if (err.code !== "ENOENT") throw new Error(`cannot inspect ${target} (${err.code})`);
  }
  if (existing?.isSymbolicLink()) throw new Error(`${target} is a symbolic link; refusing to write through it`);
  if (existing && !existing.isFile()) throw new Error(`${target} exists and is not a regular file`);
  if (existing && !force) throw new Error(`${target} already exists; re-run with --force to replace it`);
  let fd;
  try {
    fd = openSync(target, force ? "w" : "wx", 0o600);
  } catch (err) {
    throw new Error(`cannot write ${target} (${err.code})`);
  }
  try {
    chmodSync(target, 0o600); // an existing file may have had looser permissions
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
  return target;
}

/** docs/DEPLOY.md §4 request body. */
export function webhookPayload(origin, secret) {
  return {
    url: `${origin}/api/telegram/webhook`,
    secret_token: secret,
    allowed_updates: ["callback_query"],
    drop_pending_updates: true,
  };
}

/**
 * Register the webhook. Returns { ok, code } with a fixed code only: the URL
 * holds the bot token, so no URL, upstream text or error message is surfaced.
 */
export async function registerWebhook({ botToken, origin, secret, fetchImpl = fetch }) {
  const call = async (method, body) => {
    let res;
    try {
      res = await fetchImpl(`https://api.telegram.org/bot${botToken}/${method}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body ?? {}),
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      return { ok: false, code: "network_error" };
    }
    let json = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    if (!res.ok || json?.ok !== true) return { ok: false, code: `telegram_http_${Number.isInteger(json?.error_code) ? json.error_code : res.status}` };
    return { ok: true, result: json.result };
  };
  const set = await call("setWebhook", webhookPayload(origin, secret));
  if (!set.ok) return { ok: false, code: set.code };
  const info = await call("getWebhookInfo");
  if (!info.ok) return { ok: false, code: info.code };
  if (info.result?.url !== `${origin}/api/telegram/webhook`) return { ok: false, code: "webhook_url_mismatch" };
  if (info.result?.last_error_message) return { ok: false, code: "webhook_reports_last_error" };
  return { ok: true, code: "registered" };
}

/** docs/DEPLOY.md §5: [{ name, ok }]. Needs no secret. */
export async function deployChecks(origin, fetchImpl = fetch) {
  const results = [];
  const get = async (path, init) => {
    try {
      const res = await fetchImpl(`${origin}${path}`, { ...init, signal: AbortSignal.timeout(15_000) });
      let json = null;
      try {
        json = JSON.parse(await res.text());
      } catch {
        json = null;
      }
      return { status: res.status, headers: res.headers, json };
    } catch {
      return { status: 0, headers: new Headers(), json: null };
    }
  };
  const challenge = await get("/api/mcp", { method: "POST", body: "{}" });
  results.push({
    name: "POST /api/mcp without a token → 401 naming this origin's resource metadata",
    ok: challenge.status === 401 && (challenge.headers.get("www-authenticate") ?? "").includes(`resource_metadata="${origin}/.well-known/oauth-protected-resource"`),
  });
  const prm = await get("/.well-known/oauth-protected-resource");
  results.push({
    name: "/.well-known/oauth-protected-resource → this origin",
    ok: prm.status === 200 && prm.json?.resource === `${origin}/api/mcp` && Array.isArray(prm.json?.authorization_servers) && prm.json.authorization_servers[0] === origin,
  });
  const asm = await get("/.well-known/oauth-authorization-server");
  results.push({
    name: "/.well-known/oauth-authorization-server → this origin, PKCE S256",
    ok: asm.status === 200 && asm.json?.issuer === origin && Array.isArray(asm.json?.code_challenge_methods_supported) && asm.json.code_challenge_methods_supported.includes("S256"),
  });
  const header = await get("/api/mcp", { method: "POST", body: "{}", headers: { "x-echo-agent": "claude" } });
  results.push({ name: "POST /api/mcp with x-echo-agent: claude → still 401", ok: header.status === 401 });
  const webhook = await get("/api/telegram/webhook", { method: "POST", body: "{}", headers: { "content-type": "application/json" } });
  results.push({ name: "POST /api/telegram/webhook without the secret header → 401", ok: webhook.status === 401 });
  return results;
}

// ---------------------------------------------------------------- the flow (io injected; tested without a terminal)

/**
 * @param {{ out: string, force: boolean }} opts
 * @param {{
 *   ask: (q: string) => Promise<string>,        visible answer
 *   askHidden: (q: string) => Promise<string>,  no echo
 *   print: (line: string) => void,
 *   fetch?: typeof fetch,
 *   runMigrate?: (env: Record<string,string>) => Promise<number>,
 *   random?: typeof randomBytes,
 * }} io
 * @returns {Promise<number>} exit code
 */
export async function runSetup(opts, io) {
  const { print } = io;
  const target = resolve(opts.out);

  // Fail before asking for anything when the file cannot be written.
  try {
    const st = lstatSync(target);
    if (st.isSymbolicLink()) {
      print(`error: ${target} is a symbolic link; refusing to write through it.`);
      return 1;
    }
    if (!opts.force) {
      print(`error: ${target} already exists. Nothing was changed. Re-run with --force to replace it.`);
      return 1;
    }
    print(`${target} exists and will be REPLACED (--force).`);
  } catch (err) {
    if (err.code !== "ENOENT") {
      print(`error: cannot inspect ${target} (${err.code}).`);
      return 1;
    }
  }

  const values = {};
  const collect = async (name, question, { hidden = false, optional = false, fallback } = {}) => {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      let answer = (await (hidden ? io.askHidden : io.ask)(question)).trim();
      if (answer === "" && fallback !== undefined) answer = fallback;
      if (answer === "" && optional) return "";
      const problem = answer === "" ? "a value is required" : validators[name](answer);
      if (!problem) return answer;
      print(`  ${name}: ${problem}. Try again.`);
    }
    throw new Error(`${name}: no valid value after 5 attempts`);
  };

  print("ECHO Vault v2 setup. Typed secrets are not shown and no value is printed back.");
  print("");
  try {
    values.ECHO_VAULT_PUBLIC_URL = normalizeOrigin(await collect("ECHO_VAULT_PUBLIC_URL", "Public https origin of this server (e.g. https://vault.example.com): "));
    values.ECHO_VAULT_APPROVER_TELEGRAM_ID = await collect("ECHO_VAULT_APPROVER_TELEGRAM_ID", "Your numeric Telegram user id (from @userinfobot): ");
    values.TELEGRAM_BOT_TOKEN = await collect("TELEGRAM_BOT_TOKEN", "TELEGRAM_BOT_TOKEN (from @BotFather; input hidden): ", { hidden: true });
    values.ECHO_SDK_API_KEY = await collect("ECHO_SDK_API_KEY", "ECHO_SDK_API_KEY (input hidden): ", { hidden: true });
    values.ECHO_SDK_GATE_URL = await collect("ECHO_SDK_GATE_URL", "ECHO_SDK_GATE_URL (press Enter for the built-in default): ", { optional: true });
    values.DATABASE_URL = await collect("DATABASE_URL", "DATABASE_URL (Postgres; input hidden; press Enter to use an embedded data directory instead): ", { hidden: true, optional: true });
    if (values.DATABASE_URL === "") {
      values.ECHO_VAULT_DATA_DIR = await collect("ECHO_VAULT_DATA_DIR", "Data directory for the embedded database [.vault-data]: ", { fallback: ".vault-data" });
      print("  note: the embedded database is single-process and is not what a Vercel deployment can use; a deployed server needs DATABASE_URL.");
    }
  } catch (err) {
    print(`error: ${err.message}. Nothing was written.`);
    return 1;
  }
  Object.assign(values, generateKeys(io.random));

  let written;
  try {
    written = writeEnvFile(target, renderEnv(values), { force: opts.force });
  } catch (err) {
    print(`error: ${err.message}. Nothing was written.`);
    return 1;
  }
  const names = FILE_ORDER.filter((n) => values[n] !== undefined && values[n] !== "");
  print("");
  print(`Wrote ${written} (mode 0600) with ${names.length} variables:`);
  for (const n of names) print(`  ${n}${GENERATED_KEYS.includes(n) ? "  (generated here)" : ""}`);
  print("");
  print("How it is loaded:");
  print("  npm run dev / npm run build / npm run preview read <repo>/.env themselves (a shell variable wins).");
  print("  Plain-node scripts do not. Run them with the file, for example:");
  print(`    node --env-file=${written} scripts/migrate.mjs`);
  print(`    set -a; . ${written}; set +a; npm run mcp`);
  print("  Vercel: add each of these names to the project's environment variables instead; this file is not deployed.");
  if (resolve(dirname(written)) !== resolve(ROOT) || !/[\\/]\.env$/.test(written)) {
    print(`  note: Vite only reads a file named .env in ${resolve(ROOT)}. For this path, export it before every command (set -a; . <file>; set +a).`);
  }
  print("");

  const yes = async (question) => /^y(es)?$/i.test((await io.ask(`${question} [y/N] `)).trim());
  let failures = 0;

  if (values.DATABASE_URL) {
    if (await yes("Apply the database migrations now (npm run db:migrate)?")) {
      const code = await io.runMigrate({ DATABASE_URL: values.DATABASE_URL });
      print(`  migrations: ${code === 0 ? "PASS" : `FAIL (exit ${code})`}`);
      if (code !== 0) failures += 1;
    }
  } else {
    print("Migrations: the embedded database applies them itself at first start. Nothing to run.");
  }

  if (await yes(`Register the Telegram webhook for this origin now? (the server does not have to be running)`)) {
    const res = await registerWebhook({
      botToken: values.TELEGRAM_BOT_TOKEN,
      origin: values.ECHO_VAULT_PUBLIC_URL,
      secret: values.ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET,
      fetchImpl: io.fetch ?? fetch,
    });
    print(`  webhook: ${res.ok ? "PASS" : `FAIL (${res.code})`}`);
    if (!res.ok) failures += 1;
  }

  print("Start (or deploy) the server now, then run the checks. On Vercel, redeploy after adding the variables.");
  if (await yes("Is the server reachable at the public origin now? Run the docs/DEPLOY.md checks?")) {
    for (const r of await deployChecks(values.ECHO_VAULT_PUBLIC_URL, io.fetch ?? fetch)) {
      print(`  ${r.ok ? "PASS" : "FAIL"}  ${r.name}`);
      if (!r.ok) failures += 1;
    }
  } else {
    print("  later: node scripts/e2e/setup-env.mjs --verify <origin>");
  }

  print("");
  print(failures === 0 ? "Done. Next: docs/ops/e2e-proof.md (run the proof client)." : `Done with ${failures} failed step(s). The env file is written; fix the failed step and re-run it.`);
  return failures === 0 ? 0 : 1;
}

// ---------------------------------------------------------------- terminal io

/** Read one line from the terminal without echoing it. Refuses when stdin is not a terminal. */
function askHiddenTty(question) {
  return new Promise((resolvePromise, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      reject(new Error("a hidden value can only be typed at a terminal (stdin is not a TTY)"));
      return;
    }
    process.stdout.write(question);
    let value = "";
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    const finish = (fn) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener("data", onData);
      process.stdout.write("\n");
      fn();
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return finish(() => resolvePromise(value));
        if (ch === "\u0003" || ch === "\u0004") return finish(() => reject(new Error("cancelled")));
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else if (ch >= " ") value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

function askVisibleTty(question) {
  return new Promise((resolvePromise, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      reject(new Error("this helper is interactive: run it in a terminal"));
      return;
    }
    process.stdout.write(question);
    stdin.resume();
    stdin.setEncoding("utf8");
    stdin.once("data", (chunk) => {
      stdin.pause();
      resolvePromise(String(chunk).replace(/\r?\n$/, ""));
    });
  });
}

function runMigrate(extraEnv) {
  return new Promise((resolvePromise) => {
    // Output is discarded: a driver error can quote the connection string.
    const child = spawn(process.execPath, [join(ROOT, "scripts", "migrate.mjs")], { cwd: ROOT, env: { ...process.env, ...extraEnv }, stdio: "ignore" });
    child.once("error", () => resolvePromise(127));
    child.once("exit", (code) => resolvePromise(code ?? 1));
  });
}

async function main(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      out: { type: "string", default: join(ROOT, ".env") },
      force: { type: "boolean", default: false },
      verify: { type: "string" },
      help: { type: "boolean", default: false },
    },
  });
  const print = (line) => process.stdout.write(`${line}\n`);
  if (values.help) {
    print("usage: node scripts/e2e/setup-env.mjs [--out <file>] [--force]");
    print("       node scripts/e2e/setup-env.mjs --verify <https origin>   (deploy checks only, needs no secret)");
    return 0;
  }
  if (values.verify !== undefined) {
    const problem = validators.ECHO_VAULT_PUBLIC_URL(values.verify);
    if (problem) {
      print(`error: --verify ${problem}`);
      return 2;
    }
    const results = await deployChecks(normalizeOrigin(values.verify));
    for (const r of results) print(`${r.ok ? "PASS" : "FAIL"}  ${r.name}`);
    return results.every((r) => r.ok) ? 0 : 1;
  }
  return runSetup({ out: values.out, force: values.force }, { ask: askVisibleTty, askHidden: askHiddenTty, print, runMigrate });
}

function isMain() {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isMain()) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      // Fixed text only: an error here may have been built around a typed value.
      process.stderr.write(`setup-env stopped: ${err?.message === "cancelled" ? "cancelled" : /TTY|terminal/.test(err?.message ?? "") ? err.message : "unexpected error"}. \n`);
      process.exit(1);
    },
  );
}
