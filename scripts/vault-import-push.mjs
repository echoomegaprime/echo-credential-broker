#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-19)
/**
 * ECHO Vault node import — runs ON a fleet node and pushes the credentials
 * found on that node's own disks straight into the vault.
 *
 * Needs only this file and credential-scan.mjs next to it. Zero dependencies;
 * Node >= 18; Windows, Linux and macOS.
 *
 *   node vault-import-push.mjs --root /home/me                 preview (stores nothing)
 *   node vault-import-push.mjs --root /home/me --apply         import
 *   node vault-import-push.mjs --all-drives --apply            every local fixed drive
 *
 * What happens:
 *   1. The node is scanned (references only, as credential-scan.mjs does).
 *   2. The vault owner gets ONE Telegram prompt: node name, how many
 *      credentials, preview or import, and a pairing code. The same code is
 *      printed here. Nothing is sent until they approve.
 *   3. Each distinct secret is read from its file and sent to the vault over
 *      HTTPS. The vault stores it; it never sends a secret back.
 *
 * Nothing here prints, logs or writes a secret value. stdout carries counts and
 * the pairing code; the report file lists labels, statuses and path:line.
 * Source files are read, never changed.
 *
 * Options: --vault <url>          default https://credbroker.echo-op.com
 *          --node <name>          default this host's name
 *          --include-generic      also send KEY=value findings (the vault keeps
 *                                 only those whose variable names a known service)
 *          --exclude <path>       repeatable
 *          --manifest <file>      reuse a scan made on THIS node instead of scanning
 *          --report <file>        default ~/.echo-vault-scan/import-report.json
 */
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir, hostname } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { listDriveRoots, loadNodeKey, locateSecret, scan } from "./credential-scan.mjs";

const BATCH = 20;
const MAX_PLANNED = 2000;
const MAX_SOURCES = 5;
/** Findings that can never become an entry; not worth sending. */
const NEVER = new Set(["private-key", "echo-vault", "jwt", "url-credentials"]);

export function parseArgs(argv) {
  const out = { vault: "https://credbroker.echo-op.com", node: null, roots: [], excludes: [], allDrives: false, apply: false, includeGeneric: false, manifest: null, report: null, keyFile: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`missing value for ${a}`);
      return v;
    };
    if (a === "--vault") out.vault = next();
    else if (a === "--node") out.node = next();
    else if (a === "--root") out.roots.push(next());
    else if (a === "--exclude") out.excludes.push(next());
    else if (a === "--all-drives") out.allDrives = true;
    else if (a === "--apply") out.apply = true;
    else if (a === "--include-generic") out.includeGeneric = true;
    else if (a === "--manifest") out.manifest = next();
    else if (a === "--report") out.report = next();
    else if (a === "--hmac-key-file") out.keyFile = next();
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

/** "QUENCH.local" → "quench". The vault accepts [a-z0-9][a-z0-9-]{0,31}. */
export function nodeName(raw) {
  const cleaned = String(raw ?? "").toLowerCase().split(".")[0].replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32);
  return cleaned || "node";
}

/**
 * Findings → one group per distinct secret, with the places it was found.
 * Pure; holds no secret value.
 */
export function groupFindings(findings, opts = {}) {
  const groups = new Map();
  let skipped = 0;
  for (const f of findings) {
    if (typeof f.fingerprint !== "string" || NEVER.has(f.provider)) {
      skipped++;
      continue;
    }
    if ((f.detector === "generic_assignment" || f.provider === "unknown") && !opts.includeGeneric) {
      skipped++;
      continue;
    }
    const g = groups.get(f.fingerprint);
    if (g) {
      if (g.sources.length < MAX_SOURCES) g.sources.push({ path: f.path, line: f.line });
      if (!g.key_name && f.key_name) g.key_name = f.key_name;
      continue;
    }
    groups.set(f.fingerprint, {
      fingerprint: f.fingerprint,
      detector: f.detector,
      provider: f.provider,
      key_name: f.key_name ?? null,
      sources: [{ path: f.path, line: f.line }],
    });
  }
  return { groups: [...groups.values()], skipped };
}

/** Read each group's secret back from disk. Groups whose sources changed are dropped. */
async function attachSecrets(groups, key) {
  const cache = new Map();
  const linesOf = async (path) => {
    if (cache.has(path)) return cache.get(path);
    let lines = null;
    try {
      lines = (await readFile(path, "utf8")).split(/\r?\n/);
    } catch {
      lines = null;
    }
    cache.set(path, lines);
    return lines;
  };
  const items = [];
  let unreadable = 0;
  for (const g of groups) {
    let secret = null;
    for (const src of g.sources) {
      const line = (await linesOf(src.path))?.[src.line - 1];
      if (typeof line !== "string") continue;
      secret = locateSecret(line, { detector: g.detector, fingerprint: g.fingerprint }, key);
      if (secret) break;
    }
    if (secret) items.push({ ...g, secret });
    else unreadable++;
  }
  return { items, unreadable };
}

async function call(vault, path, body, bearer) {
  const res = await fetch(`${vault.replace(/\/+$/, "")}/api/import/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
    body: JSON.stringify(body),
    redirect: "error",
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const say = (obj) => process.stdout.write(`${JSON.stringify(obj)}\n`);

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const vault = new URL(args.vault);
  // Secrets only ever travel over TLS; plain http is for a vault on this same machine.
  const loopback = vault.hostname === "127.0.0.1" || vault.hostname === "localhost" || vault.hostname === "[::1]";
  if (vault.protocol !== "https:" && !(vault.protocol === "http:" && loopback)) {
    throw Object.assign(new Error("https"), { code: "vault_must_be_https" });
  }
  const node = nodeName(args.node ?? hostname());
  const key = loadNodeKey(args.keyFile ?? undefined);

  let manifest;
  if (args.manifest) {
    manifest = JSON.parse(readFileSync(resolve(args.manifest), "utf8"));
  } else {
    const roots = args.allDrives ? await listDriveRoots({}) : args.roots;
    if (roots.length === 0) throw Object.assign(new Error("roots"), { code: "give_root_or_all_drives" });
    manifest = await scan({
      roots,
      key,
      excludes: args.excludes,
      onProgress: (p) => process.stderr.write(`${new Date().toISOString()} ${JSON.stringify(p)}\n`),
    });
  }
  const { groups, skipped } = groupFindings(manifest.findings ?? [], { includeGeneric: args.includeGeneric });
  const { items: all, unreadable } = await attachSecrets(groups, key);
  say({ step: "scanned", node, findings: (manifest.findings ?? []).length, distinct_secrets: groups.length, not_sendable: skipped, unreadable, to_send: all.length, sessions: Math.ceil(all.length / MAX_PLANNED) });
  if (all.length === 0) {
    say({ ok: true, node, nothing_to_import: true });
    return 0;
  }

  const counts = {};
  const entries = [];
  let malformed = 0;
  let overPlan = 0;
  const skippedByVault = {};
  // One owner approval covers at most MAX_PLANNED credentials. A bigger node is
  // sent as consecutive sessions, each with its own prompt, so every credential
  // is reached in one run.
  for (let start = 0; start < all.length; start += MAX_PLANNED) {
    const items = all.slice(start, start + MAX_PLANNED);
    const session = randomBytes(32).toString("base64url");
    const terms = { node, planned: items.length, apply: args.apply, include_generic: args.includeGeneric };
    const began = await call(vault.origin, "begin", { ...terms, session_hash: createHash("sha256").update(session, "utf8").digest("hex") });
    if (began.status !== 200 || !began.json?.approval_id) {
      say({ ok: false, step: "begin", status: began.status, error: began.json?.error ?? "begin_failed", sent_before_failure: start });
      return 1;
    }
    const approvalId = began.json.approval_id;
    say({
      step: "waiting_for_owner",
      node,
      session: start / MAX_PLANNED + 1,
      credentials: items.length,
      pairing_code: began.json.pairing_code,
      expires_at: began.json.expires_at,
      mode: args.apply ? "import" : "preview",
    });

    for (let i = 0; i < items.length; i += BATCH) {
      const batch = items.slice(i, i + BATCH).map((it) => ({
        fingerprint: it.fingerprint,
        detector: it.detector,
        provider: it.provider,
        key_name: it.key_name,
        secret: it.secret,
        sources: it.sources,
      }));
      let res;
      for (;;) {
        res = await call(vault.origin, "submit", { ...terms, approval_id: approvalId, items: batch }, session);
        if (res.status === 409 && res.json?.error === "approval_pending") {
          await sleep(5000);
          continue;
        }
        break;
      }
      if (res.status !== 200 || !res.json?.ok) {
        say({ ok: false, step: "submit", status: res.status, error: res.json?.error ?? "submit_failed", sent_before_failure: start + i });
        return 1;
      }
      for (const [k, v] of Object.entries(res.json.counts ?? {})) counts[k] = (counts[k] ?? 0) + v;
      for (const [k, v] of Object.entries(res.json.skipped ?? {})) skippedByVault[k] = (skippedByVault[k] ?? 0) + v;
      malformed += res.json.malformed ?? 0;
      overPlan += res.json.over_plan ?? 0;
      for (const e of res.json.entries ?? []) entries.push(e);
    }
    await call(vault.origin, "finish", { ...terms, approval_id: approvalId }, session).catch(() => null);
  }
  const items = all;

  const reportPath = resolve(args.report ?? join(homedir(), ".echo-vault-scan", "import-report.json"));
  mkdirSync(dirname(reportPath), { recursive: true });
  writeFileSync(
    reportPath,
    JSON.stringify(
      {
        tool: "echo-vault-node-import",
        node,
        at: new Date().toISOString(),
        mode: args.apply ? "import" : "preview",
        contains_secret_values: false,
        counts,
        skipped_by_vault: skippedByVault,
        entries,
        sent: items.map((it) => ({ provider: it.provider, key_name: it.key_name, sources: it.sources })),
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );
  try {
    chmodSync(reportPath, 0o600);
  } catch {
    /* Windows: ACLs, not modes */
  }
  say({ ok: true, node, mode: args.apply ? "import" : "preview", sent: items.length, ...counts, malformed, over_plan: overPlan, skipped_by_vault: skippedByVault, report: reportPath });
  const failed = (counts.vault_unavailable ?? 0) + (counts.store_unavailable ?? 0) + (counts.store_failed ?? 0);
  return failed > 0 ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      // A code only: the underlying message could quote a file.
      const code = typeof err?.code === "string" && /^[a-z0-9_]{1,64}$/.test(err.code) ? err.code : "run_failed";
      process.stdout.write(`${JSON.stringify({ ok: false, error: code })}\n`);
      process.exit(1);
    },
  );
}
