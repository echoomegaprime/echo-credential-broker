#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-19)
/**
 * Import the OLD Cloudflare vault (worker echo-vault-api, D1 echo-master-vault)
 * into vault entries. Runs on the vault host, as the vault's user, with the
 * vault's environment. Reads the old vault through its own API; changes nothing
 * there except the audit rows the old worker writes for each read.
 *
 *   preview — writes nothing to the new vault:
 *     node --experimental-strip-types scripts/vault-import-cloudflare.ts \
 *       --report ~/vault-import/cf-preview.json
 *   import:
 *     node --experimental-strip-types scripts/vault-import-cloudflare.ts \
 *       --report ~/vault-import/cf-report.json --apply
 *
 * The old worker's API key is taken BY REFERENCE, never from the command line:
 *   --api-key-env <NAME>        an environment variable of this process, or
 *   --api-key-service <name>    a Master Vault entry on the gate
 *       [--api-key-username <u>]  (default: the one the gate's locate names)
 *   With neither, a short list of conventional names is tried on the gate.
 *
 * Options: --base-url <https origin>  default https://echo-vault-api.bmcii1976.workers.dev
 *          --include-unmapped         also import rows whose service names no known
 *                                     site, under <service>.legacy-vault.invalid
 *          --only-site <site>         repeatable
 *          --delay-ms <n>             pause between reads (default 1100; the old
 *                                     worker allows 60 requests a minute)
 *
 * stdout is ONE line of JSON with counts only. The report (mode 0600) lists each
 * planned entry's label, status and old row id; it holds no secret value.
 * Exit code 0 when nothing failed; 1 otherwise. See docs/ops/credential-import.md.
 */
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { dirname, resolve } from "node:path";
import { fingerprint, loadNodeKey } from "./credential-scan.mjs";
import { vaultGet, vaultLocate } from "../src/lib/vault/gate-client.ts";
import { installProcessRedaction, registerSecretForRedaction } from "../src/lib/vault/redaction.ts";
import { ensureV2Configured } from "../src/lib/vault/v2/bootstrap.ts";
import { applyImport } from "../src/lib/vault/v2/import.ts";
import { fetchLegacyVault, LegacyVaultError, planLegacyVault } from "../src/lib/vault/v2/import-legacy-vault.ts";

const DEFAULT_BASE_URL = "https://echo-vault-api.bmcii1976.workers.dev";
const CONVENTIONAL_KEY_NAMES = ["echo-vault-api", "ECHO_VAULT_API_KEY", "echo_vault_api_key", "echo-master-vault", "ECHO_API_KEY"];
const BYPASS_REASON = "legacy vault import: read the old vault's API key by reference";

interface Args {
  report: string | null;
  apply: boolean;
  includeUnmapped: boolean;
  onlySites: string[];
  baseUrl: string;
  keyEnv: string | null;
  keyService: string | null;
  keyUsername: string | null;
  delayMs: number;
}

function parseArgs(argv: string[]): Args {
  const out: Args = { report: null, apply: false, includeUnmapped: false, onlySites: [], baseUrl: DEFAULT_BASE_URL, keyEnv: null, keyService: null, keyUsername: null, delayMs: 1100 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new Error("usage");
      return v;
    };
    if (a === "--report") out.report = next();
    else if (a === "--apply") out.apply = true;
    else if (a === "--include-unmapped") out.includeUnmapped = true;
    else if (a === "--only-site") out.onlySites.push(next());
    else if (a === "--base-url") out.baseUrl = next();
    else if (a === "--api-key-env") out.keyEnv = next();
    else if (a === "--api-key-service") out.keyService = next();
    else if (a === "--api-key-username") out.keyUsername = next();
    else if (a === "--delay-ms") out.delayMs = Math.max(0, Number.parseInt(next(), 10) || 0);
    else throw new Error("usage");
  }
  return out;
}

/** The old worker's API key, by reference. Returns a secret: it goes into one request header and nowhere else. */
async function sourceKey(args: Args): Promise<{ key: string; via: "env" | "gate" }> {
  if (args.keyEnv) {
    const v = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(args.keyEnv) ? process.env[args.keyEnv] : undefined;
    if (!v) throw new LegacyVaultError("source_key_not_found");
    return { key: v, via: "env" };
  }
  const names = args.keyService ? [args.keyService] : CONVENTIONAL_KEY_NAMES;
  for (const name of names) {
    let username = args.keyUsername;
    let service = name;
    if (username === null) {
      let located;
      try {
        located = await vaultLocate(name, BYPASS_REASON);
      } catch {
        throw new LegacyVaultError("gate_unavailable");
      }
      if (located.status !== "EXACT" || !located.get_with) continue;
      service = located.get_with.service;
      username = located.get_with.username;
    }
    try {
      const got = await vaultGet(service, username, BYPASS_REASON);
      if (typeof got.secret === "string" && got.secret) return { key: got.secret, via: "gate" };
    } catch {
      if (args.keyService) throw new LegacyVaultError("source_key_not_found");
    }
  }
  throw new LegacyVaultError("source_key_not_found");
}

installProcessRedaction();

let exitCode = 1;
try {
  const args = parseArgs(process.argv.slice(2));
  if (!args.report) throw new Error("usage");
  const nodeKey = loadNodeKey();
  const { key, via } = await sourceKey(args);
  registerSecretForRedaction(key);
  const fetched = await fetchLegacyVault({
    baseUrl: args.baseUrl,
    apiKey: key,
    fingerprint: (secret) => fingerprint(secret, nodeKey),
    delayMs: args.delayMs,
  });
  const plan = planLegacyVault(fetched.items, {
    includeUnmapped: args.includeUnmapped,
    onlySites: args.onlySites.length ? args.onlySites : undefined,
  });
  ensureV2Configured();
  const result = await applyImport(plan, {
    resolveSecret: async (entry) => {
      for (const src of entry.sources) {
        const value = fetched.secrets.get(src.path);
        if (value) return value;
      }
      return null;
    },
    dryRun: !args.apply,
    actor: `local:import-cloudflare@${hostname()}`.slice(0, 80),
  });
  fetched.secrets.clear();
  const skippedByReason: Record<string, number> = {};
  for (const s of plan.skipped) skippedByReason[s.reason] = (skippedByReason[s.reason] ?? 0) + 1;
  const reportPath = resolve(args.report);
  mkdirSync(dirname(reportPath), { recursive: true });
  writeFileSync(
    reportPath,
    JSON.stringify(
      {
        tool: "echo-vault-legacy-cloudflare-import",
        source: new URL(args.baseUrl).host,
        node: hostname(),
        at: new Date().toISOString(),
        dry_run: result.dry_run,
        contains_secret_values: false,
        source_rows: fetched.rows,
        source_secrets: fetched.items.length,
        counts: result.counts,
        entries: result.outcomes,
        skipped: plan.skipped,
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
  process.stdout.write(
    `${JSON.stringify({
      ok: true,
      dry_run: result.dry_run,
      key_via: via,
      source_rows: fetched.rows,
      source_secrets: fetched.items.length,
      planned: result.planned,
      ...result.counts,
      skipped_rows: plan.skipped.length,
      skipped_by_reason: skippedByReason,
    })}\n`,
  );
  const failed =
    result.counts.source_unreadable +
    result.counts.vault_unavailable +
    result.counts.store_unavailable +
    result.counts.store_failed +
    result.counts.secret_in_metadata;
  exitCode = failed > 0 ? 1 : 0;
} catch (err) {
  // Never the underlying message: only a code.
  const raw = (err as { code?: unknown; message?: unknown } | null) ?? {};
  const code = typeof raw.code === "string" ? raw.code : raw.message === "usage" ? "usage_report_required" : "run_failed";
  process.stdout.write(`${JSON.stringify({ ok: false, error: /^[a-z0-9_]{1,64}$/.test(code) ? code : "run_failed" })}\n`);
}
process.exit(exitCode);
