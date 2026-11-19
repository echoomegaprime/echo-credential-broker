#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-19)
/**
 * Import the credentials a scan found on THIS node into vault entries.
 * Runs on the vault host, as the vault's user, with the vault's environment.
 *
 *   1. scan (references only):
 *        node scripts/credential-scan.mjs --root /home/forge --out ~/vault-import/scan.json
 *   2. preview — writes nothing:
 *        node --experimental-strip-types scripts/vault-import.ts \
 *          --manifest ~/vault-import/scan.json --report ~/vault-import/preview.json
 *   3. import:
 *        node --experimental-strip-types scripts/vault-import.ts \
 *          --manifest ~/vault-import/scan.json --report ~/vault-import/report.json --apply
 *
 * Options: --include-generic   also import KEY=value findings whose variable name
 *                              names a known service
 *          --only-site <site>  repeatable; import these sites only
 *          --hmac-key-file <f> the node key the manifest was written with
 *
 * stdout is ONE line of JSON with counts only — no labels, paths or secrets.
 * The report file (mode 0600) lists each planned entry's label, status and
 * source path:line, and each skipped finding with its reason. It holds no
 * secret value. Source files are read, never changed.
 * Exit code 0 when nothing failed; 1 otherwise. See docs/ops/credential-import.md.
 */
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { hostname } from "node:os";
import { dirname, resolve } from "node:path";
import { loadNodeKey, locateSecret } from "./credential-scan.mjs";
import { installProcessRedaction, registerSecretForRedaction } from "../src/lib/vault/redaction.ts";
import { ensureV2Configured } from "../src/lib/vault/v2/bootstrap.ts";
import { applyImport, planImport, type PlannedEntry, type ScanManifest } from "../src/lib/vault/v2/import.ts";

interface Args {
  manifest: string | null;
  report: string | null;
  apply: boolean;
  includeGeneric: boolean;
  onlySites: string[];
  keyFile: string | null;
  allowOtherNode: boolean;
}

function parseArgs(argv: string[]): Args {
  const out: Args = { manifest: null, report: null, apply: false, includeGeneric: false, onlySites: [], keyFile: null, allowOtherNode: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`missing value for ${a}`);
      return v;
    };
    if (a === "--manifest") out.manifest = next();
    else if (a === "--report") out.report = next();
    else if (a === "--apply") out.apply = true;
    else if (a === "--include-generic") out.includeGeneric = true;
    else if (a === "--only-site") out.onlySites.push(next());
    else if (a === "--hmac-key-file") out.keyFile = next();
    else if (a === "--allow-other-node") out.allowOtherNode = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

/** First source whose line still holds the scanned secret. The value never leaves this process. */
function makeResolver(key: Buffer): (entry: PlannedEntry) => Promise<string | null> {
  const cache = new Map<string, string[] | null>();
  const linesOf = async (path: string): Promise<string[] | null> => {
    if (cache.has(path)) return cache.get(path) ?? null;
    let lines: string[] | null = null;
    try {
      lines = (await readFile(path, "utf8")).split(/\r?\n/);
    } catch {
      lines = null;
    }
    cache.set(path, lines);
    return lines;
  };
  return async (entry) => {
    for (const src of entry.sources) {
      const lines = await linesOf(src.path);
      const line = lines?.[src.line - 1];
      if (typeof line !== "string") continue;
      const value = locateSecret(line, { detector: src.detector, fingerprint: entry.scan_fingerprint }, key);
      if (value) {
        registerSecretForRedaction(value);
        return value;
      }
    }
    return null;
  };
}

installProcessRedaction();

let exitCode = 1;
try {
  const args = parseArgs(process.argv.slice(2));
  if (!args.manifest) throw new Error("usage");
  if (!args.report) throw new Error("usage");
  const manifest = JSON.parse(readFileSync(resolve(args.manifest), "utf8")) as ScanManifest;
  if (!args.allowOtherNode && manifest.node && manifest.node !== hostname()) {
    // Paths in the manifest belong to the node that scanned; each node imports its own.
    throw Object.assign(new Error("other node"), { code: "manifest_from_other_node" });
  }
  const plan = planImport(manifest, { includeGeneric: args.includeGeneric, onlySites: args.onlySites.length ? args.onlySites : undefined });
  ensureV2Configured();
  const result = await applyImport(plan, {
    resolveSecret: makeResolver(loadNodeKey(args.keyFile ?? undefined)),
    dryRun: !args.apply,
    actor: `local:import@${hostname()}`.slice(0, 80),
  });
  const skippedByReason: Record<string, number> = {};
  for (const s of plan.skipped) skippedByReason[s.reason] = (skippedByReason[s.reason] ?? 0) + 1;
  const reportPath = resolve(args.report);
  mkdirSync(dirname(reportPath), { recursive: true });
  writeFileSync(
    reportPath,
    JSON.stringify(
      {
        tool: "echo-vault-credential-import",
        node: hostname(),
        at: new Date().toISOString(),
        dry_run: result.dry_run,
        contains_secret_values: false,
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
      planned: result.planned,
      ...result.counts,
      skipped_findings: plan.skipped.length,
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
  // Never the underlying message (it could quote a file): only a code.
  const raw = (err as { code?: unknown; message?: unknown } | null) ?? {};
  const code = typeof raw.code === "string" ? raw.code : raw.message === "usage" ? "usage_manifest_and_report_required" : "run_failed";
  process.stdout.write(`${JSON.stringify({ ok: false, error: /^[a-z0-9_]{1,64}$/.test(code) ? code : "run_failed" })}\n`);
}
process.exit(exitCode);
