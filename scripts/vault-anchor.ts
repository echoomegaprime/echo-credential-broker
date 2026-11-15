#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Ledger anchor runner for cron / Task Scheduler (see docs/ops/ledger-anchor.md).
 *
 *   node --experimental-strip-types scripts/vault-anchor.ts
 *       verify the ledger and publish its head to the owner's Telegram chat
 *   node --experimental-strip-types scripts/vault-anchor.ts --verify "<anchor line>"
 *       check a line copied from Telegram against the ledger
 *
 * Prints ONE small JSON object on stdout. Exit 0: anchored / unchanged / empty
 * / verdict ok. Exit 1: anything else. Secrets never print.
 */
import { installProcessRedaction } from "../src/lib/vault/redaction.ts";
import { anchorHead, verifyAnchorLine } from "../src/lib/vault/v2/ledger-anchor.ts";

installProcessRedaction();

async function main(argv: string[]): Promise<{ status: Record<string, unknown>; code: number }> {
  if (argv.length === 0) {
    const outcome = await anchorHead();
    return { status: outcome, code: outcome.ok ? 0 : 1 };
  }
  if (argv.length === 2 && argv[0] === "--verify") {
    const check = await verifyAnchorLine(argv[1]);
    if (!check) return { status: { ok: false, error: "anchor_line_invalid" }, code: 1 };
    return { status: { ok: check.verdict === "ok", ...check }, code: check.verdict === "ok" ? 0 : 1 };
  }
  return { status: { ok: false, error: "usage", usage: "vault-anchor.ts [--verify \"<anchor line>\"]" }, code: 1 };
}

let code = 1;
try {
  const result = await main(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(result.status)}\n`);
  code = result.code;
} catch (err) {
  // Fixed code only: an unexpected error's text could carry a connection string.
  const known = (err as { code?: unknown } | null)?.code;
  process.stdout.write(`${JSON.stringify({ ok: false, error: typeof known === "string" && /^[a-z0-9_]{1,64}$/.test(known) ? known : "internal_error" })}\n`);
}
process.exit(code);
