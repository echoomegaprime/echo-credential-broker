#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Daily audit digest runner (src/lib/vault/v2/digest.ts).
 *
 *   node --experimental-strip-types scripts/vault-digest.ts [--from <iso>] [--to <iso>]
 *
 * No arguments: the previous full UTC day. Prints ONE small JSON status line
 * on stdout — never the digest text — and exits 0 when the window was sent or
 * had already been sent, 1 on any failure (so a scheduler can alert/retry).
 */
import { installProcessRedaction } from "../src/lib/vault/redaction.ts";
import { sendDailyDigest } from "../src/lib/vault/v2/digest.ts";
import { defaultDigestSections } from "../src/lib/vault/v2/digest-sections.ts";

installProcessRedaction();

function parseArgs(argv: string[]): { from?: string; to?: string } | null {
  const out: { from?: string; to?: string } = {};
  for (let i = 0; i < argv.length; i += 1) {
    const [flag, inline] = argv[i].split("=", 2);
    if (flag !== "--from" && flag !== "--to") return null;
    const value = inline ?? argv[(i += 1)];
    if (!value) return null;
    out[flag === "--from" ? "from" : "to"] = value;
  }
  return out;
}

async function main(): Promise<number> {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts) {
    process.stdout.write(`${JSON.stringify({ sent: false, reason: "usage", detail: "vault-digest.ts [--from <iso>] [--to <iso>]" })}\n`);
    return 1;
  }
  const result = await sendDailyDigest({ extraSections: defaultDigestSections() }, opts);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  return result.sent || result.reason === "already_sent" ? 0 : 1;
}

let code = 1;
try {
  code = await main();
} catch {
  process.stdout.write(`${JSON.stringify({ sent: false, reason: "internal_error" })}\n`);
}
try {
  // Flush the embedded database (if one was opened) before exiting.
  const { closeDb } = await import("../src/lib/db.ts");
  await closeDb();
} catch {
  /* nothing was opened */
}
process.exit(code);
