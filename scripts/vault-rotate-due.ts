#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Rotate every vault entry whose rotation is due. For cron / Task Scheduler:
 *
 *   node --experimental-strip-types scripts/vault-rotate-due.ts
 *
 * stdout is ONE line of JSON with counts only — no ids, labels or secrets:
 *   {"due":2,"rotated":1,"failed":0,"warned":0,"needs_manual_rotation":1}
 * Exit code 0 when nothing failed; 1 on any failed or warned rotation, or if
 * the run itself could not start. Details (entry ids, short error codes) go to
 * the structured log on stderr and to the ledger (capability
 * "vault.entry.rotate"). See docs/ops/rotation-and-delete.md.
 */
import { installProcessRedaction } from "../src/lib/vault/redaction.ts";
import { ensureV2Configured } from "../src/lib/vault/v2/bootstrap.ts";
import { rotateDueEntries } from "../src/lib/vault/v2/rotation.ts";

installProcessRedaction();
ensureV2Configured();

let exitCode = 1;
try {
  const res = await rotateDueEntries(Date.now(), { actor: "local:rotate-due" });
  process.stdout.write(
    `${JSON.stringify({
      due: res.due,
      rotated: res.rotated,
      failed: res.failed,
      warned: res.warned,
      needs_manual_rotation: res.needs_manual_rotation.length,
    })}\n`,
  );
  exitCode = res.failed > 0 || res.warned > 0 ? 1 : 0;
} catch (err) {
  // Never the underlying message: only a code.
  const code = typeof (err as { code?: unknown } | null)?.code === "string" ? (err as { code: string }).code : "run_failed";
  process.stdout.write(`${JSON.stringify({ error: /^[a-z0-9_]{1,64}$/.test(code) ? code : "run_failed" })}\n`);
}
process.exit(exitCode);
