/** FORGE-only, headless, non-MCP operator entrypoint. No secret CLI/env inputs.
 * The fixed root-owned config and jobs are NOT supplied by a caller/LLM.
 */
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { executeSdkJob, reviewSdkJob, digest, operatorExitCode, type OperatorConfig } from "../src/lib/vault/sdk-operator.ts";

const CONFIG = "/etc/echo/credential-broker/sdk-operator.json";
const JOBS = "/etc/echo/credential-broker/sdk-operator-jobs";

async function protectedPath(path: string, directory = false): Promise<void> {
  const st = await lstat(path);
  if (st.isSymbolicLink() || (directory ? !st.isDirectory() : !st.isFile())
      || st.uid !== 0 || (st.mode & 0o022) !== 0 || await realpath(path) !== path) throw new Error("untrusted");
  // Parent directories cannot be writable by the broker user/other actors.
  if (path !== "/") await protectedPath(dirname(path), true);
}
async function boundedRead(path: string, max: number): Promise<string> {
  await protectedPath(path);
  const handle = await open(path, "r");
  try {
    const st = await handle.stat();
    if (st.uid !== 0 || (st.mode & 0o022) !== 0 || st.size > max) throw new Error("untrusted");
    const buffer = Buffer.alloc(max + 1);
    const { bytesRead } = await handle.read(buffer);
    if (bytesRead > max) throw new Error("oversize");
    return buffer.subarray(0, bytesRead).toString("utf8");
  } finally { await handle.close(); }
}

async function main(): Promise<void> {
  const [mode, jobId, ...extra] = process.argv.slice(2);
  // Root-owned, fixed-purpose operator process, NOT the forge/agent shell UID.
  // An agent-writable replay store would allow tombstone deletion/replay.
  if (process.platform !== "linux" || process.getuid?.() !== 0 || !["review", "execute"].includes(mode)
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(jobId ?? "")
      || extra.length) throw new Error("invalid");
  const entry = fileURLToPath(import.meta.url);
  if (!/^\/opt\/echo-credential-broker-operator\/[0-9a-f]{40}\/scripts\/sdk-operator\.ts$/.test(entry)) throw new Error("untrusted");
  await protectedPath(entry);
  const cfg = JSON.parse(await boundedRead(CONFIG, 16384)) as OperatorConfig;
  if (!cfg.claims_dir.startsWith("/var/lib/echo-credential-broker/sdk-operator/")
      || dirname(cfg.claims_dir) !== "/var/lib/echo-credential-broker/sdk-operator") throw new Error("untrusted");
  const st = await lstat(cfg.claims_dir);
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== 0
      || (st.mode & 0o077) !== 0 || await realpath(cfg.claims_dir) !== cfg.claims_dir) throw new Error("untrusted");
  await protectedPath(dirname(cfg.claims_dir), true);
  const token = (await boundedRead(join(JOBS, `${jobId}.jwt`), 65536)).trim();
  const job = await reviewSdkJob(token, cfg);
  if (job.jti !== jobId) throw new Error("invalid");
  const result = mode === "review" ? {
    status: "admission_valid", action_id: job.action_id, candidate_sha: job.candidate_sha,
    params_sha256: digest(job.params), expires_at: job.exp, state_checked: false,
    execution_verified: false, server_approval_verified: false,
  } : await executeSdkJob(token, cfg);
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exitCode = operatorExitCode(result, mode as "review" | "execute");
}
main().catch(() => {
  process.stdout.write(JSON.stringify({ status: "blocked", error: "operator_admission_or_host_unavailable",
    execution_verified: false, upstream_body_withheld: true }) + "\n");
  process.exitCode = 2;
});
