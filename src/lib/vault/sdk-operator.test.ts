import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignJWT } from "jose";
import { canonical, digest, reviewSdkJob, executeSdkJob, claimJob, totpFromSeed, operatorExitCode,
  SDK_ENDPOINT, ADMISSION_AUDIENCE, FIXTURE_SQL, FIXTURE_CLEANUP_SQL, type OperatorConfig, type AdmissionJob } from "./sdk-operator.ts";
import { spawnSync } from "node:child_process";
import type { VaultBackend } from "./backend.ts";
import { callTool, listTools } from "./tools.ts";
import { handleMcpRequest } from "./mcp.ts";

// Synthetic credentials and keys ONLY. No test calls a real vault or SDK.
const KEY = "fixture-sdk-key-never-production";
const HMAC = "ab".repeat(32);
const SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // public RFC6238 vector
const NOW = 2000000000000;
const pair = generateKeyPairSync("ed25519");
const publicPem = pair.publicKey.export({ format: "pem", type: "spki" }).toString();
const STATE = { ok: true, cap: { id: "echo.psql.execute", scope: "db.write", tier: 3 } };
function config(dir: string): OperatorConfig {
  return { enabled: true, issuer: "fixture-owner-NOT-LIVE", key_id: "fixture-key", public_key_pem: publicPem,
    claims_dir: dir, principal: { actor: "fixture-operator", mission_id: "fixture-mission",
      credential_sha256: createHash("sha256").update(KEY).digest("hex"),
      credential: { service: "fixture-sdk-principal", username: "fixture-user" },
      capabilities: ["echo.psql.execute", "echo.certforge.submit"] } };
}
function job(cfg: OperatorConfig): AdmissionJob {
  return { jti: randomUUID(), sub: cfg.principal.actor, mission_id: cfg.principal.mission_id,
    credential_sha256: cfg.principal.credential_sha256, candidate_sha: "a".repeat(40),
    action_id: "gs343.fixture.execute", capability: "echo.psql.execute", params: {
      command: "execute", sql: FIXTURE_SQL, args: ["c".repeat(64), "gs343-outcome-ledger-qa test",
        "Write-Output harmless", "quench", "proposed", "gs343-outcome-ledger-qa/fixture"] },
    expected_state: { capability: "echo.caps.detail", params: { command: "detail", id: "echo.psql.execute" },
      sha256: digest(STATE) },
    review: Object.fromEntries(["hypothesis", "evidence", "falsification_condition", "exact_action",
      "affected_resources", "rollback", "expected_local_result", "expected_public_result", "stop_condition"].map(k => [k, "fixture review only"])),
    idempotency_key: randomUUID(), iat: NOW / 1000 - 1, exp: NOW / 1000 + 60 };
}
async function sign(j: AdmissionJob, options: { issuer?: string; audience?: string; kid?: string; typ?: string } = {}) {
  return new SignJWT(j).setProtectedHeader({ alg: "EdDSA", kid: options.kid ?? "fixture-key", typ: options.typ ?? "echo-sdk-job+jwt" })
    .setIssuer(options.issuer ?? "fixture-owner-NOT-LIVE").setAudience(options.audience ?? ADMISSION_AUDIENCE).sign(pair.privateKey);
}
function fakeIo(final: object = { status: "ok", run_id: "87654321-1234-4234-9234-123456789abc", result: { status_code: 200, body: {} } }) {
  const reads: string[] = [], calls: Array<Record<string, unknown>> = [];
  const backend: VaultBackend = {
    get: async (service, username) => { reads.push(`${service}/${username}`); return {
      service, username, secret: service === "echo-sdk-tier3-totp" ? SEED : KEY, key_fingerprint: "fixture" }; },
    search: async () => ({ status: "EXACT", service: "echo-sdk-tier3-totp", candidates: [],
      get_with: { service: "echo-sdk-tier3-totp", username: "sovereign" } }),
    locate: async () => { throw new Error("unexpected"); }, put: async () => { throw new Error("unexpected"); },
  };
  const fetcher: typeof fetch = async (url, init) => {
    assert.equal(url, SDK_ENDPOINT); assert.equal(init?.redirect, "error");
    assert.equal((init?.headers as Record<string, string>)["X-Echo-API-Key"], KEY);
    const payload = JSON.parse(String(init?.body)); calls.push(payload);
    const body = calls.length === 1 ? { status: "ok", result: { status_code: 200, body: STATE } }
      : payload.capability === "echo.psql.query" ? { status: "ok", result: { status_code: 200, body: { rows: [{ secret_hmac: HMAC }] } } } : final;
    return new Response(JSON.stringify(body), { status: 200 });
  };
  return { backend, fetcher, reads, calls, clock: () => NOW };
}
async function isolated(fn: (cfg: OperatorConfig) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), "echo-sdk-operator-fixture-"));
  try { await fn(config(dir)); } finally { await rm(dir, { recursive: true, force: true }); }
}

test("canonical matches installed Python SDK sorted compact ASCII wire vector", () => {
  assert.equal(canonical({ z: [true, null, 12], a: "line\nvalue", "2": "b", "10": "a" }),
    '{"10":"a","2":"b","a":"line\\nvalue","z":[true,null,12]}');
  assert.equal(digest({ command: "execute", args: [1, false, null], sql: "SELECT $1" }),
    "89e07dee263bd40c46598a2b1213acf61419d432e89f0f63ec8ea5b8bf42c944");
});
for (const [label, value] of [["unicode", "caf\u00e9"], ["float", 1.5], ["negative-zero", -0],
  ["unsafe-integer", Number.MAX_SAFE_INTEGER + 1], ["undefined", undefined], ["nan", NaN]] as const) {
  test(`canonical rejects ${label}`, () => assert.throws(() => canonical(value)));
}
test("TOTP implements public RFC6238 6-digit vector", () => {
  assert.equal(totpFromSeed(SEED, 59000), "287082");
  assert.throws(() => totpFromSeed("not a seed", NOW));
});
test("review verifies exact signed job without vault, network or replay writes", async () => isolated(async cfg => {
  const j = job(cfg); const reviewed = await reviewSdkJob(await sign(j), cfg, NOW);
  assert.equal(digest(reviewed.params), digest(j.params)); assert.deepEqual(await readdir(cfg.claims_dir), []);
}));
for (const [label, mutate] of [
  ["expired", (j: AdmissionJob) => { j.iat -= 100; j.exp = NOW / 1000 - 1; }],
  ["future", (j: AdmissionJob) => { j.iat = NOW / 1000 + 1; }],
  ["longttl", (j: AdmissionJob) => { j.exp = j.iat + 91; }],
  ["actor", (j: AdmissionJob) => { j.sub = "other"; }],
  ["mission", (j: AdmissionJob) => { j.mission_id = "other"; }],
  ["credential", (j: AdmissionJob) => { j.credential_sha256 = "d".repeat(64); }],
  ["candidate", (j: AdmissionJob) => { j.candidate_sha = "not-a-sha"; }],
  ["capability", (j: AdmissionJob) => { j.capability = "echo.shell.run"; }],
  ["fixture-sql", (j: AdmissionJob) => { j.params.sql += "; DELETE FROM other"; }],
  ["fixture-marker", (j: AdmissionJob) => { (j.params.args as string[])[5] = "unmarked"; }],
  ["state-probe", (j: AdmissionJob) => { j.expected_state.capability = "echo.shell.run"; }],
  ["review", (j: AdmissionJob) => { delete j.review.rollback; }],
] as const) test(`rejects ${label} before any vault use`, async () => isolated(async cfg => {
  const j = job(cfg); mutate(j); const io = fakeIo();
  assert.equal((await executeSdkJob(await sign(j), cfg, io)).status, "blocked");
  assert.deepEqual(io.reads, []); assert.deepEqual(io.calls, []);
}));
for (const [field, value] of [["issuer", "wrong"], ["audience", "wrong"], ["kid", "wrong"], ["typ", "wrong"]] as const) {
  test(`rejects wrong ${field}`, async () => isolated(async cfg => {
    await assert.rejects(reviewSdkJob(await sign(job(cfg), { [field]: value }), cfg, NOW));
  }));
}
test("disabled and substituted-key configurations fail closed", async () => isolated(async cfg => {
  const token = await sign(job(cfg)); cfg.enabled = false;
  await assert.rejects(reviewSdkJob(token, cfg, NOW)); cfg.enabled = true;
  cfg.public_key_pem = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
  await assert.rejects(reviewSdkJob(token, cfg, NOW));
}));
test("one mutation, actual SDK HMAC, no secret/body returned; server approval stays refused", async () => isolated(async cfg => {
  const j = job(cfg), io = fakeIo({ status: "approval_required", result: { status_code: 403,
    body: { secret: KEY, factor: totpFromSeed(SEED, NOW), signing_secret: HMAC, reflected: SEED } } });
  const result = await executeSdkJob(await sign(j), cfg, io);
  assert.equal(result.status, "approval_required"); assert.equal(result.execution_verified, false);
  assert.equal(io.calls.length, 3); const mutation = io.calls[2]; const auth = mutation.auth as Record<string, unknown>;
  assert.equal(auth.hmac, createHmac("sha256", Buffer.from(HMAC, "hex"))
    .update(`v1|${KEY}|echo.psql.execute|${canonical(j.params)}|${auth.nonce}|${auth.ts}`).digest("hex"));
  assert.equal(auth.totp, totpFromSeed(SEED, NOW));
  for (const secret of [KEY, HMAC, SEED, auth.totp as string]) assert.ok(!JSON.stringify(result).includes(secret));
}));
test("concurrent calls and fresh consumer see one durable attempt", async () => isolated(async cfg => {
  const token = await sign(job(cfg)), io = fakeIo();
  const results = await Promise.all([executeSdkJob(token, cfg, io), executeSdkJob(token, cfg, io)]);
  assert.equal(results.filter(r => r.status === "ok").length, 1);
  assert.equal(io.calls.filter(c => c.capability === "echo.psql.execute").length, 1);
  const freshIo = fakeIo(); assert.equal((await executeSdkJob(token, structuredClone(cfg), freshIo)).status, "blocked");
  assert.deepEqual(freshIo.reads, []);
}));
test("same idempotency key with different signed jti cannot reexecute", async () => isolated(async cfg => {
  const j = job(cfg); await claimJob(cfg.claims_dir, cfg.issuer, j); j.jti = randomUUID();
  await assert.rejects(claimJob(cfg.claims_dir, cfg.issuer, j));
}));
test("replay remains blocked in an actual fresh Node process", async () => isolated(async cfg => {
  const j = job(cfg); await claimJob(cfg.claims_dir, cfg.issuer, j);
  const source = `import {claimJob} from ${JSON.stringify(new URL("./sdk-operator.ts", import.meta.url).href)};
    try { await claimJob(process.argv[1],process.argv[2],JSON.parse(process.argv[3])); process.exitCode=9; }
    catch { process.stdout.write('replay_blocked'); }`;
  const child = spawnSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", source,
    cfg.claims_dir, cfg.issuer, JSON.stringify(j)], { windowsHide: true, encoding: "utf8", timeout: 10000 });
  assert.equal(child.status, 0); assert.equal(child.stdout, "replay_blocked");
}));
test("cleanup is exact-id/signature/node/double-marker bounded, never blanket DELETE", async () => isolated(async cfg => {
  const j = job(cfg); j.action_id = "gs343.fixture.cleanup";
  j.params = { command: "execute", sql: FIXTURE_CLEANUP_SQL, args: ["9223372036854775807", "c".repeat(64), "quench", "%gs343-outcome-ledger-qa%"] };
  await reviewSdkJob(await sign(j), cfg, NOW);
  for (const args of [["0", "c".repeat(64), "quench", "%gs343-outcome-ledger-qa%"],
    ["123", "c".repeat(64), "forge", "%gs343-outcome-ledger-qa%"], ["123", "c".repeat(64), "quench", "%"],
    ["9223372036854775808", "c".repeat(64), "quench", "%gs343-outcome-ledger-qa%"]]) {
    j.params.args = args; await assert.rejects(reviewSdkJob(await sign(j), cfg, NOW));
  }
}));
test("installation/rollback are reviewed only, never dispatched as commands", async () => isolated(async cfg => {
  const j = job(cfg); j.action_id = "gs343.acceptance.rollback"; j.capability = "review-only";
  j.params = { target_node: "quench", target_root: "D:\\ECHO_OMEGA_PRIME\\03_TOOLS\\powershell\\Echo.SolProfile\\1.1.3\\runtime",
    candidate_sha: j.candidate_sha, expected_installed_manifest_sha256: "c".repeat(64), rollback_source_sha: "b".repeat(40),
    files: [{ path: "SYSTEMS/echo_node_steward_4b/outcome_ledger.py", sha256: "a".repeat(64), before_sha256: null }] };
  await reviewSdkJob(await sign(j), cfg, NOW); const io = fakeIo();
  assert.equal((await executeSdkJob(await sign(j), cfg, io)).status, "blocked");
  assert.equal(io.reads.length, 0); assert.equal(io.calls.length, 0);
}));
test("partial claim failure reports unknown consumption, never falsely reusable", async () => isolated(async cfg => {
  const first = job(cfg); await claimJob(cfg.claims_dir, cfg.issuer, first);
  const second = job(cfg); second.idempotency_key = first.idempotency_key;
  const io = fakeIo(); const result = await executeSdkJob(await sign(second), cfg, io);
  assert.equal(result.consumed, null); assert.equal(io.reads.length, 0);
  await assert.rejects(claimJob(cfg.claims_dir, cfg.issuer, second));
}));
test("audit failure is visible without repeating or hiding the attempted mutation", async () => isolated(async cfg => {
  const io = fakeIo();
  const result = await executeSdkJob(await sign(job(cfg)), cfg, { ...io, audit: () => { throw new Error(KEY); } });
  assert.equal(result.status, "ok"); assert.equal(result.audit_recorded, false); assert.equal(result.execution_verified, false);
  assert.equal(io.calls.length, 3); assert.ok(!JSON.stringify(result).includes(KEY));
}));
for (const status of ["error", "client_error", "approval_required", "unknown"]) {
  test(`semantic ${status} and wrapped HTTP403 never become execution proof`, async () => isolated(async cfg => {
    const io = fakeIo({ status, result: { status_code: 403, body: { token: KEY } } });
    const result = await executeSdkJob(await sign(job(cfg)), cfg, io);
    assert.equal(result.status, status); assert.equal(result.http_status, 403); assert.equal(result.execution_verified, false);
    assert.equal(operatorExitCode(result, "execute"), 2);
  }));
}
test("certification pins exact candidate and canonical repository; no tier3 factor use", async () => isolated(async cfg => {
  const j = job(cfg); j.action_id = "certforge.submit"; j.capability = "echo.certforge.submit";
  const url = "https://github.com/echoomegaprime/echo-omnipresence-runtime.git";
  j.params = { command: "submit", target: { source_commit: j.candidate_sha, url, ref: j.candidate_sha,
    reference: `${url}@${j.candidate_sha}` } };
  j.expected_state = { capability: "echo.certforge.service_status", params: { command: "status" }, sha256: digest(STATE) };
  const io = fakeIo(); const result = await executeSdkJob(await sign(j), cfg, io);
  assert.equal(result.status, "ok"); assert.equal(result.execution_verified, false);
  assert.equal(io.reads.length, 1); assert.equal(io.calls.length, 2);
  assert.equal(io.calls[1].capability, "echo.certforge.submit"); assert.equal(io.calls[1].auth, undefined);
  assert.ok(!io.calls.some(c => c.capability === "echo.psql.query"));
  (j.params.target as Record<string, unknown>).source_commit = "b".repeat(40);
  await assert.rejects(reviewSdkJob(await sign(j), cfg, NOW));
}));
test("changed fresh state consumes job without factor or mutation", async () => isolated(async cfg => {
  const j = job(cfg); j.expected_state.sha256 = "e".repeat(64); const io = fakeIo();
  const result = await executeSdkJob(await sign(j), cfg, io);
  assert.equal(result.consumed, true); assert.equal(io.reads.length, 1); assert.equal(io.calls.length, 1);
}));
test("credential fingerprint mismatch stops before SDK and factor", async () => isolated(async cfg => {
  const j = job(cfg), io = fakeIo();
  io.backend.get = async () => ({ service: "fixture", username: "fixture", secret: "wrong-fixture", key_fingerprint: "fixture" });
  assert.equal((await executeSdkJob(await sign(j), cfg, io)).consumed, true); assert.equal(io.calls.length, 0);
}));
test("ambiguous network error remains consumed and never returns exception contents", async () => isolated(async cfg => {
  const token = await sign(job(cfg)), io = fakeIo();
  const fetcher = io.fetcher;
  io.fetcher = async (url, init) => {
    if (JSON.parse(String(init?.body)).capability === "echo.psql.execute") throw new Error(`${KEY} ${HMAC} ${SEED}`);
    return fetcher(url, init);
  };
  const result = await executeSdkJob(token, cfg, io);
  assert.equal(result.consumed, true); assert.equal(result.execution_verified, false);
  assert.ok(!JSON.stringify(result).includes(KEY));
  const next = fakeIo(); await executeSdkJob(token, cfg, next); assert.equal(next.calls.length, 0);
}));
test("public REST/MCP dispatch cannot reach private operations for approved caller label", async () => {
  for (const name of ["sdk_action_review", "sdk_operator_execute"]) {
    assert.ok(!listTools().some(t => t.name === name));
    assert.equal((await callTool(name, {}, { caller: "vault-console" })).ok, false);
    const rpc = await handleMcpRequest({ id: 1, method: "tools/call", params: { name, arguments: {} } }, "vault-console");
    assert.ok(JSON.stringify(rpc).includes("tool_forbidden"));
  }
});
test("CLI exit status requires typed 2xx plus recorded audit, never HTTP200-wrapped refusal", () => {
  assert.equal(operatorExitCode({ status: "ok", http_status: 200, audit_recorded: true }, "execute"), 0);
  for (const result of [{ status: "ok", http_status: 403, audit_recorded: true },
    { status: "ok", http_status: "200", audit_recorded: true }, { status: "ok", http_status: 200, audit_recorded: false }]) {
    assert.equal(operatorExitCode(result, "execute"), 2);
  }
});
