/** Private-process SDK route. NEVER register this in public REST/MCP tools.
 * Admission is task-specific, not a replacement for the gate's scope/TOTP/
 * exact-parameter human approval. No credential, signature or body is returned.
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import { open, lstat } from "node:fs/promises";
import { join } from "node:path";
import { importSPKI, jwtVerify } from "jose";
import { GateVaultBackend, type VaultBackend } from "./backend.ts";
import { log } from "./log.ts";
import { registerSecretForRedaction } from "./redaction.ts";

export const SDK_ENDPOINT = "http://127.0.0.1:8000/sdk/invoke";
export const ADMISSION_AUDIENCE = "echo-sdk-operator/v1";
export const FIXTURE_SQL = "INSERT INTO arcanum_sdk.gs343_diagnoses (error_signature,error_text,proposed_fix,source_node,status,source_log_path) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,error_signature,created_at";
export const FIXTURE_CLEANUP_SQL = "DELETE FROM arcanum_sdk.gs343_diagnoses WHERE id = ($1::text)::bigint AND error_signature = $2 AND source_node = $3 AND error_text LIKE $4 AND source_log_path LIKE $4 RETURNING id";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{64}$/;
const ACTIONS: Record<string, string | null> = {
  "gs343.fixture.execute": "echo.psql.execute",
  "gs343.fixture.cleanup": "echo.psql.execute",
  "certforge.submit": "echo.certforge.submit",
  // Review only. No command runner or Windows installation authority here.
  "gs343.acceptance.install": null,
  "gs343.acceptance.rollback": null,
};
const REVIEW_FIELDS = ["hypothesis", "evidence", "falsification_condition", "exact_action",
  "affected_resources", "rollback", "expected_local_result", "expected_public_result", "stop_condition"];

export type JsonObject = Record<string, unknown>;
export interface OperatorConfig {
  enabled: boolean;
  issuer: string;
  key_id: string;
  public_key_pem: string;
  claims_dir: string;
  principal: {
    actor: string; mission_id: string; credential_sha256: string;
    credential: { service: string; username: string };
    capabilities: string[];
  };
}
export interface AdmissionJob extends JsonObject {
  jti: string; sub: string; mission_id: string; credential_sha256: string;
  candidate_sha: string; action_id: string; capability: string; params: JsonObject;
  expected_state: { capability: string; params: JsonObject; sha256: string };
  review: Record<string, string>; idempotency_key: string; iat: number; exp: number;
}
export class OperatorRouteError extends Error {
  constructor(category: string) { super(category); this.name = "OperatorRouteError"; }
}
function reject(category: string): never { throw new OperatorRouteError(category); }
function object(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Wire subset shared with installed SOL SDK json.dumps(sort_keys=True,
 * separators=(",",":"), ensure_ascii=True). Reject unsupported Unicode/floats
 * instead of signing a subtly different request. Never silently coerce types.
 */
export function canonical(value: unknown, depth = 0): string {
  if (depth > 24) reject("operator_json_invalid");
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) reject("operator_json_invalid");
    return String(value);
  }
  if (typeof value === "string") {
    if (/[^\x20-\x7e\t\r\n]/.test(value)) reject("operator_json_invalid");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(v => canonical(v, depth + 1)).join(",")}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(k =>
    `${canonical(k, depth + 1)}:${canonical(value[k], depth + 1)}`).join(",")}}`;
  return reject("operator_json_invalid");
}
export function digest(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

export async function reviewSdkJob(token: string, cfg: OperatorConfig, now = Date.now()): Promise<AdmissionJob> {
  if (cfg.enabled !== true) reject("operator_route_disabled");
  if (typeof token !== "string" || token.length > 65536) reject("operator_admission_invalid");
  try {
    const key = await importSPKI(cfg.public_key_pem, "EdDSA");
    const { payload, protectedHeader } = await jwtVerify(token, key, {
      algorithms: ["EdDSA"], issuer: cfg.issuer, audience: ADMISSION_AUDIENCE,
      requiredClaims: ["sub", "iat", "exp", "jti"], maxTokenAge: 90,
      currentDate: new Date(now), clockTolerance: 0,
    });
    if (protectedHeader.kid !== cfg.key_id || protectedHeader.typ !== "echo-sdk-job+jwt"
        || Object.keys(protectedHeader).some(k => !["kid", "typ", "alg"].includes(k))) reject("operator_admission_invalid");
    const j = payload as unknown as AdmissionJob;
    const p = cfg.principal;
    if (!UUID.test(j.jti) || !Number.isSafeInteger(j.iat) || !Number.isSafeInteger(j.exp)
        || j.iat > now / 1000 || j.exp <= j.iat || j.exp - j.iat > 90
        || j.sub !== p.actor || j.mission_id !== p.mission_id
        || !SHA.test(j.credential_sha256) || j.credential_sha256 !== p.credential_sha256
        || !/^[0-9a-f]{40}$/.test(j.candidate_sha) || !Object.hasOwn(ACTIONS, j.action_id)
        || typeof j.idempotency_key !== "string" || !/^[a-zA-Z0-9_-]{8,120}$/.test(j.idempotency_key)
        || !object(j.params) || !object(j.review)
        || REVIEW_FIELDS.some(f => typeof j.review[f] !== "string" || !j.review[f].trim())) reject("operator_admission_invalid");
    const cap = ACTIONS[j.action_id];
    if (cap !== null && (j.capability !== cap || !p.capabilities.includes(cap))) reject("operator_scope_not_admitted");
    if (cap === null && j.capability !== "review-only") reject("operator_action_not_supported");
    if (cap === null && (j.params.target_node !== "quench"
        || j.params.target_root !== "D:\\ECHO_OMEGA_PRIME\\03_TOOLS\\powershell\\Echo.SolProfile\\1.1.3\\runtime"
        || j.params.candidate_sha !== j.candidate_sha || !SHA.test(String(j.params.expected_installed_manifest_sha256))
        || !/^[0-9a-f]{40}$/.test(String(j.params.rollback_source_sha))
        || !Array.isArray(j.params.files) || j.params.files.length < 1 || j.params.files.length > 12
        || j.params.files.some(f => !object(f) || typeof f.path !== "string"
          || !/^(SYSTEMS\/echo_node_steward_4b\/(outcome_ledger|steward_common|gs343_fixture_policy)\.py|CLAUDE_CODE_MARKETPLACE\/plugins\/(echo-gs343|echo-sentinel)\/hooks\/(register\.tsx|ledger\.ts|sentinel\.ts)|CLAUDE_CODE_MARKETPLACE\/plugins\/(echo-gs343|echo-sentinel)\/\.claude-plugin\/plugin\.json)$/.test(f.path)
          || !SHA.test(String(f.sha256)) || !(f.before_sha256 === null || SHA.test(String(f.before_sha256)))))) reject("operator_target_manifest_invalid");
    if (cap && (!object(j.expected_state) || !object(j.expected_state.params)
        || !SHA.test(j.expected_state.sha256)
        || !["echo.caps.detail", "echo.certforge.service_status"].includes(j.expected_state.capability))) reject("operator_state_invalid");
    if (cap === "echo.psql.execute" && (j.expected_state.capability !== "echo.caps.detail"
        || canonical(j.expected_state.params) !== canonical({ command: "detail", id: cap }))) reject("operator_state_invalid");
    if (cap === "echo.certforge.submit" && (j.expected_state.capability !== "echo.certforge.service_status"
        || canonical(j.expected_state.params) !== canonical({ command: "status" }))) reject("operator_state_invalid");
    if (j.action_id === "gs343.fixture.execute" && (j.params.command !== "execute"
        || j.params.sql !== FIXTURE_SQL || !Array.isArray(j.params.args) || j.params.args.length !== 6
        || j.params.args.some(v => typeof v !== "string")
        || !SHA.test(j.params.args[0] as string)
        || !(j.params.args[1] as string).includes("gs343-outcome-ledger-qa")
        || !(j.params.args[5] as string).includes("gs343-outcome-ledger-qa")
        || j.params.args[3] !== "quench" || j.params.args[4] !== "proposed"
        || Object.keys(j.params).some(k => !["command", "sql", "args"].includes(k)))) reject("operator_fixture_invalid");
    if (j.action_id === "gs343.fixture.cleanup" && (j.params.command !== "execute"
        || j.params.sql !== FIXTURE_CLEANUP_SQL || !Array.isArray(j.params.args) || j.params.args.length !== 4
        || typeof j.params.args[0] !== "string" || !/^[1-9][0-9]{0,18}$/.test(j.params.args[0])
        || BigInt(j.params.args[0]) > 9223372036854775807n
        || typeof j.params.args[1] !== "string" || !SHA.test(j.params.args[1])
        || j.params.args[2] !== "quench" || j.params.args[3] !== "%gs343-outcome-ledger-qa%"
        || Object.keys(j.params).some(k => !["command", "sql", "args"].includes(k)))) reject("operator_fixture_invalid");
    if (cap === "echo.certforge.submit" && (j.params.command !== "submit" || !object(j.params.target)
        || j.params.target.source_commit !== j.candidate_sha
        || j.params.target.url !== "https://github.com/echoomegaprime/echo-omnipresence-runtime.git"
        || j.params.target.ref !== j.candidate_sha
        || j.params.target.reference !== `https://github.com/echoomegaprime/echo-omnipresence-runtime.git@${j.candidate_sha}`)) reject("operator_candidate_invalid");
    // Detached copy prevents caller mutation while async vault/state IO awaits.
    const encoded = canonical(j);
    if (encoded.length > 32768) reject("operator_admission_invalid");
    return JSON.parse(encoded) as AdmissionJob;
  } catch { return reject("operator_admission_invalid"); }
}

/** Atomic create + fsync; tombstones never removed/recycled automatically.
 * Failed/ambiguous attempts consume both jti and issuer-bound idempotency key.
 */
export async function claimJob(dir: string, issuer: string, j: AdmissionJob): Promise<void> {
  const st = await lstat(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) reject("operator_claim_store_invalid");
  for (const key of [`jti:${j.jti}`, `idempotency:${j.idempotency_key}`]) {
    const filename = createHash("sha256").update(`${issuer}\n${key}`).digest("hex");
    let handle;
    try {
      handle = await open(join(dir, `${filename}.claim`), "wx", 0o600);
      await handle.writeFile(JSON.stringify({ jti: j.jti, request_sha256: digest(j), consumed: true }) + "\n");
      await handle.sync();
    } catch { reject("operator_already_consumed_or_store_unavailable"); }
    finally { await handle?.close(); }
  }
  // POSIX directory fsync makes newly created names durable across power loss.
  if (process.platform !== "win32") {
    const parent = await open(dir, "r");
    try { await parent.sync(); } finally { await parent.close(); }
  }
}

export function totpFromSeed(seed: string, now: number): string {
  // Existing SDK factor is RFC6238 SHA1/6 digits/30s. No factor-returning tool.
  const normalized = seed.trim().replace(/=+$/, "");
  if (!/^[A-Z2-7]{16,128}$/.test(normalized)) reject("operator_factor_invalid");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, accumulator = 0;
  const bytes: number[] = [];
  for (const c of normalized) {
    accumulator = (accumulator << 5) | alphabet.indexOf(c); bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
  }
  if (bits && (accumulator & ((1 << bits) - 1))) reject("operator_factor_invalid");
  const key = Buffer.from(bytes);
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(now / 30000)));
  try {
    const mac = createHmac("sha1", key).update(counter).digest();
    const offset = mac[mac.length - 1] & 15;
    return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
  } finally { key.fill(0); bytes.fill(0); }
}

type Fetcher = typeof fetch;
async function gatePost(payload: JsonObject, key: string, fetcher: Fetcher): Promise<JsonObject> {
  const res = await fetcher(SDK_ENDPOINT, {
    method: "POST", redirect: "error", signal: AbortSignal.timeout(12000),
    headers: { "X-Echo-API-Key": key, "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
  // No upstream exception/body is ever copied to a caller or structured log.
  const reader = res.body?.getReader();
  let length = 0; const chunks: Uint8Array[] = [];
  if (reader) {
    try { for (;;) { const part = await reader.read(); if (part.done) break;
      length += part.value.byteLength; if (length > 262144) reject("operator_response_too_large"); chunks.push(part.value);
    } } finally { await reader.cancel().catch(() => {}); }
  }
  if (!res.ok) return { status: "refused", result: { status_code: res.status } };
  const text = Buffer.concat(chunks).toString("utf8");
  const body: unknown = JSON.parse(text);
  if (!object(body)) reject("operator_response_invalid");
  return body;
}
function successBody(response: JsonObject): JsonObject {
  if (response.status !== "ok" || !object(response.result)
      || typeof response.result.status_code !== "number" || response.result.status_code < 200
      || response.result.status_code >= 300 || !object(response.result.body)
      || response.result.body.ok === false) reject("operator_prerequisite_failed");
  return response.result.body;
}
function rows(value: JsonObject): JsonObject[] {
  let v = value;
  for (let i = 0; i < 5; i++) {
    if (Array.isArray(v.rows)) return v.rows.filter(object);
    const next = object(v.result) ? v.result : object(v.body) ? v.body : null;
    if (!next) break; v = next;
  }
  return [];
}

export function operatorExitCode(result: JsonObject, mode: "review" | "execute"): number {
  if (mode === "review") return result.status === "admission_valid" ? 0 : 2;
  return result.status === "ok" && typeof result.http_status === "number"
    && result.http_status >= 200 && result.http_status < 300 && result.audit_recorded === true ? 0 : 2;
}

export async function executeSdkJob(token: string, cfg: OperatorConfig, deps: {
  backend?: VaultBackend; fetcher?: Fetcher; clock?: () => number;
  audit?: (event: string, fields: JsonObject) => void;
} = {}): Promise<JsonObject> {
  const clock = deps.clock ?? Date.now;
  const start = clock(); let claimed = false, claimAttempted = false;
  const audit = (event: string, fields: JsonObject): boolean => {
    try { (deps.audit ?? log.info)(event, fields); return true; } catch { return false; }
  };
  try {
    const j = await reviewSdkJob(token, cfg, start);
    if (ACTIONS[j.action_id] === null) reject("operator_review_only_action");
    claimAttempted = true;
    await claimJob(cfg.claims_dir, cfg.issuer, j); claimed = true;
    const backend = deps.backend ?? new GateVaultBackend();
    const fetcher = deps.fetcher ?? fetch;
    const reason = "Private admitted exact-request SDK operator route; existing scoped principal and server human approval remain mandatory.";
    const coordinate = cfg.principal.credential;
    const keyResult = await backend.get(coordinate.service, coordinate.username, reason);
    const apiKey = keyResult.secret;
    registerSecretForRedaction(apiKey);
    if (createHash("sha256").update(apiKey).digest("hex") !== j.credential_sha256) reject("operator_credential_binding_failed");
    const probe = await gatePost({ envelope_version: 1, capability: j.expected_state.capability,
      params: j.expected_state.params }, apiKey, fetcher);
    const state = successBody(probe);
    if (j.capability === "echo.psql.execute" && (state.ok !== true || !object(state.cap)
        || state.cap.id !== j.capability || state.cap.scope !== "db.write" || state.cap.tier !== 3)) reject("operator_state_changed");
    if (digest(state) !== j.expected_state.sha256) reject("operator_state_changed");
    let code: string | undefined, hmacSecret: string | undefined, auth: JsonObject | undefined;
    // The fixed certification capability is tier1: do not fetch a signing
    // secret or require unrelated SQL scope for that lower-tier action.
    if (j.capability === "echo.psql.execute") {
      const escaped = apiKey.replace(/'/g, "''");
      const lookup = await gatePost({ envelope_version: 1, capability: "echo.psql.query",
        params: { command: `SELECT secret_hmac FROM arcanum_sdk.sdk_keys WHERE api_key='${escaped}' AND active` },
        context: { bypass_reason: reason } }, apiKey, fetcher);
      successBody(lookup);
      const found = rows(lookup)[0]?.secret_hmac;
      if (typeof found !== "string" || !/^[0-9a-fA-F]{64}$/.test(found)) reject("operator_signer_unavailable");
      hmacSecret = found;
      registerSecretForRedaction(hmacSecret);
      const located = await backend.search("echo-sdk-tier3-totp", reason);
      if (located.status !== "EXACT" || located.get_with?.service !== "echo-sdk-tier3-totp"
          || located.get_with?.username !== "sovereign") reject("operator_factor_unavailable");
      const factor = await backend.get(located.get_with.service, located.get_with.username, reason);
      registerSecretForRedaction(factor.secret);
      code = totpFromSeed(factor.secret, clock());
      const nonce = randomBytes(16).toString("hex"), ts = Math.floor(clock() / 1000);
      auth = { nonce, ts, totp: code, hmac: createHmac("sha256", Buffer.from(hmacSecret, "hex"))
        .update(`v1|${apiKey}|${j.capability}|${canonical(j.params)}|${nonce}|${ts}`).digest("hex") };
    }
    if (clock() / 1000 >= j.exp) reject("operator_admission_expired");
    // Exactly ONE mutation POST. Refusal/timeout/unknown outcome is not retried.
    const response = await gatePost({ envelope_version: 1, capability: j.capability, params: j.params,
      ...(auth ? { auth } : {}), context: { bypass_reason: reason } }, apiKey, fetcher);
    const result = object(response.result) ? response.result : {};
    const status = typeof response.status === "string" && ["ok", "blocked", "error", "client_error", "refused", "approval_required"].includes(response.status)
      ? response.status : "unknown";
    const httpStatus = Number.isInteger(result.status_code) && Number(result.status_code) >= 100 && Number(result.status_code) <= 599
      && !(code && Number(code) === result.status_code)
      ? result.status_code : null;
    // Do not return run IDs or other attacker-controlled strings containing a factor.
    const runId = typeof response.run_id === "string" && UUID.test(response.run_id)
      && ![apiKey, hmacSecret, code].some(s => s && response.run_id!.toString().includes(s)) ? response.run_id : null;
    const recorded = audit("sdk_operator_attempt", { action_id: j.action_id, candidate_sha: j.candidate_sha,
      request_sha256: digest(j.params), claimed, duration_ms: clock() - start, status });
    return { status, http_status: httpStatus, run_id: runId, consumed: true,
      execution_verified: false, upstream_body_withheld: true, audit_recorded: recorded };
  } catch {
    const recorded = audit("sdk_operator_attempt_failed", { claimed, claim_attempted: claimAttempted, duration_ms: clock() - start });
    return { status: "blocked", error: "operator_attempt_failed", consumed: claimed ? true : claimAttempted ? null : false,
      execution_verified: false, upstream_body_withheld: true, audit_recorded: recorded };
  }
}
