// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Owner console core: WebAuthn ceremonies, enrollment bootstrap, sessions,
 * step-up, and the one place an `owner` identity is minted. The HTTP surface
 * (pages, cookies, CSRF) is owner-console-pages.ts; storage is
 * owner-console-store.ts. See docs/ops/owner-console.md.
 *
 * WebAuthn is verified by @simplewebauthn/server 14.x. This module adds what
 * the library leaves to the relying party:
 *   - Origin and RP ID come ONLY from ECHO_VAULT_CONSOLE_ORIGIN (RP ID = its
 *     hostname). The request's Host header is never consulted. Unset or
 *     malformed → the console is disabled.
 *   - User verification is required on every ceremony; attestation "none";
 *     passkeys are registered as discoverable credentials and login sends no
 *     allow-list, so credential ids are not disclosed to anonymous callers.
 *   - Challenges: 32 random bytes, stored as sha256 with a purpose, an expiry
 *     (CHALLENGE_TTL_MS) and — for step-up / add-passkey — the session they
 *     belong to. Verification DELETES the row first (single use), then checks.
 *   - Signature counter: the library refuses a counter that did not advance.
 *     When that is the only thing wrong with an otherwise valid assertion the
 *     passkey is flagged (possible clone) and the attempt is ledgered.
 *   - Failed assertions and bootstrap-code guesses take a slot in the shared
 *     DB rate-limit store before anything is compared; a success clears the
 *     key. Store unreachable → refused.
 *
 * Enrollment: the first passkey needs the bootstrap code minted by the local
 * stdio identity (owner-identity.ts). Further passkeys need an authenticated
 * session with a fresh step-up. There is no email, password or recovery link.
 *
 * Sessions: 256-bit random token, stored as sha256. Idle 15 min, absolute 8 h.
 * Step-up = a WebAuthn assertion completed for THIS session in the last 5
 * minutes (the login assertion counts). `runOwnerTool` enforces it for
 * destructive tools and then calls the gateway's dispatchTool with the minted
 * owner identity, so policy, redaction and the ledger apply as for any caller.
 *
 * Nothing here handles a vault secret. Ledger rows carry capability names and
 * short codes only — never a token, challenge, code or credential public key.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { log } from "../log.ts";
import { sanitizeDisplayText } from "./approvals.ts";
import type { ClientIdentity, LedgerEntryInput } from "./contracts.ts";
import { dispatchTool, type GatewayDeps, type GatewayResult } from "./gateway.ts";
import { appendLedger } from "./ledger.ts";
import {
  cleanTransports,
  getDefaultOwnerConsoleStore,
  sha256Hex,
  type ChallengePurpose,
  type OwnerConsoleStore,
  type PasskeyRecord,
  type SessionRecord,
} from "./owner-console-store.ts";
import { bootstrapCodeHash, BOOTSTRAP_CODE_PATTERN, mintOwnerIdentity, ownerClientId } from "./owner-identity.ts";
import {
  getDefaultRateLimitStore,
  rateLimitKey,
  withRateLimitStore,
  type RateLimitStore,
} from "./rate-limit-store.ts";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export const CONSOLE_ORIGIN_ENV = "ECHO_VAULT_CONSOLE_ORIGIN";
export const CONSOLE_ALLOW_LOCALHOST_ENV = "ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST";

export const CHALLENGE_TTL_MS = 3 * 60 * 1000;
export const SESSION_IDLE_MS = 15 * 60 * 1000;
export const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
export const STEP_UP_MS = 5 * 60 * 1000;
export const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
/** Failed assertions per credential (or for all unknown credentials together) per window. */
export const MAX_FAILED_ASSERTIONS = 5;
/** Wrong bootstrap codes per window (one global key: there is one owner and one code). */
export const MAX_FAILED_BOOTSTRAP = 5;
/** Anonymous login challenges issued per minute. */
export const MAX_LOGIN_CHALLENGES_PER_MINUTE = 30;
export const MAX_PASSKEYS = 10;

const RP_NAME = "ECHO Vault";
const OWNER_USER_ID = new TextEncoder().encode("echo-vault-owner");
const SESSION_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{16,1366}$/;

export type ConsoleConfig =
  | { ok: true; origin: string; rpId: string }
  | { ok: false; reason: "unset" | "invalid" | "localhost_not_allowed" };

/**
 * The console's origin and RP ID, from the environment only.
 *   https://<host>[:port]            always acceptable (host must be a DNS name)
 *   http://localhost[:port]          only with ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST=1
 * Anything else — a path, query, credentials, an IP address, plain http on a
 * real host — is `invalid`, and the console refuses to operate.
 */
export function consoleConfig(env: NodeJS.ProcessEnv = process.env): ConsoleConfig {
  const raw = env[CONSOLE_ORIGIN_ENV]?.trim();
  if (!raw) return { ok: false, reason: "unset" };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "invalid" };
  }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    return { ok: false, reason: "invalid" };
  }
  if (raw.replace(/\/$/, "") !== url.origin) return { ok: false, reason: "invalid" };
  const host = url.hostname;
  if (url.protocol === "http:") {
    if (host !== "localhost") return { ok: false, reason: "invalid" };
    if (env[CONSOLE_ALLOW_LOCALHOST_ENV]?.trim() !== "1") return { ok: false, reason: "localhost_not_allowed" };
    return { ok: true, origin: url.origin, rpId: host };
  }
  if (url.protocol !== "https:") return { ok: false, reason: "invalid" };
  // An RP ID must be a registrable domain name: no IP literals.
  if (/^[0-9.]+$/.test(host) || host.includes(":") || host.startsWith("[")) return { ok: false, reason: "invalid" };
  if (!/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(host)) {
    return { ok: false, reason: "invalid" };
  }
  return { ok: true, origin: url.origin, rpId: host };
}

export interface ConsoleDeps {
  env?: NodeJS.ProcessEnv;
  now?: () => number;
  store?: OwnerConsoleStore;
  rateLimits?: RateLimitStore;
  /** dispatchTool wiring; its `ledger` is also the sink for vault.console.* rows. */
  gateway?: GatewayDeps;
}

interface Ctx {
  cfg: Extract<ConsoleConfig, { ok: true }>;
  store: OwnerConsoleStore;
  limits: RateLimitStore;
  now: number;
  ledger: (input: LedgerEntryInput) => Promise<unknown>;
  deps: ConsoleDeps;
}

export class ConsoleError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "ConsoleError";
    this.code = code;
  }
}

function ctx(deps: ConsoleDeps): Ctx {
  const cfg = consoleConfig(deps.env ?? process.env);
  if (!cfg.ok) throw new ConsoleError("console_disabled");
  return {
    cfg,
    store: deps.store ?? getDefaultOwnerConsoleStore(),
    limits: deps.rateLimits ?? getDefaultRateLimitStore(),
    now: (deps.now ?? deps.gateway?.now ?? Date.now)(),
    ledger: deps.gateway?.ledger ?? appendLedger,
    deps,
  };
}

// ---------------------------------------------------------------------------
// Ledger (vault.console.*)
// ---------------------------------------------------------------------------

const ANONYMOUS = "console:anonymous";

interface AuditRow {
  client_id: string;
  /** Suffix after "vault.console.". */
  event: string;
  resource?: string;
  /** Omitted = success. A short fixed code, never request content. */
  error?: string;
}

/** `mustSucceed`: a state change that cannot be recorded is refused (ledger_unavailable). */
async function audit(c: Ctx, row: AuditRow, mustSucceed: boolean): Promise<void> {
  try {
    await c.ledger({
      client_id: row.client_id,
      capability: `vault.console.${row.event}`,
      resource: row.resource ?? "vault:console",
      decision: row.error ? "deny" : "allow",
      tier: 3,
      result: row.error ? "denied" : "ok",
      ...(row.error ? { error: row.error } : {}),
    });
  } catch {
    log.error("vault_console_ledger_failed", { event: row.event, client_id: row.client_id });
    if (mustSucceed) throw new ConsoleError("ledger_unavailable");
  }
}

// ---------------------------------------------------------------------------
// Rate limiting (shared DB store; fail closed)
// ---------------------------------------------------------------------------

/** Take one attempt slot. False = over the limit. Throws RateLimitUnavailableError when the store is down. */
async function takeAttempt(c: Ctx, key: string, limit: number, windowMs: number = ATTEMPT_WINDOW_MS): Promise<boolean> {
  const hit = await withRateLimitStore(c.limits, "hit", (s) => s.hit(key, windowMs, c.now, limit));
  return hit.recorded;
}

async function clearAttempts(c: Ctx, key: string): Promise<void> {
  try {
    await withRateLimitStore(c.limits, "reset", (s) => s.reset(key));
  } catch {
    // The attempt already succeeded; a stale failure count only errs stricter.
  }
}

const bootstrapKey = (): string => rateLimitKey("console.bootstrap", "global");
const assertionKey = (credentialId: string | null): string => rateLimitKey("console.assert", credentialId ?? "unknown");

// ---------------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------------

const challengeHash = (challenge: string): string => sha256Hex(`echo-vault-console-challenge-v1:${challenge}`);

async function storeChallenge(c: Ctx, challenge: string, purpose: ChallengePurpose, sessionId: string | null): Promise<void> {
  await c.store.pruneChallenges(c.now).catch(() => undefined);
  await c.store.putChallenge({
    challenge_hash: challengeHash(challenge),
    purpose,
    session_id: sessionId,
    created_at: c.now,
    expires_at: c.now + CHALLENGE_TTL_MS,
  });
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The `challenge` field of a response's clientDataJSON, or null. Parsed only to find our stored row; the library re-verifies it. */
function responseChallenge(response: unknown): string | null {
  if (!isRecord(response) || !isRecord(response.response)) return null;
  const cdj = response.response.clientDataJSON;
  if (typeof cdj !== "string" || cdj.length > 8192) return null;
  try {
    const parsed = JSON.parse(Buffer.from(cdj, "base64url").toString("utf8")) as unknown;
    const challenge = isRecord(parsed) ? parsed.challenge : undefined;
    return typeof challenge === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(challenge) ? challenge : null;
  } catch {
    return null;
  }
}

type ChallengeFailure = "challenge_invalid" | "challenge_expired";

/** Single use: the row is deleted before it is judged, so a replay (or a second parallel use) finds nothing. */
async function useChallenge(
  c: Ctx,
  response: unknown,
  purpose: ChallengePurpose,
  sessionId: string | null,
): Promise<{ ok: true; challenge: string } | { ok: false; code: ChallengeFailure }> {
  const challenge = responseChallenge(response);
  if (!challenge) return { ok: false, code: "challenge_invalid" };
  const row = await c.store.takeChallenge(challengeHash(challenge));
  if (!row || row.purpose !== purpose || row.session_id !== sessionId) return { ok: false, code: "challenge_invalid" };
  if (row.expires_at <= c.now) return { ok: false, code: "challenge_expired" };
  return { ok: true, challenge };
}

// ---------------------------------------------------------------------------
// Registration (enroll with bootstrap code / add from a session)
// ---------------------------------------------------------------------------

export interface PasskeyView {
  /** `owner:<12 hex>` — what the ledger shows for this passkey. */
  owner_id: string;
  credential_id: string;
  label: string;
  transports: string[];
  created_at: string;
  last_used_at: string | null;
  flagged_at: string | null;
  flag_reason: string | null;
}

const iso = (ms: number | null): string | null => (ms === null ? null : new Date(ms).toISOString());

function passkeyView(p: PasskeyRecord): PasskeyView {
  return {
    owner_id: ownerClientId(p.credential_id),
    credential_id: p.credential_id,
    label: p.label,
    transports: [...p.transports],
    created_at: new Date(p.created_at).toISOString(),
    last_used_at: iso(p.last_used_at),
    flagged_at: iso(p.flagged_at),
    flag_reason: p.flag_reason,
  };
}

async function registrationOptions(c: Ctx, purpose: "enroll" | "add_passkey", sessionId: string | null): Promise<unknown> {
  const existing = await c.store.listPasskeys();
  if (existing.length >= MAX_PASSKEYS) throw new ConsoleError("too_many_passkeys");
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: c.cfg.rpId,
    userName: "owner",
    userDisplayName: "ECHO Vault owner",
    userID: OWNER_USER_ID,
    challenge: new Uint8Array(randomBytes(32)),
    timeout: CHALLENGE_TTL_MS,
    attestationType: "none",
    excludeCredentials: existing.map((p) => ({ id: p.credential_id, transports: p.transports })),
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  });
  await storeChallenge(c, options.challenge, purpose, sessionId);
  return options;
}

function cleanLabel(label: unknown, now: number): string {
  const text = sanitizeDisplayText(typeof label === "string" ? label : "", 64);
  return text || `Passkey ${new Date(now).toISOString().slice(0, 10)}`;
}

type Verified = { ok: true; passkey: PasskeyRecord } | { ok: false; code: string };

async function verifyRegistration(
  c: Ctx,
  response: unknown,
  purpose: "enroll" | "add_passkey",
  sessionId: string | null,
  label: unknown,
): Promise<Verified> {
  const used = await useChallenge(c, response, purpose, sessionId);
  if (!used.ok) return used;
  let info;
  try {
    const verification = await verifyRegistrationResponse({
      response: response as Parameters<typeof verifyRegistrationResponse>[0]["response"],
      expectedChallenge: used.challenge,
      expectedOrigin: c.cfg.origin,
      expectedRPID: c.cfg.rpId,
      requireUserPresence: true,
      requireUserVerification: true,
    });
    if (!verification.verified) return { ok: false, code: "registration_invalid" };
    info = verification.registrationInfo;
  } catch {
    // The library's message can quote request fields; only a fixed code leaves here.
    return { ok: false, code: "registration_invalid" };
  }
  if (!info.userVerified || !CREDENTIAL_ID.test(info.credential.id)) return { ok: false, code: "registration_invalid" };
  return {
    ok: true,
    passkey: {
      credential_id: info.credential.id,
      public_key: Buffer.from(info.credential.publicKey).toString("base64url"),
      counter: info.credential.counter,
      transports: cleanTransports(info.credential.transports),
      label: cleanLabel(label, c.now),
      created_at: c.now,
      last_used_at: null,
      flagged_at: null,
      flag_reason: null,
    },
  };
}

export type ConsoleResult<T> = ({ ok: true } & T) | { ok: false; error: string };

/** Check a bootstrap code under the guess limiter. Never consumes it. */
async function checkBootstrap(c: Ctx, code: unknown): Promise<"ok" | "rate_limited" | "bootstrap_code_invalid"> {
  if (!(await takeAttempt(c, bootstrapKey(), MAX_FAILED_BOOTSTRAP))) return "rate_limited";
  const wellFormed = typeof code === "string" && BOOTSTRAP_CODE_PATTERN.test(code);
  if (!wellFormed || !(await c.store.checkBootstrapCode(bootstrapCodeHash(code), c.now))) return "bootstrap_code_invalid";
  await clearAttempts(c, bootstrapKey());
  return "ok";
}

/** Step 1 of enrollment: a valid bootstrap code buys a registration challenge. */
export async function beginEnroll(code: unknown, deps: ConsoleDeps = {}): Promise<ConsoleResult<{ options: unknown }>> {
  const c = ctx(deps);
  const checked = await checkBootstrap(c, code);
  if (checked !== "ok") {
    await audit(c, { client_id: ANONYMOUS, event: "enroll", error: checked }, false);
    return { ok: false, error: checked };
  }
  try {
    return { ok: true, options: await registrationOptions(c, "enroll", null) };
  } catch (err) {
    if (err instanceof ConsoleError) return { ok: false, error: err.code };
    throw err;
  }
}

/** Step 2: verify the registration, then consume the code (single use), then store the passkey. */
export async function finishEnroll(
  code: unknown,
  response: unknown,
  label: unknown,
  deps: ConsoleDeps = {},
): Promise<ConsoleResult<{ passkey: PasskeyView }>> {
  const c = ctx(deps);
  const fail = async (error: string): Promise<{ ok: false; error: string }> => {
    await audit(c, { client_id: ANONYMOUS, event: "enroll", error }, false);
    return { ok: false, error };
  };
  const checked = await checkBootstrap(c, code);
  if (checked !== "ok") return fail(checked);
  const verified = await verifyRegistration(c, response, "enroll", null, label);
  if (!verified.ok) return fail(verified.code);
  // Atomic: of two parallel enrollments with the same code, one gets here.
  if (!(await c.store.consumeBootstrapCode(bootstrapCodeHash(code as string), c.now))) return fail("bootstrap_code_invalid");
  const owner = ownerClientId(verified.passkey.credential_id);
  // Recorded before the passkey exists: an enrollment that cannot be audited does not happen.
  await audit(c, { client_id: owner, event: "enroll", resource: "vault:console/passkey" }, true);
  if (!(await c.store.insertPasskey(verified.passkey))) return fail("passkey_exists");
  log.warn("vault_console_passkey_enrolled", { owner_id: owner, via: "bootstrap" });
  return { ok: true, passkey: passkeyView(verified.passkey) };
}

// ---------------------------------------------------------------------------
// Assertions (login / step-up)
// ---------------------------------------------------------------------------

async function assertionOptions(c: Ctx, purpose: "login" | "stepup", sessionId: string | null): Promise<unknown> {
  const options = await generateAuthenticationOptions({
    rpID: c.cfg.rpId,
    challenge: new Uint8Array(randomBytes(32)),
    timeout: CHALLENGE_TTL_MS,
    userVerification: "required",
    // No allowCredentials: discoverable credentials only, nothing disclosed.
  });
  await storeChallenge(c, options.challenge, purpose, sessionId);
  return options;
}

/** Signature counter (bytes 33..36 of authenticatorData), or null when unreadable. */
function responseCounter(response: unknown): number | null {
  if (!isRecord(response) || !isRecord(response.response)) return null;
  const raw = response.response.authenticatorData;
  if (typeof raw !== "string" || raw.length > 4096) return null;
  const data = Buffer.from(raw, "base64url");
  return data.length >= 37 ? data.readUInt32BE(33) : null;
}

type AssertionResult =
  | { ok: true; passkey: PasskeyRecord }
  | { ok: false; code: string; credentialId: string | null };

async function verifyAssertion(
  c: Ctx,
  response: unknown,
  purpose: "login" | "stepup",
  sessionId: string | null,
): Promise<AssertionResult> {
  const id = isRecord(response) && typeof response.id === "string" && CREDENTIAL_ID.test(response.id) ? response.id : null;
  const passkey = id ? await c.store.getPasskey(id) : null;
  const known = passkey ? passkey.credential_id : null;
  const key = assertionKey(known);
  // The slot is taken BEFORE anything is verified; only a success gives it back.
  if (!(await takeAttempt(c, key, MAX_FAILED_ASSERTIONS))) return { ok: false, code: "rate_limited", credentialId: known };
  const used = await useChallenge(c, response, purpose, sessionId);
  if (!passkey) return { ok: false, code: "unknown_credential", credentialId: null };
  if (!used.ok) return { ok: false, code: used.code, credentialId: known };

  const check = async (counter: number): Promise<number | null> => {
    try {
      const verification = await verifyAuthenticationResponse({
        response: response as Parameters<typeof verifyAuthenticationResponse>[0]["response"],
        expectedChallenge: used.challenge,
        expectedOrigin: c.cfg.origin,
        expectedRPID: c.cfg.rpId,
        requireUserVerification: true,
        credential: {
          id: passkey.credential_id,
          publicKey: new Uint8Array(Buffer.from(passkey.public_key, "base64url")),
          counter,
          transports: passkey.transports as never,
        },
      });
      return verification.verified && verification.authenticationInfo.userVerified ? verification.authenticationInfo.newCounter : null;
    } catch {
      return null;
    }
  };

  const newCounter = await check(passkey.counter);
  if (newCounter === null) {
    // Was the non-advancing counter the ONLY problem? Re-check the same response
    // as if no counter were stored: if it verifies, the signature is genuine and
    // the authenticator (or a copy of it) is behind the stored counter.
    const seen = responseCounter(response);
    const regressed = seen !== null && (seen > 0 || passkey.counter > 0) && seen <= passkey.counter;
    if (regressed && (await check(0)) !== null) {
      await c.store.flagPasskey(passkey.credential_id, "counter_regression", c.now);
      log.warn("vault_console_counter_regression", { owner_id: ownerClientId(passkey.credential_id) });
      return { ok: false, code: "counter_regression", credentialId: known };
    }
    return { ok: false, code: "assertion_invalid", credentialId: known };
  }
  await c.store.updatePasskeyUse(passkey.credential_id, newCounter, c.now);
  await clearAttempts(c, key);
  return { ok: true, passkey: { ...passkey, counter: newCounter, last_used_at: c.now } };
}

export async function beginLogin(deps: ConsoleDeps = {}): Promise<ConsoleResult<{ options: unknown }>> {
  const c = ctx(deps);
  if (!(await takeAttempt(c, rateLimitKey("console.challenge", "login"), MAX_LOGIN_CHALLENGES_PER_MINUTE, 60_000))) {
    return { ok: false, error: "rate_limited" };
  }
  return { ok: true, options: await assertionOptions(c, "login", null) };
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

const sessionTokenHash = (token: string): string => sha256Hex(`echo-vault-console-session-v1:${token}`);

/** Per-session CSRF token: an HMAC keyed by the session token. Only a party that can read the HttpOnly cookie could compute it. */
export function csrfTokenFor(sessionToken: string): string {
  return createHmac("sha256", sessionToken).update("echo-vault-console-csrf-v1").digest("base64url");
}

export function csrfTokenMatches(sessionToken: string, provided: unknown): boolean {
  if (typeof provided !== "string" || provided.length === 0 || provided.length > 128) return false;
  const expected = Buffer.from(csrfTokenFor(sessionToken));
  const got = Buffer.from(provided);
  return got.length === expected.length && timingSafeEqual(got, expected);
}

export interface SessionView {
  id: string;
  owner_id: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  step_up_at: string | null;
  user_agent: string;
  current: boolean;
}

/** An authenticated console session. `identity` is the minted owner identity for dispatchTool. */
export interface ConsoleSession {
  session: SessionRecord;
  identity: ClientIdentity;
  csrf: string;
  /** Milliseconds of step-up freshness left (0 = a new assertion is needed). */
  stepUpRemainingMs: number;
}

function stepUpRemaining(session: SessionRecord, now: number): number {
  if (session.step_up_at === null || session.step_up_at > now) return 0;
  return Math.max(0, session.step_up_at + STEP_UP_MS - now);
}

/** Complete a login assertion and open a session. The raw token is returned once, for the cookie. */
export async function finishLogin(
  response: unknown,
  meta: { userAgent?: string | null },
  deps: ConsoleDeps = {},
): Promise<ConsoleResult<{ token: string; owner_id: string }>> {
  const c = ctx(deps);
  const result = await verifyAssertion(c, response, "login", null);
  if (!result.ok) {
    const who = result.credentialId ? ownerClientId(result.credentialId) : ANONYMOUS;
    // Limiter refusals are logged, not ledgered: a flood must not grow the chain.
    if (result.code === "rate_limited") log.warn("vault_console_login_rate_limited", { client_id: who });
    else await audit(c, { client_id: who, event: "login", error: result.code }, false);
    return { ok: false, error: result.code };
  }
  const owner = ownerClientId(result.passkey.credential_id);
  const token = randomBytes(32).toString("base64url");
  await c.store.pruneSessions(c.now, SESSION_IDLE_MS).catch(() => undefined);
  await audit(c, { client_id: owner, event: "login" }, true);
  await c.store.insertSession({
    id: randomBytes(16).toString("hex"),
    token_hash: sessionTokenHash(token),
    credential_id: result.passkey.credential_id,
    created_at: c.now,
    last_seen_at: c.now,
    absolute_expires_at: c.now + SESSION_ABSOLUTE_MS,
    // The login assertion is a WebAuthn assertion completed for this session.
    step_up_at: c.now,
    revoked_at: null,
    user_agent: sanitizeDisplayText(meta.userAgent ?? "", 200),
  });
  return { ok: true, token, owner_id: owner };
}

/**
 * The ONLY place an owner identity is minted: a presented token whose hash
 * matches a live session row (unrevoked, inside the idle and absolute limits).
 */
export async function authenticateSession(token: unknown, deps: ConsoleDeps = {}): Promise<ConsoleSession | null> {
  if (typeof token !== "string" || !SESSION_TOKEN.test(token)) return null;
  const c = ctx(deps);
  const session = await c.store.touchSession(sessionTokenHash(token), c.now, SESSION_IDLE_MS);
  if (!session) return null;
  return {
    session,
    identity: mintOwnerIdentity(session.credential_id),
    csrf: csrfTokenFor(token),
    stepUpRemainingMs: stepUpRemaining(session, c.now),
  };
}

export async function logout(s: ConsoleSession, deps: ConsoleDeps = {}): Promise<void> {
  const c = ctx(deps);
  await c.store.revokeSession(s.session.id, c.now);
  await audit(c, { client_id: s.identity.client_id, event: "logout" }, false);
}

export async function listSessions(s: ConsoleSession, deps: ConsoleDeps = {}): Promise<SessionView[]> {
  const c = ctx(deps);
  return (await c.store.listSessions(c.now, SESSION_IDLE_MS)).map((r) => ({
    id: r.id,
    owner_id: ownerClientId(r.credential_id),
    created_at: new Date(r.created_at).toISOString(),
    last_seen_at: new Date(r.last_seen_at).toISOString(),
    expires_at: new Date(Math.min(r.absolute_expires_at, r.last_seen_at + SESSION_IDLE_MS)).toISOString(),
    step_up_at: iso(r.step_up_at),
    user_agent: r.user_agent,
    current: r.id === s.session.id,
  }));
}

export async function revokeSession(s: ConsoleSession, sessionId: unknown, deps: ConsoleDeps = {}): Promise<ConsoleResult<object>> {
  const c = ctx(deps);
  if (typeof sessionId !== "string" || !/^[0-9a-f]{32}$/.test(sessionId)) return { ok: false, error: "session_not_found" };
  const revoked = await c.store.revokeSession(sessionId, c.now);
  await audit(
    c,
    { client_id: s.identity.client_id, event: "session.revoke", resource: `vault:console/session/${sessionId.slice(0, 8)}`, ...(revoked ? {} : { error: "session_not_found" }) },
    false,
  );
  return revoked ? { ok: true } : { ok: false, error: "session_not_found" };
}

// ---------------------------------------------------------------------------
// Step-up
// ---------------------------------------------------------------------------

export async function beginStepUp(s: ConsoleSession, deps: ConsoleDeps = {}): Promise<ConsoleResult<{ options: unknown }>> {
  const c = ctx(deps);
  return { ok: true, options: await assertionOptions(c, "stepup", s.session.id) };
}

/** Any enrolled passkey may confirm; the challenge is bound to this session. */
export async function finishStepUp(s: ConsoleSession, response: unknown, deps: ConsoleDeps = {}): Promise<ConsoleResult<object>> {
  const c = ctx(deps);
  const result = await verifyAssertion(c, response, "stepup", s.session.id);
  if (!result.ok) {
    if (result.code === "rate_limited") log.warn("vault_console_stepup_rate_limited", { client_id: s.identity.client_id });
    else await audit(c, { client_id: s.identity.client_id, event: "stepup", error: result.code }, false);
    return { ok: false, error: result.code };
  }
  await audit(c, { client_id: s.identity.client_id, event: "stepup" }, true);
  await c.store.markStepUp(s.session.id, c.now);
  return { ok: true };
}

async function requireStepUp(c: Ctx, s: ConsoleSession, event: string, resource: string): Promise<boolean> {
  // Re-read from the row state carried by this request's touchSession.
  if (stepUpRemaining(s.session, c.now) > 0) return true;
  await audit(c, { client_id: s.identity.client_id, event, resource, error: "step_up_required" }, false);
  return false;
}

// ---------------------------------------------------------------------------
// Passkey management (session + step-up)
// ---------------------------------------------------------------------------

export async function listPasskeys(deps: ConsoleDeps = {}): Promise<PasskeyView[]> {
  const c = ctx(deps);
  return (await c.store.listPasskeys()).map(passkeyView);
}

/** Ledger row for a console page that reads only console state (the security page). */
export async function recordView(s: ConsoleSession, view: string, deps: ConsoleDeps = {}): Promise<void> {
  await audit(ctx(deps), { client_id: s.identity.client_id, event: `${view}.view` }, false);
}

export async function beginAddPasskey(s: ConsoleSession, deps: ConsoleDeps = {}): Promise<ConsoleResult<{ options: unknown }>> {
  const c = ctx(deps);
  if (!(await requireStepUp(c, s, "passkey.add", "vault:console/passkey"))) return { ok: false, error: "step_up_required" };
  try {
    return { ok: true, options: await registrationOptions(c, "add_passkey", s.session.id) };
  } catch (err) {
    if (err instanceof ConsoleError) return { ok: false, error: err.code };
    throw err;
  }
}

export async function finishAddPasskey(
  s: ConsoleSession,
  response: unknown,
  label: unknown,
  deps: ConsoleDeps = {},
): Promise<ConsoleResult<{ passkey: PasskeyView }>> {
  const c = ctx(deps);
  if (!(await requireStepUp(c, s, "passkey.add", "vault:console/passkey"))) return { ok: false, error: "step_up_required" };
  const fail = async (error: string): Promise<{ ok: false; error: string }> => {
    await audit(c, { client_id: s.identity.client_id, event: "passkey.add", resource: "vault:console/passkey", error }, false);
    return { ok: false, error };
  };
  const verified = await verifyRegistration(c, response, "add_passkey", s.session.id, label);
  if (!verified.ok) return fail(verified.code);
  const added = ownerClientId(verified.passkey.credential_id);
  await audit(c, { client_id: s.identity.client_id, event: "passkey.add", resource: `vault:console/passkey/${added.slice(6)}` }, true);
  if (!(await c.store.insertPasskey(verified.passkey))) return fail("passkey_exists");
  log.warn("vault_console_passkey_enrolled", { owner_id: added, via: "session" });
  return { ok: true, passkey: passkeyView(verified.passkey) };
}

/** Removing a passkey also ends every session opened with it. The last passkey cannot be removed. */
export async function removePasskey(s: ConsoleSession, credentialId: unknown, deps: ConsoleDeps = {}): Promise<ConsoleResult<object>> {
  const c = ctx(deps);
  const known = typeof credentialId === "string" && CREDENTIAL_ID.test(credentialId) ? credentialId : null;
  const resource = `vault:console/passkey/${known ? ownerClientId(known).slice(6) : "?"}`;
  if (!(await requireStepUp(c, s, "passkey.remove", resource))) return { ok: false, error: "step_up_required" };
  const fail = async (error: string): Promise<{ ok: false; error: string }> => {
    await audit(c, { client_id: s.identity.client_id, event: "passkey.remove", resource, error }, false);
    return { ok: false, error };
  };
  if (!known) return fail("passkey_not_found");
  if (!(await c.store.getPasskey(known))) return fail("passkey_not_found");
  if ((await c.store.listPasskeys()).length <= 1) return fail("last_passkey");
  await audit(c, { client_id: s.identity.client_id, event: "passkey.remove", resource }, true);
  const outcome = await c.store.deletePasskeyUnlessLast(known);
  if (outcome === "last") return fail("last_passkey");
  if (outcome === "not_found") return fail("passkey_not_found");
  log.warn("vault_console_passkey_removed", { owner_id: ownerClientId(known) });
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Tools through the gateway
// ---------------------------------------------------------------------------

/** Everything the console may call. `admin_console_bootstrap` is deliberately absent (local stdio only). */
export const CONSOLE_TOOLS: ReadonlySet<string> = new Set([
  "audit_list",
  "audit_verify",
  "admin_anchor_now",
  "admin_verify_anchor",
  "admin_list_clients",
  "admin_set_client_scopes",
  "admin_revoke_client",
  "admin_list_grants",
  "admin_revoke_grant",
  "admin_list_entries",
  "admin_set_rotation",
  "admin_rotate_entry",
  "admin_rotation_due",
  "admin_purge_entry",
  "admin_delete_entry",
  "admin_request_reentry",
  "admin_digest_now",
]);

/** Destructive calls: a WebAuthn assertion for this session in the last STEP_UP_MS is required. */
export function toolNeedsStepUp(tool: string, args: Record<string, unknown>): boolean {
  switch (tool) {
    case "admin_purge_entry":
    case "admin_delete_entry":
    case "admin_revoke_client":
    case "admin_set_client_scopes":
    case "admin_rotate_entry":
      return true;
    case "admin_set_rotation":
      // Only an explicit "manual" is exempt; a malformed mode is treated as destructive.
      return args.mode !== "manual";
    case "admin_revoke_grant":
      // No host = every grant of the (client, entry) pair.
      return typeof args.host !== "string" || args.host === "";
    default:
      return false;
  }
}

/**
 * Run one tool as the owner. Same dispatchTool as every other caller, so the
 * policy engine, result redaction and the ledger apply; the gateway writes
 * the ledger row. A destructive tool without a fresh step-up is refused here
 * (and that refusal is ledgered) before the gateway is reached.
 */
export async function runOwnerTool(
  s: ConsoleSession,
  tool: string,
  args: Record<string, unknown>,
  deps: ConsoleDeps = {},
): Promise<GatewayResult> {
  const c = ctx(deps);
  if (!CONSOLE_TOOLS.has(tool)) {
    await audit(c, { client_id: s.identity.client_id, event: "tool.refused", resource: `tool:${sanitizeDisplayText(tool, 64) || "?"}`, error: "tool_not_available" }, false);
    return { ok: false, error: "tool_not_available" };
  }
  if (toolNeedsStepUp(tool, args) && !(await requireStepUp(c, s, "stepup.required", `tool:${tool}`))) {
    return { ok: false, error: "step_up_required" };
  }
  return dispatchTool(s.identity, tool, args, deps.gateway ?? {});
}
