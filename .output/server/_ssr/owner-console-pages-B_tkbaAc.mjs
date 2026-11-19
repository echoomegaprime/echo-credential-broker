import { o as log } from "./log-BHJOU13W.mjs";
import { a as rateLimitKey, i as getDefaultRateLimitStore, o as withRateLimitStore, r as RateLimitUnavailableError } from "./rate-limit-store-D2QvwAS2.mjs";
import { h as sanitizeDisplayText } from "./approvals-vHr7W1Jg.mjs";
import { r as SUPPORTED_SCOPES } from "./oauth-server-BJCUNFGm.mjs";
import { t as appendLedger } from "./ledger-DtKvLmuw.mjs";
import { escapeHtml, readLimited } from "./card-pages-DKhV17Ik.mjs";
import { a as bootstrapCodeHash, c as cleanTransports, i as BOOTSTRAP_CODE_PATTERN, l as getDefaultOwnerConsoleStore, o as mintOwnerIdentity, s as ownerClientId, t as dispatchTool, u as sha256Hex } from "./gateway-iAPpU1jx.mjs";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
//#region node_modules/.nitro/vite/services/ssr/assets/owner-console-pages-B_tkbaAc.js
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
var webauthnLib;
/**
* @simplewebauthn/server pulls in tsyringe (via @peculiar/x509), which throws at module
* load unless the Reflect metadata polyfill is already installed. A bare
* `import "reflect-metadata"` is dropped by the production bundler, so every /console
* request failed in a built server while unbundled Node (the tests) worked. Loading both
* here, in order, at first use is the one form the bundler keeps.
*/
function webauthn() {
	return webauthnLib ??= import("reflect-metadata").then(() => import("@simplewebauthn/server"));
}
var CONSOLE_ORIGIN_ENV = "ECHO_VAULT_CONSOLE_ORIGIN";
var CHALLENGE_TTL_MS = 18e4;
var SESSION_IDLE_MS = 9e5;
var SESSION_ABSOLUTE_MS = 288e5;
var STEP_UP_MS = 3e5;
var ATTEMPT_WINDOW_MS = 9e5;
var RP_NAME = "ECHO Vault";
var OWNER_USER_ID = new TextEncoder().encode("echo-vault-owner");
var SESSION_TOKEN = /^[A-Za-z0-9_-]{43}$/;
var CREDENTIAL_ID = /^[A-Za-z0-9_-]{16,1366}$/;
/**
* The console's origin and RP ID, from the environment only.
*   https://<host>[:port]            always acceptable (host must be a DNS name)
*   http://localhost[:port]          only with ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST=1
* Anything else — a path, query, credentials, an IP address, plain http on a
* real host — is `invalid`, and the console refuses to operate.
*/
function consoleConfig(env = process.env) {
	const raw = env[CONSOLE_ORIGIN_ENV]?.trim();
	if (!raw) return {
		ok: false,
		reason: "unset"
	};
	let url;
	try {
		url = new URL(raw);
	} catch {
		return {
			ok: false,
			reason: "invalid"
		};
	}
	if (url.username || url.password || url.search || url.hash || url.pathname !== "/" && url.pathname !== "") return {
		ok: false,
		reason: "invalid"
	};
	if (raw.replace(/\/$/, "") !== url.origin) return {
		ok: false,
		reason: "invalid"
	};
	const host = url.hostname;
	if (url.protocol === "http:") {
		if (host !== "localhost") return {
			ok: false,
			reason: "invalid"
		};
		if (env["ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST"]?.trim() !== "1") return {
			ok: false,
			reason: "localhost_not_allowed"
		};
		return {
			ok: true,
			origin: url.origin,
			rpId: host
		};
	}
	if (url.protocol !== "https:") return {
		ok: false,
		reason: "invalid"
	};
	if (/^[0-9.]+$/.test(host) || host.includes(":") || host.startsWith("[")) return {
		ok: false,
		reason: "invalid"
	};
	if (!/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(host)) return {
		ok: false,
		reason: "invalid"
	};
	return {
		ok: true,
		origin: url.origin,
		rpId: host
	};
}
var ConsoleError = class extends Error {
	code;
	constructor(code) {
		super(code);
		this.name = "ConsoleError";
		this.code = code;
	}
};
function ctx(deps) {
	const cfg = consoleConfig(deps.env ?? process.env);
	if (!cfg.ok) throw new ConsoleError("console_disabled");
	return {
		cfg,
		store: deps.store ?? getDefaultOwnerConsoleStore(),
		limits: deps.rateLimits ?? getDefaultRateLimitStore(),
		now: (deps.now ?? deps.gateway?.now ?? Date.now)(),
		ledger: deps.gateway?.ledger ?? appendLedger,
		deps
	};
}
var ANONYMOUS = "console:anonymous";
/** `mustSucceed`: a state change that cannot be recorded is refused (ledger_unavailable). */
async function audit(c, row, mustSucceed) {
	try {
		await c.ledger({
			client_id: row.client_id,
			capability: `vault.console.${row.event}`,
			resource: row.resource ?? "vault:console",
			decision: row.error ? "deny" : "allow",
			tier: 3,
			result: row.error ? "denied" : "ok",
			...row.error ? { error: row.error } : {}
		});
	} catch {
		log.error("vault_console_ledger_failed", {
			event: row.event,
			client_id: row.client_id
		});
		if (mustSucceed) throw new ConsoleError("ledger_unavailable");
	}
}
/** Take one attempt slot. False = over the limit. Throws RateLimitUnavailableError when the store is down. */
async function takeAttempt(c, key, limit, windowMs = ATTEMPT_WINDOW_MS) {
	return (await withRateLimitStore(c.limits, "hit", (s) => s.hit(key, windowMs, c.now, limit))).recorded;
}
async function clearAttempts(c, key) {
	try {
		await withRateLimitStore(c.limits, "reset", (s) => s.reset(key));
	} catch {}
}
var bootstrapKey = () => rateLimitKey("console.bootstrap", "global");
var assertionKey = (credentialId) => rateLimitKey("console.assert", credentialId ?? "unknown");
var challengeHash = (challenge) => sha256Hex(`echo-vault-console-challenge-v1:${challenge}`);
async function storeChallenge(c, challenge, purpose, sessionId) {
	await c.store.pruneChallenges(c.now).catch(() => void 0);
	await c.store.putChallenge({
		challenge_hash: challengeHash(challenge),
		purpose,
		session_id: sessionId,
		created_at: c.now,
		expires_at: c.now + CHALLENGE_TTL_MS
	});
}
function isRecord(v) {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}
/** The `challenge` field of a response's clientDataJSON, or null. Parsed only to find our stored row; the library re-verifies it. */
function responseChallenge(response) {
	if (!isRecord(response) || !isRecord(response.response)) return null;
	const cdj = response.response.clientDataJSON;
	if (typeof cdj !== "string" || cdj.length > 8192) return null;
	try {
		const parsed = JSON.parse(Buffer.from(cdj, "base64url").toString("utf8"));
		const challenge = isRecord(parsed) ? parsed.challenge : void 0;
		return typeof challenge === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(challenge) ? challenge : null;
	} catch {
		return null;
	}
}
/** Single use: the row is deleted before it is judged, so a replay (or a second parallel use) finds nothing. */
async function useChallenge(c, response, purpose, sessionId) {
	const challenge = responseChallenge(response);
	if (!challenge) return {
		ok: false,
		code: "challenge_invalid"
	};
	const row = await c.store.takeChallenge(challengeHash(challenge));
	if (!row || row.purpose !== purpose || row.session_id !== sessionId) return {
		ok: false,
		code: "challenge_invalid"
	};
	if (row.expires_at <= c.now) return {
		ok: false,
		code: "challenge_expired"
	};
	return {
		ok: true,
		challenge
	};
}
var iso = (ms) => ms === null ? null : new Date(ms).toISOString();
function passkeyView(p) {
	return {
		owner_id: ownerClientId(p.credential_id),
		credential_id: p.credential_id,
		label: p.label,
		transports: [...p.transports],
		created_at: new Date(p.created_at).toISOString(),
		last_used_at: iso(p.last_used_at),
		flagged_at: iso(p.flagged_at),
		flag_reason: p.flag_reason
	};
}
async function registrationOptions(c, purpose, sessionId) {
	const existing = await c.store.listPasskeys();
	if (existing.length >= 10) throw new ConsoleError("too_many_passkeys");
	const options = await (await webauthn()).generateRegistrationOptions({
		rpName: RP_NAME,
		rpID: c.cfg.rpId,
		userName: "owner",
		userDisplayName: "ECHO Vault owner",
		userID: OWNER_USER_ID,
		challenge: new Uint8Array(randomBytes(32)),
		timeout: CHALLENGE_TTL_MS,
		attestationType: "none",
		excludeCredentials: existing.map((p) => ({
			id: p.credential_id,
			transports: p.transports
		})),
		authenticatorSelection: {
			residentKey: "required",
			userVerification: "required"
		}
	});
	await storeChallenge(c, options.challenge, purpose, sessionId);
	return options;
}
function cleanLabel(label, now) {
	return sanitizeDisplayText(typeof label === "string" ? label : "", 64) || `Passkey ${new Date(now).toISOString().slice(0, 10)}`;
}
async function verifyRegistration(c, response, purpose, sessionId, label) {
	const used = await useChallenge(c, response, purpose, sessionId);
	if (!used.ok) return used;
	let info;
	try {
		const verification = await (await webauthn()).verifyRegistrationResponse({
			response,
			expectedChallenge: used.challenge,
			expectedOrigin: c.cfg.origin,
			expectedRPID: c.cfg.rpId,
			requireUserPresence: true,
			requireUserVerification: true
		});
		if (!verification.verified) return {
			ok: false,
			code: "registration_invalid"
		};
		info = verification.registrationInfo;
	} catch {
		return {
			ok: false,
			code: "registration_invalid"
		};
	}
	if (!info.userVerified || !CREDENTIAL_ID.test(info.credential.id)) return {
		ok: false,
		code: "registration_invalid"
	};
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
			flag_reason: null
		}
	};
}
/** Check a bootstrap code under the guess limiter. Never consumes it. */
async function checkBootstrap(c, code) {
	if (!await takeAttempt(c, bootstrapKey(), 5)) return "rate_limited";
	if (!(typeof code === "string" && BOOTSTRAP_CODE_PATTERN.test(code)) || !await c.store.checkBootstrapCode(bootstrapCodeHash(code), c.now)) return "bootstrap_code_invalid";
	await clearAttempts(c, bootstrapKey());
	return "ok";
}
/** Step 1 of enrollment: a valid bootstrap code buys a registration challenge. */
async function beginEnroll(code, deps = {}) {
	const c = ctx(deps);
	const checked = await checkBootstrap(c, code);
	if (checked !== "ok") {
		await audit(c, {
			client_id: ANONYMOUS,
			event: "enroll",
			error: checked
		}, false);
		return {
			ok: false,
			error: checked
		};
	}
	try {
		return {
			ok: true,
			options: await registrationOptions(c, "enroll", null)
		};
	} catch (err) {
		if (err instanceof ConsoleError) return {
			ok: false,
			error: err.code
		};
		throw err;
	}
}
/** Step 2: verify the registration, then consume the code (single use), then store the passkey. */
async function finishEnroll(code, response, label, deps = {}) {
	const c = ctx(deps);
	const fail = async (error) => {
		await audit(c, {
			client_id: ANONYMOUS,
			event: "enroll",
			error
		}, false);
		return {
			ok: false,
			error
		};
	};
	const checked = await checkBootstrap(c, code);
	if (checked !== "ok") return fail(checked);
	const verified = await verifyRegistration(c, response, "enroll", null, label);
	if (!verified.ok) return fail(verified.code);
	if (!await c.store.consumeBootstrapCode(bootstrapCodeHash(code), c.now)) return fail("bootstrap_code_invalid");
	const owner = ownerClientId(verified.passkey.credential_id);
	await audit(c, {
		client_id: owner,
		event: "enroll",
		resource: "vault:console/passkey"
	}, true);
	if (!await c.store.insertPasskey(verified.passkey)) return fail("passkey_exists");
	log.warn("vault_console_passkey_enrolled", {
		owner_id: owner,
		via: "bootstrap"
	});
	return {
		ok: true,
		passkey: passkeyView(verified.passkey)
	};
}
async function assertionOptions(c, purpose, sessionId) {
	const options = await (await webauthn()).generateAuthenticationOptions({
		rpID: c.cfg.rpId,
		challenge: new Uint8Array(randomBytes(32)),
		timeout: CHALLENGE_TTL_MS,
		userVerification: "required"
	});
	await storeChallenge(c, options.challenge, purpose, sessionId);
	return options;
}
/** Signature counter (bytes 33..36 of authenticatorData), or null when unreadable. */
function responseCounter(response) {
	if (!isRecord(response) || !isRecord(response.response)) return null;
	const raw = response.response.authenticatorData;
	if (typeof raw !== "string" || raw.length > 4096) return null;
	const data = Buffer.from(raw, "base64url");
	return data.length >= 37 ? data.readUInt32BE(33) : null;
}
async function verifyAssertion(c, response, purpose, sessionId) {
	const id = isRecord(response) && typeof response.id === "string" && CREDENTIAL_ID.test(response.id) ? response.id : null;
	const passkey = id ? await c.store.getPasskey(id) : null;
	const known = passkey ? passkey.credential_id : null;
	const key = assertionKey(known);
	if (!await takeAttempt(c, key, 5)) return {
		ok: false,
		code: "rate_limited",
		credentialId: known
	};
	const used = await useChallenge(c, response, purpose, sessionId);
	if (!passkey) return {
		ok: false,
		code: "unknown_credential",
		credentialId: null
	};
	if (!used.ok) return {
		ok: false,
		code: used.code,
		credentialId: known
	};
	const check = async (counter) => {
		try {
			const verification = await (await webauthn()).verifyAuthenticationResponse({
				response,
				expectedChallenge: used.challenge,
				expectedOrigin: c.cfg.origin,
				expectedRPID: c.cfg.rpId,
				requireUserVerification: true,
				credential: {
					id: passkey.credential_id,
					publicKey: new Uint8Array(Buffer.from(passkey.public_key, "base64url")),
					counter,
					transports: passkey.transports
				}
			});
			return verification.verified && verification.authenticationInfo.userVerified ? verification.authenticationInfo.newCounter : null;
		} catch {
			return null;
		}
	};
	const newCounter = await check(passkey.counter);
	if (newCounter === null) {
		const seen = responseCounter(response);
		if (seen !== null && (seen > 0 || passkey.counter > 0) && seen <= passkey.counter && await check(0) !== null) {
			await c.store.flagPasskey(passkey.credential_id, "counter_regression", c.now);
			log.warn("vault_console_counter_regression", { owner_id: ownerClientId(passkey.credential_id) });
			return {
				ok: false,
				code: "counter_regression",
				credentialId: known
			};
		}
		return {
			ok: false,
			code: "assertion_invalid",
			credentialId: known
		};
	}
	await c.store.updatePasskeyUse(passkey.credential_id, newCounter, c.now);
	await clearAttempts(c, key);
	return {
		ok: true,
		passkey: {
			...passkey,
			counter: newCounter,
			last_used_at: c.now
		}
	};
}
async function beginLogin(deps = {}) {
	const c = ctx(deps);
	if (!await takeAttempt(c, rateLimitKey("console.challenge", "login"), 30, 6e4)) return {
		ok: false,
		error: "rate_limited"
	};
	return {
		ok: true,
		options: await assertionOptions(c, "login", null)
	};
}
var sessionTokenHash = (token) => sha256Hex(`echo-vault-console-session-v1:${token}`);
/** Per-session CSRF token: an HMAC keyed by the session token. Only a party that can read the HttpOnly cookie could compute it. */
function csrfTokenFor(sessionToken) {
	return createHmac("sha256", sessionToken).update("echo-vault-console-csrf-v1").digest("base64url");
}
function csrfTokenMatches(sessionToken, provided) {
	if (typeof provided !== "string" || provided.length === 0 || provided.length > 128) return false;
	const expected = Buffer.from(csrfTokenFor(sessionToken));
	const got = Buffer.from(provided);
	return got.length === expected.length && timingSafeEqual(got, expected);
}
function stepUpRemaining(session, now) {
	if (session.step_up_at === null || session.step_up_at > now) return 0;
	return Math.max(0, session.step_up_at + STEP_UP_MS - now);
}
/** Complete a login assertion and open a session. The raw token is returned once, for the cookie. */
async function finishLogin(response, meta, deps = {}) {
	const c = ctx(deps);
	const result = await verifyAssertion(c, response, "login", null);
	if (!result.ok) {
		const who = result.credentialId ? ownerClientId(result.credentialId) : ANONYMOUS;
		if (result.code === "rate_limited") log.warn("vault_console_login_rate_limited", { client_id: who });
		else await audit(c, {
			client_id: who,
			event: "login",
			error: result.code
		}, false);
		return {
			ok: false,
			error: result.code
		};
	}
	const owner = ownerClientId(result.passkey.credential_id);
	const token = randomBytes(32).toString("base64url");
	await c.store.pruneSessions(c.now, SESSION_IDLE_MS).catch(() => void 0);
	await audit(c, {
		client_id: owner,
		event: "login"
	}, true);
	await c.store.insertSession({
		id: randomBytes(16).toString("hex"),
		token_hash: sessionTokenHash(token),
		credential_id: result.passkey.credential_id,
		created_at: c.now,
		last_seen_at: c.now,
		absolute_expires_at: c.now + SESSION_ABSOLUTE_MS,
		step_up_at: c.now,
		revoked_at: null,
		user_agent: sanitizeDisplayText(meta.userAgent ?? "", 200)
	});
	return {
		ok: true,
		token,
		owner_id: owner
	};
}
/**
* The ONLY place an owner identity is minted: a presented token whose hash
* matches a live session row (unrevoked, inside the idle and absolute limits).
*/
async function authenticateSession(token, deps = {}) {
	if (typeof token !== "string" || !SESSION_TOKEN.test(token)) return null;
	const c = ctx(deps);
	const session = await c.store.touchSession(sessionTokenHash(token), c.now, SESSION_IDLE_MS);
	if (!session) return null;
	return {
		session,
		identity: mintOwnerIdentity(session.credential_id),
		csrf: csrfTokenFor(token),
		stepUpRemainingMs: stepUpRemaining(session, c.now)
	};
}
async function logout(s, deps = {}) {
	const c = ctx(deps);
	await c.store.revokeSession(s.session.id, c.now);
	await audit(c, {
		client_id: s.identity.client_id,
		event: "logout"
	}, false);
}
async function listSessions(s, deps = {}) {
	const c = ctx(deps);
	return (await c.store.listSessions(c.now, SESSION_IDLE_MS)).map((r) => ({
		id: r.id,
		owner_id: ownerClientId(r.credential_id),
		created_at: new Date(r.created_at).toISOString(),
		last_seen_at: new Date(r.last_seen_at).toISOString(),
		expires_at: new Date(Math.min(r.absolute_expires_at, r.last_seen_at + SESSION_IDLE_MS)).toISOString(),
		step_up_at: iso(r.step_up_at),
		user_agent: r.user_agent,
		current: r.id === s.session.id
	}));
}
async function revokeSession(s, sessionId, deps = {}) {
	const c = ctx(deps);
	if (typeof sessionId !== "string" || !/^[0-9a-f]{32}$/.test(sessionId)) return {
		ok: false,
		error: "session_not_found"
	};
	const revoked = await c.store.revokeSession(sessionId, c.now);
	await audit(c, {
		client_id: s.identity.client_id,
		event: "session.revoke",
		resource: `vault:console/session/${sessionId.slice(0, 8)}`,
		...revoked ? {} : { error: "session_not_found" }
	}, false);
	return revoked ? { ok: true } : {
		ok: false,
		error: "session_not_found"
	};
}
async function beginStepUp(s, deps = {}) {
	return {
		ok: true,
		options: await assertionOptions(ctx(deps), "stepup", s.session.id)
	};
}
/** Any enrolled passkey may confirm; the challenge is bound to this session. */
async function finishStepUp(s, response, deps = {}) {
	const c = ctx(deps);
	const result = await verifyAssertion(c, response, "stepup", s.session.id);
	if (!result.ok) {
		if (result.code === "rate_limited") log.warn("vault_console_stepup_rate_limited", { client_id: s.identity.client_id });
		else await audit(c, {
			client_id: s.identity.client_id,
			event: "stepup",
			error: result.code
		}, false);
		return {
			ok: false,
			error: result.code
		};
	}
	await audit(c, {
		client_id: s.identity.client_id,
		event: "stepup"
	}, true);
	await c.store.markStepUp(s.session.id, c.now);
	return { ok: true };
}
async function requireStepUp(c, s, event, resource) {
	if (stepUpRemaining(s.session, c.now) > 0) return true;
	await audit(c, {
		client_id: s.identity.client_id,
		event,
		resource,
		error: "step_up_required"
	}, false);
	return false;
}
async function listPasskeys(deps = {}) {
	return (await ctx(deps).store.listPasskeys()).map(passkeyView);
}
/** Ledger row for a console page that reads only console state (the security page). */
async function recordView(s, view, deps = {}) {
	await audit(ctx(deps), {
		client_id: s.identity.client_id,
		event: `${view}.view`
	}, false);
}
async function beginAddPasskey(s, deps = {}) {
	const c = ctx(deps);
	if (!await requireStepUp(c, s, "passkey.add", "vault:console/passkey")) return {
		ok: false,
		error: "step_up_required"
	};
	try {
		return {
			ok: true,
			options: await registrationOptions(c, "add_passkey", s.session.id)
		};
	} catch (err) {
		if (err instanceof ConsoleError) return {
			ok: false,
			error: err.code
		};
		throw err;
	}
}
async function finishAddPasskey(s, response, label, deps = {}) {
	const c = ctx(deps);
	if (!await requireStepUp(c, s, "passkey.add", "vault:console/passkey")) return {
		ok: false,
		error: "step_up_required"
	};
	const fail = async (error) => {
		await audit(c, {
			client_id: s.identity.client_id,
			event: "passkey.add",
			resource: "vault:console/passkey",
			error
		}, false);
		return {
			ok: false,
			error
		};
	};
	const verified = await verifyRegistration(c, response, "add_passkey", s.session.id, label);
	if (!verified.ok) return fail(verified.code);
	const added = ownerClientId(verified.passkey.credential_id);
	await audit(c, {
		client_id: s.identity.client_id,
		event: "passkey.add",
		resource: `vault:console/passkey/${added.slice(6)}`
	}, true);
	if (!await c.store.insertPasskey(verified.passkey)) return fail("passkey_exists");
	log.warn("vault_console_passkey_enrolled", {
		owner_id: added,
		via: "session"
	});
	return {
		ok: true,
		passkey: passkeyView(verified.passkey)
	};
}
/** Removing a passkey also ends every session opened with it. The last passkey cannot be removed. */
async function removePasskey(s, credentialId, deps = {}) {
	const c = ctx(deps);
	const known = typeof credentialId === "string" && CREDENTIAL_ID.test(credentialId) ? credentialId : null;
	const resource = `vault:console/passkey/${known ? ownerClientId(known).slice(6) : "?"}`;
	if (!await requireStepUp(c, s, "passkey.remove", resource)) return {
		ok: false,
		error: "step_up_required"
	};
	const fail = async (error) => {
		await audit(c, {
			client_id: s.identity.client_id,
			event: "passkey.remove",
			resource,
			error
		}, false);
		return {
			ok: false,
			error
		};
	};
	if (!known) return fail("passkey_not_found");
	if (!await c.store.getPasskey(known)) return fail("passkey_not_found");
	if ((await c.store.listPasskeys()).length <= 1) return fail("last_passkey");
	await audit(c, {
		client_id: s.identity.client_id,
		event: "passkey.remove",
		resource
	}, true);
	const outcome = await c.store.deletePasskeyUnlessLast(known);
	if (outcome === "last") return fail("last_passkey");
	if (outcome === "not_found") return fail("passkey_not_found");
	log.warn("vault_console_passkey_removed", { owner_id: ownerClientId(known) });
	return { ok: true };
}
/** Everything the console may call. `admin_console_bootstrap` is deliberately absent (local stdio only). */
var CONSOLE_TOOLS = /* @__PURE__ */ new Set([
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
	"admin_enroll_injector",
	"admin_list_injectors",
	"admin_revoke_injector"
]);
/** Destructive calls: a WebAuthn assertion for this session in the last STEP_UP_MS is required. */
function toolNeedsStepUp(tool, args) {
	switch (tool) {
		case "admin_purge_entry":
		case "admin_delete_entry":
		case "admin_revoke_client":
		case "admin_set_client_scopes":
		case "admin_rotate_entry":
		case "admin_enroll_injector": return true;
		case "admin_set_rotation": return args.mode !== "manual";
		case "admin_revoke_grant": return typeof args.host !== "string" || args.host === "";
		default: return false;
	}
}
/**
* Run one tool as the owner. Same dispatchTool as every other caller, so the
* policy engine, result redaction and the ledger apply; the gateway writes
* the ledger row. A destructive tool without a fresh step-up is refused here
* (and that refusal is ledgered) before the gateway is reached.
*/
async function runOwnerTool(s, tool, args, deps = {}) {
	const c = ctx(deps);
	if (!CONSOLE_TOOLS.has(tool)) {
		await audit(c, {
			client_id: s.identity.client_id,
			event: "tool.refused",
			resource: `tool:${sanitizeDisplayText(tool, 64) || "?"}`,
			error: "tool_not_available"
		}, false);
		return {
			ok: false,
			error: "tool_not_available"
		};
	}
	if (toolNeedsStepUp(tool, args) && !await requireStepUp(c, s, "stepup.required", `tool:${tool}`)) return {
		ok: false,
		error: "step_up_required"
	};
	return dispatchTool(s.identity, tool, args, deps.gateway ?? {});
}
var WEBAUTHN_BROWSER_BUNDLE = "/* [@simplewebauthn/browser@14.0.0] */\n!function(e,t){\"object\"==typeof exports&&\"undefined\"!=typeof module?t(exports):\"function\"==typeof define&&define.amd?define([\"exports\"],t):t((e=\"undefined\"!=typeof globalThis?globalThis:e||self).SimpleWebAuthnBrowser={})}(this,(function(e){\"use strict\";function t(e){const t=new Uint8Array(e);let n=\"\";for(const e of t)n+=String.fromCharCode(e);return btoa(n).replace(/\\+/g,\"-\").replace(/\\//g,\"_\").replace(/=/g,\"\")}function n(e){const t=e.replace(/-/g,\"+\").replace(/_/g,\"/\"),n=(4-t.length%4)%4,r=t.padEnd(t.length+n,\"=\"),i=atob(r),o=new ArrayBuffer(i.length),a=new Uint8Array(o);for(let e=0;e<i.length;e++)a[e]=i.charCodeAt(e);return o}function r(){return i.stubThis(void 0!==globalThis?.PublicKeyCredential&&\"function\"==typeof globalThis.PublicKeyCredential)}const i={stubThis:e=>e};function o(e){const{id:t}=e;return{...e,id:n(t),transports:e.transports,type:e.type}}function a(e){return\"localhost\"===e||/^((xn--[a-z0-9-]+|[a-z0-9]+(-[a-z0-9]+)*)\\.)+([a-z]{2,}|xn--[a-z0-9-]+)$/i.test(e)}class s extends Error{constructor({message:e,code:t,cause:n,name:r}){super(e,{cause:n}),Object.defineProperty(this,\"code\",{enumerable:!0,configurable:!0,writable:!0,value:void 0}),this.name=r??n.name,this.code=t}}const l=new class{constructor(){Object.defineProperty(this,\"controller\",{enumerable:!0,configurable:!0,writable:!0,value:void 0})}createNewAbortSignal(){if(this.controller){const e=new Error(\"Cancelling existing WebAuthn API call for new one\");e.name=\"AbortError\",this.controller.abort(e)}const e=new AbortController;return this.controller=e,e.signal}cancelCeremony(){if(this.controller){const e=new Error(\"Manually cancelling existing WebAuthn API call\");e.name=\"AbortError\",this.controller.abort(e),this.controller=void 0}}},c=[\"cross-platform\",\"platform\"];function u(e){if(e&&!(c.indexOf(e)<0))return e}function d(e,t){console.warn(`The browser extension that intercepted this WebAuthn API call incorrectly implemented ${e}. You should report this error to them.\\n`,t)}function p(){if(!r())return h.stubThis(new Promise((e=>e(!1))));const e=globalThis.PublicKeyCredential;return void 0===e?.isConditionalMediationAvailable?h.stubThis(new Promise((e=>e(!1)))):h.stubThis(e.isConditionalMediationAvailable())}const h={stubThis:e=>e};function f({error:e,options:t}){if(\"SecurityError\"===e.name){return a(globalThis.location.hostname)?new s({message:`The browser does not support Related Origins to enable signals for RP ID \"${t.rpID}\" on domain \"${globalThis.location.hostname}\"`,code:\"ERROR_INVALID_RP_ID\",cause:e}):new s({message:`\"${globalThis.location.hostname}\" is an invalid domain`,code:\"ERROR_INVALID_DOMAIN\",cause:e})}if(\"unknownCredential\"===t.signalName){if(\"TypeError\"===e.name)return new s({message:\"credentialID is an invalid base64url string\",code:\"ERROR_SIGNAL_INVALID_ARGUMENT\",cause:e})}else if(\"allAcceptedCredentials\"===t.signalName){if(\"TypeError\"===e.name)return new s({message:\"userID, or an entry in allAcceptedCredentialIDs, is an invalid base64url string\",code:\"ERROR_SIGNAL_INVALID_ARGUMENT\",cause:e})}else if(\"currentUserDetails\"===t.signalName&&\"TypeError\"===e.name)return new s({message:\"userID is an invalid base64url string\",code:\"ERROR_SIGNAL_INVALID_ARGUMENT\",cause:e});return new s({message:e.message,code:\"ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY\",cause:e})}async function g(){if(\"function\"==typeof PublicKeyCredential.getClientCapabilities){const e=await PublicKeyCredential.getClientCapabilities();let t=w(e.userVerifyingPlatformAuthenticator);if(\"unknown\"===t&&\"function\"==typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable){t=await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()?\"supported\":\"unsupported\"}let n=w(e.conditionalGet);if(\"unknown\"===n&&\"function\"==typeof PublicKeyCredential.isConditionalMediationAvailable){n=await PublicKeyCredential.isConditionalMediationAvailable()?\"supported\":\"unsupported\"}return b.stubThis({conditionalCreate:w(e.conditionalCreate),conditionalGet:n,hybridTransport:w(e.hybridTransport),passkeyPlatformAuthenticator:w(e.passkeyPlatformAuthenticator),userVerifyingPlatformAuthenticator:t,relatedOrigins:w(e.relatedOrigins),signalAllAcceptedCredentials:w(e.signalAllAcceptedCredentials),signalCurrentUserDetails:w(e.signalCurrentUserDetails),signalUnknownCredential:w(e.signalUnknownCredential)})}return b.stubThis({conditionalCreate:\"unknown\",conditionalGet:\"unknown\",hybridTransport:\"unknown\",passkeyPlatformAuthenticator:\"unknown\",userVerifyingPlatformAuthenticator:\"unknown\",relatedOrigins:\"unknown\",signalAllAcceptedCredentials:\"unknown\",signalCurrentUserDetails:\"unknown\",signalUnknownCredential:\"unknown\"})}function w(e){if(!0===e)return\"supported\";if(!1===e)return\"unsupported\";if(void 0===e)return\"unknown\";throw new Error(\"Unexpected capability value:\",e)}const b={stubThis:e=>e};e.WebAuthnAbortService=l,e.WebAuthnError=s,e._browserSupportsWebAuthnAutofillInternals=h,e._browserSupportsWebAuthnInternals=i,e._getBrowserCapabilitiesInternals=b,e.base64URLStringToBuffer=n,e.browserSupportsPasskeys=async function(){if(!r())return new Promise((e=>e(!1)));const e=await g(),{passkeyPlatformAuthenticator:t,userVerifyingPlatformAuthenticator:n,hybridTransport:i}=e;return\"supported\"===t||\"supported\"===i||\"supported\"===n},e.browserSupportsWebAuthn=r,e.browserSupportsWebAuthnAutofill=p,e.bufferToBase64URLString=t,e.getBrowserCapabilities=g,e.platformAuthenticatorIsAvailable=function(){return r()?PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable():new Promise((e=>e(!1)))},e.sendSignal=async function(e){const{signalName:t}=e;if(\"unknownCredential\"===t)return async function(e){const t=globalThis.PublicKeyCredential;if(\"function\"!=typeof t.signalUnknownCredential)throw new Error(\"This browser does not support PublicKeyCredential.signalUnknownCredential()\");try{await t.signalUnknownCredential({rpId:e.rpID,credentialId:e.credentialID})}catch(t){throw f({error:t,options:e})}return}(e);if(\"allAcceptedCredentials\"===t)return async function(e){const t=globalThis.PublicKeyCredential;if(\"function\"!=typeof t.signalAllAcceptedCredentials)throw new Error(\"This browser does not support PublicKeyCredential.signalAllAcceptedCredentials()\");try{await t.signalAllAcceptedCredentials({rpId:e.rpID,userId:e.userID,allAcceptedCredentialIds:e.allAcceptedCredentialIDs})}catch(t){throw f({error:t,options:e})}return}(e);if(\"currentUserDetails\"===t)return async function(e){const t=globalThis.PublicKeyCredential;if(\"function\"!=typeof t.signalCurrentUserDetails)throw new Error(\"This browser does not support PublicKeyCredential.signalCurrentUserDetails()\");try{await t.signalCurrentUserDetails({rpId:e.rpID,userId:e.userID,name:e.userName,displayName:e.userDisplayName??\"\"})}catch(t){throw f({error:t,options:e})}return}(e);throw new Error(`Received unrecognized signalName \"${e.signalName}\"`)},e.startAuthentication=async function(e){!e.optionsJSON&&e.challenge&&(console.warn(\"startAuthentication() was not called correctly. It will try to continue with the provided options, but this call should be refactored to use the expected call structure instead. See https://simplewebauthn.dev/docs/packages/browser#typeerror-cannot-read-properties-of-undefined-reading-challenge for more information.\"),e={optionsJSON:e});const{optionsJSON:i,useBrowserAutofill:c=!1,verifyBrowserAutofillInput:d=!0}=e;if(!r())throw new Error(\"WebAuthn is not supported in this browser\");let h;0!==i.allowCredentials?.length&&(h=i.allowCredentials?.map(o));const f={...i,challenge:n(i.challenge),allowCredentials:h},g={};if(c){if(!await p())throw Error(\"Browser does not support WebAuthn autofill\");if(document.querySelectorAll(\"input[autocomplete$='webauthn']\").length<1&&d)throw Error('No <input> with \"webauthn\" as the only or last value in its `autocomplete` attribute was detected');g.mediation=\"conditional\",f.allowCredentials=[]}let w;g.publicKey=f,g.signal=l.createNewAbortSignal();try{w=await navigator.credentials.get(g)}catch(e){throw function({error:e,options:t}){const{publicKey:n}=t;if(!n)throw Error(\"options was missing required publicKey property\");if(\"AbortError\"===e.name){if(t.signal instanceof AbortSignal)return new s({message:\"Authentication ceremony was sent an abort signal\",code:\"ERROR_CEREMONY_ABORTED\",cause:e})}else{if(\"NotAllowedError\"===e.name)return new s({message:e.message,code:\"ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY\",cause:e});if(\"SecurityError\"===e.name){const t=globalThis.location.hostname;if(!a(t))return new s({message:`${globalThis.location.hostname} is an invalid domain`,code:\"ERROR_INVALID_DOMAIN\",cause:e});if(n.rpId!==t)return new s({message:`The RP ID \"${n.rpId}\" is invalid for this domain`,code:\"ERROR_INVALID_RP_ID\",cause:e})}else if(\"UnknownError\"===e.name)return new s({message:\"The authenticator was unable to process the specified options, or could not create a new assertion signature\",code:\"ERROR_AUTHENTICATOR_GENERAL_ERROR\",cause:e})}return e}({error:e,options:g})}if(!w)throw new Error(\"Authentication was not completed\");const{id:b,rawId:A,response:R,type:m}=w;let y;return R.userHandle&&(y=t(R.userHandle)),{id:b,rawId:t(A),response:{authenticatorData:t(R.authenticatorData),clientDataJSON:t(R.clientDataJSON),signature:t(R.signature),userHandle:y},type:m,clientExtensionResults:w.getClientExtensionResults(),authenticatorAttachment:u(w.authenticatorAttachment)}},e.startRegistration=async function(e){!e.optionsJSON&&e.challenge&&(console.warn(\"startRegistration() was not called correctly. It will try to continue with the provided options, but this call should be refactored to use the expected call structure instead. See https://simplewebauthn.dev/docs/packages/browser#typeerror-cannot-read-properties-of-undefined-reading-challenge for more information.\"),e={optionsJSON:e});const{optionsJSON:i,useAutoRegister:c=!1}=e;if(!r())throw new Error(\"WebAuthn is not supported in this browser\");const p={...i,challenge:n(i.challenge),user:{...i.user,id:n(i.user.id)},excludeCredentials:i.excludeCredentials?.map(o)},h={};let f;c&&(h.mediation=\"conditional\"),h.publicKey=p,h.signal=l.createNewAbortSignal();try{f=await navigator.credentials.create(h)}catch(e){throw function({error:e,options:t}){const{publicKey:n}=t;if(!n)throw Error(\"options was missing required publicKey property\");if(\"AbortError\"===e.name){if(t.signal instanceof AbortSignal)return new s({message:\"Registration ceremony was sent an abort signal\",code:\"ERROR_CEREMONY_ABORTED\",cause:e})}else if(\"ConstraintError\"===e.name){if(!0===n.authenticatorSelection?.requireResidentKey)return new s({message:\"Discoverable credentials were required but no available authenticator supported it\",code:\"ERROR_AUTHENTICATOR_MISSING_DISCOVERABLE_CREDENTIAL_SUPPORT\",cause:e});if(\"conditional\"===t.mediation&&\"required\"===n.authenticatorSelection?.userVerification)return new s({message:\"User verification was required during automatic registration but it could not be performed\",code:\"ERROR_AUTO_REGISTER_USER_VERIFICATION_FAILURE\",cause:e});if(\"required\"===n.authenticatorSelection?.userVerification)return new s({message:\"User verification was required but no available authenticator supported it\",code:\"ERROR_AUTHENTICATOR_MISSING_USER_VERIFICATION_SUPPORT\",cause:e})}else{if(\"InvalidStateError\"===e.name)return new s({message:\"The authenticator was previously registered\",code:\"ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED\",cause:e});if(\"NotAllowedError\"===e.name)return new s({message:e.message,code:\"ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY\",cause:e});if(\"NotSupportedError\"===e.name)return 0===n.pubKeyCredParams.filter((e=>\"public-key\"===e.type)).length?new s({message:'No entry in pubKeyCredParams was of type \"public-key\"',code:\"ERROR_MALFORMED_PUBKEYCREDPARAMS\",cause:e}):new s({message:\"No available authenticator supported any of the specified pubKeyCredParams algorithms\",code:\"ERROR_AUTHENTICATOR_NO_SUPPORTED_PUBKEYCREDPARAMS_ALG\",cause:e});if(\"SecurityError\"===e.name){const t=globalThis.location.hostname;if(!a(t))return new s({message:`${globalThis.location.hostname} is an invalid domain`,code:\"ERROR_INVALID_DOMAIN\",cause:e});if(n.rp.id!==t)return new s({message:`The RP ID \"${n.rp.id}\" is invalid for this domain`,code:\"ERROR_INVALID_RP_ID\",cause:e})}else if(\"TypeError\"===e.name){if(n.user.id.byteLength<1||n.user.id.byteLength>64)return new s({message:\"User ID was not between 1 and 64 characters\",code:\"ERROR_INVALID_USER_ID_LENGTH\",cause:e})}else if(\"UnknownError\"===e.name)return new s({message:\"The authenticator was unable to process the specified options, or could not create a new credential\",code:\"ERROR_AUTHENTICATOR_GENERAL_ERROR\",cause:e})}return e}({error:e,options:h})}if(!f)throw new Error(\"Registration was not completed\");const{id:g,rawId:w,response:b,type:A}=f;let R,m,y,E;if(\"function\"==typeof b.getTransports&&(R=b.getTransports()),\"function\"==typeof b.getPublicKeyAlgorithm)try{m=b.getPublicKeyAlgorithm()}catch(e){d(\"getPublicKeyAlgorithm()\",e)}if(\"function\"==typeof b.getPublicKey)try{const e=b.getPublicKey();null!==e&&(y=t(e))}catch(e){d(\"getPublicKey()\",e)}if(\"function\"==typeof b.getAuthenticatorData)try{E=t(b.getAuthenticatorData())}catch(e){d(\"getAuthenticatorData()\",e)}return{id:g,rawId:t(w),response:{attestationObject:t(b.attestationObject),clientDataJSON:t(b.clientDataJSON),transports:R,publicKeyAlgorithm:m,publicKey:y,authenticatorData:E},type:A,clientExtensionResults:f.getClientExtensionResults(),authenticatorAttachment:u(f.authenticatorAttachment)}}}));";
/**
* Owner console HTTP surface — framework-free Request → Response, in the
* style of card-pages.ts. The route files under src/routes/console are thin
* wrappers around `handleConsoleRequest`.
*
* Every response: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`,
* `frame-ancestors 'none'`, and a CSP of `default-src 'none'` plus a per-
* response nonce for the one inline style and (only on pages that run a
* WebAuthn ceremony) the one inline script. No inline event handlers, no
* third-party origin, no images. Every dynamic value is HTML-escaped.
*
* No page, JSON body, header or log line here ever contains a vault secret:
* the console has no reveal, copy or export feature, and all vault data it
* shows comes out of dispatchTool (metadata only, already redacted).
*
* State-changing requests (every POST):
*   1. `Sec-Fetch-Site: same-origin` must be present, and `Origin` must be the
*      configured console origin. `Origin: null` is accepted only because (1)
*      already holds — with `Referrer-Policy: no-referrer` browsers send
*      `Origin: null` on same-origin form navigations (Fetch spec).
*   2. Behind a session: the `SameSite=Strict` cookie plus the per-session
*      CSRF token, in the `csrf` form field or the `x-csrf-token` header.
* The expected origin is ECHO_VAULT_CONSOLE_ORIGIN — never the Host header.
*/
var CONSOLE_BASE = "/console";
/**
* `__Secure-`, not `__Host-`: the cookie is scoped to Path=/console so the
* owner's session token is not sent to /api/mcp, /card or the app's other
* routes, and `__Host-` requires Path=/. `__Secure-` still forces the Secure
* attribute and a secure origin.
*/
var CONSOLE_COOKIE = "__Secure-echo_vault_console";
var MAX_CONSOLE_BODY_BYTES = 65536;
var STYLE = "body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#0f1115;color:#e8eaed}a{color:#8ab4f8}a:focus,button:focus,input:focus,select:focus,summary:focus{outline:3px solid #fdd663;outline-offset:2px}header{background:#171a21;border-bottom:1px solid #3a3f4b;padding:.6rem 1rem}nav ul{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:.3rem 1rem;align-items:center}nav form{margin:0}main{max-width:70rem;margin:0 auto;padding:1rem}h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.6rem}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #2a2e37;vertical-align:top;word-break:break-word}th{color:#bdc1c6}label{display:block;margin:.6rem 0 .2rem;font-weight:600}input,select{box-sizing:border-box;max-width:100%;padding:.45rem;font:inherit;color:inherit;background:#1a1d24;border:1px solid #5f6368;border-radius:.3rem}input[type=text],input[type=password]{width:28rem}button{margin-top:.6rem;padding:.5rem .9rem;font:inherit;font-weight:600;color:#0f1115;background:#8ab4f8;border:0;border-radius:.3rem;cursor:pointer}button.danger{background:#f28b82}button.plain{background:#bdc1c6}button[disabled]{opacity:.6}fieldset{border:1px solid #3a3f4b;border-radius:.4rem;margin:.8rem 0;padding:.4rem .8rem .8rem}legend{font-weight:600;padding:0 .3rem}.inline{display:inline-block;margin-right:1rem;font-weight:400}.inline input{width:auto;margin-right:.3rem}.ok{padding:.6rem;border:1px solid #81c995;border-radius:.4rem;color:#81c995}.err{padding:.6rem;border:1px solid #f28b82;border-radius:.4rem;color:#f28b82}.muted{color:#bdc1c6;font-size:.88rem}.bad{color:#f28b82;font-weight:600}.good{color:#81c995;font-weight:600}pre{white-space:pre-wrap;word-break:break-word;background:#171a21;padding:.8rem;border-radius:.4rem}dl{margin:0;display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem}dt{color:#bdc1c6}dd{margin:0;word-break:break-word}.skip{position:absolute;left:-999rem}.skip:focus{left:.5rem;top:.5rem;background:#0f1115;padding:.4rem}details{margin:.4rem 0}summary{cursor:pointer}";
/** Glue for the three ceremonies. Reads everything from data-* attributes; talks only to this origin. */
var GLUE_SCRIPT = "(function(){var W=window.SimpleWebAuthnBrowser;function post(u,b,c){var h={'content-type':'application/json'};if(c){h['x-csrf-token']=c;}return fetch(u,{method:'POST',credentials:'same-origin',headers:h,body:JSON.stringify(b||{})}).then(function(r){return r.json().catch(function(){return{ok:false,error:'bad_response'};});});}function say(b,m,e){var o=document.getElementById(b.getAttribute('data-status'));if(o){o.textContent=m;o.className=e?'err':'muted';}}function val(id){var e=document.getElementById(id);return e?e.value:undefined;}function run(b){var k=b.getAttribute('data-webauthn'),base=b.getAttribute('data-base'),c=b.getAttribute('data-csrf')||'';var x={};var code=val('f-code');if(code!==undefined){x.code=code.trim();}var label=val('f-label');if(label!==undefined){x.label=label;}if(!W||!W.browserSupportsWebAuthn()){say(b,'This browser does not support passkeys.',true);return;}b.disabled=true;say(b,'Waiting for your passkey\\u2026');post(base+'/options',x,c).then(function(o){if(!o.ok){throw new Error(o.error||'failed');}return k==='register'?W.startRegistration({optionsJSON:o.options}):W.startAuthentication({optionsJSON:o.options});}).then(function(r){var y={response:r};for(var p in x){y[p]=x[p];}return post(base+'/verify',y,c);}).then(function(v){if(!v.ok){throw new Error(v.error||'failed');}say(b,'Done.');window.location.assign(b.getAttribute('data-next')||'/console');}).catch(function(e){b.disabled=false;say(b,'Failed: '+(e&&e.message?e.message:'error'),true);});}var bs=document.querySelectorAll('[data-webauthn]');for(var i=0;i<bs.length;i++){(function(b){b.addEventListener('click',function(ev){ev.preventDefault();run(b);});})(bs[i]);}})();";
var BASE_HEADERS = {
	"cache-control": "no-store",
	pragma: "no-cache",
	"referrer-policy": "no-referrer",
	"x-content-type-options": "nosniff",
	"x-frame-options": "DENY",
	"x-robots-tag": "noindex, nofollow",
	"cross-origin-opener-policy": "same-origin",
	"cross-origin-resource-policy": "same-origin"
};
var CSP_TAIL = "img-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
function withExtra(headers, extra) {
	const h = new Headers(headers);
	if (extra.cookie) h.append("set-cookie", extra.cookie);
	if (extra.location) h.set("location", extra.location);
	if (extra.allow) h.set("allow", extra.allow);
	return h;
}
function json(status, body, extra = {}) {
	return new Response(JSON.stringify(body), {
		status,
		headers: withExtra({
			...BASE_HEADERS,
			"content-type": "application/json; charset=utf-8",
			"content-security-policy": "default-src 'none'; frame-ancestors 'none'"
		}, extra)
	});
}
function redirect(location, extra = {}) {
	return new Response(null, {
		status: 303,
		headers: withExtra({
			...BASE_HEADERS,
			"content-security-policy": "default-src 'none'; frame-ancestors 'none'"
		}, {
			...extra,
			location
		})
	});
}
var NAV = [
	["", "Overview"],
	["/clients", "Clients"],
	["/grants", "Consent grants"],
	["/entries", "Entries"],
	["/audit", "Audit"],
	["/digest", "Digest"],
	["/security", "Security"]
];
function page(o) {
	const nonce = randomBytes(18).toString("base64");
	const nav = o.session ? `<header><nav aria-label="Console"><ul>` + NAV.map(([path, label]) => `<li><a href="${CONSOLE_BASE}${path}">${escapeHtml(label)}</a></li>`).join("") + `<li><span class="muted">${escapeHtml(o.session.identity.client_id)}</span></li><li><form method="post" action="${CONSOLE_BASE}/logout">${csrfField(o.session)}<button class="plain" type="submit">Sign out</button></form></li></ul></nav></header>` : "";
	const notice = o.notice ? `<p class="${o.notice.ok ? "ok" : "err"}" role="${o.notice.ok ? "status" : "alert"}">${escapeHtml(o.notice.text)}</p>` : "";
	const script = o.script ? `<script nonce="${nonce}">${WEBAUTHN_BROWSER_BUNDLE}\n${GLUE_SCRIPT}<\/script>` : "";
	const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${escapeHtml(o.title)} — ECHO Vault console</title><style nonce="${nonce}">${STYLE}</style></head><body><a class="skip" href="#main">Skip to content</a>${nav}<main id="main"><h1>${escapeHtml(o.title)}</h1>${notice}${o.body}</main>${script}</body></html>`;
	const csp = `default-src 'none'; style-src 'nonce-${nonce}'; script-src ${o.script ? `'nonce-${nonce}'` : "'none'"}; connect-src ${o.script ? "'self'" : "'none'"}; ${CSP_TAIL}`;
	return new Response(html, {
		status: o.status ?? 200,
		headers: withExtra({
			...BASE_HEADERS,
			"content-type": "text/html; charset=utf-8",
			"content-security-policy": csp
		}, o.extra ?? {})
	});
}
function message(status, title, text, extra = {}) {
	return page({
		status,
		title,
		body: `<p>${escapeHtml(text)}</p>`,
		extra
	});
}
function sessionCookie(token) {
	return `${CONSOLE_COOKIE}=${token}; Path=${CONSOLE_BASE}; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1e3}`;
}
var CLEAR_COOKIE = `${CONSOLE_COOKIE}=; Path=${CONSOLE_BASE}; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
/** Every value presented under the console cookie name (a tossed duplicate must not mask the real one). */
function cookieTokens(request) {
	const out = [];
	for (const part of (request.headers.get("cookie") ?? "").split(";")) {
		const eq = part.indexOf("=");
		if (eq > 0 && part.slice(0, eq).trim() === "__Secure-echo_vault_console") out.push(part.slice(eq + 1).trim());
		if (out.length === 4) break;
	}
	return out;
}
async function sessionOf(request, deps) {
	for (const token of cookieTokens(request)) {
		const session = await authenticateSession(token, deps);
		if (session) return {
			session,
			token
		};
	}
	return null;
}
/** Rule 1 of the module header. */
function sameOriginConsolePost(request, cfg) {
	if ((request.headers.get("sec-fetch-site") ?? "").toLowerCase() !== "same-origin") return false;
	const origin = request.headers.get("origin");
	return origin === cfg.origin || origin === "null";
}
async function readBody(request) {
	const type = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
	if (type !== "application/json" && type !== "application/x-www-form-urlencoded") return "unsupported";
	const raw = await readLimited(request, MAX_CONSOLE_BODY_BYTES);
	if (raw === null) return "too_large";
	if (type === "application/x-www-form-urlencoded") return {
		kind: "form",
		value: new URLSearchParams(raw)
	};
	try {
		const value = JSON.parse(raw === "" ? "{}" : raw);
		if (typeof value !== "object" || value === null || Array.isArray(value)) return "invalid";
		return {
			kind: "json",
			value
		};
	} catch {
		return "invalid";
	}
}
function csrfField(s) {
	return `<input type="hidden" name="csrf" value="${escapeHtml(s.csrf)}">`;
}
function dataOf(result) {
	return result.ok && typeof result.data === "object" && result.data !== null ? result.data : null;
}
function listOf(result, key) {
	const value = dataOf(result)?.[key];
	return Array.isArray(value) ? value : [];
}
var ERROR_TEXT = {
	step_up_required: "Confirm with your passkey first (valid for 5 minutes), then repeat the action.",
	confirmation_required: "Type the confirmation exactly: \"PURGE <entry_id>\".",
	last_passkey: "The last passkey cannot be removed. Add another passkey first.",
	rate_limited: "Too many attempts. Wait and try again.",
	ledger_unavailable: "The audit ledger could not record this, so nothing was done."
};
function failureText(result) {
	const detail = "detail" in result && typeof result.detail === "string" ? ` — ${result.detail}` : "";
	return `${ERROR_TEXT[result.error] ?? `Refused: ${result.error}`}${ERROR_TEXT[result.error] ? "" : detail}`;
}
function noticeOf(result, okText) {
	if (result.ok) return {
		ok: true,
		text: okText
	};
	const failure = result;
	return {
		ok: false,
		text: failureText(failure),
		code: failure.error
	};
}
function unavailable(result) {
	return result.ok ? "" : `<p class="err" role="alert">${escapeHtml(failureText(result))}</p>`;
}
function table(caption, heads, rows) {
	if (rows.length === 0) return `<p class="muted">${escapeHtml(caption)}: none.</p>`;
	return `<table><caption class="skip">${escapeHtml(caption)}</caption><thead><tr>` + heads.map((h) => `<th scope="col">${escapeHtml(h)}</th>`).join("") + `</tr></thead><tbody>` + rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") + `</tbody></table>`;
}
var e = escapeHtml;
var txt = (v) => e(v === null || v === void 0 || v === "" ? "—" : String(v));
function postForm(s, action, inner, submit, cls = "") {
	return `<form method="post" action="${CONSOLE_BASE}${action}" autocomplete="off">${csrfField(s)}${inner}<button type="submit"${cls ? ` class="${cls}"` : ""}>${e(submit)}</button></form>`;
}
var hidden = (name, value) => `<input type="hidden" name="${name}" value="${e(value)}">`;
var fieldSeq = 0;
function input(name, label, opts = {}) {
	fieldSeq = (fieldSeq + 1) % 1e6;
	const id = `i-${name}-${fieldSeq}`;
	return `<label for="${id}">${e(label)}</label><input id="${id}" name="${name}" type="${opts.type ?? "text"}" value="${e(opts.value ?? "")}" maxlength="${opts.max ?? 400}" autocomplete="off" autocapitalize="off" spellcheck="false"${opts.required ? " required" : ""}>`;
}
/** Step-up status + the button that runs the assertion. Shown on every page with a destructive form. */
function stepUpPanel(s, next) {
	const fresh = s.stepUpRemainingMs > 0;
	return "<fieldset><legend>Passkey confirmation</legend><p class=\"muted\">Destructive actions need a passkey confirmation from the last 5 minutes. " + (fresh ? `Confirmed: about ${Math.ceil(s.stepUpRemainingMs / 6e4)} min left.` : `<span class="bad">Not confirmed.</span>`) + `</p><button type="button" data-webauthn="auth" data-base="${CONSOLE_BASE}/stepup" data-csrf="${e(s.csrf)}" data-next="${e(next)}" data-status="stepup-status">${fresh ? "Confirm again" : "Confirm with passkey"}</button><p id="stepup-status" class="muted" role="status" aria-live="polite"></p></fieldset>`;
}
var call = (v, tool, args = {}) => runOwnerTool(v.s, tool, args, v.deps);
async function overviewPage(v) {
	const [verify, entries, due, clients, grants] = await Promise.all([
		call(v, "audit_verify"),
		call(v, "admin_list_entries"),
		call(v, "admin_rotation_due"),
		call(v, "admin_list_clients"),
		call(v, "admin_list_grants")
	]);
	const chain = dataOf(verify);
	const anchor = chain && typeof chain.anchor === "object" && chain.anchor !== null ? chain.anchor : null;
	const allEntries = listOf(entries, "entries");
	const needs = allEntries.filter((x) => x.status === "needs_reentry");
	const dueList = listOf(due, "entries");
	const clientList = listOf(clients, "clients");
	const chainLine = !chain ? `<span class="bad">unavailable</span>` : chain.ok === true ? `<span class="good">intact</span> (${txt(chain.count)} rows)` : `<span class="bad">BROKEN at seq ${txt(chain.broken_at_seq)}: ${txt(chain.reason)}</span>`;
	const anchorLine = !chain ? `<span class="bad">unavailable</span>` : chain.anchor_error ? `<span class="bad">${txt(chain.anchor_error)}</span>` : !anchor ? "nothing anchored yet" : `<span class="${anchor.verdict === "ok" ? "good" : "bad"}">${txt(anchor.verdict)}</span>`;
	return page({
		title: "Overview",
		body: unavailable(verify) + `<h2>Ledger</h2><dl><dt>Hash chain</dt><dd>${chainLine}</dd><dt>Newest anchor</dt><dd>${anchorLine}</dd></dl><h2>Counts</h2><dl><dt>Entries</dt><dd>${entries.ok ? `${allEntries.filter((x) => x.status !== "deleted").length} live, ${allEntries.filter((x) => x.status === "deleted").length} soft-deleted` : "unavailable"}</dd><dt>Clients</dt><dd>${clients.ok ? `${clientList.filter((x) => x.status === "approved").length} approved of ${clientList.length}` : "unavailable"}</dd><dt>Consent grants</dt><dd>${grants.ok ? listOf(grants, "grants").length : "unavailable"}</dd></dl><h2>Entries needing re-entry</h2>` + table("Entries needing re-entry", ["Entry", "Reason"], needs.map((x) => [txt(x.label), txt(x.reentry_reason)])) + `<h2>Rotation due</h2>` + table("Rotation due", [
			"Entry",
			"Mode",
			"Due"
		], dueList.map((x) => [
			txt(x.label),
			txt(x.rotation_mode),
			txt(x.rotate_by)
		])),
		session: v.s,
		notice: v.notice,
		status: v.status
	});
}
async function clientsPage(v) {
	const result = await call(v, "admin_list_clients");
	const rows = listOf(result, "clients").map((c) => {
		const granted = Array.isArray(c.granted_scopes) ? c.granted_scopes.map(String) : [];
		const id = String(c.client_id ?? "");
		const boxes = SUPPORTED_SCOPES.map((scope) => `<label class="inline"><input type="checkbox" name="scope" value="${e(scope)}"${granted.includes(scope) ? " checked" : ""}>${e(scope)}</label>`).join("");
		const actions = c.status === "approved" ? `<details><summary>Manage ${txt(c.client_name)}</summary>` + postForm(v.s, "/clients/scopes", hidden("client_id", id) + `<fieldset><legend>Granted scopes</legend>${boxes}</fieldset>`, "Set scopes") + postForm(v.s, "/clients/revoke", hidden("client_id", id), "Revoke client", "danger") + `</details>` : "";
		return [
			`${txt(c.client_name)}<br><span class="muted">${txt(id)}</span>`,
			txt(c.status),
			txt(granted.join(", ")),
			txt(c.created_at),
			actions
		];
	});
	return page({
		title: "Clients",
		body: stepUpPanel(v.s, `${CONSOLE_BASE}/clients`) + unavailable(result) + table("OAuth clients", [
			"Client",
			"Status",
			"Granted scopes",
			"Registered",
			"Actions"
		], rows),
		session: v.s,
		notice: v.notice,
		status: v.status,
		script: true
	});
}
async function grantsPage(v) {
	const result = await call(v, "admin_list_grants");
	const grants = listOf(result, "grants");
	const rows = grants.map((g) => [
		txt(g.client_id),
		txt(g.entry_id),
		txt(g.host),
		txt(g.path_prefix),
		txt(g.expires_at),
		txt(g.uses_remaining === null ? "unlimited" : g.uses_remaining),
		postForm(v.s, "/grants/revoke", hidden("client_id", g.client_id) + hidden("entry_id", g.entry_id) + hidden("host", g.host) + hidden("path_prefix", g.path_prefix), "Revoke this grant")
	]);
	const pairs = [...new Map(grants.map((g) => [`${String(g.client_id)}\u0000${String(g.entry_id)}`, g])).values()];
	const pairForms = pairs.map((g) => postForm(v.s, "/grants/revoke", hidden("client_id", g.client_id) + hidden("entry_id", g.entry_id) + hidden("all", "1") + `<p>${txt(g.client_id)} → ${txt(g.entry_id)}</p>`, "Revoke ALL grants for this pair", "danger")).join("");
	return page({
		title: "Consent grants",
		body: stepUpPanel(v.s, `${CONSOLE_BASE}/grants`) + unavailable(result) + table("Consent grants", [
			"Client",
			"Entry",
			"Host",
			"Path prefix",
			"Expires",
			"Uses left",
			"Action"
		], rows) + (pairs.length ? `<h2>Revoke all grants for a client and entry</h2>${pairForms}` : ""),
		session: v.s,
		notice: v.notice,
		status: v.status,
		script: true
	});
}
async function entriesPage(v) {
	const result = await call(v, "admin_list_entries");
	const sections = listOf(result, "entries").map((x) => {
		const id = String(x.id ?? "");
		const live = x.status !== "deleted";
		const rotation = `<fieldset><legend>Rotation policy</legend><label class="inline"><input type="radio" name="mode" value="manual"${x.rotation_mode !== "auto" ? " checked" : ""}>manual</label><label class="inline"><input type="radio" name="mode" value="auto"${x.rotation_mode === "auto" ? " checked" : ""}>auto (needs confirmation)</label>` + input("interval_days", "Rotate every N days (blank = keep)", {
			value: x.rotate_interval_days ?? "",
			max: 4
		}) + input("provider_token_id", "Provider token ID — the non-secret ID, never the token (blank = keep)", { max: 64 }) + `</fieldset>`;
		const jar = x.kind === "cookie" && x.cookie_jar && typeof x.cookie_jar === "object" ? x.cookie_jar : null;
		const joined = (v) => Array.isArray(v) && v.length ? v.map(String).join(", ") : "—";
		const cookieRows = jar ? `<dt>Cookies</dt><dd>${txt(jar.count)} stored${jar.truncated === true ? " (lists below are shortened)" : ""}</dd><dt>Cookie names</dt><dd>${txt(joined(jar.names))}</dd><dt>Cookie domains</dt><dd>${txt(joined(jar.domains))}</dd><dt>Earliest cookie expiry</dt><dd>${txt(jar.expires_at ?? "session cookies only")}</dd>` : "";
		return `<section aria-label="${e(x.label)}"><h2>${txt(x.label)}</h2><dl><dt>Entry ID</dt><dd>${txt(id)}</dd><dt>Kind</dt><dd>${txt(x.kind)}</dd><dt>Status</dt><dd>${x.status === "active" ? txt(x.status) : `<span class="bad">${txt(x.status)}</span>`}${x.reentry_reason ? ` — ${txt(x.reentry_reason)}` : ""}</dd><dt>Fingerprint</dt><dd>${txt(x.fingerprint)}</dd><dt>Secret length</dt><dd>${txt(x.secret_length)} characters</dd>` + cookieRows + `<dt>Default for site</dt><dd>${x.is_default ? "yes" : "no"}</dd><dt>Rotation</dt><dd>${txt(x.rotation_mode)}, every ${txt(x.rotate_interval_days)} days, due ${txt(x.rotate_by)}, last ${txt(x.last_rotated_at)}, count ${txt(x.rotation_count)}${x.last_rotation_error ? `, <span class="bad">last error ${txt(x.last_rotation_error)}</span>` : ""}</dd><dt>Last used</dt><dd>${txt(x.last_used_at)}</dd></dl><details><summary>Actions for ${txt(x.label)}</summary>` + (live ? postForm(v.s, "/entries/rotation", hidden("entry_id", id) + rotation, "Set rotation policy") + postForm(v.s, "/entries/rotate", hidden("entry_id", id), "Rotate now", "danger") + postForm(v.s, "/entries/reentry", hidden("entry_id", id), "Send a re-entry card to Telegram") + postForm(v.s, "/entries/delete", hidden("entry_id", id), "Soft delete", "danger") : "") + postForm(v.s, "/entries/purge", hidden("entry_id", id) + input("confirm", `Irreversible. Type: PURGE ${id}`, {
			required: true,
			max: 60
		}), "Purge permanently", "danger") + `</details></section>`;
	}).join("");
	return page({
		title: "Entries",
		body: `<p class="muted">Metadata only. The console cannot show, copy or export a stored secret.</p>` + stepUpPanel(v.s, `${CONSOLE_BASE}/entries`) + unavailable(result) + (sections || (result.ok ? `<p class="muted">No entries.</p>` : "")),
		session: v.s,
		notice: v.notice,
		status: v.status,
		script: true
	});
}
async function auditPage(v, extra = "") {
	const q = v.url.searchParams;
	const clientId = (q.get("client_id") ?? "").slice(0, 200);
	const capability = (q.get("capability") ?? "").slice(0, 200);
	const limitRaw = Number(q.get("limit") ?? "100");
	const limit = Number.isInteger(limitRaw) && limitRaw >= 1 && limitRaw <= 1e3 ? limitRaw : 100;
	const result = await call(v, "audit_list", {
		limit,
		...clientId ? { client_id: clientId } : {},
		...capability ? { capability } : {}
	});
	const rows = listOf(result, "records").map((r) => [
		txt(r.seq),
		txt(r.timestamp),
		txt(r.client_id),
		txt(r.capability),
		txt(r.resource),
		txt(r.decision),
		txt(r.tier),
		r.result === "ok" ? txt(r.result) : `<span class="bad">${txt(r.result)}</span>`,
		txt(r.error)
	]);
	return page({
		title: "Audit",
		body: extra + `<h2>Ledger checks</h2>` + postForm(v.s, "/audit/verify", "", "Verify hash chain") + postForm(v.s, "/audit/anchor", "", "Anchor head to Telegram now") + postForm(v.s, "/audit/verify-anchor", input("line", "Anchor line copied from Telegram", { required: true }), "Verify anchor line") + `<h2>Recent ledger rows</h2><form method="get" action="${CONSOLE_BASE}/audit">` + input("client_id", "Client ID (exact)", {
			value: clientId,
			max: 200
		}) + input("capability", "Capability (exact)", {
			value: capability,
			max: 200
		}) + input("limit", "Rows (1–1000)", {
			value: limit,
			max: 4
		}) + `<button type="submit">Filter</button></form>` + unavailable(result) + table("Ledger rows", [
			"Seq",
			"Time",
			"Client",
			"Capability",
			"Resource",
			"Decision",
			"Tier",
			"Result",
			"Error"
		], rows),
		session: v.s,
		notice: v.notice,
		status: v.status
	});
}
async function digestPage(v, send = false) {
	const from = (v.url.searchParams.get("from") ?? "").slice(0, 40);
	const to = (v.url.searchParams.get("to") ?? "").slice(0, 40);
	const result = await call(v, "admin_digest_now", {
		...from ? { from } : {},
		...to ? { to } : {},
		...send ? { send: true } : {}
	});
	const data = dataOf(result);
	const sent = data && typeof data.send === "object" && data.send !== null ? data.send : null;
	const window = data && typeof data.digest === "object" && data.digest !== null ? data.digest.window : void 0;
	return page({
		title: "Digest",
		body: `<form method="get" action="${CONSOLE_BASE}/digest">` + input("from", "From (YYYY-MM-DD, UTC; blank = previous full day)", {
			value: from,
			max: 40
		}) + input("to", "To (exclusive; blank = one day)", {
			value: to,
			max: 40
		}) + `<button type="submit">Preview</button></form>` + unavailable(result) + (sent ? `<p class="${sent.ok ? "ok" : "err"}" role="status">Send: ${txt(sent.ok ? sent.status ?? "sent" : sent.error ?? "failed")}</p>` : "") + (data ? `<h2>Preview${window ? ` ${txt(window.from)} → ${txt(window.to)}` : ""}</h2><pre>${txt(data.text)}</pre>` + postForm(v.s, "/digest/send", hidden("from", from) + hidden("to", to), "Send this digest to Telegram now") : ""),
		session: v.s,
		notice: v.notice,
		status: v.status
	});
}
async function securityPage(v) {
	await recordView(v.s, "security", v.deps);
	const [passkeys, sessions] = await Promise.all([listPasskeys(v.deps), listSessions(v.s, v.deps)]);
	const passkeyRows = passkeys.map((p) => [
		`${txt(p.label)}<br><span class="muted">${txt(p.owner_id)}</span>`,
		txt(p.transports.join(", ")),
		txt(p.created_at),
		txt(p.last_used_at),
		p.flagged_at ? `<span class="bad">${txt(p.flag_reason)} at ${txt(p.flagged_at)} — remove this passkey</span>` : "—",
		postForm(v.s, "/security/passkeys/remove", hidden("credential_id", p.credential_id), "Remove", "danger")
	]);
	const sessionRows = sessions.map((x) => [
		`${txt(x.id.slice(0, 8))}${x.current ? " (this session)" : ""}`,
		txt(x.owner_id),
		txt(x.created_at),
		txt(x.last_seen_at),
		txt(x.expires_at),
		txt(x.user_agent),
		postForm(v.s, "/security/sessions/revoke", hidden("session_id", x.id), x.current ? "Sign out" : "Revoke")
	]);
	const injectors = await call(v, "admin_list_injectors");
	const injectorRows = listOf(injectors, "injectors").map((i) => [
		`${txt(i.name)}<br><span class="muted">${txt(i.injector_id)}</span>`,
		txt(i.key_thumbprint),
		txt(i.created_at),
		txt(i.last_used_at),
		i.status === "active" ? "active" : `<span class="bad">revoked ${txt(i.revoked_at)}</span>`,
		i.status === "active" ? postForm(v.s, "/security/injectors/revoke", hidden("injector_id", i.injector_id), "Revoke", "danger") : "—"
	]);
	return page({
		title: "Security",
		body: stepUpPanel(v.s, `${CONSOLE_BASE}/security`) + (v.notice?.once ?? "") + "<h2>Injectors</h2><p class=\"muted\">A browser injector is your own browser extension. After you approve one request on Telegram it receives that credential encrypted to its key and places it in your browser. See docs/ops/injector-channel.md.</p>" + unavailable(injectors) + table("Injectors", [
			"Injector",
			"Public key thumbprint",
			"Enrolled",
			"Last used",
			"Status",
			"Action"
		], injectorRows) + `<fieldset><legend>Enroll an injector</legend>` + postForm(v.s, "/security/injectors/enroll", input("name", "Name for this browser", {
			required: true,
			max: 64
		}) + input("public_key_jwk", "Public key (JWK) shown by the extension", {
			required: true,
			max: 600
		}), "Enroll (needs passkey confirmation)") + "</fieldset><h2>Passkeys</h2>" + table("Passkeys", [
			"Passkey",
			"Transports",
			"Added",
			"Last used",
			"Flag",
			"Action"
		], passkeyRows) + `<fieldset><legend>Add a passkey</legend><label for="f-label">Name for the new passkey</label><input id="f-label" type="text" maxlength="64" autocomplete="off"><button type="button" data-webauthn="register" data-base="${CONSOLE_BASE}/security/passkeys" data-csrf="${e(v.s.csrf)}" data-next="${CONSOLE_BASE}/security" data-status="add-status">Add passkey</button><p id="add-status" class="muted" role="status" aria-live="polite"></p></fieldset><h2>Sessions</h2>` + table("Sessions", [
			"Session",
			"Passkey",
			"Opened",
			"Last seen",
			"Expires",
			"Browser",
			"Action"
		], sessionRows) + `<p class="muted">Lost every passkey? Run admin_console_bootstrap over local stdio and enroll again at ${CONSOLE_BASE}/enroll.</p>`,
		session: v.s,
		notice: v.notice,
		status: v.status,
		script: true
	});
}
function loginPage(notice, extra = {}) {
	return page({
		title: "Sign in",
		body: `<p>Sign in with the passkey you enrolled for this vault.</p><button type="button" data-webauthn="auth" data-base="${CONSOLE_BASE}/login" data-next="${CONSOLE_BASE}" data-status="login-status">Sign in with passkey</button><p id="login-status" class="muted" role="status" aria-live="polite"></p><p class="muted">No passkey yet, or lost them all? <a href="${CONSOLE_BASE}/enroll">Enroll with a bootstrap code</a>.</p>`,
		script: true,
		notice,
		extra
	});
}
function enrollPage() {
	return page({
		title: "Enroll a passkey",
		body: `<p>Enrolling a passkey needs a one-time bootstrap code. Mint it on the vault host over local stdio (<code>admin_console_bootstrap</code>); it is valid for 15 minutes and works once.</p><label for="f-code">Bootstrap code</label><input id="f-code" type="password" maxlength="64" autocomplete="off" autocapitalize="off" spellcheck="false" required><label for="f-label">Name for this passkey</label><input id="f-label" type="text" maxlength="64" autocomplete="off"><button type="button" data-webauthn="register" data-base="${CONSOLE_BASE}/enroll" data-next="${CONSOLE_BASE}/login" data-status="enroll-status">Register passkey</button><p id="enroll-status" class="muted" role="status" aria-live="polite"></p><p class="muted"><a href="${CONSOLE_BASE}/login">Back to sign in</a></p>`,
		script: true
	});
}
function disabledPage(cfg) {
	return message(503, "Owner console disabled", `${cfg.reason === "unset" ? "ECHO_VAULT_CONSOLE_ORIGIN is not set." : cfg.reason === "localhost_not_allowed" ? "ECHO_VAULT_CONSOLE_ORIGIN is an http://localhost origin and ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST=1 is not set." : "ECHO_VAULT_CONSOLE_ORIGIN is not a bare https origin (https://host[:port])."} The console does not operate until the operator configures it. The local stdio interface is unaffected.`);
}
var FORM_ACTIONS = {
	"/clients/scopes": {
		run: async (v, f, form) => noticeOf(await call(v, "admin_set_client_scopes", {
			client_id: f("client_id"),
			scopes: form.getAll("scope")
		}), "Scopes updated."),
		render: clientsPage
	},
	"/clients/revoke": {
		run: async (v, f) => noticeOf(await call(v, "admin_revoke_client", { client_id: f("client_id") }), "Client revoked."),
		render: clientsPage
	},
	"/grants/revoke": {
		run: async (v, f) => {
			const all = f("all") === "1";
			const args = {
				client_id: f("client_id"),
				entry_id: f("entry_id")
			};
			if (!all) {
				if (!f("host") || !f("path_prefix")) return {
					ok: false,
					text: "Refused: host and path_prefix are required to revoke one grant."
				};
				args.host = f("host");
				args.path_prefix = f("path_prefix");
			}
			return noticeOf(await call(v, "admin_revoke_grant", args), all ? "All grants for the pair revoked." : "Grant revoked.");
		},
		render: grantsPage
	},
	"/entries/rotation": {
		run: async (v, f) => {
			const args = {
				entry_id: f("entry_id"),
				mode: f("mode")
			};
			if (f("interval_days")) args.interval_days = Number(f("interval_days"));
			if (f("provider_token_id")) args.provider_token_id = f("provider_token_id");
			return noticeOf(await call(v, "admin_set_rotation", args), "Rotation policy saved.");
		},
		render: entriesPage
	},
	"/entries/rotate": {
		run: async (v, f) => noticeOf(await call(v, "admin_rotate_entry", { entry_id: f("entry_id") }), "Entry rotated. The new secret went straight to the vault."),
		render: entriesPage
	},
	"/entries/reentry": {
		run: async (v, f) => noticeOf(await call(v, "admin_request_reentry", { entry_id: f("entry_id") }), "A single-use card link was sent to Telegram."),
		render: entriesPage
	},
	"/entries/delete": {
		run: async (v, f) => noticeOf(await call(v, "admin_delete_entry", { entry_id: f("entry_id") }), "Entry soft-deleted."),
		render: entriesPage
	},
	"/entries/purge": {
		run: async (v, f) => noticeOf(await call(v, "admin_purge_entry", {
			entry_id: f("entry_id"),
			confirm: f("confirm")
		}), "Entry purged."),
		render: entriesPage
	},
	"/audit/verify": {
		run: async (v) => {
			const result = await call(v, "audit_verify");
			const d = dataOf(result);
			if (!d) return noticeOf(result, "");
			const anchor = typeof d.anchor === "object" && d.anchor !== null ? String(d.anchor.verdict) : d.anchor_error ? String(d.anchor_error) : "nothing anchored";
			return d.ok === true ? {
				ok: true,
				text: `Chain intact: ${String(d.count)} rows. Newest anchor: ${anchor}.`
			} : {
				ok: false,
				text: `Chain BROKEN at seq ${String(d.broken_at_seq)} (${String(d.reason)}). Newest anchor: ${anchor}.`
			};
		},
		render: (v) => auditPage(v)
	},
	"/audit/anchor": {
		run: async (v) => {
			const result = await call(v, "admin_anchor_now");
			const d = dataOf(result);
			return d ? {
				ok: true,
				text: `Anchor: ${String(d.status)}${d.seq !== void 0 ? ` (seq ${String(d.seq)})` : ""}.`
			} : noticeOf(result, "");
		},
		render: (v) => auditPage(v)
	},
	"/audit/verify-anchor": {
		run: async (v, f) => {
			const result = await call(v, "admin_verify_anchor", { line: f("line").slice(0, 400) });
			const d = dataOf(result);
			if (!d) return noticeOf(result, "");
			return {
				ok: d.verdict === "ok",
				text: `Anchor verdict: ${String(d.verdict)} (mac checked: ${String(d.mac_checked)}, known locally: ${String(d.known_locally)}, ledger head seq ${String(d.head_seq)}).`
			};
		},
		render: (v) => auditPage(v)
	},
	"/security/injectors/enroll": {
		run: async (v, f) => {
			const result = await call(v, "admin_enroll_injector", {
				name: f("name"),
				public_key_jwk: f("public_key_jwk")
			});
			const d = dataOf(result);
			if (!d) return noticeOf(result, "");
			return {
				ok: true,
				text: "Injector enrolled.",
				once: `<fieldset><legend>New injector — copy these now</legend><dl><dt>Injector id</dt><dd><code>${e(d.injector_id)}</code></dd><dt>Injector token</dt><dd><code>${e(d.injector_token)}</code></dd></dl><p class="bad">The token is shown only this once and is stored as a hash. Paste it into the extension, then leave this page.</p></fieldset>`
			};
		},
		render: securityPage
	},
	"/security/injectors/revoke": {
		run: async (v, f) => noticeOf(await call(v, "admin_revoke_injector", { injector_id: f("injector_id") }), "Injector revoked."),
		render: securityPage
	},
	"/security/passkeys/remove": {
		run: async (v, f) => noticeOf(await removePasskey(v.s, f("credential_id"), v.deps), "Passkey removed."),
		render: securityPage
	},
	"/security/sessions/revoke": {
		run: async (v, f) => noticeOf(await revokeSession(v.s, f("session_id"), v.deps), "Session revoked."),
		render: securityPage
	}
};
var GET_PAGES = {
	"": overviewPage,
	"/clients": clientsPage,
	"/grants": grantsPage,
	"/entries": entriesPage,
	"/audit": (v) => auditPage(v),
	"/digest": (v) => digestPage(v),
	"/security": securityPage
};
var JSON_ANON = /* @__PURE__ */ new Set([
	"/login/options",
	"/login/verify",
	"/enroll/options",
	"/enroll/verify"
]);
var JSON_SESSION = /* @__PURE__ */ new Set([
	"/stepup/options",
	"/stepup/verify",
	"/security/passkeys/options",
	"/security/passkeys/verify"
]);
var JSON_STATUS = {
	rate_limited: 429,
	step_up_required: 403,
	ledger_unavailable: 503
};
function jsonResult(result) {
	if (result.ok) return json(200, { ok: true });
	const error = result.error ?? "failed";
	return json(JSON_STATUS[error] ?? 400, {
		ok: false,
		error
	});
}
[
	...Object.keys(GET_PAGES).map((p) => `GET ${CONSOLE_BASE}${p}`),
	`${CONSOLE_BASE}`,
	`${CONSOLE_BASE}`,
	...[...JSON_ANON, ...JSON_SESSION].map((p) => `POST ${CONSOLE_BASE}${p}`),
	...Object.keys(FORM_ACTIONS).map((p) => `POST ${CONSOLE_BASE}${p}`),
	`${CONSOLE_BASE}`,
	`${CONSOLE_BASE}`
];
async function handlePost(request, path, url, cfg, deps) {
	const wantsJson = JSON_ANON.has(path) || JSON_SESSION.has(path);
	const refuse = (status, error, text) => wantsJson ? json(status, {
		ok: false,
		error
	}) : message(status, "Request refused", text);
	if (!(wantsJson || path === "/logout" || path === "/digest/send" || Object.prototype.hasOwnProperty.call(FORM_ACTIONS, path))) return message(404, "Not found", "No such console page.");
	if (!sameOriginConsolePost(request, cfg)) {
		log.warn("vault_console_post_rejected", {
			reason: "cross_origin",
			path
		});
		return refuse(403, "cross_origin", "This request did not come from the console's own pages.");
	}
	const body = await readBody(request);
	if (body === "unsupported") return refuse(415, "unsupported_media_type", "Unsupported request encoding.");
	if (body === "too_large") return refuse(413, "request_too_large", "The request is too large.");
	if (body === "invalid" || body.kind === "json" !== wantsJson) return refuse(400, "invalid_body", "The request body is not valid.");
	if (JSON_ANON.has(path) && body.kind === "json") {
		const b = body.value;
		if (path === "/login/options") {
			const started = await beginLogin(deps);
			return started.ok ? json(200, {
				ok: true,
				options: started.options
			}) : jsonResult(started);
		}
		if (path === "/login/verify") {
			const done = await finishLogin(b.response, { userAgent: request.headers.get("user-agent") }, deps);
			return done.ok ? json(200, { ok: true }, { cookie: sessionCookie(done.token) }) : jsonResult(done);
		}
		if (path === "/enroll/options") {
			const started = await beginEnroll(b.code, deps);
			return started.ok ? json(200, {
				ok: true,
				options: started.options
			}) : jsonResult(started);
		}
		return jsonResult(await finishEnroll(b.code, b.response, b.label, deps));
	}
	const auth = await sessionOf(request, deps);
	if (!auth) return wantsJson ? json(401, {
		ok: false,
		error: "unauthenticated"
	}) : redirect(`${CONSOLE_BASE}/login`, { cookie: CLEAR_COOKIE });
	const presented = body.kind === "form" ? body.value.get("csrf") : request.headers.get("x-csrf-token");
	if (!csrfTokenMatches(auth.token, presented)) {
		log.warn("vault_console_post_rejected", {
			reason: "csrf",
			path
		});
		return refuse(403, "csrf", "The form's security token is missing or stale. Reload the page and try again.");
	}
	const s = auth.session;
	if (body.kind === "json") {
		const b = body.value;
		if (path === "/stepup/options") {
			const started = await beginStepUp(s, deps);
			return started.ok ? json(200, {
				ok: true,
				options: started.options
			}) : jsonResult(started);
		}
		if (path === "/stepup/verify") return jsonResult(await finishStepUp(s, b.response, deps));
		if (path === "/security/passkeys/options") {
			const started = await beginAddPasskey(s, deps);
			return started.ok ? json(200, {
				ok: true,
				options: started.options
			}) : jsonResult(started);
		}
		return jsonResult(await finishAddPasskey(s, b.response, b.label, deps));
	}
	const form = body.value;
	if (path === "/logout") {
		await logout(s, deps);
		return redirect(`${CONSOLE_BASE}/login`, { cookie: CLEAR_COOKIE });
	}
	const view = {
		s,
		deps,
		url
	};
	if (path === "/digest/send") {
		for (const k of ["from", "to"]) if (form.get(k)) url.searchParams.set(k, String(form.get(k)));
		return digestPage(view, true);
	}
	const action = FORM_ACTIONS[path];
	const notice = await action.run(view, (name) => (form.get(name) ?? "").trim(), form);
	const again = await sessionOf(request, deps);
	if (!again) return redirect(`${CONSOLE_BASE}/login`, { cookie: CLEAR_COOKIE });
	return action.render({
		s: again.session,
		deps,
		url,
		notice,
		status: notice.ok ? 200 : notice.code === "step_up_required" ? 403 : 400
	});
}
/**
* Entry point for every request under /console. `deps` is the test seam
* (stores, clock, env, gateway wiring); production passes nothing.
*/
async function handleConsoleRequest(request, deps = {}) {
	const method = request.method.toUpperCase();
	let wantsJson = false;
	try {
		const cfg = consoleConfig(deps.env ?? process.env);
		if (!cfg.ok) return disabledPage(cfg);
		const url = new URL(request.url);
		const full = url.pathname.replace(/\/+$/, "");
		if (full !== "/console" && !full.startsWith(`/console/`)) return message(404, "Not found", "No such console page.");
		const path = full.slice(8);
		wantsJson = JSON_ANON.has(path) || JSON_SESSION.has(path);
		if (method === "POST") return await handlePost(request, path, url, cfg, deps);
		if (method !== "GET" && method !== "HEAD") return message(405, "Method not allowed", "Use the console's pages.", { allow: "GET, HEAD, POST" });
		if (path === "/enroll") return enrollPage();
		const auth = await sessionOf(request, deps);
		if (path === "/login") return auth ? redirect(CONSOLE_BASE) : loginPage();
		const render = Object.prototype.hasOwnProperty.call(GET_PAGES, path) ? GET_PAGES[path] : void 0;
		if (!render) return message(404, "Not found", "No such console page.");
		if (!auth) return redirect(`${CONSOLE_BASE}/login`, cookieTokens(request).length ? { cookie: CLEAR_COOKIE } : {});
		return await render({
			s: auth.session,
			deps,
			url
		});
	} catch (err) {
		const limited = err instanceof RateLimitUnavailableError;
		const code = limited ? "rate_limit_unavailable" : err instanceof ConsoleError ? err.code : "internal_error";
		log.error("vault_console_page_error", {
			code,
			error_class: err instanceof Error ? err.name : "unknown",
			method
		});
		const status = limited || code === "ledger_unavailable" || code === "console_disabled" ? 503 : 500;
		if (wantsJson) return json(status, {
			ok: false,
			error: code
		});
		return message(status, status === 503 ? "Temporarily unavailable" : "Something went wrong", "The console could not process this request. Nothing was changed by it.");
	}
}
//#endregion
export { handleConsoleRequest };
