// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Owner console storage (migrations/0011_vault_owner_console.sql).
 *
 * Four record kinds: passkeys (credential id, PUBLIC key, counter, transports),
 * WebAuthn challenges, console sessions and the single bootstrap code.
 * Challenges, session tokens and the bootstrap code are held as sha256 hex
 * only; the raw values never reach a store. Nothing here is a vault secret.
 *
 * Times are epoch milliseconds from the caller's clock (same convention as
 * rate-limit-store.ts), so the memory and SQL stores behave identically under
 * an injected clock. Every multi-condition transition is ONE statement (the
 * shared `Sql` surface has no transactions):
 *   - takeChallenge        delete … returning            (single use)
 *   - touchSession         update … where still valid    (idle + absolute expiry)
 *   - consumeBootstrapCode update … where unconsumed and unexpired
 *   - deletePasskeyUnlessLast: the delete requires another passkey row and
 *     locks it (`for update`), so two concurrent removals cannot both succeed
 *     and leave the console with no passkey.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import type { Sql } from "../../db.ts";

export type ChallengePurpose = "enroll" | "login" | "stepup" | "add_passkey";

export interface PasskeyRecord {
  /** base64url credential id. */
  credential_id: string;
  /** base64url COSE public key. Public material only. */
  public_key: string;
  counter: number;
  transports: string[];
  label: string;
  created_at: number;
  last_used_at: number | null;
  flagged_at: number | null;
  flag_reason: "counter_regression" | null;
}

export interface ChallengeRecord {
  challenge_hash: string;
  purpose: ChallengePurpose;
  session_id: string | null;
  created_at: number;
  expires_at: number;
}

export interface SessionRecord {
  /** Public handle (listing / revoking). Not the token. */
  id: string;
  token_hash: string;
  credential_id: string;
  created_at: number;
  last_seen_at: number;
  absolute_expires_at: number;
  step_up_at: number | null;
  revoked_at: number | null;
  user_agent: string;
}

export interface BootstrapRecord {
  code_hash: string;
  minted_by: string;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
}

export interface OwnerConsoleStore {
  readonly kind: "memory" | "sql";
  listPasskeys(): Promise<PasskeyRecord[]>;
  getPasskey(credentialId: string): Promise<PasskeyRecord | null>;
  /** False when the credential id already exists. */
  insertPasskey(rec: PasskeyRecord): Promise<boolean>;
  updatePasskeyUse(credentialId: string, counter: number, usedAt: number): Promise<void>;
  flagPasskey(credentialId: string, reason: "counter_regression", at: number): Promise<void>;
  /** Atomic: removes the passkey (and its sessions) only while another passkey exists. */
  deletePasskeyUnlessLast(credentialId: string): Promise<"deleted" | "last" | "not_found">;

  putChallenge(rec: ChallengeRecord): Promise<void>;
  /** Atomic single use: returns the row and deletes it, or null. Expiry is the caller's check. */
  takeChallenge(challengeHash: string): Promise<ChallengeRecord | null>;
  pruneChallenges(now: number): Promise<number>;

  insertSession(rec: SessionRecord): Promise<void>;
  /** Atomic: when the session is unrevoked, inside idle and absolute limits, set last_seen_at = now and return it. */
  touchSession(tokenHash: string, now: number, idleMs: number): Promise<SessionRecord | null>;
  /** Sessions that are still valid at `now`. */
  listSessions(now: number, idleMs: number): Promise<SessionRecord[]>;
  markStepUp(sessionId: string, at: number): Promise<void>;
  revokeSession(sessionId: string, at: number): Promise<boolean>;
  pruneSessions(now: number, idleMs: number): Promise<number>;

  /** Replace whatever code existed (at most one row ever exists). */
  setBootstrapCode(rec: BootstrapRecord): Promise<void>;
  /** True when this hash is the active, unconsumed, unexpired code. Does not consume. */
  checkBootstrapCode(codeHash: string, now: number): Promise<boolean>;
  /** Atomic single use. */
  consumeBootstrapCode(codeHash: string, now: number): Promise<boolean>;
}

export function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{16,1366}$/;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{32,8192}$/;
const TRANSPORT = /^[a-z][a-z-]{1,15}$/;
const MINTED_BY = /^local:[a-z0-9][a-z0-9._-]{0,63}$/;

function invalid(field: string): Error {
  return new Error(`owner_console_invalid_${field}`);
}

/** Keeps only well-formed transport hints (at most 8); anything else is dropped. */
export function cleanTransports(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const out: string[] = [];
  for (const t of input) {
    if (typeof t === "string" && TRANSPORT.test(t) && !out.includes(t)) out.push(t);
    if (out.length === 8) break;
  }
  return out;
}

function checkPasskey(rec: PasskeyRecord): void {
  if (!CREDENTIAL_ID.test(rec.credential_id)) throw invalid("credential_id");
  if (!PUBLIC_KEY.test(rec.public_key)) throw invalid("public_key");
  if (!Number.isInteger(rec.counter) || rec.counter < 0 || rec.counter > 0xffffffff) throw invalid("counter");
  if (rec.transports.length > 8 || !rec.transports.every((t) => TRANSPORT.test(t))) throw invalid("transports");
  if (typeof rec.label !== "string" || rec.label.length < 1 || rec.label.length > 64) throw invalid("label");
}

function checkChallenge(rec: ChallengeRecord): void {
  if (!HEX64.test(rec.challenge_hash)) throw invalid("challenge_hash");
  const bound = rec.purpose === "stepup" || rec.purpose === "add_passkey";
  if (bound !== (rec.session_id !== null)) throw invalid("challenge_session");
  if (rec.session_id !== null && !HEX32.test(rec.session_id)) throw invalid("challenge_session");
  if (!(rec.expires_at > rec.created_at)) throw invalid("challenge_expiry");
}

function checkSession(rec: SessionRecord): void {
  if (!HEX32.test(rec.id)) throw invalid("session_id");
  if (!HEX64.test(rec.token_hash)) throw invalid("token_hash");
  if (rec.user_agent.length > 200) throw invalid("user_agent");
}

function checkBootstrap(rec: BootstrapRecord): void {
  if (!HEX64.test(rec.code_hash)) throw invalid("code_hash");
  if (!MINTED_BY.test(rec.minted_by)) throw invalid("minted_by");
  if (!(rec.expires_at > rec.created_at)) throw invalid("bootstrap_expiry");
}

function sessionLive(s: SessionRecord, now: number, idleMs: number): boolean {
  return s.revoked_at === null && s.last_seen_at > now - idleMs && s.absolute_expires_at > now;
}

function sameHash(a: string, b: string): boolean {
  return a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** In-process store (tests). Same semantics as the SQL store. */
export class MemoryOwnerConsoleStore implements OwnerConsoleStore {
  readonly kind = "memory" as const;
  readonly passkeys = new Map<string, PasskeyRecord>();
  readonly challenges = new Map<string, ChallengeRecord>();
  readonly sessions = new Map<string, SessionRecord>();
  bootstrap: BootstrapRecord | null = null;

  async listPasskeys(): Promise<PasskeyRecord[]> {
    return [...this.passkeys.values()].sort((a, b) => a.created_at - b.created_at).map((p) => ({ ...p, transports: [...p.transports] }));
  }
  async getPasskey(credentialId: string): Promise<PasskeyRecord | null> {
    const p = this.passkeys.get(credentialId);
    return p ? { ...p, transports: [...p.transports] } : null;
  }
  async insertPasskey(rec: PasskeyRecord): Promise<boolean> {
    checkPasskey(rec);
    if (this.passkeys.has(rec.credential_id)) return false;
    this.passkeys.set(rec.credential_id, { ...rec, transports: [...rec.transports] });
    return true;
  }
  async updatePasskeyUse(credentialId: string, counter: number, usedAt: number): Promise<void> {
    const p = this.passkeys.get(credentialId);
    if (p) {
      p.counter = counter;
      p.last_used_at = usedAt;
    }
  }
  async flagPasskey(credentialId: string, reason: "counter_regression", at: number): Promise<void> {
    const p = this.passkeys.get(credentialId);
    if (p) {
      p.flagged_at = at;
      p.flag_reason = reason;
    }
  }
  async deletePasskeyUnlessLast(credentialId: string): Promise<"deleted" | "last" | "not_found"> {
    if (!this.passkeys.has(credentialId)) return "not_found";
    if (this.passkeys.size <= 1) return "last";
    this.passkeys.delete(credentialId);
    for (const [hash, s] of this.sessions) if (s.credential_id === credentialId) this.sessions.delete(hash);
    return "deleted";
  }

  async putChallenge(rec: ChallengeRecord): Promise<void> {
    checkChallenge(rec);
    this.challenges.set(rec.challenge_hash, { ...rec });
  }
  async takeChallenge(challengeHash: string): Promise<ChallengeRecord | null> {
    const rec = this.challenges.get(challengeHash) ?? null;
    this.challenges.delete(challengeHash);
    return rec;
  }
  async pruneChallenges(now: number): Promise<number> {
    let n = 0;
    for (const [hash, c] of this.challenges) {
      if (c.expires_at <= now) {
        this.challenges.delete(hash);
        n += 1;
      }
    }
    return n;
  }

  async insertSession(rec: SessionRecord): Promise<void> {
    checkSession(rec);
    if (!this.passkeys.has(rec.credential_id)) throw invalid("session_credential");
    this.sessions.set(rec.token_hash, { ...rec });
  }
  async touchSession(tokenHash: string, now: number, idleMs: number): Promise<SessionRecord | null> {
    const s = this.sessions.get(tokenHash);
    if (!s || !sessionLive(s, now, idleMs)) return null;
    s.last_seen_at = Math.max(s.last_seen_at, now);
    return { ...s };
  }
  async listSessions(now: number, idleMs: number): Promise<SessionRecord[]> {
    return [...this.sessions.values()].filter((s) => sessionLive(s, now, idleMs)).sort((a, b) => a.created_at - b.created_at).map((s) => ({ ...s }));
  }
  async markStepUp(sessionId: string, at: number): Promise<void> {
    for (const s of this.sessions.values()) if (s.id === sessionId) s.step_up_at = at;
  }
  async revokeSession(sessionId: string, at: number): Promise<boolean> {
    for (const s of this.sessions.values()) {
      if (s.id === sessionId && s.revoked_at === null) {
        s.revoked_at = at;
        return true;
      }
    }
    return false;
  }
  async pruneSessions(now: number, idleMs: number): Promise<number> {
    let n = 0;
    for (const [hash, s] of this.sessions) {
      if (!sessionLive(s, now, idleMs)) {
        this.sessions.delete(hash);
        n += 1;
      }
    }
    return n;
  }

  async setBootstrapCode(rec: BootstrapRecord): Promise<void> {
    checkBootstrap(rec);
    this.bootstrap = { ...rec };
  }
  private bootstrapLive(codeHash: string, now: number): BootstrapRecord | null {
    const b = this.bootstrap;
    return b && sameHash(b.code_hash, codeHash) && b.consumed_at === null && b.expires_at > now ? b : null;
  }
  async checkBootstrapCode(codeHash: string, now: number): Promise<boolean> {
    return this.bootstrapLive(codeHash, now) !== null;
  }
  async consumeBootstrapCode(codeHash: string, now: number): Promise<boolean> {
    // No await between the check and the write: one caller wins.
    const live = this.bootstrapLive(codeHash, now);
    if (!live) return false;
    live.consumed_at = now;
    return true;
  }
}

type SqlQuery = Pick<Sql, "query">;
type Row = Record<string, unknown>;

const num = (v: unknown): number => Number(v);
const numOrNull = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));

function passkeyRow(r: Row): PasskeyRecord {
  return {
    credential_id: String(r.credential_id),
    public_key: String(r.public_key),
    counter: num(r.counter),
    transports: String(r.transports ?? "") === "" ? [] : String(r.transports).split(","),
    label: String(r.label),
    created_at: num(r.created_at),
    last_used_at: numOrNull(r.last_used_at),
    flagged_at: numOrNull(r.flagged_at),
    flag_reason: r.flag_reason === "counter_regression" ? "counter_regression" : null,
  };
}

function sessionRow(r: Row): SessionRecord {
  return {
    id: String(r.id),
    token_hash: String(r.token_hash),
    credential_id: String(r.credential_id),
    created_at: num(r.created_at),
    last_seen_at: num(r.last_seen_at),
    absolute_expires_at: num(r.absolute_expires_at),
    step_up_at: numOrNull(r.step_up_at),
    revoked_at: numOrNull(r.revoked_at),
    user_agent: String(r.user_agent ?? ""),
  };
}

const SESSION_LIVE = "revoked_at is null and last_seen_at > $1::bigint - $2::bigint and absolute_expires_at > $1::bigint";

/** Postgres / PGlite store over the vault_console_* tables. */
export class SqlOwnerConsoleStore implements OwnerConsoleStore {
  readonly kind = "sql" as const;
  private readonly getSql: () => Promise<SqlQuery>;

  constructor(getSql?: () => Promise<SqlQuery>) {
    this.getSql =
      getSql ??
      (async () => {
        const db = await import("../../db.ts");
        return db.getSql();
      });
  }

  private async q(text: string, params: unknown[] = []): Promise<Row[]> {
    return (await this.getSql()).query<Row>(text, params);
  }

  async listPasskeys(): Promise<PasskeyRecord[]> {
    return (await this.q("select * from vault_console_passkeys order by created_at, credential_id")).map(passkeyRow);
  }
  async getPasskey(credentialId: string): Promise<PasskeyRecord | null> {
    const rows = await this.q("select * from vault_console_passkeys where credential_id = $1", [credentialId]);
    return rows[0] ? passkeyRow(rows[0]) : null;
  }
  async insertPasskey(rec: PasskeyRecord): Promise<boolean> {
    checkPasskey(rec);
    const rows = await this.q(
      `insert into vault_console_passkeys (credential_id, public_key, counter, transports, label, created_at)
       values ($1, $2, $3, $4, $5, $6) on conflict (credential_id) do nothing returning credential_id`,
      [rec.credential_id, rec.public_key, rec.counter, rec.transports.join(","), rec.label, rec.created_at],
    );
    return rows.length === 1;
  }
  async updatePasskeyUse(credentialId: string, counter: number, usedAt: number): Promise<void> {
    await this.q("update vault_console_passkeys set counter = $2, last_used_at = $3 where credential_id = $1", [credentialId, counter, usedAt]);
  }
  async flagPasskey(credentialId: string, reason: "counter_regression", at: number): Promise<void> {
    await this.q("update vault_console_passkeys set flagged_at = $3, flag_reason = $2 where credential_id = $1", [credentialId, reason, at]);
  }
  async deletePasskeyUnlessLast(credentialId: string): Promise<"deleted" | "last" | "not_found"> {
    // The EXISTS row is locked: a concurrent removal of that other passkey waits,
    // then re-checks and finds it gone (or deadlocks and errors). Either way the
    // table never reaches zero rows through this method.
    const rows = await this.q(
      `delete from vault_console_passkeys p
        where p.credential_id = $1
          and exists (select 1 from vault_console_passkeys o where o.credential_id <> $1 for update)
       returning p.credential_id`,
      [credentialId],
    );
    if (rows.length === 1) return "deleted";
    return (await this.getPasskey(credentialId)) ? "last" : "not_found";
  }

  async putChallenge(rec: ChallengeRecord): Promise<void> {
    checkChallenge(rec);
    await this.q(
      "insert into vault_console_challenges (challenge_hash, purpose, session_id, created_at, expires_at) values ($1, $2, $3, $4, $5)",
      [rec.challenge_hash, rec.purpose, rec.session_id, rec.created_at, rec.expires_at],
    );
  }
  async takeChallenge(challengeHash: string): Promise<ChallengeRecord | null> {
    const rows = await this.q("delete from vault_console_challenges where challenge_hash = $1 returning *", [challengeHash]);
    const r = rows[0];
    if (!r) return null;
    return {
      challenge_hash: String(r.challenge_hash),
      purpose: String(r.purpose) as ChallengePurpose,
      session_id: r.session_id === null || r.session_id === undefined ? null : String(r.session_id),
      created_at: num(r.created_at),
      expires_at: num(r.expires_at),
    };
  }
  async pruneChallenges(now: number): Promise<number> {
    return (await this.q("delete from vault_console_challenges where expires_at <= $1 returning challenge_hash", [now])).length;
  }

  async insertSession(rec: SessionRecord): Promise<void> {
    checkSession(rec);
    await this.q(
      `insert into vault_console_sessions
         (id, token_hash, credential_id, created_at, last_seen_at, absolute_expires_at, step_up_at, revoked_at, user_agent)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [rec.id, rec.token_hash, rec.credential_id, rec.created_at, rec.last_seen_at, rec.absolute_expires_at, rec.step_up_at, rec.revoked_at, rec.user_agent],
    );
  }
  async touchSession(tokenHash: string, now: number, idleMs: number): Promise<SessionRecord | null> {
    const rows = await this.q(
      `update vault_console_sessions set last_seen_at = greatest(last_seen_at, $1::bigint)
        where token_hash = $3 and ${SESSION_LIVE} returning *`,
      [now, idleMs, tokenHash],
    );
    return rows[0] ? sessionRow(rows[0]) : null;
  }
  async listSessions(now: number, idleMs: number): Promise<SessionRecord[]> {
    return (await this.q(`select * from vault_console_sessions where ${SESSION_LIVE} order by created_at, id`, [now, idleMs])).map(sessionRow);
  }
  async markStepUp(sessionId: string, at: number): Promise<void> {
    await this.q("update vault_console_sessions set step_up_at = $2 where id = $1", [sessionId, at]);
  }
  async revokeSession(sessionId: string, at: number): Promise<boolean> {
    const rows = await this.q("update vault_console_sessions set revoked_at = $2 where id = $1 and revoked_at is null returning id", [sessionId, at]);
    return rows.length === 1;
  }
  async pruneSessions(now: number, idleMs: number): Promise<number> {
    return (await this.q(`delete from vault_console_sessions where not (${SESSION_LIVE}) returning id`, [now, idleMs])).length;
  }

  async setBootstrapCode(rec: BootstrapRecord): Promise<void> {
    checkBootstrap(rec);
    await this.q(
      `insert into vault_console_bootstrap (id, code_hash, minted_by, created_at, expires_at, consumed_at)
       values (1, $1, $2, $3, $4, null)
       on conflict (id) do update set code_hash = excluded.code_hash, minted_by = excluded.minted_by,
         created_at = excluded.created_at, expires_at = excluded.expires_at, consumed_at = null`,
      [rec.code_hash, rec.minted_by, rec.created_at, rec.expires_at],
    );
  }
  async checkBootstrapCode(codeHash: string, now: number): Promise<boolean> {
    const rows = await this.q(
      "select 1 as ok from vault_console_bootstrap where id = 1 and code_hash = $1 and consumed_at is null and expires_at > $2",
      [codeHash, now],
    );
    return rows.length === 1;
  }
  async consumeBootstrapCode(codeHash: string, now: number): Promise<boolean> {
    const rows = await this.q(
      `update vault_console_bootstrap set consumed_at = $2
        where id = 1 and code_hash = $1 and consumed_at is null and expires_at > $2 returning id`,
      [codeHash, now],
    );
    return rows.length === 1;
  }
}

let defaultStore: OwnerConsoleStore | null = null;

/** SQL by default (Postgres when DATABASE_URL is set, otherwise the embedded PGlite). */
export function getDefaultOwnerConsoleStore(): OwnerConsoleStore {
  defaultStore ??= new SqlOwnerConsoleStore();
  return defaultStore;
}

/** Wiring/test hook. Pass null to restore the SQL default. */
export function setDefaultOwnerConsoleStore(store: OwnerConsoleStore | null): void {
  defaultStore = store;
}
