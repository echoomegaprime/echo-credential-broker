// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 OAuth persistence: registered clients, pending owner approvals,
 * authorization codes, and access/refresh tokens.
 *
 * Invariant: no raw bearer material is ever stored. Codes, tokens, and
 * pending-authorization handles are persisted only as lowercase sha256 hex
 * (`*_hash` columns, enforced by CHECK constraints in
 * migrations/0002_vault_oauth.sql). A database dump therefore cannot be
 * replayed as a credential.
 *
 * Two implementations sit behind one `OAuthStore` interface:
 *   - `MemoryOAuthStore` — tests and single-process dev.
 *   - `SqlOAuthStore`    — `getSql()` from src/lib/db.ts (PGlite locally,
 *                          Postgres when DATABASE_URL is set). db.ts is imported
 *                          lazily so this module stays loadable under plain
 *                          `node --experimental-strip-types` (no Vite globals).
 *
 * All timestamps are epoch milliseconds (bigint columns) so the caller's
 * injectable clock is the only source of time.
 */
import type { Sql } from "../../db.ts";

export type ClientStatus = "registered" | "approved" | "denied" | "revoked";
export type PendingStatus = "pending" | "completed" | "denied" | "expired";
export type TokenKind = "access" | "refresh";

export interface OAuthClientRecord {
  /** "oc_<random>" */
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  /** Scopes the client asked for at registration (filtered to supported). Informational. */
  requested_scopes: string[];
  /** Scopes the owner granted. Empty until the owner approves the client. */
  granted_scopes: string[];
  status: ClientStatus;
  created_at: number;
  approved_at: number | null;
  revoked_at: number | null;
}

export interface PendingAuthorizationRecord {
  /** sha256 hex of the "evp_…" handle shown to the browser. */
  id_hash: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scopes: string[];
  resource: string;
  state: string | null;
  approval_id: string;
  is_new_client: boolean;
  status: PendingStatus;
  created_at: number;
  expires_at: number;
}

export interface AuthCodeRecord {
  /** sha256 hex of the "evc_…" code. */
  code_hash: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scopes: string[];
  resource: string;
  /** Token family every token minted from this code joins (used for reuse revocation). */
  family_id: string;
  created_at: number;
  expires_at: number;
  used_at: number | null;
}

export interface TokenRecord {
  /** sha256 hex of the "eva_…" / "evr_…" token. */
  token_hash: string;
  kind: TokenKind;
  client_id: string;
  family_id: string;
  scopes: string[];
  resource: string;
  created_at: number;
  expires_at: number;
  /** Refresh tokens only: set when rotated. A second presentation = reuse. */
  used_at: number | null;
  revoked_at: number | null;
}

export type ConsumeCodeResult =
  | { status: "ok"; code: AuthCodeRecord }
  | { status: "reused"; code: AuthCodeRecord }
  | { status: "not_found" };

export interface OAuthStore {
  // clients
  createClient(rec: OAuthClientRecord): Promise<void>;
  getClient(client_id: string): Promise<OAuthClientRecord | null>;
  listClients(): Promise<OAuthClientRecord[]>;
  countClients(): Promise<number>;
  updateClient(
    client_id: string,
    patch: Partial<Pick<OAuthClientRecord, "granted_scopes" | "status" | "approved_at" | "revoked_at">>,
  ): Promise<OAuthClientRecord | null>;
  /** Delete never-approved (registered/denied) clients created before `before`. Returns count. */
  deleteStaleClients(before: number): Promise<number>;

  // pending owner approvals
  createPending(rec: PendingAuthorizationRecord): Promise<void>;
  getPending(id_hash: string): Promise<PendingAuthorizationRecord | null>;
  /** Atomically move pending → completed. Returns the record only for the caller that won. */
  claimPending(id_hash: string): Promise<PendingAuthorizationRecord | null>;
  setPendingStatus(id_hash: string, status: Exclude<PendingStatus, "completed">): Promise<void>;
  /** Mark every still-pending authorization of a client as denied. */
  denyPendingForClient(client_id: string): Promise<number>;
  countActivePending(now: number): Promise<number>;
  expirePending(now: number): Promise<number>;

  // authorization codes
  saveCode(rec: AuthCodeRecord): Promise<void>;
  /** Atomically mark a code used. "reused" if it had already been used. */
  consumeCode(code_hash: string, now: number): Promise<ConsumeCodeResult>;

  // tokens
  saveToken(rec: TokenRecord): Promise<void>;
  getToken(token_hash: string): Promise<TokenRecord | null>;
  /** Atomically mark an unused, unrevoked refresh token used. true only for the caller that won. */
  markRefreshUsed(token_hash: string, now: number): Promise<boolean>;
  revokeToken(token_hash: string, now: number): Promise<boolean>;
  revokeFamily(family_id: string, now: number): Promise<number>;
  revokeClientTokens(client_id: string, now: number): Promise<number>;

  /** Housekeeping: drop expired codes/pending rows and long-expired tokens. */
  purgeExpired(now: number): Promise<void>;
}

/** Keep expired token rows this long so refresh-token reuse is still detectable. */
const TOKEN_RETENTION_AFTER_EXPIRY_MS = 24 * 60 * 60 * 1000;
const CODE_RETENTION_AFTER_EXPIRY_MS = 60 * 60 * 1000;
const PENDING_RETENTION_AFTER_EXPIRY_MS = 60 * 60 * 1000;

const HASH_RE = /^[0-9a-f]{64}$/;

function assertHash(value: string, what: string): void {
  if (!HASH_RE.test(value)) {
    // Never echo the value — if a caller passed a raw token here, the message
    // must not become the leak.
    throw new Error(`oauth_store_refused_unhashed_${what}`);
  }
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

function clone<T>(value: T): T {
  return structuredClone(value);
}

export class MemoryOAuthStore implements OAuthStore {
  private clients = new Map<string, OAuthClientRecord>();
  private pending = new Map<string, PendingAuthorizationRecord>();
  private codes = new Map<string, AuthCodeRecord>();
  private tokens = new Map<string, TokenRecord>();

  /** Test/inspection hook: a deep copy of everything persisted. */
  snapshot(): {
    clients: OAuthClientRecord[];
    pending: PendingAuthorizationRecord[];
    codes: AuthCodeRecord[];
    tokens: TokenRecord[];
  } {
    return {
      clients: [...this.clients.values()].map(clone),
      pending: [...this.pending.values()].map(clone),
      codes: [...this.codes.values()].map(clone),
      tokens: [...this.tokens.values()].map(clone),
    };
  }

  async createClient(rec: OAuthClientRecord): Promise<void> {
    if (this.clients.has(rec.client_id)) throw new Error("oauth_store_duplicate_client");
    this.clients.set(rec.client_id, clone(rec));
  }

  async getClient(client_id: string): Promise<OAuthClientRecord | null> {
    const rec = this.clients.get(client_id);
    return rec ? clone(rec) : null;
  }

  async listClients(): Promise<OAuthClientRecord[]> {
    return [...this.clients.values()].sort((a, b) => a.created_at - b.created_at).map(clone);
  }

  async countClients(): Promise<number> {
    return this.clients.size;
  }

  async updateClient(
    client_id: string,
    patch: Partial<Pick<OAuthClientRecord, "granted_scopes" | "status" | "approved_at" | "revoked_at">>,
  ): Promise<OAuthClientRecord | null> {
    const rec = this.clients.get(client_id);
    if (!rec) return null;
    const next = { ...rec, ...clone(patch) };
    this.clients.set(client_id, next);
    return clone(next);
  }

  async deleteStaleClients(before: number): Promise<number> {
    let n = 0;
    for (const [id, rec] of this.clients) {
      if ((rec.status === "registered" || rec.status === "denied") && rec.created_at < before) {
        const hasPending = [...this.pending.values()].some(
          (p) => p.client_id === id && p.status === "pending",
        );
        if (hasPending) continue;
        this.clients.delete(id);
        for (const [h, p] of this.pending) if (p.client_id === id) this.pending.delete(h);
        for (const [h, c] of this.codes) if (c.client_id === id) this.codes.delete(h);
        n += 1;
      }
    }
    return n;
  }

  async createPending(rec: PendingAuthorizationRecord): Promise<void> {
    assertHash(rec.id_hash, "pending");
    this.pending.set(rec.id_hash, clone(rec));
  }

  async getPending(id_hash: string): Promise<PendingAuthorizationRecord | null> {
    const rec = this.pending.get(id_hash);
    return rec ? clone(rec) : null;
  }

  async claimPending(id_hash: string): Promise<PendingAuthorizationRecord | null> {
    const rec = this.pending.get(id_hash);
    if (!rec || rec.status !== "pending") return null;
    rec.status = "completed";
    return clone(rec);
  }

  async setPendingStatus(id_hash: string, status: Exclude<PendingStatus, "completed">): Promise<void> {
    const rec = this.pending.get(id_hash);
    if (rec && rec.status === "pending") rec.status = status;
  }

  async denyPendingForClient(client_id: string): Promise<number> {
    let n = 0;
    for (const rec of this.pending.values()) {
      if (rec.client_id === client_id && rec.status === "pending") {
        rec.status = "denied";
        n += 1;
      }
    }
    return n;
  }

  async countActivePending(now: number): Promise<number> {
    let n = 0;
    for (const rec of this.pending.values()) if (rec.status === "pending" && rec.expires_at > now) n += 1;
    return n;
  }

  async expirePending(now: number): Promise<number> {
    let n = 0;
    for (const rec of this.pending.values()) {
      if (rec.status === "pending" && rec.expires_at <= now) {
        rec.status = "expired";
        n += 1;
      }
    }
    return n;
  }

  async saveCode(rec: AuthCodeRecord): Promise<void> {
    assertHash(rec.code_hash, "code");
    this.codes.set(rec.code_hash, clone(rec));
  }

  async consumeCode(code_hash: string, now: number): Promise<ConsumeCodeResult> {
    const rec = this.codes.get(code_hash);
    if (!rec) return { status: "not_found" };
    if (rec.used_at !== null) return { status: "reused", code: clone(rec) };
    rec.used_at = now;
    return { status: "ok", code: clone(rec) };
  }

  async saveToken(rec: TokenRecord): Promise<void> {
    assertHash(rec.token_hash, "token");
    this.tokens.set(rec.token_hash, clone(rec));
  }

  async getToken(token_hash: string): Promise<TokenRecord | null> {
    const rec = this.tokens.get(token_hash);
    return rec ? clone(rec) : null;
  }

  async markRefreshUsed(token_hash: string, now: number): Promise<boolean> {
    const rec = this.tokens.get(token_hash);
    if (!rec || rec.kind !== "refresh" || rec.used_at !== null || rec.revoked_at !== null) return false;
    rec.used_at = now;
    return true;
  }

  async revokeToken(token_hash: string, now: number): Promise<boolean> {
    const rec = this.tokens.get(token_hash);
    if (!rec || rec.revoked_at !== null) return false;
    rec.revoked_at = now;
    return true;
  }

  async revokeFamily(family_id: string, now: number): Promise<number> {
    let n = 0;
    for (const rec of this.tokens.values()) {
      if (rec.family_id === family_id && rec.revoked_at === null) {
        rec.revoked_at = now;
        n += 1;
      }
    }
    return n;
  }

  async revokeClientTokens(client_id: string, now: number): Promise<number> {
    let n = 0;
    for (const rec of this.tokens.values()) {
      if (rec.client_id === client_id && rec.revoked_at === null) {
        rec.revoked_at = now;
        n += 1;
      }
    }
    return n;
  }

  async purgeExpired(now: number): Promise<void> {
    for (const [h, c] of this.codes) if (c.expires_at + CODE_RETENTION_AFTER_EXPIRY_MS < now) this.codes.delete(h);
    for (const [h, p] of this.pending) {
      if (p.expires_at + PENDING_RETENTION_AFTER_EXPIRY_MS < now) this.pending.delete(h);
    }
    for (const [h, t] of this.tokens) {
      if (t.expires_at + TOKEN_RETENTION_AFTER_EXPIRY_MS < now) this.tokens.delete(h);
    }
  }
}

// ---------------------------------------------------------------------------
// SQL implementation (Postgres / PGlite via src/lib/db.ts)
// ---------------------------------------------------------------------------

type Row = Record<string, unknown>;

function num(v: unknown): number {
  return typeof v === "number" ? v : Number(v);
}

function numOrNull(v: unknown): number | null {
  return v === null || v === undefined ? null : num(v);
}

function strArray(v: unknown): string[] {
  const parsed = typeof v === "string" ? (JSON.parse(v) as unknown) : v;
  return Array.isArray(parsed) ? parsed.map(String) : [];
}

function toClient(r: Row): OAuthClientRecord {
  return {
    client_id: String(r.client_id),
    client_name: String(r.client_name),
    redirect_uris: strArray(r.redirect_uris),
    requested_scopes: strArray(r.requested_scopes),
    granted_scopes: strArray(r.granted_scopes),
    status: String(r.status) as ClientStatus,
    created_at: num(r.created_at),
    approved_at: numOrNull(r.approved_at),
    revoked_at: numOrNull(r.revoked_at),
  };
}

function toPending(r: Row): PendingAuthorizationRecord {
  return {
    id_hash: String(r.id_hash),
    client_id: String(r.client_id),
    redirect_uri: String(r.redirect_uri),
    code_challenge: String(r.code_challenge),
    scopes: strArray(r.scopes),
    resource: String(r.resource),
    state: r.state === null || r.state === undefined ? null : String(r.state),
    approval_id: String(r.approval_id),
    is_new_client: Boolean(r.is_new_client),
    status: String(r.status) as PendingStatus,
    created_at: num(r.created_at),
    expires_at: num(r.expires_at),
  };
}

function toCode(r: Row): AuthCodeRecord {
  return {
    code_hash: String(r.code_hash),
    client_id: String(r.client_id),
    redirect_uri: String(r.redirect_uri),
    code_challenge: String(r.code_challenge),
    scopes: strArray(r.scopes),
    resource: String(r.resource),
    family_id: String(r.family_id),
    created_at: num(r.created_at),
    expires_at: num(r.expires_at),
    used_at: numOrNull(r.used_at),
  };
}

function toToken(r: Row): TokenRecord {
  return {
    token_hash: String(r.token_hash),
    kind: String(r.kind) as TokenKind,
    client_id: String(r.client_id),
    family_id: String(r.family_id),
    scopes: strArray(r.scopes),
    resource: String(r.resource),
    created_at: num(r.created_at),
    expires_at: num(r.expires_at),
    used_at: numOrNull(r.used_at),
    revoked_at: numOrNull(r.revoked_at),
  };
}

async function defaultSqlProvider(): Promise<Sql> {
  // Lazy: db.ts relies on Vite's import.meta.glob for PGlite migrations.
  const { getSql } = await import("../../db.ts");
  return getSql();
}

export class SqlOAuthStore implements OAuthStore {
  private readonly provider: () => Promise<Sql>;

  constructor(provider: () => Promise<Sql> = defaultSqlProvider) {
    this.provider = provider;
  }

  private async q(text: string, params: unknown[] = []): Promise<Row[]> {
    const sql = await this.provider();
    return sql.query<Row>(text, params);
  }

  async createClient(rec: OAuthClientRecord): Promise<void> {
    await this.q(
      `insert into vault_oauth_clients
         (client_id, client_name, redirect_uris, requested_scopes, granted_scopes, status, created_at, approved_at, revoked_at)
       values ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6, $7, $8, $9)`,
      [
        rec.client_id,
        rec.client_name,
        JSON.stringify(rec.redirect_uris),
        JSON.stringify(rec.requested_scopes),
        JSON.stringify(rec.granted_scopes),
        rec.status,
        rec.created_at,
        rec.approved_at,
        rec.revoked_at,
      ],
    );
  }

  async getClient(client_id: string): Promise<OAuthClientRecord | null> {
    const rows = await this.q(`select * from vault_oauth_clients where client_id = $1`, [client_id]);
    return rows[0] ? toClient(rows[0]) : null;
  }

  async listClients(): Promise<OAuthClientRecord[]> {
    const rows = await this.q(`select * from vault_oauth_clients order by created_at asc, client_id asc`);
    return rows.map(toClient);
  }

  async countClients(): Promise<number> {
    const rows = await this.q(`select count(*)::int as n from vault_oauth_clients`);
    return num(rows[0]?.n ?? 0);
  }

  async updateClient(
    client_id: string,
    patch: Partial<Pick<OAuthClientRecord, "granted_scopes" | "status" | "approved_at" | "revoked_at">>,
  ): Promise<OAuthClientRecord | null> {
    const sets: string[] = [];
    const params: unknown[] = [client_id];
    if (patch.granted_scopes !== undefined) {
      params.push(JSON.stringify(patch.granted_scopes));
      sets.push(`granted_scopes = $${params.length}::jsonb`);
    }
    if (patch.status !== undefined) {
      params.push(patch.status);
      sets.push(`status = $${params.length}`);
    }
    if (patch.approved_at !== undefined) {
      params.push(patch.approved_at);
      sets.push(`approved_at = $${params.length}`);
    }
    if (patch.revoked_at !== undefined) {
      params.push(patch.revoked_at);
      sets.push(`revoked_at = $${params.length}`);
    }
    if (sets.length === 0) return this.getClient(client_id);
    const rows = await this.q(
      `update vault_oauth_clients set ${sets.join(", ")} where client_id = $1 returning *`,
      params,
    );
    return rows[0] ? toClient(rows[0]) : null;
  }

  async deleteStaleClients(before: number): Promise<number> {
    const rows = await this.q(
      `delete from vault_oauth_clients c
        where c.status in ('registered', 'denied')
          and c.created_at < $1
          and not exists (
            select 1 from vault_oauth_pending p
             where p.client_id = c.client_id and p.status = 'pending')
        returning c.client_id`,
      [before],
    );
    return rows.length;
  }

  async createPending(rec: PendingAuthorizationRecord): Promise<void> {
    assertHash(rec.id_hash, "pending");
    await this.q(
      `insert into vault_oauth_pending
         (id_hash, client_id, redirect_uri, code_challenge, scopes, resource, state, approval_id,
          is_new_client, status, created_at, expires_at)
       values ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12)`,
      [
        rec.id_hash,
        rec.client_id,
        rec.redirect_uri,
        rec.code_challenge,
        JSON.stringify(rec.scopes),
        rec.resource,
        rec.state,
        rec.approval_id,
        rec.is_new_client,
        rec.status,
        rec.created_at,
        rec.expires_at,
      ],
    );
  }

  async getPending(id_hash: string): Promise<PendingAuthorizationRecord | null> {
    const rows = await this.q(`select * from vault_oauth_pending where id_hash = $1`, [id_hash]);
    return rows[0] ? toPending(rows[0]) : null;
  }

  async claimPending(id_hash: string): Promise<PendingAuthorizationRecord | null> {
    const rows = await this.q(
      `update vault_oauth_pending set status = 'completed'
        where id_hash = $1 and status = 'pending' returning *`,
      [id_hash],
    );
    return rows[0] ? toPending(rows[0]) : null;
  }

  async setPendingStatus(id_hash: string, status: Exclude<PendingStatus, "completed">): Promise<void> {
    await this.q(
      `update vault_oauth_pending set status = $2 where id_hash = $1 and status = 'pending'`,
      [id_hash, status],
    );
  }

  async denyPendingForClient(client_id: string): Promise<number> {
    const rows = await this.q(
      `update vault_oauth_pending set status = 'denied'
        where client_id = $1 and status = 'pending' returning id_hash`,
      [client_id],
    );
    return rows.length;
  }

  async countActivePending(now: number): Promise<number> {
    const rows = await this.q(
      `select count(*)::int as n from vault_oauth_pending where status = 'pending' and expires_at > $1`,
      [now],
    );
    return num(rows[0]?.n ?? 0);
  }

  async expirePending(now: number): Promise<number> {
    const rows = await this.q(
      `update vault_oauth_pending set status = 'expired'
        where status = 'pending' and expires_at <= $1 returning id_hash`,
      [now],
    );
    return rows.length;
  }

  async saveCode(rec: AuthCodeRecord): Promise<void> {
    assertHash(rec.code_hash, "code");
    await this.q(
      `insert into vault_oauth_codes
         (code_hash, client_id, redirect_uri, code_challenge, scopes, resource, family_id,
          created_at, expires_at, used_at)
       values ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10)`,
      [
        rec.code_hash,
        rec.client_id,
        rec.redirect_uri,
        rec.code_challenge,
        JSON.stringify(rec.scopes),
        rec.resource,
        rec.family_id,
        rec.created_at,
        rec.expires_at,
        rec.used_at,
      ],
    );
  }

  async consumeCode(code_hash: string, now: number): Promise<ConsumeCodeResult> {
    const won = await this.q(
      `update vault_oauth_codes set used_at = $2
        where code_hash = $1 and used_at is null returning *`,
      [code_hash, now],
    );
    if (won[0]) return { status: "ok", code: toCode(won[0]) };
    const existing = await this.q(`select * from vault_oauth_codes where code_hash = $1`, [code_hash]);
    if (existing[0]) return { status: "reused", code: toCode(existing[0]) };
    return { status: "not_found" };
  }

  async saveToken(rec: TokenRecord): Promise<void> {
    assertHash(rec.token_hash, "token");
    await this.q(
      `insert into vault_oauth_tokens
         (token_hash, kind, client_id, family_id, scopes, resource, created_at, expires_at, used_at, revoked_at)
       values ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10)`,
      [
        rec.token_hash,
        rec.kind,
        rec.client_id,
        rec.family_id,
        JSON.stringify(rec.scopes),
        rec.resource,
        rec.created_at,
        rec.expires_at,
        rec.used_at,
        rec.revoked_at,
      ],
    );
  }

  async getToken(token_hash: string): Promise<TokenRecord | null> {
    const rows = await this.q(`select * from vault_oauth_tokens where token_hash = $1`, [token_hash]);
    return rows[0] ? toToken(rows[0]) : null;
  }

  async markRefreshUsed(token_hash: string, now: number): Promise<boolean> {
    const rows = await this.q(
      `update vault_oauth_tokens set used_at = $2
        where token_hash = $1 and kind = 'refresh' and used_at is null and revoked_at is null
        returning token_hash`,
      [token_hash, now],
    );
    return rows.length === 1;
  }

  async revokeToken(token_hash: string, now: number): Promise<boolean> {
    const rows = await this.q(
      `update vault_oauth_tokens set revoked_at = $2
        where token_hash = $1 and revoked_at is null returning token_hash`,
      [token_hash, now],
    );
    return rows.length === 1;
  }

  async revokeFamily(family_id: string, now: number): Promise<number> {
    const rows = await this.q(
      `update vault_oauth_tokens set revoked_at = $2
        where family_id = $1 and revoked_at is null returning token_hash`,
      [family_id, now],
    );
    return rows.length;
  }

  async revokeClientTokens(client_id: string, now: number): Promise<number> {
    const rows = await this.q(
      `update vault_oauth_tokens set revoked_at = $2
        where client_id = $1 and revoked_at is null returning token_hash`,
      [client_id, now],
    );
    return rows.length;
  }

  async purgeExpired(now: number): Promise<void> {
    await this.q(`delete from vault_oauth_codes where expires_at < $1`, [now - CODE_RETENTION_AFTER_EXPIRY_MS]);
    await this.q(`delete from vault_oauth_pending where expires_at < $1`, [
      now - PENDING_RETENTION_AFTER_EXPIRY_MS,
    ]);
    await this.q(`delete from vault_oauth_tokens where expires_at < $1`, [now - TOKEN_RETENTION_AFTER_EXPIRY_MS]);
  }
}

// ---------------------------------------------------------------------------
// Process-wide default (kept on globalThis so Vite HMR module copies share it)
// ---------------------------------------------------------------------------

const storeRef = globalThis as typeof globalThis & { __echoVaultOAuthStore__?: OAuthStore };

/** The active store. Defaults to SQL (PGlite / Postgres via getSql()). */
export function getOAuthStore(): OAuthStore {
  storeRef.__echoVaultOAuthStore__ ??= new SqlOAuthStore();
  return storeRef.__echoVaultOAuthStore__;
}

/** Replace the active store (tests inject MemoryOAuthStore). */
export function setOAuthStore(store: OAuthStore): void {
  storeRef.__echoVaultOAuthStore__ = store;
}
