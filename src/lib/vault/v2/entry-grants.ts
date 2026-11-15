// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 entry consent grants.
 *
 * The owner's rule: "every use is consent-gated and audit-logged". A grant is
 * the record that the owner approved — on Telegram, for one specific first
 * request — that a client may repeat that read without being asked again.
 * gateway.ts consults it only for read-only (GET/HEAD) entry uses; non-GET uses
 * always need a fresh approval and never create or read a grant.
 *
 * Least privilege: a grant is NOT "this client may read the whole site forever".
 * It is scoped to (client_id, entry_id, host, path_prefix) and it expires
 * (`expires_at`) and may be use-capped (`uses_remaining`). A request matches a
 * grant only when the host is identical, the request path equals `path_prefix`
 * or sits under it (`path_prefix + "/"`), the grant has not expired, and it has
 * uses left. A client can therefore hold several narrow grants for one entry
 * (hence the four-column primary key), each for a different host/path.
 *
 * A grant holds no secret and no request content. `revokeEntryGrant` deletes
 * it (one narrow grant, or every grant for the pair); the approval that created
 * it stays in vault_approvals and the ledger. After revocation the client's
 * next use of that entry prompts the owner again.
 */
import type { Sql } from "../../db.ts";
import { log } from "../log.ts";

export interface EntryGrant {
  client_id: string;
  entry_id: string;
  /** The exact host the owner approved, e.g. "api.github.com". */
  host: string;
  /** The approved request's path; later requests must equal it or sit under it. */
  path_prefix: string;
  approval_id: string;
  granted_at: string;
  expires_at: string;
  /** The cap the grant was created with (audit only). null = unlimited. */
  max_uses: number | null;
  /** Remaining un-prompted uses. null = unlimited; 0 = spent (no longer matches). */
  uses_remaining: number | null;
}

export interface EntryGrantStore {
  /**
   * The matching grant (not expired at `now`, host identical, request `path`
   * equals `path_prefix` or sits under it, uses_remaining null or > 0), or null.
   * When several grants match, the most specific (longest path_prefix) wins.
   */
  find(client_id: string, entry_id: string, host: string, path: string, now: number): Promise<EntryGrant | null>;
  /**
   * Atomically spend one use of a matching grant: decrement `uses_remaining`
   * when it is non-null; an unlimited grant (null) is never decremented. Returns
   * true when a matching, unspent, unexpired grant was found (and spent).
   */
  consume(client_id: string, entry_id: string, host: string, path: string, now: number): Promise<boolean>;
  /** Idempotent: an existing grant (same primary key) is kept as is. */
  add(grant: EntryGrant): Promise<void>;
  /**
   * Remove one narrow grant (host + path_prefix given) or EVERY grant for the
   * (client_id, entry_id) pair (both omitted). Returns whether anything was removed.
   */
  remove(client_id: string, entry_id: string, host?: string, path_prefix?: string): Promise<boolean>;
  list(filter?: { client_id?: string; entry_id?: string }): Promise<EntryGrant[]>;
}

const ENTRY_ID_PATTERN = /^ve_[0-9a-f]{32}$/;

function validKey(client_id: unknown, entry_id: unknown): boolean {
  return (
    typeof client_id === "string" &&
    client_id.length > 0 &&
    client_id.length <= 200 &&
    typeof entry_id === "string" &&
    ENTRY_ID_PATTERN.test(entry_id)
  );
}

function validScope(host: unknown, path_prefix: unknown): boolean {
  return (
    typeof host === "string" &&
    host.length > 0 &&
    host.length <= 253 &&
    typeof path_prefix === "string" &&
    path_prefix.length > 0 &&
    path_prefix.length <= 1024
  );
}

/** A request path is covered by a grant's prefix when it equals it or sits under it. */
export function pathUnderPrefix(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(`${prefix}/`);
}

function unexpired(grant: EntryGrant, now: number): boolean {
  const exp = Date.parse(grant.expires_at);
  return Number.isFinite(exp) && exp > now;
}

function hasUsesLeft(grant: EntryGrant): boolean {
  return grant.uses_remaining === null || grant.uses_remaining > 0;
}

/** In-memory store (tests / single process). */
export class MemoryEntryGrantStore implements EntryGrantStore {
  private readonly rows = new Map<string, EntryGrant>();

  private key(client_id: string, entry_id: string, host: string, path_prefix: string): string {
    return [client_id, entry_id, host, path_prefix].join("\u0000");
  }

  /** Non-expired, unspent grants matching (client, entry, host) whose prefix covers `path`, most specific first. */
  private matches(client_id: string, entry_id: string, host: string, path: string, now: number): EntryGrant[] {
    if (!validKey(client_id, entry_id)) return [];
    return [...this.rows.values()]
      .filter(
        (g) =>
          g.client_id === client_id &&
          g.entry_id === entry_id &&
          g.host === host &&
          pathUnderPrefix(path, g.path_prefix) &&
          unexpired(g, now) &&
          hasUsesLeft(g),
      )
      .sort((a, b) => b.path_prefix.length - a.path_prefix.length);
  }

  async find(client_id: string, entry_id: string, host: string, path: string, now: number): Promise<EntryGrant | null> {
    const [best] = this.matches(client_id, entry_id, host, path, now);
    return best ? { ...best } : null;
  }

  async consume(client_id: string, entry_id: string, host: string, path: string, now: number): Promise<boolean> {
    const [best] = this.matches(client_id, entry_id, host, path, now);
    if (!best) return false;
    if (best.uses_remaining !== null) best.uses_remaining -= 1;
    return true;
  }

  async add(grant: EntryGrant): Promise<void> {
    if (!validKey(grant.client_id, grant.entry_id) || !validScope(grant.host, grant.path_prefix)) {
      throw new Error("invalid_entry_grant");
    }
    const key = this.key(grant.client_id, grant.entry_id, grant.host, grant.path_prefix);
    if (!this.rows.has(key)) this.rows.set(key, { ...grant });
  }

  async remove(client_id: string, entry_id: string, host?: string, path_prefix?: string): Promise<boolean> {
    if (!validKey(client_id, entry_id)) return false;
    if (host !== undefined && path_prefix !== undefined) {
      return this.rows.delete(this.key(client_id, entry_id, host, path_prefix));
    }
    let removed = false;
    for (const [key, g] of this.rows) {
      if (g.client_id === client_id && g.entry_id === entry_id) {
        this.rows.delete(key);
        removed = true;
      }
    }
    return removed;
  }

  async list(filter: { client_id?: string; entry_id?: string } = {}): Promise<EntryGrant[]> {
    return [...this.rows.values()]
      .filter((g) => (filter.client_id ? g.client_id === filter.client_id : true))
      .filter((g) => (filter.entry_id ? g.entry_id === filter.entry_id : true))
      .sort((a, b) => (a.granted_at < b.granted_at ? 1 : a.granted_at > b.granted_at ? -1 : 0))
      .map((g) => ({ ...g }));
  }
}

type SqlQuery = Pick<Sql, "query">;

function toIso(v: unknown): string {
  return v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString();
}

function toNum(v: unknown): number | null {
  return v == null ? null : Number(v);
}

function rowToGrant(r: Record<string, unknown>): EntryGrant {
  return {
    client_id: String(r.client_id),
    entry_id: String(r.entry_id),
    host: String(r.host),
    path_prefix: String(r.path_prefix),
    approval_id: String(r.approval_id),
    granted_at: toIso(r.granted_at),
    expires_at: toIso(r.expires_at),
    max_uses: toNum(r.max_uses),
    uses_remaining: toNum(r.uses_remaining),
  };
}

const GRANT_COLUMNS = "client_id, entry_id, host, path_prefix, approval_id, granted_at, expires_at, max_uses, uses_remaining";

// A request path is covered when it equals path_prefix or sits directly under
// it. `left(..)` avoids LIKE wildcards in a stored path_prefix matching loosely.
const PATH_MATCH = "($4::text = path_prefix or left($4::text, length(path_prefix) + 1) = path_prefix || '/')";

/** Postgres/PGLite store over `vault_entry_grants` (migrations/0006_vault_entry_grants.sql). */
export class SqlEntryGrantStore implements EntryGrantStore {
  private readonly getSql: () => Promise<SqlQuery>;

  constructor(getSql?: () => Promise<SqlQuery>) {
    this.getSql =
      getSql ??
      (async () => {
        const db = await import("../../db.ts");
        return db.getSql();
      });
  }

  async find(client_id: string, entry_id: string, host: string, path: string, now: number): Promise<EntryGrant | null> {
    if (!validKey(client_id, entry_id) || !validScope(host, path)) return null;
    const sql = await this.getSql();
    const rows = await sql.query<Record<string, unknown>>(
      `select ${GRANT_COLUMNS} from vault_entry_grants
        where client_id = $1 and entry_id = $2 and host = $3 and ${PATH_MATCH}
          and expires_at > $5::timestamptz and (uses_remaining is null or uses_remaining > 0)
        order by length(path_prefix) desc
        limit 1`,
      [client_id, entry_id, host, path, new Date(now).toISOString()],
    );
    return rows[0] ? rowToGrant(rows[0]) : null;
  }

  async consume(client_id: string, entry_id: string, host: string, path: string, now: number): Promise<boolean> {
    if (!validKey(client_id, entry_id) || !validScope(host, path)) return false;
    const sql = await this.getSql();
    const rows = await sql.query(
      `update vault_entry_grants set uses_remaining = uses_remaining - 1
        where client_id = $1 and entry_id = $2 and host = $3 and ${PATH_MATCH}
          and expires_at > $5::timestamptz and (uses_remaining is null or uses_remaining > 0)
        returning client_id`,
      [client_id, entry_id, host, path, new Date(now).toISOString()],
    );
    return rows.length >= 1;
  }

  async add(grant: EntryGrant): Promise<void> {
    if (!validKey(grant.client_id, grant.entry_id) || !validScope(grant.host, grant.path_prefix)) {
      throw new Error("invalid_entry_grant");
    }
    const sql = await this.getSql();
    await sql.query(
      `insert into vault_entry_grants
         (client_id, entry_id, host, path_prefix, approval_id, granted_at, expires_at, max_uses, uses_remaining)
       values ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8::integer, $9::integer)
       on conflict (client_id, entry_id, host, path_prefix) do nothing`,
      [
        grant.client_id,
        grant.entry_id,
        grant.host,
        grant.path_prefix,
        grant.approval_id,
        grant.granted_at,
        grant.expires_at,
        grant.max_uses,
        grant.uses_remaining,
      ],
    );
  }

  async remove(client_id: string, entry_id: string, host?: string, path_prefix?: string): Promise<boolean> {
    if (!validKey(client_id, entry_id)) return false;
    const sql = await this.getSql();
    const narrow = host !== undefined && path_prefix !== undefined;
    const rows = await sql.query(
      `delete from vault_entry_grants
        where client_id = $1 and entry_id = $2
          and ($3::boolean = false or (host = $4::text and path_prefix = $5::text))
        returning path_prefix`,
      [client_id, entry_id, narrow, host ?? null, path_prefix ?? null],
    );
    return rows.length >= 1;
  }

  async list(filter: { client_id?: string; entry_id?: string } = {}): Promise<EntryGrant[]> {
    const sql = await this.getSql();
    const rows = await sql.query<Record<string, unknown>>(
      `select ${GRANT_COLUMNS} from vault_entry_grants
        where ($1::text is null or client_id = $1::text) and ($2::text is null or entry_id = $2::text)
        order by granted_at desc`,
      [filter.client_id ?? null, filter.entry_id ?? null],
    );
    return rows.map(rowToGrant);
  }
}

let defaultStore: EntryGrantStore | null = null;

export function getDefaultEntryGrantStore(): EntryGrantStore {
  defaultStore ??= new SqlEntryGrantStore();
  return defaultStore;
}

/** Wiring/test hook. Pass null to restore the SQL default. */
export function setDefaultEntryGrantStore(store: EntryGrantStore | null): void {
  defaultStore = store;
}

/**
 * Owner action: withdraw a client's standing consent for one entry. With
 * `host`/`path_prefix` it removes one narrow grant; without, every grant for
 * the pair. The client's next covered use — read-only included — asks on
 * Telegram again. Returns whether anything was removed.
 */
export async function revokeEntryGrant(
  client_id: string,
  entry_id: string,
  store: EntryGrantStore = getDefaultEntryGrantStore(),
  host?: string,
  path_prefix?: string,
): Promise<boolean> {
  const removed = await store.remove(client_id, entry_id, host, path_prefix);
  log.warn("vault_entry_grant_revoked", { client_id, entry_id, host, path_prefix, existed: removed });
  return removed;
}

export async function listEntryGrants(
  filter: { client_id?: string; entry_id?: string } = {},
  store: EntryGrantStore = getDefaultEntryGrantStore(),
): Promise<EntryGrant[]> {
  return store.list(filter);
}
