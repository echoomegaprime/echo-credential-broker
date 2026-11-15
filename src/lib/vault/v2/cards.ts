// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 credential entries + credential cards.
 *
 * Invariant: agents may USE credentials, agents may NEVER READ credentials.
 *
 *   Entries   Metadata rows (`vault_entries`): site, account, purpose, kind,
 *             default flag, status, fingerprint (first 8 hex of sha256) and
 *             length. The secret VALUE lives only in the canonical vault
 *             backend under a per-entry key (`echo_vault_entry_<id>` / "entry")
 *             and is never written to SQL, a log line, an error or a return
 *             value. Many entries per site; identity is (site, account, kind).
 *
 *   useEntry  The one read path: the secret is handed to a callback that runs
 *             inside this module, the callback's result is scrubbed, the use is
 *             written to the ledger, and only metadata comes back.
 *
 *   Cards     An agent that needs a credential it does not have calls
 *             requestCard(). The operator gets a Telegram message with a
 *             single-use link (256-bit token, stored hashed, 30 minutes) to a
 *             page where they type the secret (card-pages.ts → submitCard()).
 *             The agent only ever sees {card_id, status, expires_at} and, once
 *             completed, the entry's metadata.
 *
 * deleteEntry is the reversible SOFT delete (status → deleted; the secret is
 * untouched). The irreversible step is rotation.ts → purgeEntry: it destroys the
 * stored secret (backend delete where one exists, otherwise an overwrite with
 * random bytes — the canonical vault has no delete, see store.ts) and then
 * hard-deletes the row, its cards and its grants.
 *
 * Rotation state (migrations/0007): rotation_mode, rotate_interval_days,
 * last_rotated_at, rotate_by, rotation_count, last_rotation_error and the
 * non-secret provider_token_id. A completed card re-entry counts as a manual
 * rotation; auto-rotation lives in rotation.ts.
 */
import { createHash, randomBytes } from "node:crypto";
import type { Sql } from "../../db.ts";
import type { VaultBackend } from "../backend.ts";
import { log } from "../log.ts";
import { containsSecretPrefix, redactString, redactValue, registerSecretForRedaction } from "../redaction.ts";
import { approverTelegramId, constantTimeEqual, sanitizeDisplayText } from "./approvals.ts";
import type { ClientIdentity, Decision, LedgerEntryInput, Tier } from "./contracts.ts";
import { appendLedger } from "./ledger.ts";

// ---------------------------------------------------------------- types

export type EntryKind = "password" | "api_key" | "oauth_token" | "operator_secret";
export type EntryStatus = "active" | "needs_reentry" | "deleted";
export type RotationMode = "manual" | "auto";

export const ENTRY_KINDS: readonly EntryKind[] = ["password", "api_key", "oauth_token", "operator_secret"];

/** Everything this module ever returns about an entry. No secret material. */
export interface EntryMetadata {
  id: string;
  /** `vault://entry/<id>` — an opaque reference, never a value. */
  ref: string;
  site: string;
  account: string;
  purpose: string;
  /** "site — account — purpose". */
  label: string;
  kind: EntryKind;
  is_default: boolean;
  status: EntryStatus;
  /** First 8 hex chars of sha256(secret). */
  fingerprint: string;
  secret_length: number;
  created_at: string;
  updated_at: string;
  last_used_at: string | null;
  last_verified_at: string | null;
  reentry_reason?: string;
  /** "manual": the owner re-enters the secret on a card. "auto": a provider rotator rolls it (rotation.ts). */
  rotation_mode: RotationMode;
  /** Rotate every N days (1..3650); null = no schedule. */
  rotate_interval_days: number | null;
  /** Last successful rotation (card re-entry or auto-rotate). */
  last_rotated_at: string | null;
  /** When the next rotation is due; null = never. */
  rotate_by: string | null;
  rotation_count: number;
  /** Short code of the last failed rotation attempt (never provider text); cleared by a success. */
  last_rotation_error: string | null;
  /** Provider-side NON-SECRET id needed to rotate (e.g. a Cloudflare API token id). Never a token value. */
  provider_token_id: string | null;
}

export type CardStoredStatus = "pending" | "claimed" | "completed" | "expired";
export type CardStatus = "pending" | "completed" | "expired";

export interface CardRecord {
  id: string;
  /** sha256 hex of the URL token. The token itself is never stored. */
  token_hash: string;
  client_id: string;
  client_name: string;
  site: string;
  account: string | null;
  purpose: string | null;
  kind: EntryKind;
  reason: string;
  /** Re-entry: the entry whose secret is replaced. New card: set on completion. */
  entry_id: string | null;
  is_reentry: boolean;
  status: CardStoredStatus;
  created_at: string;
  expires_at: string;
  completed_at?: string;
}

/** Sanitized error: `code` is stable; the message never carries a secret or upstream text. */
export class EntryError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "EntryError";
    this.code = code;
  }
}

export class CardError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "CardError";
    this.code = code;
  }
}

// ---------------------------------------------------------------- constants

export const CARD_TTL_MS = 30 * 60 * 1000;
export const MIN_SECRET_LENGTH = 8; // redaction.ts only arms secrets of 8+ chars
export const MAX_SECRET_LENGTH = 4096;
export const MAX_PENDING_CARDS_PER_CLIENT = 5;
const TOKEN_BYTES = 32; // 256 bits
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const ENTRY_ID_PATTERN = /^ve_[0-9a-f]{32}$/;
const CARD_ID_PATTERN = /^vc_[0-9a-f]{32}$/;
const SITE_PATTERN = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const ACCOUNT_PATTERN = /^[\x21-\x7e]{1,254}$/;
const PURPOSE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._:@/+-]{0,63}$/;
const PROVIDER_TOKEN_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const ROTATION_ERROR_PATTERN = /^[a-z0-9_]{1,64}$/;
export const MAX_ROTATE_INTERVAL_DAYS = 3650;
const DAY_MS = 86_400_000;
const DEFAULT_PURPOSE = "general";
const BACKEND_USERNAME = "entry";
const BYPASS_REASON =
  "echo-credential-broker vault v2 entry: the secret is typed by the operator on a single-use card page or used " +
  "server-side inside useEntry for one audited action; it is never returned across an MCP/HTTP boundary.";

// ---------------------------------------------------------------- normalization

function invalid(field: string, message: string): EntryError {
  return new EntryError(`invalid_${field}`, message);
}

function looksLikeSecret(value: string): boolean {
  return containsSecretPrefix(value) || redactString(value) !== value;
}

/** "https://www.GitHub.com:443/login" → "github.com". Throws `invalid_site`. */
export function normalizeSite(input: unknown): string {
  if (typeof input !== "string") throw invalid("site", "Site must be a domain such as github.com");
  let s = input.trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  s = s.split(/[/?#]/)[0] ?? "";
  s = s.slice(s.lastIndexOf("@") + 1);
  s = s.replace(/:\d{1,5}$/, "").replace(/\.$/, "").replace(/^www\./, "");
  if (!SITE_PATTERN.test(s)) throw invalid("site", "Site must be a domain such as github.com");
  return s;
}

export function normalizeAccount(input: unknown): string {
  const a = typeof input === "string" ? input.trim() : "";
  if (!ACCOUNT_PATTERN.test(a)) {
    throw invalid("account", "Account must be 1-254 printable ASCII characters without spaces");
  }
  if (looksLikeSecret(a)) throw invalid("account", "Account looks like a secret; enter the username or email instead");
  return a;
}

export function normalizePurpose(input: unknown): string {
  const p = typeof input === "string" ? input.trim().replace(/\s+/g, " ") : "";
  if (!p) return DEFAULT_PURPOSE;
  if (!PURPOSE_PATTERN.test(p)) {
    throw invalid("purpose", "Purpose must be a short tag (letters, digits, space and . _ : @ / + -; max 64)");
  }
  if (looksLikeSecret(p)) throw invalid("purpose", "Purpose looks like a secret; enter a short tag instead");
  return p;
}

function normalizeKind(input: unknown): EntryKind {
  if (typeof input !== "string" || !ENTRY_KINDS.includes(input as EntryKind)) {
    throw invalid("kind", `Kind must be one of: ${ENTRY_KINDS.join(", ")}`);
  }
  return input as EntryKind;
}

export function entryLabel(site: string, account: string, purpose: string): string {
  return `${site} — ${account} — ${purpose}`;
}

export function entryRef(id: string): string {
  return `vault://entry/${id}`;
}

function entryResource(site: string, account: string): string {
  return `entry:${site}/${account}`;
}

export function secretFingerprint(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex").slice(0, 8);
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function backendService(id: string): string {
  return `echo_vault_entry_${id}`;
}

function toIso(v: unknown): string {
  return v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString();
}

function toIsoOrNull(v: unknown): string | null {
  return v == null ? null : toIso(v);
}

function publicEntry(row: EntryMetadata): EntryMetadata {
  const out: EntryMetadata = {
    id: row.id,
    ref: entryRef(row.id),
    site: row.site,
    account: row.account,
    purpose: row.purpose,
    label: row.label,
    kind: row.kind,
    is_default: row.is_default,
    status: row.status,
    fingerprint: row.fingerprint,
    secret_length: row.secret_length,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_used_at: row.last_used_at,
    last_verified_at: row.last_verified_at,
    rotation_mode: row.rotation_mode,
    rotate_interval_days: row.rotate_interval_days,
    last_rotated_at: row.last_rotated_at,
    rotate_by: row.rotate_by,
    rotation_count: row.rotation_count,
    last_rotation_error: row.last_rotation_error,
    provider_token_id: row.provider_token_id,
  };
  if (row.reentry_reason) out.reentry_reason = row.reentry_reason;
  return out;
}

/** `fromIso` + N days, or null when there is no interval. */
function rotateByFrom(fromIso: string, intervalDays: number | null): string | null {
  return intervalDays === null ? null : new Date(Date.parse(fromIso) + intervalDays * DAY_MS).toISOString();
}

/** Full replacement values for an entry's rotation policy (computed by setRotationPolicy). */
export interface RotationPolicyRow {
  rotation_mode: RotationMode;
  rotate_interval_days: number | null;
  provider_token_id: string | null;
  rotate_by: string | null;
}

// ---------------------------------------------------------------- entry storage

export interface NewEntryRow {
  id: string;
  site: string;
  account: string;
  purpose: string;
  label: string;
  kind: EntryKind;
  fingerprint: string;
  secret_length: number;
  nowIso: string;
}

export interface EntryStore {
  /** Insert; becomes default iff the site has no default. Throws EntryError("entry_exists") on an identity clash. */
  insert(row: NewEntryRow): Promise<EntryMetadata>;
  get(id: string): Promise<EntryMetadata | null>;
  /** Non-deleted unless includeDeleted. `query` is a case-insensitive substring of the label. */
  list(filter: { site?: string; query?: string; includeDeleted?: boolean }): Promise<EntryMetadata[]>;
  /** The non-deleted entry with this identity, if any. */
  findIdentity(site: string, account: string, kind: EntryKind): Promise<EntryMetadata | null>;
  /** Atomically make `id` the only default of its site. Null when missing/deleted. */
  setDefault(id: string): Promise<EntryMetadata | null>;
  updateMeta(
    id: string,
    patch: { account?: string; purpose?: string; label?: string; last_verified_at?: string },
    nowIso: string,
  ): Promise<EntryMetadata | null>;
  /**
   * New fingerprint/length for the same id; status → active, re-entry reason cleared, verification reset.
   * This IS a rotation: last_rotated_at = now, rotation_count + 1, rotate_by = now + interval (or null),
   * last_rotation_error cleared.
   */
  replaceSecretMeta(id: string, fingerprint: string, secretLength: number, nowIso: string): Promise<EntryMetadata | null>;
  flag(id: string, reason: string, nowIso: string): Promise<EntryMetadata | null>;
  markDeleted(id: string, nowIso: string): Promise<EntryMetadata | null>;
  touchUsed(id: string, nowIso: string): Promise<EntryMetadata | null>;
  /** Replace the rotation policy columns. Null when missing/deleted. */
  setRotation(id: string, policy: RotationPolicyRow, nowIso: string): Promise<EntryMetadata | null>;
  /** Record (or clear, with null) the short code of a failed rotation attempt. */
  setRotationError(id: string, code: string | null, nowIso: string): Promise<EntryMetadata | null>;
  /** Active entries whose rotate_by <= nowIso, oldest due first. */
  listRotationDue(nowIso: string): Promise<EntryMetadata[]>;
  /** Remove the row itself (any status). True when a row was removed. Callers destroy the secret FIRST. */
  hardDelete(id: string): Promise<boolean>;
}

function sortEntries(rows: EntryMetadata[]): EntryMetadata[] {
  return rows.sort(
    (a, b) =>
      a.site.localeCompare(b.site) ||
      Number(b.is_default) - Number(a.is_default) ||
      a.account.toLowerCase().localeCompare(b.account.toLowerCase()) ||
      a.kind.localeCompare(b.kind),
  );
}

/** In-memory store (tests / single process). Every mutation is a synchronous check-and-set. */
export class MemoryEntryStore implements EntryStore {
  private readonly rows = new Map<string, EntryMetadata>();

  private live(): EntryMetadata[] {
    return [...this.rows.values()].filter((r) => r.status !== "deleted");
  }

  private clash(site: string, account: string, kind: EntryKind, exceptId?: string): boolean {
    const a = account.toLowerCase();
    return this.live().some(
      (r) => r.id !== exceptId && r.site === site && r.kind === kind && r.account.toLowerCase() === a,
    );
  }

  async insert(row: NewEntryRow): Promise<EntryMetadata> {
    if (this.rows.has(row.id)) throw new EntryError("entry_store_failed", "Entry could not be stored");
    if (this.clash(row.site, row.account, row.kind)) {
      throw new EntryError("entry_exists", "An entry already exists for this site, account and kind");
    }
    const rec: EntryMetadata = {
      id: row.id,
      ref: entryRef(row.id),
      site: row.site,
      account: row.account,
      purpose: row.purpose,
      label: row.label,
      kind: row.kind,
      is_default: !this.live().some((r) => r.site === row.site && r.is_default),
      status: "active",
      fingerprint: row.fingerprint,
      secret_length: row.secret_length,
      created_at: row.nowIso,
      updated_at: row.nowIso,
      last_used_at: null,
      last_verified_at: null,
      rotation_mode: "manual",
      rotate_interval_days: null,
      last_rotated_at: null,
      rotate_by: null,
      rotation_count: 0,
      last_rotation_error: null,
      provider_token_id: null,
    };
    this.rows.set(rec.id, rec);
    return { ...rec };
  }

  async get(id: string): Promise<EntryMetadata | null> {
    const rec = this.rows.get(id);
    return rec ? { ...rec } : null;
  }

  async list(filter: { site?: string; query?: string; includeDeleted?: boolean }): Promise<EntryMetadata[]> {
    const q = filter.query?.toLowerCase();
    return sortEntries(
      [...this.rows.values()]
        .filter((r) => filter.includeDeleted || r.status !== "deleted")
        .filter((r) => (filter.site ? r.site === filter.site : true))
        .filter((r) => (q ? r.label.toLowerCase().includes(q) : true))
        .map((r) => ({ ...r })),
    );
  }

  async findIdentity(site: string, account: string, kind: EntryKind): Promise<EntryMetadata | null> {
    const a = account.toLowerCase();
    const rec = this.live().find((r) => r.site === site && r.kind === kind && r.account.toLowerCase() === a);
    return rec ? { ...rec } : null;
  }

  async setDefault(id: string): Promise<EntryMetadata | null> {
    const rec = this.rows.get(id);
    if (!rec || rec.status === "deleted") return null;
    for (const other of this.rows.values()) {
      if (other.site === rec.site && other.id !== id) other.is_default = false;
    }
    rec.is_default = true;
    return { ...rec };
  }

  async updateMeta(
    id: string,
    patch: { account?: string; purpose?: string; label?: string; last_verified_at?: string },
    nowIso: string,
  ): Promise<EntryMetadata | null> {
    const rec = this.rows.get(id);
    if (!rec || rec.status === "deleted") return null;
    if (patch.account !== undefined && this.clash(rec.site, patch.account, rec.kind, id)) {
      throw new EntryError("entry_exists", "An entry already exists for this site, account and kind");
    }
    if (patch.account !== undefined) rec.account = patch.account;
    if (patch.purpose !== undefined) rec.purpose = patch.purpose;
    if (patch.label !== undefined) rec.label = patch.label;
    if (patch.last_verified_at !== undefined) rec.last_verified_at = patch.last_verified_at;
    rec.updated_at = nowIso;
    return { ...rec };
  }

  async replaceSecretMeta(
    id: string,
    fingerprint: string,
    secretLength: number,
    nowIso: string,
  ): Promise<EntryMetadata | null> {
    const rec = this.rows.get(id);
    if (!rec || rec.status === "deleted") return null;
    rec.fingerprint = fingerprint;
    rec.secret_length = secretLength;
    rec.status = "active";
    delete rec.reentry_reason;
    rec.last_verified_at = null;
    rec.last_rotated_at = nowIso;
    rec.rotation_count += 1;
    rec.rotate_by = rotateByFrom(nowIso, rec.rotate_interval_days);
    rec.last_rotation_error = null;
    rec.updated_at = nowIso;
    return { ...rec };
  }

  async flag(id: string, reason: string, nowIso: string): Promise<EntryMetadata | null> {
    const rec = this.rows.get(id);
    if (!rec || rec.status === "deleted") return null;
    rec.status = "needs_reentry";
    rec.reentry_reason = reason;
    rec.updated_at = nowIso;
    return { ...rec };
  }

  async markDeleted(id: string, nowIso: string): Promise<EntryMetadata | null> {
    const rec = this.rows.get(id);
    if (!rec || rec.status === "deleted") return null;
    rec.status = "deleted";
    rec.is_default = false;
    rec.updated_at = nowIso;
    return { ...rec };
  }

  async touchUsed(id: string, nowIso: string): Promise<EntryMetadata | null> {
    const rec = this.rows.get(id);
    if (!rec || rec.status === "deleted") return null;
    rec.last_used_at = nowIso;
    return { ...rec };
  }

  async setRotation(id: string, policy: RotationPolicyRow, nowIso: string): Promise<EntryMetadata | null> {
    const rec = this.rows.get(id);
    if (!rec || rec.status === "deleted") return null;
    rec.rotation_mode = policy.rotation_mode;
    rec.rotate_interval_days = policy.rotate_interval_days;
    rec.provider_token_id = policy.provider_token_id;
    rec.rotate_by = policy.rotate_by;
    rec.updated_at = nowIso;
    return { ...rec };
  }

  async setRotationError(id: string, code: string | null, nowIso: string): Promise<EntryMetadata | null> {
    const rec = this.rows.get(id);
    if (!rec || rec.status === "deleted") return null;
    rec.last_rotation_error = code;
    rec.updated_at = nowIso;
    return { ...rec };
  }

  async listRotationDue(nowIso: string): Promise<EntryMetadata[]> {
    const now = Date.parse(nowIso);
    return [...this.rows.values()]
      .filter((r) => r.status === "active" && r.rotate_by !== null && Date.parse(r.rotate_by) <= now)
      .sort((a, b) => Date.parse(a.rotate_by as string) - Date.parse(b.rotate_by as string) || a.id.localeCompare(b.id))
      .map((r) => ({ ...r }));
  }

  async hardDelete(id: string): Promise<boolean> {
    return this.rows.delete(id);
  }

  /** TEST ONLY: every stored row, for leak scans. */
  dumpForTests(): EntryMetadata[] {
    return [...this.rows.values()].map((r) => ({ ...r }));
  }
}

type SqlProvider = () => Promise<Pick<Sql, "query">>;

async function defaultSqlProvider(): Promise<Pick<Sql, "query">> {
  // Lazy: db.ts boots PGlite / a pg pool at import time, which tests must avoid.
  const { getSql } = await import("../../db.ts");
  return getSql();
}

function violates(err: unknown, constraint: string): boolean {
  const e = err as { constraint?: unknown; message?: unknown } | null;
  return e?.constraint === constraint || (typeof e?.message === "string" && e.message.includes(constraint));
}

const ENTRY_COLUMNS =
  "id, site, account, purpose, label, kind, is_default, status, fingerprint, secret_length, reentry_reason, " +
  "created_at, updated_at, last_used_at, last_verified_at, rotation_mode, rotate_interval_days, last_rotated_at, " +
  "rotate_by, rotation_count, last_rotation_error, provider_token_id";

function rowToEntry(row: Record<string, unknown>): EntryMetadata {
  const rec: EntryMetadata = {
    id: String(row.id),
    ref: entryRef(String(row.id)),
    site: String(row.site),
    account: String(row.account),
    purpose: String(row.purpose),
    label: String(row.label),
    kind: String(row.kind) as EntryKind,
    is_default: row.is_default === true,
    status: String(row.status) as EntryStatus,
    fingerprint: String(row.fingerprint),
    secret_length: Number(row.secret_length),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
    last_used_at: toIsoOrNull(row.last_used_at),
    last_verified_at: toIsoOrNull(row.last_verified_at),
    rotation_mode: row.rotation_mode === "auto" ? "auto" : "manual",
    rotate_interval_days: row.rotate_interval_days == null ? null : Number(row.rotate_interval_days),
    last_rotated_at: toIsoOrNull(row.last_rotated_at),
    rotate_by: toIsoOrNull(row.rotate_by),
    rotation_count: Number(row.rotation_count ?? 0),
    last_rotation_error: row.last_rotation_error == null ? null : String(row.last_rotation_error),
    provider_token_id: row.provider_token_id == null ? null : String(row.provider_token_id),
  };
  if (row.reentry_reason != null && row.reentry_reason !== "") rec.reentry_reason = String(row.reentry_reason);
  return rec;
}

/** Postgres/PGlite store over `vault_entries` (migrations/0005_vault_entries.sql). */
export class SqlEntryStore implements EntryStore {
  private readonly sql: SqlProvider;

  constructor(sqlProvider: SqlProvider = defaultSqlProvider) {
    this.sql = sqlProvider;
  }

  private async one(text: string, params: unknown[]): Promise<EntryMetadata | null> {
    const rows = await (await this.sql()).query<Record<string, unknown>>(text, params);
    return rows[0] ? rowToEntry(rows[0]) : null;
  }

  async insert(row: NewEntryRow): Promise<EntryMetadata> {
    const sql = await this.sql();
    // First entry for a site (or a site with no default) becomes default. If a
    // concurrent insert takes the default first, retry once as a non-default.
    for (const allowDefault of [true, false]) {
      try {
        const rows = await sql.query<Record<string, unknown>>(
          `insert into vault_entries
             (id, site, account, purpose, label, kind, is_default, status, fingerprint, secret_length, created_at, updated_at)
           select $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,
                  ($10::boolean and not exists (select 1 from vault_entries where site = $2::text and is_default)),
                  'active', $7::text, $8::integer, $9::timestamptz, $9::timestamptz
           returning ${ENTRY_COLUMNS}`,
          [
            row.id,
            row.site,
            row.account,
            row.purpose,
            row.label,
            row.kind,
            row.fingerprint,
            row.secret_length,
            row.nowIso,
            allowDefault,
          ],
        );
        if (rows[0]) return rowToEntry(rows[0]);
      } catch (err) {
        if (violates(err, "vault_entries_identity_uidx")) {
          throw new EntryError("entry_exists", "An entry already exists for this site, account and kind");
        }
        if (allowDefault && violates(err, "vault_entries_one_default_uidx")) continue;
        throw new EntryError("entry_store_failed", "Entry could not be stored");
      }
    }
    throw new EntryError("entry_store_failed", "Entry could not be stored");
  }

  get(id: string): Promise<EntryMetadata | null> {
    return this.one(`select ${ENTRY_COLUMNS} from vault_entries where id = $1::text`, [id]);
  }

  async list(filter: { site?: string; query?: string; includeDeleted?: boolean }): Promise<EntryMetadata[]> {
    const rows = await (await this.sql()).query<Record<string, unknown>>(
      `select ${ENTRY_COLUMNS} from vault_entries
        where ($1::text is null or site = $1::text)
          and ($2::text is null or position(lower($2::text) in lower(label)) > 0)
          and ($3::boolean or status <> 'deleted')
        order by site asc, is_default desc, lower(account) asc, kind asc`,
      [filter.site ?? null, filter.query ?? null, filter.includeDeleted === true],
    );
    return rows.map(rowToEntry);
  }

  findIdentity(site: string, account: string, kind: EntryKind): Promise<EntryMetadata | null> {
    return this.one(
      `select ${ENTRY_COLUMNS} from vault_entries
        where site = $1::text and lower(account) = lower($2::text) and kind = $3::text and status <> 'deleted'`,
      [site, account, kind],
    );
  }

  async setDefault(id: string): Promise<EntryMetadata | null> {
    const rows = await (await this.sql()).query<{ ok: unknown }>(
      "select vault_entries_set_default($1::text) as ok",
      [id],
    );
    if (rows[0]?.ok !== true) return null;
    return this.get(id);
  }

  async updateMeta(
    id: string,
    patch: { account?: string; purpose?: string; label?: string; last_verified_at?: string },
    nowIso: string,
  ): Promise<EntryMetadata | null> {
    try {
      return await this.one(
        `update vault_entries
            set account = coalesce($2::text, account),
                purpose = coalesce($3::text, purpose),
                label = coalesce($4::text, label),
                last_verified_at = coalesce($5::timestamptz, last_verified_at),
                updated_at = $6::timestamptz
          where id = $1::text and status <> 'deleted'
          returning ${ENTRY_COLUMNS}`,
        [id, patch.account ?? null, patch.purpose ?? null, patch.label ?? null, patch.last_verified_at ?? null, nowIso],
      );
    } catch (err) {
      if (violates(err, "vault_entries_identity_uidx")) {
        throw new EntryError("entry_exists", "An entry already exists for this site, account and kind");
      }
      throw new EntryError("entry_store_failed", "Entry could not be updated");
    }
  }

  replaceSecretMeta(id: string, fingerprint: string, secretLength: number, nowIso: string): Promise<EntryMetadata | null> {
    return this.one(
      `update vault_entries
          set fingerprint = $2::text, secret_length = $3::integer, status = 'active', reentry_reason = null,
              last_verified_at = null, updated_at = $4::timestamptz,
              last_rotated_at = $4::timestamptz, rotation_count = rotation_count + 1, last_rotation_error = null,
              rotate_by = case when rotate_interval_days is null then null
                               else $4::timestamptz + make_interval(days => rotate_interval_days) end
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`,
      [id, fingerprint, secretLength, nowIso],
    );
  }

  flag(id: string, reason: string, nowIso: string): Promise<EntryMetadata | null> {
    return this.one(
      `update vault_entries
          set status = 'needs_reentry', reentry_reason = $2::text, updated_at = $3::timestamptz
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`,
      [id, reason, nowIso],
    );
  }

  markDeleted(id: string, nowIso: string): Promise<EntryMetadata | null> {
    return this.one(
      `update vault_entries
          set status = 'deleted', is_default = false, deleted_at = $2::timestamptz, updated_at = $2::timestamptz
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`,
      [id, nowIso],
    );
  }

  touchUsed(id: string, nowIso: string): Promise<EntryMetadata | null> {
    return this.one(
      `update vault_entries set last_used_at = $2::timestamptz
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`,
      [id, nowIso],
    );
  }

  setRotation(id: string, policy: RotationPolicyRow, nowIso: string): Promise<EntryMetadata | null> {
    return this.one(
      `update vault_entries
          set rotation_mode = $2::text, rotate_interval_days = $3::integer, provider_token_id = $4::text,
              rotate_by = $5::timestamptz, updated_at = $6::timestamptz
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`,
      [id, policy.rotation_mode, policy.rotate_interval_days, policy.provider_token_id, policy.rotate_by, nowIso],
    );
  }

  setRotationError(id: string, code: string | null, nowIso: string): Promise<EntryMetadata | null> {
    return this.one(
      `update vault_entries set last_rotation_error = $2::text, updated_at = $3::timestamptz
        where id = $1::text and status <> 'deleted'
        returning ${ENTRY_COLUMNS}`,
      [id, code, nowIso],
    );
  }

  async listRotationDue(nowIso: string): Promise<EntryMetadata[]> {
    const rows = await (await this.sql()).query<Record<string, unknown>>(
      `select ${ENTRY_COLUMNS} from vault_entries
        where status = 'active' and rotate_by is not null and rotate_by <= $1::timestamptz
        order by rotate_by asc, id asc`,
      [nowIso],
    );
    return rows.map(rowToEntry);
  }

  async hardDelete(id: string): Promise<boolean> {
    const rows = await (await this.sql()).query("delete from vault_entries where id = $1::text returning id", [id]);
    return rows.length === 1;
  }
}

// ---------------------------------------------------------------- card storage

export interface CardStore {
  insert(rec: CardRecord): Promise<void>;
  get(id: string): Promise<CardRecord | null>;
  getByTokenHash(tokenHash: string): Promise<CardRecord | null>;
  /** Unexpired pending/claimed cards of one client. */
  countOpen(clientId: string, nowIso: string): Promise<number>;
  /** Atomically pending → claimed iff expires_at > nowIso. True when this call won. */
  claim(id: string, nowIso: string): Promise<boolean>;
  /** claimed → pending (the POST failed before anything was completed). */
  release(id: string): Promise<void>;
  /** claimed → completed with the resulting entry id. */
  complete(id: string, entryId: string, nowIso: string): Promise<boolean>;
  /** pending|claimed → expired. */
  expire(id: string): Promise<void>;
  /** Remove every card that points at this entry (purge; vault_cards.entry_id references vault_entries). */
  deleteForEntry(entryId: string): Promise<number>;
}

export class MemoryCardStore implements CardStore {
  private readonly rows = new Map<string, CardRecord>();

  async insert(rec: CardRecord): Promise<void> {
    if (this.rows.has(rec.id) || [...this.rows.values()].some((r) => r.token_hash === rec.token_hash)) {
      throw new CardError("card_store_failed", "Card could not be recorded");
    }
    this.rows.set(rec.id, { ...rec });
  }

  async get(id: string): Promise<CardRecord | null> {
    const rec = this.rows.get(id);
    return rec ? { ...rec } : null;
  }

  async getByTokenHash(tokenHash: string): Promise<CardRecord | null> {
    const rec = [...this.rows.values()].find((r) => r.token_hash === tokenHash);
    return rec ? { ...rec } : null;
  }

  async countOpen(clientId: string, nowIso: string): Promise<number> {
    const now = Date.parse(nowIso);
    return [...this.rows.values()].filter(
      (r) =>
        r.client_id === clientId && (r.status === "pending" || r.status === "claimed") && Date.parse(r.expires_at) > now,
    ).length;
  }

  async claim(id: string, nowIso: string): Promise<boolean> {
    const rec = this.rows.get(id);
    if (!rec || rec.status !== "pending" || Date.parse(rec.expires_at) <= Date.parse(nowIso)) return false;
    rec.status = "claimed";
    return true;
  }

  async release(id: string): Promise<void> {
    const rec = this.rows.get(id);
    if (rec && rec.status === "claimed") rec.status = "pending";
  }

  async complete(id: string, entryId: string, nowIso: string): Promise<boolean> {
    const rec = this.rows.get(id);
    if (!rec || rec.status !== "claimed") return false;
    rec.status = "completed";
    rec.entry_id = entryId;
    rec.completed_at = nowIso;
    return true;
  }

  async expire(id: string): Promise<void> {
    const rec = this.rows.get(id);
    if (rec && (rec.status === "pending" || rec.status === "claimed")) rec.status = "expired";
  }

  async deleteForEntry(entryId: string): Promise<number> {
    let n = 0;
    for (const [id, rec] of this.rows) {
      if (rec.entry_id === entryId && this.rows.delete(id)) n += 1;
    }
    return n;
  }

  /** TEST ONLY: every stored row, for leak scans. */
  dumpForTests(): CardRecord[] {
    return [...this.rows.values()].map((r) => ({ ...r }));
  }
}

const CARD_COLUMNS =
  "id, token_hash, client_id, client_name, site, account, purpose, kind, reason, entry_id, is_reentry, status, " +
  "created_at, expires_at, completed_at";

function rowToCard(row: Record<string, unknown>): CardRecord {
  const rec: CardRecord = {
    id: String(row.id),
    token_hash: String(row.token_hash),
    client_id: String(row.client_id),
    client_name: String(row.client_name ?? ""),
    site: String(row.site),
    account: row.account == null ? null : String(row.account),
    purpose: row.purpose == null ? null : String(row.purpose),
    kind: String(row.kind) as EntryKind,
    reason: String(row.reason ?? ""),
    entry_id: row.entry_id == null ? null : String(row.entry_id),
    is_reentry: row.is_reentry === true,
    status: String(row.status) as CardStoredStatus,
    created_at: toIso(row.created_at),
    expires_at: toIso(row.expires_at),
  };
  if (row.completed_at != null) rec.completed_at = toIso(row.completed_at);
  return rec;
}

/** Postgres/PGlite store over `vault_cards` (migrations/0005_vault_entries.sql). */
export class SqlCardStore implements CardStore {
  private readonly sql: SqlProvider;

  constructor(sqlProvider: SqlProvider = defaultSqlProvider) {
    this.sql = sqlProvider;
  }

  async insert(rec: CardRecord): Promise<void> {
    await (await this.sql()).query(
      `insert into vault_cards
         (id, token_hash, client_id, client_name, site, account, purpose, kind, reason, entry_id, is_reentry, status,
          created_at, expires_at)
       values ($1::text, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text, $9::text, $10::text,
               $11::boolean, 'pending', $12::timestamptz, $13::timestamptz)`,
      [
        rec.id,
        rec.token_hash,
        rec.client_id,
        rec.client_name,
        rec.site,
        rec.account,
        rec.purpose,
        rec.kind,
        rec.reason,
        rec.entry_id,
        rec.is_reentry,
        rec.created_at,
        rec.expires_at,
      ],
    );
  }

  private async one(text: string, params: unknown[]): Promise<CardRecord | null> {
    const rows = await (await this.sql()).query<Record<string, unknown>>(text, params);
    return rows[0] ? rowToCard(rows[0]) : null;
  }

  get(id: string): Promise<CardRecord | null> {
    return this.one(`select ${CARD_COLUMNS} from vault_cards where id = $1::text`, [id]);
  }

  getByTokenHash(tokenHash: string): Promise<CardRecord | null> {
    return this.one(`select ${CARD_COLUMNS} from vault_cards where token_hash = $1::text`, [tokenHash]);
  }

  async countOpen(clientId: string, nowIso: string): Promise<number> {
    const rows = await (await this.sql()).query<{ n: unknown }>(
      `select count(*)::integer as n from vault_cards
        where client_id = $1::text and status in ('pending', 'claimed') and expires_at > $2::timestamptz`,
      [clientId, nowIso],
    );
    return Number(rows[0]?.n ?? 0);
  }

  async claim(id: string, nowIso: string): Promise<boolean> {
    const rows = await (await this.sql()).query(
      `update vault_cards set status = 'claimed'
        where id = $1::text and status = 'pending' and expires_at > $2::timestamptz
        returning id`,
      [id, nowIso],
    );
    return rows.length === 1;
  }

  async release(id: string): Promise<void> {
    await (await this.sql()).query(
      "update vault_cards set status = 'pending' where id = $1::text and status = 'claimed'",
      [id],
    );
  }

  async complete(id: string, entryId: string, nowIso: string): Promise<boolean> {
    const rows = await (await this.sql()).query(
      `update vault_cards set status = 'completed', entry_id = $2::text, completed_at = $3::timestamptz
        where id = $1::text and status = 'claimed'
        returning id`,
      [id, entryId, nowIso],
    );
    return rows.length === 1;
  }

  async expire(id: string): Promise<void> {
    await (await this.sql()).query(
      "update vault_cards set status = 'expired' where id = $1::text and status in ('pending', 'claimed')",
      [id],
    );
  }

  async deleteForEntry(entryId: string): Promise<number> {
    const rows = await (await this.sql()).query("delete from vault_cards where entry_id = $1::text returning id", [
      entryId,
    ]);
    return rows.length;
  }
}

// ---------------------------------------------------------------- wiring

/** Sends the operator the card link. Default: Telegram sendMessage via telegram.ts. */
export type CardNotifier = (input: {
  card: CardRecord;
  /** Full card URL including the single-use token. Operator-only. */
  url: string;
  fetch?: typeof fetch;
  env?: NodeJS.ProcessEnv;
}) => Promise<void>;

/** Ledger rows written by this module (`task` is part of LedgerEntryInput and is persisted). */
export type EntryLedgerInput = LedgerEntryInput;

export interface CardsDeps {
  entries?: EntryStore;
  cards?: CardStore;
  /** Canonical vault backend. Tests MUST pass a FakeVaultBackend. */
  backend?: VaultBackend;
  /** Ledger sink. Default: appendLedger. */
  ledger?: (input: EntryLedgerInput) => Promise<unknown>;
  /** Injected into the default Telegram notifier. */
  fetch?: typeof fetch;
  notify?: CardNotifier;
  env?: NodeJS.ProcessEnv;
  /** Epoch-ms clock. */
  now?: () => number;
}

let defaults: CardsDeps = {};
let defaultEntryStore: EntryStore | null = null;
let defaultCardStore: CardStore | null = null;
let defaultBackend: VaultBackend | null = null;

/** Process-wide wiring (tests, or an integrator). Pass null to restore the SQL + gate defaults. */
export function configureCards(deps: CardsDeps | null): void {
  defaults = deps ?? {};
}

interface Ctx {
  entries: EntryStore;
  cards: CardStore;
  backend: () => Promise<VaultBackend>;
  ledger: (input: EntryLedgerInput) => Promise<unknown>;
  fetch?: typeof fetch;
  notify: CardNotifier;
  env: NodeJS.ProcessEnv;
  nowMs: number;
  nowIso: string;
}

function ctx(deps: CardsDeps = {}): Ctx {
  const d = { ...defaults, ...deps };
  const nowMs = (d.now ?? Date.now)();
  return {
    entries: d.entries ?? (defaultEntryStore ??= new SqlEntryStore()),
    cards: d.cards ?? (defaultCardStore ??= new SqlCardStore()),
    backend: async () => {
      if (d.backend) return d.backend;
      if (!defaultBackend) {
        const { GateVaultBackend } = await import("../backend.ts");
        defaultBackend = new GateVaultBackend();
      }
      return defaultBackend;
    },
    ledger: d.ledger ?? appendLedger,
    fetch: d.fetch,
    notify: d.notify ?? defaultNotifier,
    env: d.env ?? process.env,
    nowMs,
    nowIso: new Date(nowMs).toISOString(),
  };
}

function requireEntryId(id: unknown): string {
  if (typeof id !== "string" || !ENTRY_ID_PATTERN.test(id)) {
    throw new EntryError("entry_not_found", "No such entry");
  }
  return id;
}

function requireClient(client: ClientIdentity): ClientIdentity {
  if (
    !client ||
    typeof client.client_id !== "string" ||
    client.client_id.length === 0 ||
    client.client_id.length > 200
  ) {
    throw new EntryError("invalid_client", "An authenticated client identity is required");
  }
  return client;
}

async function writeLedger(c: Ctx, input: EntryLedgerInput, mustSucceed: boolean): Promise<void> {
  try {
    await c.ledger(input);
  } catch {
    log.error("vault_entry_ledger_failed", { capability: input.capability, client_id: input.client_id });
    if (mustSucceed) throw new EntryError("ledger_unavailable", "The action could not be recorded in the ledger");
  }
}

/**
 * The ONE place an entry's secret is read from the backend (useEntry, and
 * rotation.ts through openEntryVault). Arms the value for redaction before
 * returning it. Throws EntryError("entry_secret_missing" | "vault_unavailable").
 */
async function loadEntrySecret(c: Ctx, row: EntryMetadata): Promise<string> {
  let secret: string;
  try {
    const backend = await c.backend();
    const coordinate = await backend.locate(backendService(row.id), BACKEND_USERNAME, BYPASS_REASON);
    if (!coordinate) throw new EntryError("entry_secret_missing", "The vault has no secret for this entry");
    const got = await backend.get(coordinate.service, coordinate.username, BYPASS_REASON);
    if (typeof got?.secret !== "string" || got.secret.length === 0) {
      throw new EntryError("entry_secret_missing", "The vault has no secret for this entry");
    }
    secret = got.secret;
  } catch (err) {
    if (err instanceof EntryError) throw err;
    throw new EntryError("vault_unavailable", "The vault could not be reached");
  }
  registerSecretForRedaction(secret);
  if (secretFingerprint(secret) !== row.fingerprint) {
    log.warn("vault_entry_fingerprint_drift", { entry_id: row.id });
  }
  return secret;
}

async function storeEntrySecret(c: Ctx, row: Pick<EntryMetadata, "id" | "site" | "account" | "purpose" | "kind">, secret: string): Promise<void> {
  registerSecretForRedaction(secret);
  try {
    const backend = await c.backend();
    const put = await backend.put(
      backendService(row.id),
      BACKEND_USERNAME,
      secret,
      `echo-credential-broker vault v2 entry: ${entryLabel(row.site, row.account, row.purpose)} (${row.kind})`,
      BYPASS_REASON,
    );
    if (put && put.stored === false) throw new Error("not stored");
  } catch {
    throw new EntryError("vault_unavailable", "vault write failed");
  }
}

/**
 * SERVER-INTERNAL seam for rotation.ts (auto-rotate and purge). It hands out the
 * same stores, clock, ledger sink and backend access that useEntry/submitCard
 * use, so rotation never grows a second, weaker copy of the secret path.
 * `readSecret` returns a secret VALUE: it must only ever be called by code that
 * keeps it inside the process (provider request → backend put). Never wire this
 * to a tool, a route or a log line.
 */
export interface EntryVault {
  entries: EntryStore;
  cards: CardStore;
  nowMs: number;
  nowIso: string;
  /** Write a ledger row; with mustSucceed a failure throws EntryError("ledger_unavailable"). */
  ledger(input: EntryLedgerInput, mustSucceed: boolean): Promise<void>;
  readSecret(row: EntryMetadata): Promise<string>;
  /** `put` the secret under the entry's backend key. Throws EntryError("vault_unavailable"). */
  writeSecret(row: EntryMetadata, secret: string): Promise<void>;
  /**
   * Destroy the stored secret: backend.delete when the backend has one,
   * otherwise overwrite it with 64 random bytes (base64url) and read it back to
   * confirm the original value is gone. Throws EntryError("vault_unavailable" |
   * "purge_secret_not_destroyed").
   */
  destroySecret(row: EntryMetadata): Promise<"deleted" | "overwritten">;
}

export function openEntryVault(deps: CardsDeps = {}): EntryVault {
  const c = ctx(deps);
  return {
    entries: c.entries,
    cards: c.cards,
    nowMs: c.nowMs,
    nowIso: c.nowIso,
    ledger: (input, mustSucceed) => writeLedger(c, input, mustSucceed),
    readSecret: (row) => loadEntrySecret(c, row),
    writeSecret: (row, secret) => storeEntrySecret(c, row, secret),
    destroySecret: async (row) => {
      const service = backendService(requireEntryId(row.id));
      let backend: VaultBackend;
      try {
        backend = await c.backend();
      } catch {
        throw new EntryError("vault_unavailable", "The vault could not be reached");
      }
      if (typeof backend.delete === "function") {
        try {
          // `ok: false` also covers "nothing was stored"; the locate below is what decides.
          await backend.delete(service, BACKEND_USERNAME, BYPASS_REASON);
        } catch {
          throw new EntryError("vault_unavailable", "The vault could not be reached");
        }
        let still: unknown = null;
        try {
          still = await backend.locate(service, BACKEND_USERNAME, BYPASS_REASON);
        } catch {
          throw new EntryError("vault_unavailable", "The delete could not be verified");
        }
        if (still) throw new EntryError("purge_secret_not_destroyed", "The secret is still present after the delete");
        return "deleted";
      }
      // No delete in this backend: destroy the value by overwriting it.
      const filler = randomBytes(64).toString("base64url");
      registerSecretForRedaction(filler);
      let readBack: string;
      try {
        const put = await backend.put(
          service,
          BACKEND_USERNAME,
          filler,
          "echo-credential-broker vault v2 entry: PURGED (random filler, not a credential)",
          BYPASS_REASON,
        );
        if (put && put.stored === false) throw new Error("not stored");
        const got = await backend.get(service, BACKEND_USERNAME, BYPASS_REASON);
        readBack = typeof got?.secret === "string" ? got.secret : "";
        if (readBack) registerSecretForRedaction(readBack);
      } catch {
        throw new EntryError("vault_unavailable", "The vault could not be reached");
      }
      if (!constantTimeEqual(sha256Hex(readBack), sha256Hex(filler))) {
        throw new EntryError("purge_secret_not_destroyed", "The overwrite could not be confirmed");
      }
      return "overwritten";
    },
  };
}

// ---------------------------------------------------------------- entries API

export async function listEntries(
  filter: { site?: string; query?: string } = {},
  deps: CardsDeps = {},
): Promise<EntryMetadata[]> {
  const c = ctx(deps);
  const site = filter.site !== undefined && filter.site !== "" ? normalizeSite(filter.site) : undefined;
  const query = typeof filter.query === "string" && filter.query.trim() ? filter.query.trim().slice(0, 200) : undefined;
  return (await c.entries.list({ site, query })).map(publicEntry);
}

/** Metadata for one entry (including a deleted one), or null. */
export async function getEntryMetadata(id: string, deps: CardsDeps = {}): Promise<EntryMetadata | null> {
  if (typeof id !== "string" || !ENTRY_ID_PATTERN.test(id)) return null;
  const row = await ctx(deps).entries.get(id);
  return row ? publicEntry(row) : null;
}

/**
 * Pick ONE entry. With `account`: that account's entry (add `kind` when the
 * account has several kinds). Without: the site's default; if there is no
 * default and exactly one candidate, that one; otherwise `ambiguous_entry`.
 * Never returns a deleted entry. The result may be `needs_reentry` — check
 * `status` (useEntry refuses it).
 */
export async function resolveEntry(
  query: { site: string; account?: string; kind?: EntryKind },
  deps: CardsDeps = {},
): Promise<EntryMetadata> {
  const c = ctx(deps);
  const site = normalizeSite(query?.site);
  const kind = query.kind !== undefined ? normalizeKind(query.kind) : undefined;
  const rows = (await c.entries.list({ site })).filter((r) => (kind ? r.kind === kind : true));
  const accounts = () =>
    sanitizeDisplayText([...new Set(rows.map((r) => r.account))].slice(0, 10).join(", "), 400) || "(none)";

  if (query.account !== undefined && query.account !== "") {
    const account = normalizeAccount(query.account).toLowerCase();
    const matches = rows.filter((r) => r.account.toLowerCase() === account);
    if (matches.length === 1) return publicEntry(matches[0]);
    if (matches.length === 0) {
      throw new EntryError("entry_not_found", `No entry for that account on ${site}. Known accounts: ${accounts()}`);
    }
    throw new EntryError(
      "ambiguous_entry",
      `That account has ${matches.length} entries on ${site} (${matches.map((r) => r.kind).join(", ")}); specify kind`,
    );
  }

  if (rows.length === 0) throw new EntryError("entry_not_found", `No entry for ${site}`);
  const def = rows.find((r) => r.is_default);
  if (def) return publicEntry(def);
  if (rows.length === 1) return publicEntry(rows[0]);
  throw new EntryError(
    "ambiguous_entry",
    `${rows.length} entries for ${site} and no default; specify account. Known accounts: ${accounts()}`,
  );
}

export async function setDefault(id: string, deps: CardsDeps = {}): Promise<EntryMetadata> {
  const c = ctx(deps);
  const row = await c.entries.setDefault(requireEntryId(id));
  if (!row) throw new EntryError("entry_not_found", "No such entry");
  log.info("vault_entry_default_set", { entry_id: row.id, site: row.site });
  return publicEntry(row);
}

/** Change account / purpose, or stamp `last_verified_at` (verified: true). Site and kind are immutable. */
export async function updateEntryMetadata(
  id: string,
  patch: { account?: string; purpose?: string; verified?: boolean },
  deps: CardsDeps = {},
): Promise<EntryMetadata> {
  const c = ctx(deps);
  const current = await c.entries.get(requireEntryId(id));
  if (!current || current.status === "deleted") throw new EntryError("entry_not_found", "No such entry");
  const account = patch?.account !== undefined ? normalizeAccount(patch.account) : undefined;
  const purpose = patch?.purpose !== undefined ? normalizePurpose(patch.purpose) : undefined;
  const label =
    account !== undefined || purpose !== undefined
      ? entryLabel(current.site, account ?? current.account, purpose ?? current.purpose)
      : undefined;
  const row = await c.entries.updateMeta(
    id,
    { account, purpose, label, last_verified_at: patch?.verified === true ? c.nowIso : undefined },
    c.nowIso,
  );
  if (!row) throw new EntryError("entry_not_found", "No such entry");
  return publicEntry(row);
}

/** Soft-delete exactly this entry. Other entries (and the site's other defaults) are untouched. */
export async function deleteEntry(id: string, deps: CardsDeps = {}): Promise<EntryMetadata> {
  const c = ctx(deps);
  const row = await c.entries.markDeleted(requireEntryId(id), c.nowIso);
  if (!row) throw new EntryError("entry_not_found", "No such entry");
  log.warn("vault_entry_deleted", { entry_id: row.id, site: row.site });
  return publicEntry(row);
}

/** Mark exactly this entry as needing its secret re-typed. useEntry refuses it until a card completes. */
export async function flagForReentry(id: string, reason: string, deps: CardsDeps = {}): Promise<EntryMetadata> {
  const c = ctx(deps);
  const clean = sanitizeDisplayText(reason, 300) || "unspecified";
  const row = await c.entries.flag(requireEntryId(id), clean, c.nowIso);
  if (!row) throw new EntryError("entry_not_found", "No such entry");
  log.warn("vault_entry_flagged_for_reentry", { entry_id: row.id, site: row.site });
  return publicEntry(row);
}

export interface RotationPolicyInput {
  mode: RotationMode;
  /** A number sets it, null clears it, undefined keeps the current value. */
  interval_days?: number | null;
  /** A string sets it, null clears it, undefined keeps the current value. Non-secret id only. */
  provider_token_id?: string | null;
}

/**
 * Set an entry's rotation policy. `rotate_by` is recomputed as (last rotation,
 * or creation when it was never rotated) + interval; no interval → never due.
 * mode "auto" needs an interval. `provider_token_id` is a NON-SECRET provider
 * id: anything secret-shaped, or equal to the entry's own secret, is refused.
 */
export async function setRotationPolicy(
  id: string,
  policy: RotationPolicyInput,
  deps: CardsDeps = {},
): Promise<EntryMetadata> {
  const c = ctx(deps);
  const current = await c.entries.get(requireEntryId(id));
  if (!current || current.status === "deleted") throw new EntryError("entry_not_found", "No such entry");
  if (policy?.mode !== "manual" && policy?.mode !== "auto") {
    throw invalid("rotation_mode", "mode must be manual or auto");
  }
  let interval = current.rotate_interval_days;
  if (policy.interval_days !== undefined) {
    const n = policy.interval_days;
    if (n !== null && !(Number.isInteger(n) && n >= 1 && n <= MAX_ROTATE_INTERVAL_DAYS)) {
      throw invalid("interval_days", `interval_days must be a whole number from 1 to ${MAX_ROTATE_INTERVAL_DAYS}`);
    }
    interval = n;
  }
  if (policy.mode === "auto" && interval === null) {
    throw invalid("interval_days", "auto rotation needs interval_days");
  }
  let tokenId = current.provider_token_id;
  if (policy.provider_token_id !== undefined) {
    const t = policy.provider_token_id === null ? null : String(policy.provider_token_id).trim();
    if (t !== null) {
      if (!PROVIDER_TOKEN_ID_PATTERN.test(t)) {
        throw invalid("provider_token_id", "provider_token_id must be 1-128 characters of A-Z a-z 0-9 . _ : -");
      }
      // The id is stored and shown as metadata: it must never be the credential itself.
      if (looksLikeSecret(t) || secretFingerprint(t) === current.fingerprint) {
        throw invalid("provider_token_id", "provider_token_id looks like a secret; give the provider's token ID, not its value");
      }
    }
    tokenId = t;
  }
  const row = await c.entries.setRotation(
    id,
    {
      rotation_mode: policy.mode,
      rotate_interval_days: interval,
      provider_token_id: tokenId,
      rotate_by: rotateByFrom(current.last_rotated_at ?? current.created_at, interval),
    },
    c.nowIso,
  );
  if (!row) throw new EntryError("entry_not_found", "No such entry");
  log.info("vault_entry_rotation_policy_set", {
    entry_id: row.id,
    site: row.site,
    mode: row.rotation_mode,
    interval_days: row.rotate_interval_days,
  });
  return publicEntry(row);
}

/** Active entries whose rotation is due at `now` (rotate_by <= now), oldest due first. Metadata only. */
export async function listRotationDue(now: number | Date = Date.now(), deps: CardsDeps = {}): Promise<EntryMetadata[]> {
  const ms = now instanceof Date ? now.getTime() : now;
  if (!Number.isFinite(ms)) throw invalid("now", "now must be a valid time");
  return (await ctx(deps).entries.listRotationDue(new Date(ms).toISOString())).map(publicEntry);
}

/** Record a failed rotation attempt as a SHORT CODE (anything else becomes "rotation_failed"). */
export async function recordRotationError(id: string, code: string, deps: CardsDeps = {}): Promise<void> {
  const c = ctx(deps);
  const safe = ROTATION_ERROR_PATTERN.test(code) ? code : "rotation_failed";
  await c.entries.setRotationError(requireEntryId(id), safe, c.nowIso);
}

export async function markUsed(id: string, deps: CardsDeps = {}): Promise<EntryMetadata> {
  const c = ctx(deps);
  const row = await c.entries.touchUsed(requireEntryId(id), c.nowIso);
  if (!row) throw new EntryError("entry_not_found", "No such entry");
  return publicEntry(row);
}

export interface UseEntryOptions extends CardsDeps {
  /** Policy outcome recorded in the ledger. Default allow / tier 1. */
  decision?: Decision;
  tier?: Tier;
  approval_id?: string;
}

/**
 * Use an entry's secret without reading it: `fn(secret, entry)` runs here, the
 * secret is armed for redaction first, the use is ledgered
 * (capability "vault.entry.use"), and the caller gets `{ entry, result }` where
 * `result` is fn's return value scrubbed through redactValue — so it must be
 * JSON-serializable (anything else comes back as `{ error: "unserializable_redacted" }`).
 * fn's errors surface as EntryError("entry_use_failed") with a redacted message.
 */
export async function useEntry<T>(
  id: string,
  client: ClientIdentity,
  task: string,
  fn: (secret: string, entry: EntryMetadata) => Promise<T> | T,
  opts: UseEntryOptions = {},
): Promise<{ entry: EntryMetadata; result: T }> {
  const c = ctx(opts);
  const started = Date.now();
  const who = requireClient(client);
  const taskText = sanitizeDisplayText(task, 300);
  if (!taskText) throw new EntryError("invalid_task", "A task description is required to use an entry");
  if (typeof fn !== "function") throw new EntryError("invalid_callback", "useEntry needs a callback");

  const base = {
    client_id: who.client_id,
    capability: "vault.entry.use",
    decision: opts.decision ?? ("allow" as Decision),
    tier: opts.tier ?? (1 as Tier),
    approval_id: opts.approval_id,
    task: taskText,
  };
  const refuse = async (code: string, message: string, row: EntryMetadata | null): Promise<never> => {
    await writeLedger(
      c,
      {
        ...base,
        resource: row ? entryResource(row.site, row.account) : "entry:unknown",
        credential_ref: row ? entryRef(row.id) : undefined,
        result: "error",
        error: code,
        duration_ms: Date.now() - started,
      },
      false,
    );
    throw new EntryError(code, message);
  };

  const row = typeof id === "string" && ENTRY_ID_PATTERN.test(id) ? await c.entries.get(id) : null;
  if (!row || row.status === "deleted") return refuse("entry_not_found", "No such entry", null);
  if (row.status !== "active") {
    return refuse("entry_needs_reentry", "This entry needs its secret re-entered before it can be used", row);
  }

  let secret: string;
  try {
    secret = await loadEntrySecret(c, row);
  } catch (err) {
    const e = err instanceof EntryError ? err : new EntryError("vault_unavailable", "The vault could not be reached");
    return refuse(e.code, e.message, row);
  }

  let result: T;
  try {
    result = redactValue(await fn(secret, publicEntry(row)));
  } catch (err) {
    const detail = sanitizeDisplayText(err instanceof Error ? err.message : "callback failed", 200);
    return refuse("entry_use_failed", `The action failed: ${detail || "callback failed"}`, row);
  }

  const touched = (await c.entries.touchUsed(row.id, c.nowIso).catch(() => null)) ?? row;
  // Fail closed: an un-audited use is not reported as a success.
  await writeLedger(
    c,
    {
      ...base,
      resource: entryResource(row.site, row.account),
      credential_ref: entryRef(row.id),
      result: "ok",
      duration_ms: Date.now() - started,
    },
    true,
  );
  log.info("vault_entry_used", { entry_id: row.id, client_id: who.client_id, site: row.site, task: taskText });
  return { entry: publicEntry(touched), result };
}

// ---------------------------------------------------------------- cards API

/** Validated origin + path prefix for card links; throws when unset or not https (http only for localhost). */
export function cardBaseUrl(env: NodeJS.ProcessEnv = process.env): string {
  const raw = env.ECHO_VAULT_PUBLIC_URL?.trim();
  let url: URL | null = null;
  try {
    url = raw ? new URL(raw) : null;
  } catch {
    url = null;
  }
  const local = url ? ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) : false;
  if (!url || url.username || url.password || !(url.protocol === "https:" || (url.protocol === "http:" && local))) {
    throw new CardError("public_url_not_configured", "ECHO_VAULT_PUBLIC_URL must be an https URL");
  }
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/** Operator-facing prompt. Plain text; every agent-supplied field is sanitized. The URL is appended verbatim. */
export function formatCardText(card: CardRecord, url: string): string {
  const name = sanitizeDisplayText(card.client_name, 80);
  const clientId = sanitizeDisplayText(card.client_id, 120);
  return [
    card.is_reentry ? "ECHO Vault: re-enter a credential" : "ECHO Vault: new credential requested",
    "",
    `Client: ${name ? `${name} (${clientId})` : clientId}`,
    `Site: ${sanitizeDisplayText(card.site, 253)}`,
    `Account: ${card.account ? sanitizeDisplayText(card.account, 254) : "(you choose)"}`,
    `Kind: ${card.kind}`,
    `Purpose: ${card.purpose ? sanitizeDisplayText(card.purpose, 64) : DEFAULT_PURPOSE}`,
    `Reason: ${sanitizeDisplayText(card.reason, 300) || "(none)"}`,
    card.is_reentry ? "This REPLACES the stored secret of the existing entry." : "This creates a new entry.",
    `Expires: ${card.expires_at}`,
    "",
    "Open this single-use link to type the secret:",
    url,
  ].join("\n");
}

const defaultNotifier: CardNotifier = async (input) => {
  const env = input.env ?? process.env;
  const chatId = approverTelegramId(env);
  if (!chatId) throw new CardError("approver_not_configured", "Operator is not configured");
  const { callBotApi } = await import("./telegram.ts");
  await callBotApi(
    "sendMessage",
    { chat_id: chatId, text: formatCardText(input.card, input.url), link_preview_options: { is_disabled: true } },
    { fetch: input.fetch, env },
  );
};

export interface RequestCardInput {
  client: ClientIdentity;
  site: string;
  account?: string;
  purpose?: string;
  kind: EntryKind;
  reason: string;
  /** Re-entry of a specific entry. Also implied when (site, account, kind) already exists. */
  entry_id?: string;
}

export interface CardReceipt {
  card_id: string;
  status: "pending";
  expires_at: string;
}

/**
 * Ask the operator to type a secret. Returns only {card_id, status, expires_at}:
 * the token and the secret never reach the requester. When the identity already
 * exists (or `entry_id` is given) the card is a re-entry bound to that entry id.
 */
export async function requestCard(input: RequestCardInput, deps: CardsDeps = {}): Promise<CardReceipt> {
  const c = ctx(deps);
  let client: ClientIdentity;
  try {
    client = requireClient(input?.client);
  } catch {
    throw new CardError("invalid_client", "An authenticated client identity is required");
  }
  const reason = sanitizeDisplayText(input.reason, 300);
  if (!reason) throw new CardError("invalid_reason", "A reason is required so the operator knows why");

  let site = normalizeSite(input.site);
  let kind = normalizeKind(input.kind);
  let account = input.account !== undefined && input.account !== "" ? normalizeAccount(input.account) : null;
  let purpose = input.purpose !== undefined && input.purpose !== "" ? normalizePurpose(input.purpose) : null;

  let target: EntryMetadata | null = null;
  if (input.entry_id !== undefined) {
    target = typeof input.entry_id === "string" && ENTRY_ID_PATTERN.test(input.entry_id)
      ? await c.entries.get(input.entry_id)
      : null;
    if (!target || target.status === "deleted") throw new CardError("entry_not_found", "No such entry to re-enter");
    if (target.site !== site || target.kind !== kind) {
      throw new CardError("entry_mismatch", "site/kind do not match the entry being re-entered");
    }
  } else if (account) {
    target = await c.entries.findIdentity(site, account, kind);
  }
  if (target) {
    site = target.site;
    kind = target.kind;
    account = target.account;
    purpose = target.purpose;
  }

  // Fail closed before anything is stored or sent.
  const base = cardBaseUrl(c.env);
  if (!deps.notify && !defaults.notify && !approverTelegramId(c.env)) {
    throw new CardError("approver_not_configured", "Operator is not configured");
  }
  if ((await c.cards.countOpen(client.client_id, c.nowIso)) >= MAX_PENDING_CARDS_PER_CLIENT) {
    throw new CardError("too_many_pending_cards", "Too many pending cards for this client; wait for one to finish");
  }

  const token = randomBytes(TOKEN_BYTES).toString("base64url");
  registerSecretForRedaction(token); // never in a log line, ledger row or error
  const card: CardRecord = {
    id: `vc_${randomBytes(16).toString("hex")}`,
    token_hash: sha256Hex(token),
    client_id: client.client_id,
    client_name: sanitizeDisplayText(client.name ?? "", 120),
    site,
    account,
    purpose,
    kind,
    reason,
    entry_id: target ? target.id : null,
    is_reentry: target !== null,
    status: "pending",
    created_at: c.nowIso,
    expires_at: new Date(c.nowMs + CARD_TTL_MS).toISOString(),
  };

  try {
    await c.cards.insert(card);
  } catch {
    log.error("vault_card_store_failed", { card_id: card.id });
    throw new CardError("card_store_failed", "Card could not be recorded");
  }

  try {
    await c.notify({ card: { ...card }, url: `${base}/card/${token}`, fetch: c.fetch, env: c.env });
  } catch (err) {
    // Never leave a usable card behind when the operator was not reached.
    await c.cards.expire(card.id).catch(() => undefined);
    log.error("vault_card_notify_failed", {
      card_id: card.id,
      error: err instanceof Error && "code" in err ? String((err as { code: unknown }).code) : "notify_error",
    });
    throw new CardError("card_notification_failed", "The card could not be delivered to the operator");
  }

  await writeLedger(
    c,
    {
      client_id: card.client_id,
      capability: "vault.card.request",
      resource: entryResource(site, account ?? "*"),
      credential_ref: target ? entryRef(target.id) : undefined,
      decision: "escalate",
      tier: 2,
      result: "pending_approval",
    },
    false,
  );
  log.info("vault_card_requested", {
    card_id: card.id,
    client_id: card.client_id,
    site,
    kind,
    reentry: card.is_reentry,
    expires_at: card.expires_at,
  });
  return { card_id: card.id, status: "pending", expires_at: card.expires_at };
}

function cardExpired(card: CardRecord, nowMs: number): boolean {
  const exp = Date.parse(card.expires_at);
  return !Number.isFinite(exp) || nowMs >= exp;
}

export interface CardStatusResult {
  card_id: string;
  status: CardStatus;
  expires_at: string;
  /** Present once completed. */
  entry_id?: string;
  entry?: EntryMetadata;
}

/**
 * pending | completed (entry id + metadata) | expired. Pass `client` to make a
 * card visible only to the client that requested it.
 */
export async function getCardStatus(
  cardId: string,
  deps: CardsDeps & { client?: ClientIdentity } = {},
): Promise<CardStatusResult> {
  const c = ctx(deps);
  const card = typeof cardId === "string" && CARD_ID_PATTERN.test(cardId) ? await c.cards.get(cardId) : null;
  if (!card || (deps.client && deps.client.client_id !== card.client_id)) {
    throw new CardError("card_not_found", "No such card");
  }
  if (card.status === "completed" && card.entry_id) {
    const entry = await c.entries.get(card.entry_id);
    const out: CardStatusResult = {
      card_id: card.id,
      status: "completed",
      expires_at: card.expires_at,
      entry_id: card.entry_id,
    };
    if (entry) out.entry = publicEntry(entry);
    return out;
  }
  const status: CardStatus = card.status === "expired" || cardExpired(card, c.nowMs) ? "expired" : "pending";
  return { card_id: card.id, status, expires_at: card.expires_at };
}

// ---------------------------------------------------------------- card page backend (card-pages.ts)

/** What the card page may show. No token, no hash, no secret. */
export interface CardView {
  card_id: string;
  client_name: string;
  client_id: string;
  site: string;
  account: string | null;
  purpose: string | null;
  kind: EntryKind;
  reason: string;
  expires_at: string;
  /** Re-entry: site/account/purpose are fixed to the existing entry. */
  reentry: boolean;
}

export type CardLookup = { state: "pending"; card: CardView } | { state: "invalid" | "expired" | "used" };

function cardView(card: CardRecord): CardView {
  return {
    card_id: card.id,
    client_name: card.client_name,
    client_id: card.client_id,
    site: card.site,
    account: card.account,
    purpose: card.purpose,
    kind: card.kind,
    reason: card.reason,
    expires_at: card.expires_at,
    reentry: card.is_reentry,
  };
}

async function findCardByToken(c: Ctx, token: unknown): Promise<CardRecord | null> {
  if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) return null;
  const hash = sha256Hex(token);
  const card = await c.cards.getByTokenHash(hash);
  // Constant-time re-check on the hash, independent of how the store matched it.
  return card && constantTimeEqual(card.token_hash, hash) ? card : null;
}

function cardState(card: CardRecord | null, nowMs: number): "pending" | "invalid" | "expired" | "used" {
  if (!card) return "invalid";
  if (card.status === "completed" || card.status === "claimed") return "used";
  if (card.status === "expired" || cardExpired(card, nowMs)) return "expired";
  return "pending";
}

/** GET side of the card page: never consumes the token. */
export async function lookupCard(token: string, deps: CardsDeps = {}): Promise<CardLookup> {
  const c = ctx(deps);
  const card = await findCardByToken(c, token);
  const state = cardState(card, c.nowMs);
  return state === "pending" && card ? { state, card: cardView(card) } : { state: state as "invalid" | "expired" | "used" };
}

export interface CardSubmission {
  site?: string;
  account?: string;
  purpose?: string;
  secret: string;
}

export type CardSubmitFailure =
  | "invalid_token"
  | "expired"
  | "already_used"
  | "invalid_input"
  | "entry_exists"
  | "entry_gone"
  | "vault_unavailable"
  | "store_failed";

export type CardSubmitResult =
  | { ok: true; entry: EntryMetadata; reentry: boolean }
  | {
      ok: false;
      code: CardSubmitFailure;
      /** Fixed, safe text. Never contains submitted content. */
      message: string;
      /** Present when the card is still pending and the form can be shown again. */
      card?: CardView;
    };

/**
 * POST side of the card page. Validates the token (hash lookup + constant-time
 * compare, pending, unexpired), claims it atomically (single use), writes the
 * secret through the vault backend, creates the entry (or, for a re-entry,
 * replaces only the secret of the same entry id), completes the card and
 * ledgers "vault.entry.create" / "vault.entry.reentry". On a failure before
 * completion the claim is released so the operator can retry until expiry.
 * The result never contains the secret.
 */
export async function submitCard(token: string, submission: CardSubmission, deps: CardsDeps = {}): Promise<CardSubmitResult> {
  const c = ctx(deps);
  const card = await findCardByToken(c, token);
  const state = cardState(card, c.nowMs);
  if (state !== "pending" || !card) {
    if (card && state === "expired" && card.status !== "expired") await c.cards.expire(card.id).catch(() => undefined);
    log.warn("vault_card_submit_rejected", { reason: state, card_id: card?.id ?? "unknown" });
    const code: CardSubmitFailure = state === "expired" ? "expired" : state === "used" ? "already_used" : "invalid_token";
    return { ok: false, code, message: "This card link is invalid, expired or already used." };
  }
  const view = cardView(card);
  const retry = (code: CardSubmitFailure, message: string): CardSubmitResult => ({ ok: false, code, message, card: view });

  // The secret: armed for redaction before anything else can fail around it.
  const secret = typeof submission?.secret === "string" ? submission.secret.trim() : "";
  if (secret.length >= MIN_SECRET_LENGTH) registerSecretForRedaction(secret);
  if (secret.length < MIN_SECRET_LENGTH || secret.length > MAX_SECRET_LENGTH) {
    return retry("invalid_input", `The secret must be ${MIN_SECRET_LENGTH}-${MAX_SECRET_LENGTH} characters.`);
  }

  let target: EntryMetadata | null = null;
  let site: string;
  let account: string;
  let purpose: string;
  if (card.is_reentry) {
    target = card.entry_id ? await c.entries.get(card.entry_id) : null;
    if (!target || target.status === "deleted") {
      await c.cards.expire(card.id).catch(() => undefined);
      return { ok: false, code: "entry_gone", message: "The entry this card was for no longer exists." };
    }
    ({ site, account, purpose } = target);
  } else {
    try {
      site = normalizeSite(submission.site || card.site);
      account = normalizeAccount(submission.account || card.account || "");
      purpose = normalizePurpose(submission.purpose || card.purpose || "");
    } catch (err) {
      return retry("invalid_input", err instanceof EntryError ? err.message : "A field is invalid.");
    }
    // A secret pasted into the wrong field must not become metadata.
    if ([site, account, purpose].some((v) => v.includes(secret))) {
      return retry("invalid_input", "The secret must only be typed in the secret field.");
    }
    if (await c.entries.findIdentity(site, account, card.kind)) {
      return retry("entry_exists", "An entry already exists for this site, account and kind. Request a re-entry instead.");
    }
  }

  if (!(await c.cards.claim(card.id, c.nowIso))) {
    const after = await c.cards.get(card.id);
    const s = cardState(after, c.nowMs);
    log.warn("vault_card_submit_rejected", { reason: s === "pending" ? "used" : s, card_id: card.id });
    return {
      ok: false,
      code: s === "expired" ? "expired" : "already_used",
      message: "This card link is invalid, expired or already used.",
    };
  }

  const fingerprint = secretFingerprint(secret);
  let entry: EntryMetadata;
  try {
    const id = target ? target.id : `ve_${randomBytes(16).toString("hex")}`;
    const backend = await c.backend();
    try {
      await backend.put(
        backendService(id),
        BACKEND_USERNAME,
        secret,
        `echo-credential-broker vault v2 entry: ${entryLabel(site, account, purpose)} (${card.kind})`,
        BYPASS_REASON,
      );
    } catch {
      throw new EntryError("vault_unavailable", "vault write failed");
    }
    if (target) {
      const updated = await c.entries.replaceSecretMeta(id, fingerprint, secret.length, c.nowIso);
      if (!updated) throw new EntryError("entry_gone", "entry vanished");
      entry = updated;
    } else {
      entry = await c.entries.insert({
        id,
        site,
        account,
        purpose,
        label: entryLabel(site, account, purpose),
        kind: card.kind,
        fingerprint,
        secret_length: secret.length,
        nowIso: c.nowIso,
      });
    }
  } catch (err) {
    await c.cards.release(card.id).catch(() => undefined);
    const code = err instanceof EntryError ? err.code : "store_failed";
    log.error("vault_card_submit_failed", { card_id: card.id, error: code });
    if (code === "vault_unavailable") return retry("vault_unavailable", "The vault could not be reached. Try again.");
    if (code === "entry_exists") {
      return retry("entry_exists", "An entry already exists for this site, account and kind. Request a re-entry instead.");
    }
    if (code === "entry_gone") return retry("entry_gone", "The entry this card was for no longer exists.");
    return retry("store_failed", "The entry could not be stored. Try again.");
  }

  // The entry exists from here on; nothing below may turn this into a retry.
  const completed = await c.cards.complete(card.id, entry.id, c.nowIso).catch(() => false);
  if (!completed) log.error("vault_card_complete_failed", { card_id: card.id, entry_id: entry.id });
  await writeLedger(
    c,
    {
      client_id: card.client_id,
      capability: target ? "vault.entry.reentry" : "vault.entry.create",
      resource: entryResource(entry.site, entry.account),
      credential_ref: entryRef(entry.id),
      decision: "escalate",
      tier: 2,
      result: "ok",
    },
    false,
  );
  log.info("vault_card_completed", {
    card_id: card.id,
    entry_id: entry.id,
    client_id: card.client_id,
    site: entry.site,
    reentry: target !== null,
  });
  return { ok: true, entry: publicEntry(entry), reentry: target !== null };
}
