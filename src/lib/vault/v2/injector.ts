// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 browser injector channel (docs/ops/injector-contract.md,
 * docs/ops/injector-channel.md).
 *
 * An "injector" is an enrolled browser extension instance on the owner's own
 * machine. It holds a P-256 ECDH private key (non-extractable, in the browser)
 * and an injector token. An agent can ask for a credential to be placed in the
 * owner's browser (`entry_inject`, gateway.ts); after the owner approved that
 * one request on Telegram the agent gets a single-use TICKET, and the injector
 * exchanges the ticket for the credential SEALED to its public key.
 *
 * Invariant of this module: plaintext of a stored credential exists only
 * inside this process and, as ciphertext only the injector's private key can
 * open, on the wire. Nothing here returns, logs, ledgers or stores a secret, a
 * cookie value, the ECDH shared secret, the derived AES key, an injector token
 * or a raw ticket (the mint result, returned once to the caller, excepted).
 *
 *   enrollInjector   owner only (gateway admin tool). Validates the public JWK
 *                    by importing it with WebCrypto, mints `ein_<43 base64url>`
 *                    (256 bit), stores sha256(token) only.
 *   mintTicket       `eit_<32 base64url>` (192 bit), stored as sha256, TTL
 *                    120 s, bound to entry, mode, target origin, injector,
 *                    approval and requesting client. No ticket without its
 *                    ledger row.
 *   redeemTicket     atomic single use (see the table below), then the secret
 *                    is read through cards.useEntry (the one read path), the
 *                    plaintext is assembled and sealed, and the redeem row is
 *                    written — fail closed: no ciphertext leaves when that row
 *                    cannot be written.
 *   reportResult     the injector's outcome ("injected" | "failed").
 *
 * Redeem outcomes, in this order (first match wins):
 *   store down / rate-limit store down          503 unavailable       not burned
 *   over the per-injector rate limit            429 rate_limited      not burned
 *   malformed or unknown ticket                 404 ticket_not_found  —
 *   ticket bound to ANOTHER injector            403 ticket_wrong_injector  not burned
 *   already redeemed (burned)                   409 ticket_used       —
 *   expired, never redeemed                     410 ticket_expired    —
 *   bound injector, live ticket                 BURNED here, atomically; then
 *     entry gone / needs re-entry / kind changed / no cookie for the origin /
 *     vault unreachable / sealing failed / ledger unavailable → 503 unavailable
 *     (the ticket stays burned), otherwise 200 with the sealed blob.
 * An unauthenticated caller (bad, revoked or foreign token) never reaches this
 * function: injector-http.ts answers 401 invalid_injector first.
 *
 * Sealing (exactly the contract): ephemeral P-256 key pair; Z = ECDH(ephemeral
 * private, injector public); K = HKDF-SHA256(Z, salt[32], info
 * "echo-vault-injector-v1", 32 bytes); ct = AES-256-GCM(K, iv[12], plaintext,
 * aad) with the 16-byte tag appended; aad = UTF-8 of
 * `eit:${sha256hex(ticket)}|${injector_id}|${target_origin}|${mode}`.
 * K is derived as a non-extractable CryptoKey, so its bytes never exist in JS.
 * The Z and plaintext byte buffers are zeroed after use; JS strings (the
 * secret as read from the backend, the plaintext JSON) cannot be zeroed and
 * live until garbage collection.
 */
import { createHash, randomBytes, timingSafeEqual, webcrypto } from "node:crypto";
import type { Sql } from "../../db.ts";
import { log } from "../log.ts";
import { isBlockedHost } from "../policy.ts";
import { registerSecretForRedaction } from "../redaction.ts";
import { sanitizeDisplayText } from "./approvals.ts";
import { getEntryMetadata, useEntry, type CardsDeps, type EntryKind, type EntryMetadata } from "./cards.ts";
import type { ClientIdentity, LedgerEntryInput } from "./contracts.ts";
import { domainMatches, isPublicSuffix, jarRedactionForms, parseStoredJar, type CookieJar } from "./cookie-jar.ts";
import { appendLedger } from "./ledger.ts";
import { getDefaultRateLimitStore, rateLimitKey, withRateLimitStore, type RateLimitStore } from "./rate-limit-store.ts";

// ---------------------------------------------------------------------------
// Constants and shapes
// ---------------------------------------------------------------------------

export const INJECTOR_ID_PATTERN = /^inj_[0-9a-f]{16}$/;
/** What this vault mints: `ein_` + 43 base64url chars (32 random bytes). Longer is tolerated on input, per the contract's "43+". */
export const INJECTOR_TOKEN_PATTERN = /^ein_[A-Za-z0-9_-]{43,128}$/;
/** `eit_` + 32 base64url chars (24 random bytes, 192 bit). */
export const TICKET_PATTERN = /^eit_[A-Za-z0-9_-]{32}$/;
export const TICKET_TTL_MS = 120_000;
export const MAX_ACTIVE_INJECTORS = 20;
export const MAX_INJECTOR_NAME_CHARS = 64;
export const SEAL_ALG = "ECDH-ES+HKDF-SHA256+A256GCM";
export const SEAL_INFO = "echo-vault-injector-v1";
export const REDEEM_WINDOW_MS = 60_000;
export const REDEEM_MAX_PER_WINDOW = 30;
export const REPORT_MAX_PER_WINDOW = 60;
export const INJECT_CAPABILITY = "vault.entry.inject";
export const REDEEM_CAPABILITY = "vault.entry.inject.redeem";
export const RESULT_CAPABILITY = "vault.entry.inject.result";

export type InjectMode = "cookies" | "field";
export const INJECT_MODES: readonly InjectMode[] = ["cookies", "field"];
export type InjectResult = "injected" | "failed";

const HEX64 = /^[0-9a-f]{64}$/;
const ENTRY_ID = /^ve_[0-9a-f]{32}$/;
const COORD = /^[A-Za-z0-9_-]{43}$/;
const HOST = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const DETAIL_CODE = /^[a-z0-9_]{1,64}$/;
/** JWK members a browser's exportKey may add to a public key. Anything else — "d" above all — is refused. */
const JWK_PUBLIC_MEMBERS = new Set(["kty", "crv", "x", "y", "ext", "key_ops", "alg", "use", "kid"]);

const subtle = webcrypto.subtle;

/** A fixed short code. The message IS the code: no caller text, no secret ever rides in it. */
export class InjectorError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "InjectorError";
    this.code = code;
  }
}

export interface PublicJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

export interface InjectorRecord {
  id: string;
  name: string;
  /** Canonical JSON `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`. Public. */
  public_key_jwk: string;
  token_sha256: string;
  created_at: number;
  revoked_at: number | null;
  last_used_at: number | null;
}

export interface InjectTicketRecord {
  sha256: string;
  entry_id: string;
  mode: InjectMode;
  target_origin: string;
  injector_id: string;
  approval_id: string;
  client_id: string;
  created_at: number;
  expires_at: number;
  redeemed_at: number | null;
  result: InjectResult | null;
}

export interface InjectorStore {
  readonly kind: "memory" | "sql";
  insert(rec: InjectorRecord): Promise<void>;
  get(id: string): Promise<InjectorRecord | null>;
  findByTokenHash(tokenSha256: string): Promise<InjectorRecord | null>;
  list(): Promise<InjectorRecord[]>;
  /** True when this call revoked it (false: unknown or already revoked). */
  revoke(id: string, at: number): Promise<boolean>;
  touch(id: string, at: number): Promise<void>;
}

export interface InjectTicketStore {
  readonly kind: "memory" | "sql";
  /** Throws InjectorError("approval_already_used") when the approval already minted a ticket. */
  insert(rec: InjectTicketRecord): Promise<void>;
  get(sha256: string): Promise<InjectTicketRecord | null>;
  /**
   * The burn. Atomic: sets redeemed_at only when the ticket exists, is bound to
   * `injectorId`, was never redeemed and is unexpired at `now`; returns the row
   * then, null in every other case (nothing changed).
   */
  redeem(sha256: string, injectorId: string, now: number): Promise<InjectTicketRecord | null>;
  /** Atomic, once: only for a redeemed ticket of that injector without a result. */
  setResult(sha256: string, injectorId: string, result: InjectResult): Promise<boolean>;
  delete(sha256: string): Promise<void>;
  /** Drop tickets that expired more than `keepMs` before `now`. */
  prune(now: number, keepMs?: number): Promise<number>;
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function checkInjector(rec: InjectorRecord): void {
  if (!INJECTOR_ID_PATTERN.test(rec.id)) throw new InjectorError("injector_invalid_id");
  if (typeof rec.name !== "string" || rec.name.length < 1 || rec.name.length > MAX_INJECTOR_NAME_CHARS) throw new InjectorError("injector_invalid_name");
  if (canonicalJwkText(parseCanonicalJwk(rec.public_key_jwk)) !== rec.public_key_jwk) throw new InjectorError("injector_invalid_key");
  if (!HEX64.test(rec.token_sha256)) throw new InjectorError("injector_invalid_token_hash");
  if (!Number.isInteger(rec.created_at) || rec.created_at <= 0) throw new InjectorError("injector_invalid_time");
}

function checkTicket(rec: InjectTicketRecord): void {
  if (!HEX64.test(rec.sha256)) throw new InjectorError("ticket_invalid_hash");
  if (!ENTRY_ID.test(rec.entry_id)) throw new InjectorError("ticket_invalid_entry");
  if (!INJECT_MODES.includes(rec.mode)) throw new InjectorError("ticket_invalid_mode");
  if (!isCanonicalOrigin(rec.target_origin)) throw new InjectorError("ticket_invalid_origin");
  if (!INJECTOR_ID_PATTERN.test(rec.injector_id)) throw new InjectorError("ticket_invalid_injector");
  if (typeof rec.approval_id !== "string" || rec.approval_id.length < 1 || rec.approval_id.length > 256) throw new InjectorError("ticket_invalid_approval");
  if (typeof rec.client_id !== "string" || rec.client_id.length < 1 || rec.client_id.length > 200) throw new InjectorError("ticket_invalid_client");
  if (!Number.isInteger(rec.created_at) || rec.created_at <= 0 || !Number.isInteger(rec.expires_at) || rec.expires_at <= rec.created_at) {
    throw new InjectorError("ticket_invalid_time");
  }
}

// ---------------------------------------------------------------------------
// Memory stores
// ---------------------------------------------------------------------------

export class MemoryInjectorStore implements InjectorStore {
  readonly kind = "memory" as const;
  private readonly rows = new Map<string, InjectorRecord>();

  async insert(rec: InjectorRecord): Promise<void> {
    checkInjector(rec);
    if (this.rows.has(rec.id) || [...this.rows.values()].some((r) => r.token_sha256 === rec.token_sha256)) throw new InjectorError("injector_exists");
    this.rows.set(rec.id, { ...rec });
  }
  async get(id: string): Promise<InjectorRecord | null> {
    const r = this.rows.get(id);
    return r ? { ...r } : null;
  }
  async findByTokenHash(tokenSha256: string): Promise<InjectorRecord | null> {
    const r = [...this.rows.values()].find((x) => x.token_sha256 === tokenSha256);
    return r ? { ...r } : null;
  }
  async list(): Promise<InjectorRecord[]> {
    return [...this.rows.values()].sort((a, b) => a.created_at - b.created_at || a.id.localeCompare(b.id)).map((r) => ({ ...r }));
  }
  async revoke(id: string, at: number): Promise<boolean> {
    const r = this.rows.get(id);
    if (!r || r.revoked_at !== null) return false;
    r.revoked_at = Math.max(at, r.created_at);
    return true;
  }
  async touch(id: string, at: number): Promise<void> {
    const r = this.rows.get(id);
    if (r) r.last_used_at = Math.max(at, r.created_at);
  }
  dumpForTests(): InjectorRecord[] {
    return [...this.rows.values()].map((r) => ({ ...r }));
  }
}

export class MemoryInjectTicketStore implements InjectTicketStore {
  readonly kind = "memory" as const;
  private readonly rows = new Map<string, InjectTicketRecord>();

  async insert(rec: InjectTicketRecord): Promise<void> {
    checkTicket(rec);
    if (this.rows.has(rec.sha256)) throw new InjectorError("ticket_exists");
    if ([...this.rows.values()].some((r) => r.approval_id === rec.approval_id)) throw new InjectorError("approval_already_used");
    this.rows.set(rec.sha256, { ...rec });
  }
  async get(sha256: string): Promise<InjectTicketRecord | null> {
    const r = this.rows.get(sha256);
    return r ? { ...r } : null;
  }
  async redeem(sha256: string, injectorId: string, now: number): Promise<InjectTicketRecord | null> {
    const r = this.rows.get(sha256);
    if (!r || r.injector_id !== injectorId || r.redeemed_at !== null || r.expires_at <= now) return null;
    r.redeemed_at = Math.max(now, r.created_at);
    return { ...r };
  }
  async setResult(sha256: string, injectorId: string, result: InjectResult): Promise<boolean> {
    const r = this.rows.get(sha256);
    if (!r || r.injector_id !== injectorId || r.redeemed_at === null || r.result !== null) return false;
    r.result = result;
    return true;
  }
  async delete(sha256: string): Promise<void> {
    this.rows.delete(sha256);
  }
  async prune(now: number, keepMs = 0): Promise<number> {
    let n = 0;
    for (const [k, r] of this.rows) {
      if (r.expires_at + keepMs <= now) {
        this.rows.delete(k);
        n += 1;
      }
    }
    return n;
  }
  dumpForTests(): InjectTicketRecord[] {
    return [...this.rows.values()].map((r) => ({ ...r }));
  }
}

// ---------------------------------------------------------------------------
// SQL stores (migrations/0013_vault_injectors.sql)
// ---------------------------------------------------------------------------

type SqlQuery = Pick<Sql, "query">;

async function defaultSql(): Promise<SqlQuery> {
  const db = await import("../../db.ts");
  return db.getSql();
}

function violates(err: unknown, constraint: string): boolean {
  const e = err as { constraint?: unknown; message?: unknown } | null;
  return e?.constraint === constraint || (typeof e?.message === "string" && e.message.includes(constraint));
}

const num = (v: unknown): number => Number(v);
const numOrNull = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));

const INJECTOR_COLUMNS = "id, name, public_key_jwk, token_sha256, created_at, revoked_at, last_used_at";

function rowToInjector(row: Record<string, unknown>): InjectorRecord {
  return {
    id: String(row.id),
    name: String(row.name),
    public_key_jwk: String(row.public_key_jwk),
    token_sha256: String(row.token_sha256),
    created_at: num(row.created_at),
    revoked_at: numOrNull(row.revoked_at),
    last_used_at: numOrNull(row.last_used_at),
  };
}

export class SqlInjectorStore implements InjectorStore {
  readonly kind = "sql" as const;
  private readonly getSql: () => Promise<SqlQuery>;
  constructor(getSql: () => Promise<SqlQuery> = defaultSql) {
    this.getSql = getSql;
  }
  async insert(rec: InjectorRecord): Promise<void> {
    checkInjector(rec);
    const sql = await this.getSql();
    try {
      await sql.query(
        `insert into vault_injectors (${INJECTOR_COLUMNS}) values ($1, $2, $3, $4, $5, $6, $7)`,
        [rec.id, rec.name, rec.public_key_jwk, rec.token_sha256, rec.created_at, rec.revoked_at, rec.last_used_at],
      );
    } catch (err) {
      if (violates(err, "vault_injectors_pkey") || violates(err, "vault_injectors_token_sha256_key")) throw new InjectorError("injector_exists");
      throw err;
    }
  }
  async get(id: string): Promise<InjectorRecord | null> {
    if (!INJECTOR_ID_PATTERN.test(id)) return null;
    const rows = await (await this.getSql()).query<Record<string, unknown>>(`select ${INJECTOR_COLUMNS} from vault_injectors where id = $1`, [id]);
    return rows[0] ? rowToInjector(rows[0]) : null;
  }
  async findByTokenHash(tokenSha256: string): Promise<InjectorRecord | null> {
    if (!HEX64.test(tokenSha256)) return null;
    const rows = await (await this.getSql()).query<Record<string, unknown>>(
      `select ${INJECTOR_COLUMNS} from vault_injectors where token_sha256 = $1`,
      [tokenSha256],
    );
    return rows[0] ? rowToInjector(rows[0]) : null;
  }
  async list(): Promise<InjectorRecord[]> {
    const rows = await (await this.getSql()).query<Record<string, unknown>>(`select ${INJECTOR_COLUMNS} from vault_injectors order by created_at, id`);
    return rows.map(rowToInjector);
  }
  async revoke(id: string, at: number): Promise<boolean> {
    if (!INJECTOR_ID_PATTERN.test(id)) return false;
    const rows = await (await this.getSql()).query(
      `update vault_injectors set revoked_at = greatest($2::bigint, created_at) where id = $1 and revoked_at is null returning id`,
      [id, at],
    );
    return rows.length === 1;
  }
  async touch(id: string, at: number): Promise<void> {
    if (!INJECTOR_ID_PATTERN.test(id)) return;
    await (await this.getSql()).query(`update vault_injectors set last_used_at = greatest($2::bigint, created_at) where id = $1`, [id, at]);
  }
}

const TICKET_COLUMNS = "sha256, entry_id, mode, target_origin, injector_id, approval_id, client_id, created_at, expires_at, redeemed_at, result";

function rowToTicket(row: Record<string, unknown>): InjectTicketRecord {
  return {
    sha256: String(row.sha256),
    entry_id: String(row.entry_id),
    mode: String(row.mode) as InjectMode,
    target_origin: String(row.target_origin),
    injector_id: String(row.injector_id),
    approval_id: String(row.approval_id),
    client_id: String(row.client_id),
    created_at: num(row.created_at),
    expires_at: num(row.expires_at),
    redeemed_at: numOrNull(row.redeemed_at),
    result: row.result === null || row.result === undefined ? null : (String(row.result) as InjectResult),
  };
}

export class SqlInjectTicketStore implements InjectTicketStore {
  readonly kind = "sql" as const;
  private readonly getSql: () => Promise<SqlQuery>;
  constructor(getSql: () => Promise<SqlQuery> = defaultSql) {
    this.getSql = getSql;
  }
  async insert(rec: InjectTicketRecord): Promise<void> {
    checkTicket(rec);
    const sql = await this.getSql();
    try {
      await sql.query(
        `insert into vault_inject_tickets (${TICKET_COLUMNS}) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [rec.sha256, rec.entry_id, rec.mode, rec.target_origin, rec.injector_id, rec.approval_id, rec.client_id, rec.created_at, rec.expires_at, rec.redeemed_at, rec.result],
      );
    } catch (err) {
      if (violates(err, "vault_inject_tickets_approval_id_key")) throw new InjectorError("approval_already_used");
      if (violates(err, "vault_inject_tickets_pkey")) throw new InjectorError("ticket_exists");
      throw err;
    }
  }
  async get(sha256: string): Promise<InjectTicketRecord | null> {
    if (!HEX64.test(sha256)) return null;
    const rows = await (await this.getSql()).query<Record<string, unknown>>(`select ${TICKET_COLUMNS} from vault_inject_tickets where sha256 = $1`, [sha256]);
    return rows[0] ? rowToTicket(rows[0]) : null;
  }
  async redeem(sha256: string, injectorId: string, now: number): Promise<InjectTicketRecord | null> {
    if (!HEX64.test(sha256) || !INJECTOR_ID_PATTERN.test(injectorId)) return null;
    // One statement: the row lock serializes concurrent redeems, and the WHERE is
    // re-evaluated against the committed row, so exactly one caller gets the row.
    const rows = await (await this.getSql()).query<Record<string, unknown>>(
      `update vault_inject_tickets set redeemed_at = greatest($3::bigint, created_at)
        where sha256 = $1 and injector_id = $2 and redeemed_at is null and expires_at > $3::bigint
        returning ${TICKET_COLUMNS}`,
      [sha256, injectorId, now],
    );
    return rows[0] ? rowToTicket(rows[0]) : null;
  }
  async setResult(sha256: string, injectorId: string, result: InjectResult): Promise<boolean> {
    if (!HEX64.test(sha256) || !INJECTOR_ID_PATTERN.test(injectorId) || (result !== "injected" && result !== "failed")) return false;
    const rows = await (await this.getSql()).query(
      `update vault_inject_tickets set result = $3
        where sha256 = $1 and injector_id = $2 and redeemed_at is not null and result is null returning sha256`,
      [sha256, injectorId, result],
    );
    return rows.length === 1;
  }
  async delete(sha256: string): Promise<void> {
    if (!HEX64.test(sha256)) return;
    await (await this.getSql()).query(`delete from vault_inject_tickets where sha256 = $1`, [sha256]);
  }
  async prune(now: number, keepMs = 0): Promise<number> {
    const rows = await (await this.getSql()).query(`delete from vault_inject_tickets where expires_at + $2::bigint <= $1::bigint returning sha256`, [now, keepMs]);
    return rows.length;
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

export interface InjectorDeps {
  injectors?: InjectorStore;
  tickets?: InjectTicketStore;
  /** Epoch-ms clock. */
  now?: () => number;
  /** Per-injector redeem / report limits. Default: the shared DB rate-limit store. */
  rateLimit?: RateLimitStore;
  /** Entries + backend (the secret is read only through cards.useEntry). */
  cards?: CardsDeps;
  /** Ledger sink. Default: appendLedger. */
  ledger?: (input: LedgerEntryInput) => Promise<unknown>;
}

let defaultInjectorStore: InjectorStore | null = null;
let defaultTicketStore: InjectTicketStore | null = null;

export function getDefaultInjectorStore(): InjectorStore {
  defaultInjectorStore ??= new SqlInjectorStore();
  return defaultInjectorStore;
}

export function getDefaultInjectTicketStore(): InjectTicketStore {
  defaultTicketStore ??= new SqlInjectTicketStore();
  return defaultTicketStore;
}

/** Wiring/test hook. Pass null to restore the SQL defaults. */
export function setDefaultInjectorStores(stores: { injectors: InjectorStore; tickets: InjectTicketStore } | null): void {
  defaultInjectorStore = stores?.injectors ?? null;
  defaultTicketStore = stores?.tickets ?? null;
}

interface Ctx {
  injectors: InjectorStore;
  tickets: InjectTicketStore;
  now: number;
  limits: RateLimitStore;
  cards: CardsDeps | undefined;
  ledger: (input: LedgerEntryInput) => Promise<unknown>;
}

function ctx(deps: InjectorDeps = {}): Ctx {
  return {
    injectors: deps.injectors ?? getDefaultInjectorStore(),
    tickets: deps.tickets ?? getDefaultInjectTicketStore(),
    now: Math.floor((deps.now ?? Date.now)()),
    limits: deps.rateLimit ?? getDefaultRateLimitStore(),
    cards: deps.cards,
    ledger: deps.ledger ?? deps.cards?.ledger ?? appendLedger,
  };
}

// ---------------------------------------------------------------------------
// Public key handling
// ---------------------------------------------------------------------------

function canonicalJwkText(jwk: PublicJwk): string {
  return `{"crv":"P-256","kty":"EC","x":${JSON.stringify(jwk.x)},"y":${JSON.stringify(jwk.y)}}`;
}

/** Structural check only (no curve check). Throws InjectorError("invalid_public_key"). */
function parseCanonicalJwk(input: unknown): PublicJwk {
  let value: unknown = input;
  if (typeof value === "string") {
    if (value.length > 2048) throw new InjectorError("invalid_public_key");
    try {
      value = JSON.parse(value);
    } catch {
      throw new InjectorError("invalid_public_key");
    }
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new InjectorError("invalid_public_key");
  const o = value as Record<string, unknown>;
  // A private JWK must never be sent here, let alone stored.
  if (Object.hasOwn(o, "d")) throw new InjectorError("private_key_not_allowed");
  for (const key of Object.keys(o)) if (!JWK_PUBLIC_MEMBERS.has(key)) throw new InjectorError("invalid_public_key");
  if (o.kty !== "EC" || o.crv !== "P-256" || typeof o.x !== "string" || typeof o.y !== "string" || !COORD.test(o.x) || !COORD.test(o.y)) {
    throw new InjectorError("invalid_public_key");
  }
  return { kty: "EC", crv: "P-256", x: o.x, y: o.y };
}

async function importPublicKey(jwk: PublicJwk): Promise<webcrypto.CryptoKey> {
  try {
    // WebCrypto rejects a point that is not on the curve.
    return await subtle.importKey("jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true }, { name: "ECDH", namedCurve: "P-256" }, true, []);
  } catch {
    throw new InjectorError("invalid_public_key");
  }
}

/** Validate a P-256 ECDH PUBLIC JWK (object or JSON text) by importing it. Returns the canonical four-member form. */
export async function validatePublicJwk(input: unknown): Promise<PublicJwk> {
  const jwk = parseCanonicalJwk(input);
  await importPublicKey(jwk);
  return jwk;
}

/** RFC 7638 thumbprint (base64url of sha256 over the canonical members). Lets the owner compare with what the extension shows. */
export function jwkThumbprint(canonicalJwk: string): string {
  return createHash("sha256").update(canonicalJwk, "utf8").digest("base64url");
}

// ---------------------------------------------------------------------------
// Enrollment, listing, revocation, authentication
// ---------------------------------------------------------------------------

/** What the owner sees about an injector. Public material and times only. */
export interface InjectorView {
  injector_id: string;
  name: string;
  key_thumbprint: string;
  status: "active" | "revoked";
  created_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
}

const iso = (ms: number | null): string | null => (ms === null ? null : new Date(ms).toISOString());

export function injectorView(r: InjectorRecord): InjectorView {
  return {
    injector_id: r.id,
    name: r.name,
    key_thumbprint: jwkThumbprint(r.public_key_jwk),
    status: r.revoked_at === null ? "active" : "revoked",
    created_at: iso(r.created_at) as string,
    revoked_at: iso(r.revoked_at),
    last_used_at: iso(r.last_used_at),
  };
}

/**
 * Enroll an injector. The returned `token` is shown ONCE by the caller (the
 * gateway's owner-only admin tool); only its sha256 is stored. Throws
 * InjectorError: invalid_name | invalid_public_key | private_key_not_allowed |
 * too_many_injectors | key_already_enrolled.
 */
export async function enrollInjector(
  input: { name: unknown; public_key_jwk: unknown },
  deps: InjectorDeps = {},
): Promise<{ injector: InjectorView; token: string }> {
  const c = ctx(deps);
  const name = typeof input.name === "string" ? sanitizeDisplayText(input.name, MAX_INJECTOR_NAME_CHARS) : "";
  if (!name) throw new InjectorError("invalid_name");
  const jwk = await validatePublicJwk(input.public_key_jwk);
  const canonical = canonicalJwkText(jwk);
  const active = (await c.injectors.list()).filter((r) => r.revoked_at === null);
  if (active.length >= MAX_ACTIVE_INJECTORS) throw new InjectorError("too_many_injectors");
  if (active.some((r) => r.public_key_jwk === canonical)) throw new InjectorError("key_already_enrolled");
  const token = `ein_${randomBytes(32).toString("base64url")}`;
  const rec: InjectorRecord = {
    id: `inj_${randomBytes(8).toString("hex")}`,
    name,
    public_key_jwk: canonical,
    token_sha256: sha256Hex(token),
    created_at: c.now,
    revoked_at: null,
    last_used_at: null,
  };
  await c.injectors.insert(rec);
  log.info("vault_injector_enrolled", { injector_id: rec.id });
  return { injector: injectorView(rec), token };
}

export async function listInjectors(deps: InjectorDeps = {}): Promise<InjectorView[]> {
  return (await ctx(deps).injectors.list()).map(injectorView);
}

/** Revoke. Its token stops authenticating at once, so its outstanding tickets can never be redeemed. */
export async function revokeInjector(id: unknown, deps: InjectorDeps = {}): Promise<boolean> {
  const c = ctx(deps);
  if (typeof id !== "string" || !INJECTOR_ID_PATTERN.test(id)) throw new InjectorError("injector_not_found");
  const existing = await c.injectors.get(id);
  if (!existing) throw new InjectorError("injector_not_found");
  const revoked = await c.injectors.revoke(id, c.now);
  log.warn("vault_injector_revoked", { injector_id: id, was_active: revoked });
  return revoked;
}

/**
 * Which injector an `entry_inject` call targets. With `requested`: that one,
 * if active. Without: the only active injector, if there is exactly one.
 * Throws InjectorError: injector_not_found | no_injector_enrolled | injector_required.
 */
export async function resolveInjector(requested: string | undefined, deps: InjectorDeps = {}): Promise<InjectorView> {
  const c = ctx(deps);
  if (requested !== undefined) {
    const r = INJECTOR_ID_PATTERN.test(requested) ? await c.injectors.get(requested) : null;
    if (!r || r.revoked_at !== null) throw new InjectorError("injector_not_found");
    return injectorView(r);
  }
  const active = (await c.injectors.list()).filter((r) => r.revoked_at === null);
  if (active.length === 0) throw new InjectorError("no_injector_enrolled");
  if (active.length > 1) throw new InjectorError("injector_required");
  return injectorView(active[0]);
}

/**
 * `Authorization: Bearer ein_…` → the active injector, or null. Nothing else
 * authenticates here: an OAuth (`eva_`) or workload (`ewk_`) token does not
 * match the pattern, and an `ein_` token is never looked at by
 * http-transport.ts. Throws only when the store is unreachable.
 */
export async function authenticateInjector(headers: Headers, deps: InjectorDeps = {}): Promise<InjectorRecord | null> {
  const match = /^Bearer\s+(\S+)$/i.exec((headers.get("authorization") ?? "").trim());
  if (!match || !INJECTOR_TOKEN_PATTERN.test(match[1])) return null;
  const digest = sha256Hex(match[1]);
  const rec = await ctx(deps).injectors.findByTokenHash(digest);
  if (!rec || rec.revoked_at !== null) return null;
  if (!timingSafeEqual(Buffer.from(rec.token_sha256, "hex"), Buffer.from(digest, "hex"))) return null;
  return rec;
}

// ---------------------------------------------------------------------------
// Target origin and mode rules (shared by the gateway planner and the mint)
// ---------------------------------------------------------------------------

function isCanonicalOrigin(origin: unknown): origin is string {
  return typeof origin === "string" && origin.length <= 261 && origin.startsWith("https://") && HOST.test(origin.slice(8));
}

/**
 * `target_origin` must be exactly `https://<host>` (lower case, no port, path,
 * query, fragment or credentials) where host is the entry's site or a
 * subdomain of it, and not a blocked/internal host. Returns the host.
 * Throws InjectorError: invalid_target_origin | target_origin_not_allowed.
 */
export function checkTargetOrigin(origin: unknown, site: string): string {
  if (!isCanonicalOrigin(origin)) throw new InjectorError("invalid_target_origin");
  const host = origin.slice(8);
  if (!site || (host !== site && !host.endsWith(`.${site}`))) throw new InjectorError("target_origin_not_allowed");
  if (isBlockedHost(host)) throw new InjectorError("target_origin_not_allowed");
  return host;
}

/** cookies ↔ a `cookie` entry; field ↔ a `password` entry. */
export function kindForMode(mode: InjectMode): EntryKind {
  return mode === "cookies" ? "cookie" : "password";
}

/** `entry:<site>/<account>#<injector id>` — the ledger resource of every inject row. */
export function injectResource(site: string, account: string, injectorId: string): string {
  return `entry:${site}/${account}#${injectorId}`;
}

// ---------------------------------------------------------------------------
// Mint
// ---------------------------------------------------------------------------

export interface MintTicketInput {
  client_id: string;
  entry: EntryMetadata;
  mode: InjectMode;
  target_origin: string;
  injector_id: string;
  /** The consumed, request-bound approval this ticket exists because of. Required. */
  approval_id: string;
  /**
   * Writes the `vault.entry.inject` ok row. MUST reject when the row was not
   * written: the ticket is then deleted and never returned.
   */
  record: () => Promise<unknown>;
}

export interface MintedTicket {
  ticket: string;
  expires_at: string;
  injector_id: string;
  entry: { id: string; label: string; kind: EntryKind };
  target_origin: string;
  mode: InjectMode;
}

/**
 * Mint one ticket. Re-checks everything the planner checked (time passed
 * while the owner decided). Throws InjectorError: approval_required |
 * invalid_mode | mode_kind_mismatch | entry_not_active | invalid_target_origin |
 * target_origin_not_allowed | injector_not_found | approval_already_used |
 * ledger_unavailable.
 */
export async function mintTicket(input: MintTicketInput, deps: InjectorDeps = {}): Promise<MintedTicket> {
  const c = ctx(deps);
  if (typeof input.approval_id !== "string" || !input.approval_id) throw new InjectorError("approval_required");
  if (!INJECT_MODES.includes(input.mode)) throw new InjectorError("invalid_mode");
  if (input.entry.kind !== kindForMode(input.mode)) throw new InjectorError("mode_kind_mismatch");
  if (input.entry.status !== "active") throw new InjectorError("entry_not_active");
  checkTargetOrigin(input.target_origin, input.entry.site);
  const injector = INJECTOR_ID_PATTERN.test(input.injector_id) ? await c.injectors.get(input.injector_id) : null;
  if (!injector || injector.revoked_at !== null) throw new InjectorError("injector_not_found");

  const ticket = `eit_${randomBytes(24).toString("base64url")}`;
  const rec: InjectTicketRecord = {
    sha256: sha256Hex(ticket),
    entry_id: input.entry.id,
    mode: input.mode,
    target_origin: input.target_origin,
    injector_id: injector.id,
    approval_id: input.approval_id,
    client_id: input.client_id,
    created_at: c.now,
    expires_at: c.now + TICKET_TTL_MS,
    redeemed_at: null,
    result: null,
  };
  await c.tickets.insert(rec);
  try {
    await input.record();
  } catch {
    // No ticket without its row: take it back, and never hand it out.
    await c.tickets.delete(rec.sha256).catch(() => log.error("vault_inject_ticket_cleanup_failed", { injector_id: injector.id }));
    throw new InjectorError("ledger_unavailable");
  }
  // Opportunistic housekeeping; a day of history is kept for the report and for audits.
  void c.tickets.prune(c.now, 86_400_000).catch(() => undefined);
  log.info("vault_inject_ticket_minted", { entry_id: rec.entry_id, injector_id: rec.injector_id, mode: rec.mode, approval_id: rec.approval_id });
  return {
    ticket,
    expires_at: new Date(rec.expires_at).toISOString(),
    injector_id: rec.injector_id,
    entry: { id: input.entry.id, label: input.entry.label, kind: input.entry.kind },
    target_origin: rec.target_origin,
    mode: rec.mode,
  };
}

// ---------------------------------------------------------------------------
// Plaintext assembly
// ---------------------------------------------------------------------------

export interface InjectedCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  hostOnly: boolean;
  /** Epoch seconds, or null for a session cookie. */
  expires: number | null;
  /** The vault does not store SameSite; always "unspecified" (chrome.cookies' default). */
  sameSite: "unspecified";
}

/**
 * The cookies of `jar` that a browser would send to `host` — domain match
 * only (RFC 6265 §5.1.3), every path, unexpired. A host-only cookie needs the
 * exact host; a domain cookie matches its domain and subdomains, never a
 * public suffix. A cookie stored with domain "" is host-only for the entry's
 * site and is emitted with that site as its domain. Nothing scoped to another
 * registrable domain can match, because the cookie's domain must be `host` or
 * a parent of it and `host` is the entry's site or a subdomain of it.
 */
export function cookiesForOrigin(jar: CookieJar, host: string, site: string, nowMs: number): InjectedCookie[] {
  const out: InjectedCookie[] = [];
  for (const c of jar.cookies) {
    if (c.expires !== null && c.expires * 1000 <= nowMs) continue;
    const domain = c.domain || site;
    if (!domain) continue;
    if (c.hostOnly ? host !== domain : !domainMatches(host, domain) || isPublicSuffix(domain)) continue;
    out.push({ name: c.name, value: c.value, domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, hostOnly: c.hostOnly, expires: c.expires, sameSite: "unspecified" });
  }
  return out;
}

/** The plaintext JSON for one redeem. Throws Error(<short code>) — never with content. */
function assemblePlaintext(secret: string, entry: EntryMetadata, ticket: InjectTicketRecord, nowMs: number): string {
  if (entry.kind !== kindForMode(ticket.mode)) throw new Error("mode_kind_mismatch");
  const host = checkTargetOrigin(ticket.target_origin, entry.site);
  if (ticket.mode === "cookies") {
    let jar: CookieJar;
    try {
      jar = parseStoredJar(secret);
    } catch {
      throw new Error("cookie_jar_invalid");
    }
    // Defense in depth for logs: the wire carries ciphertext, but arm the values anyway.
    for (const form of jarRedactionForms(jar)) registerSecretForRedaction(form);
    const cookies = cookiesForOrigin(jar, host, entry.site, nowMs);
    if (cookies.length === 0) throw new Error("no_cookie_for_origin");
    return JSON.stringify({ v: 1, cookies });
  }
  return JSON.stringify({ v: 1, username: entry.account, secret });
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

export interface SealedBlob {
  alg: typeof SEAL_ALG;
  epk: PublicJwk;
  salt: string;
  iv: string;
  ct: string;
  aad: string;
}

/** The AAD string of the contract. `ticketSha256` is sha256 hex of the raw ticket. */
export function sealAad(ticketSha256: string, injectorId: string, targetOrigin: string, mode: InjectMode): string {
  return `eit:${ticketSha256}|${injectorId}|${targetOrigin}|${mode}`;
}

const b64u = (bytes: Uint8Array): string => Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");

/**
 * Seal `plaintext` to a P-256 public key. ECDH-ES (ephemeral key) → HKDF-SHA256
 * (random 32-byte salt, info "echo-vault-injector-v1") → AES-256-GCM (random
 * 12-byte IV, AAD). The AES key is a non-extractable CryptoKey; the shared
 * secret and plaintext buffers are zeroed before returning.
 */
export async function sealForInjector(plaintext: string, recipient: PublicJwk, aad: string): Promise<SealedBlob> {
  const recipientKey = await importPublicKey(recipient);
  const ephemeral = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as webcrypto.CryptoKeyPair;
  const z = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: recipientKey }, ephemeral.privateKey, 256));
  const pt = new TextEncoder().encode(plaintext);
  try {
    const salt = webcrypto.getRandomValues(new Uint8Array(32));
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const ikm = await subtle.importKey("raw", z, "HKDF", false, ["deriveKey"]);
    const key = await subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(SEAL_INFO) },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
    const aadBytes = new TextEncoder().encode(aad);
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aadBytes, tagLength: 128 }, key, pt));
    const epk = await subtle.exportKey("jwk", ephemeral.publicKey);
    return {
      alg: SEAL_ALG,
      epk: { kty: "EC", crv: "P-256", x: String(epk.x), y: String(epk.y) },
      salt: b64u(salt),
      iv: b64u(iv),
      ct: b64u(ct),
      aad: b64u(aadBytes),
    };
  } finally {
    z.fill(0);
    pt.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Redeem
// ---------------------------------------------------------------------------

export interface RedeemBody {
  ok: true;
  mode: InjectMode;
  target_origin: string;
  entry: { id: string; label: string; kind: EntryKind };
  sealed: SealedBlob;
}

export type InjectorFailure = { ok: false; status: number; error: string };
export type RedeemOutcome = RedeemBody | InjectorFailure;

const fail = (status: number, error: string): InjectorFailure => ({ ok: false, status, error });

function injectorIdentity(injector: InjectorRecord): ClientIdentity {
  return { client_id: `injector:${injector.id}`, name: injector.name, kind: "workload", scopes: [] };
}

/** Take one slot of a per-injector limit. Throws when the store is unreachable (callers fail closed). */
async function takeSlot(c: Ctx, namespace: string, injectorId: string, limit: number): Promise<boolean> {
  const hit = await withRateLimitStore(c.limits, "hit", (s) => s.hit(rateLimitKey(namespace, injectorId), REDEEM_WINDOW_MS, c.now, limit));
  return hit.recorded;
}

async function bestEffortRow(c: Ctx, row: LedgerEntryInput): Promise<void> {
  try {
    await c.ledger(row);
  } catch {
    log.error("vault_inject_ledger_failed", { capability: row.capability, result: row.result });
  }
}

/** The ledger resource of a ticket's rows; falls back to the entry id when the entry cannot be read. */
async function ticketResource(c: Ctx, entryId: string, injectorId: string): Promise<string> {
  const entry = await getEntryMetadata(entryId, c.cards).catch(() => null);
  return entry ? injectResource(entry.site, entry.account, injectorId) : `entry:${entryId}#${injectorId}`;
}

/**
 * Exchange a ticket for the sealed credential. `injector` comes from
 * authenticateInjector. Never throws; every failure is a status and a short
 * code (see the table in the module header).
 */
export async function redeemTicket(injector: InjectorRecord, ticket: unknown, deps: InjectorDeps = {}): Promise<RedeemOutcome> {
  const c = ctx(deps);
  const who = injectorIdentity(injector);
  const refusal = { client_id: who.client_id, capability: REDEEM_CAPABILITY, decision: "deny" as const, tier: 2 as const, result: "error" as const };
  try {
    let allowed: boolean;
    try {
      allowed = await takeSlot(c, "injector.redeem", injector.id, REDEEM_MAX_PER_WINDOW);
    } catch {
      return fail(503, "unavailable");
    }
    if (!allowed) {
      log.warn("vault_inject_redeem_rate_limited", { injector_id: injector.id });
      return fail(429, "rate_limited");
    }

    if (typeof ticket !== "string" || !TICKET_PATTERN.test(ticket)) {
      await bestEffortRow(c, { ...refusal, resource: `entry:unknown#${injector.id}`, error: "ticket_not_found" });
      return fail(404, "ticket_not_found");
    }
    const digest = sha256Hex(ticket);
    let burned: InjectTicketRecord | null;
    let seen: InjectTicketRecord | null = null;
    try {
      burned = await c.tickets.redeem(digest, injector.id, c.now);
      if (!burned) seen = await c.tickets.get(digest);
    } catch {
      log.error("vault_inject_ticket_store_error", { injector_id: injector.id });
      return fail(503, "unavailable");
    }
    if (!burned) {
      const [status, code] = !seen
        ? [404, "ticket_not_found"]
        : seen.injector_id !== injector.id
          ? [403, "ticket_wrong_injector"]
          : seen.redeemed_at !== null
            ? [409, "ticket_used"]
            : [410, "ticket_expired"];
      await bestEffortRow(c, {
        ...refusal,
        resource: seen ? await ticketResource(c, seen.entry_id, seen.injector_id) : `entry:unknown#${injector.id}`,
        credential_ref: seen ? `vault://entry/${seen.entry_id}` : undefined,
        approval_id: seen?.approval_id,
        error: code,
      });
      log.warn("vault_inject_redeem_refused", { injector_id: injector.id, code });
      return fail(status as number, code as string);
    }

    // From here the ticket is spent, whatever happens.
    const bound = burned;
    // A holder object: the fields are assigned inside callbacks.
    const box: { sealed: SealedBlob | null; entry: RedeemBody["entry"] | null; code: string | null } = { sealed: null, entry: null, code: null };
    const recipient = parseCanonicalJwk(injector.public_key_jwk);
    const aad = sealAad(digest, injector.id, bound.target_origin, bound.mode);
    try {
      await useEntry(
        bound.entry_id,
        who,
        `inject ${bound.mode} into ${bound.target_origin}`,
        async (secret, meta) => {
          try {
            box.sealed = await sealForInjector(assemblePlaintext(secret, meta, bound, c.now), recipient, aad);
          } catch (err) {
            // Only fixed codes may travel: a WebCrypto or JSON error is reduced to one.
            const known = err instanceof Error && /^[a-z_]{1,40}$/.test(err.message) ? err.message : "seal_failed";
            box.code = known;
            throw new Error(known);
          }
          box.entry = { id: meta.id, label: meta.label, kind: meta.kind };
          // The return value passes through redaction; the blob does not ride in it.
          return { sealed: true };
        },
        {
          ...c.cards,
          decision: "escalate",
          tier: 2,
          approval_id: bound.approval_id,
          // useEntry writes exactly one row and, on success, fails closed when it cannot.
          ledger: async (row) => {
            const out: LedgerEntryInput = { ...row, capability: REDEEM_CAPABILITY, resource: `${row.resource}#${injector.id}` };
            if (box.code) {
              out.result = "error";
              out.error = box.code;
            }
            await c.ledger(out);
          },
        },
      );
    } catch {
      // Entry gone or flagged, vault unreachable, sealing failed, or the ok row could not be written.
      box.sealed = null;
    }
    if (!box.sealed || !box.entry) {
      log.warn("vault_inject_redeem_failed", { injector_id: injector.id, entry_id: bound.entry_id, code: box.code ?? "entry_or_ledger_unavailable" });
      return fail(503, "unavailable");
    }
    await c.injectors.touch(injector.id, c.now).catch(() => undefined);
    log.info("vault_inject_redeemed", { injector_id: injector.id, entry_id: bound.entry_id, mode: bound.mode, approval_id: bound.approval_id });
    return { ok: true, mode: bound.mode, target_origin: bound.target_origin, entry: box.entry, sealed: box.sealed };
  } catch {
    log.error("vault_inject_redeem_internal_error", { injector_id: injector.id });
    return fail(503, "unavailable");
  }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/**
 * Record the injector's outcome for a ticket it redeemed. Once per ticket.
 *   400 invalid_request · 404 ticket_not_found · 403 ticket_wrong_injector ·
 *   409 ticket_not_redeemed | result_already_reported · 429 rate_limited · 503 unavailable
 */
export async function reportResult(
  injector: InjectorRecord,
  body: { ticket_sha256?: unknown; result?: unknown; detail_code?: unknown },
  deps: InjectorDeps = {},
): Promise<{ ok: true } | InjectorFailure> {
  const c = ctx(deps);
  try {
    let allowed: boolean;
    try {
      allowed = await takeSlot(c, "injector.report", injector.id, REPORT_MAX_PER_WINDOW);
    } catch {
      return fail(503, "unavailable");
    }
    if (!allowed) return fail(429, "rate_limited");
    const digest = body?.ticket_sha256;
    const result = body?.result;
    const detail = body?.detail_code;
    if (typeof digest !== "string" || !HEX64.test(digest) || (result !== "injected" && result !== "failed")) return fail(400, "invalid_request");
    if (detail !== undefined && (typeof detail !== "string" || !DETAIL_CODE.test(detail))) return fail(400, "invalid_request");

    let rec: InjectTicketRecord | null;
    let set = false;
    try {
      rec = await c.tickets.get(digest);
      if (rec && rec.injector_id === injector.id && rec.redeemed_at !== null && rec.result === null) {
        set = await c.tickets.setResult(digest, injector.id, result);
      }
    } catch {
      return fail(503, "unavailable");
    }
    if (!rec) return fail(404, "ticket_not_found");
    if (rec.injector_id !== injector.id) return fail(403, "ticket_wrong_injector");
    if (rec.redeemed_at === null) return fail(409, "ticket_not_redeemed");
    if (!set) return fail(409, "result_already_reported");
    try {
      await c.ledger({
        client_id: `injector:${injector.id}`,
        capability: RESULT_CAPABILITY,
        resource: await ticketResource(c, rec.entry_id, injector.id),
        decision: "allow",
        tier: 2,
        result: result === "injected" ? "ok" : "error",
        approval_id: rec.approval_id,
        credential_ref: `vault://entry/${rec.entry_id}`,
        error: result === "injected" ? undefined : (detail ?? "failed"),
        task: `inject ${rec.mode} into ${rec.target_origin}${result === "injected" && detail ? ` (${detail})` : ""}`,
      });
    } catch {
      log.error("vault_inject_ledger_failed", { capability: RESULT_CAPABILITY, result });
      return fail(503, "unavailable");
    }
    log.info("vault_inject_result", { injector_id: injector.id, entry_id: rec.entry_id, result });
    return { ok: true };
  } catch {
    return fail(503, "unavailable");
  }
}
