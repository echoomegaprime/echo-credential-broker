//#region node_modules/.nitro/vite/services/ssr/assets/db-YAhc1k3o.js
var _0002_vault_oauth_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n-- ECHO Vault v2 — OAuth 2.1 authorization server state for the remote MCP endpoint.\n--\n-- Invariant: no raw bearer material is stored. Authorization codes, access /\n-- refresh tokens and pending-authorization handles are stored ONLY as\n-- lowercase sha256 hex; the CHECK constraints below reject anything else, so a\n-- code path that tried to persist a raw \"eva_…\"/\"evr_…\"/\"evc_…\" value fails\n-- loudly instead of leaking it into a dump.\n--\n-- All timestamps are epoch milliseconds (bigint) supplied by the application\n-- clock. Applied by scripts/migrate.mjs (Postgres) and src/lib/db.ts (PGlite).\n\ncreate table if not exists vault_oauth_clients (\n  client_id        text primary key check (client_id ~ '^oc_[A-Za-z0-9_-]{16,64}$'),\n  client_name      text not null check (char_length(client_name) between 1 and 100),\n  redirect_uris    jsonb not null,\n  requested_scopes jsonb not null default '[]'::jsonb,\n  granted_scopes   jsonb not null default '[]'::jsonb,\n  status           text not null check (status in ('registered', 'approved', 'denied', 'revoked')),\n  created_at       bigint not null,\n  approved_at      bigint,\n  revoked_at       bigint\n);\n\ncreate table if not exists vault_oauth_pending (\n  id_hash        text primary key check (id_hash ~ '^[0-9a-f]{64}$'),\n  client_id      text not null references vault_oauth_clients (client_id) on delete cascade,\n  redirect_uri   text not null,\n  code_challenge text not null,\n  scopes         jsonb not null,\n  resource       text not null,\n  state          text,\n  approval_id    text not null,\n  is_new_client  boolean not null,\n  status         text not null check (status in ('pending', 'completed', 'denied', 'expired')),\n  created_at     bigint not null,\n  expires_at     bigint not null\n);\n\ncreate index if not exists vault_oauth_pending_client_idx on vault_oauth_pending (client_id);\ncreate index if not exists vault_oauth_pending_status_idx on vault_oauth_pending (status, expires_at);\n\ncreate table if not exists vault_oauth_codes (\n  code_hash      text primary key check (code_hash ~ '^[0-9a-f]{64}$'),\n  client_id      text not null references vault_oauth_clients (client_id) on delete cascade,\n  redirect_uri   text not null,\n  code_challenge text not null,\n  scopes         jsonb not null,\n  resource       text not null,\n  family_id      text not null,\n  created_at     bigint not null,\n  expires_at     bigint not null,\n  used_at        bigint\n);\n\ncreate table if not exists vault_oauth_tokens (\n  token_hash text primary key check (token_hash ~ '^[0-9a-f]{64}$'),\n  kind       text not null check (kind in ('access', 'refresh')),\n  client_id  text not null references vault_oauth_clients (client_id) on delete cascade,\n  family_id  text not null,\n  scopes     jsonb not null,\n  resource   text not null,\n  created_at bigint not null,\n  expires_at bigint not null,\n  used_at    bigint,\n  revoked_at bigint\n);\n\ncreate index if not exists vault_oauth_tokens_family_idx on vault_oauth_tokens (family_id);\ncreate index if not exists vault_oauth_tokens_client_idx on vault_oauth_tokens (client_id);\ncreate index if not exists vault_oauth_tokens_expires_idx on vault_oauth_tokens (expires_at);\n";
var _0003_vault_ledger_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n--\n-- Vault v2 ledger (src/lib/vault/v2/ledger.ts): append-only, hash-chained\n-- audit of every capability request. Metadata only — never a secret value;\n-- credential_ref is a vault:// reference.\n--\n-- Integrity layers:\n--   1. seq PRIMARY KEY + UNIQUE prev_hash: two writers can never both append\n--      after the same predecessor, so the chain cannot fork. ledger.ts appends\n--      with a single compare-and-append INSERT ... SELECT ... ON CONFLICT DO\n--      NOTHING and retries from the new head when it loses a race.\n--   2. Triggers refuse UPDATE / DELETE / TRUNCATE.\n--   3. verifyLedger() recomputes every hash (and the optional HMAC from\n--      ECHO_VAULT_LEDGER_HMAC_KEY), so a privileged writer who disables (2)\n--      is still detected at the first edited seq.\n-- Every column except hmac is covered by the hash; hmac covers the hash.\n\nCREATE TABLE IF NOT EXISTS vault_ledger (\n  seq            BIGINT   PRIMARY KEY CHECK (seq >= 1),\n  id             TEXT     NOT NULL UNIQUE,\n  ts             TEXT     NOT NULL,\n  prev_hash      TEXT     NOT NULL UNIQUE CHECK (prev_hash ~ '^[0-9a-f]{64}$'),\n  hash           TEXT     NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$'),\n  hmac           TEXT     NULL CHECK (hmac IS NULL OR hmac ~ '^[0-9a-f]{64}$'),\n  client_id      TEXT     NOT NULL,\n  capability     TEXT     NOT NULL,\n  resource       TEXT     NOT NULL,\n  decision       TEXT     NOT NULL CHECK (decision IN ('allow', 'escalate', 'deny')),\n  tier           SMALLINT NOT NULL CHECK (tier BETWEEN 0 AND 3),\n  result         TEXT     NOT NULL CHECK (result IN ('ok', 'error', 'denied', 'pending_approval', 'committing')),\n  approval_id    TEXT     NULL,\n  credential_ref TEXT     NULL CHECK (credential_ref IS NULL OR credential_ref ~ '^vault://[a-z0-9-]+/[A-Za-z0-9._-]+$'),\n  http_status    INTEGER  NULL CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),\n  error          TEXT     NULL,\n  duration_ms    BIGINT   NULL CHECK (duration_ms IS NULL OR duration_ms >= 0),\n  task           TEXT     NULL CHECK (task IS NULL OR length(task) <= 300),\n  credential_path TEXT    NULL CHECK (credential_path IS NULL OR credential_path IN ('installation', 'pat_fallback')),\n  fallback_reason TEXT    NULL CHECK (fallback_reason IS NULL OR length(fallback_reason) <= 200)\n);\n\nCREATE INDEX IF NOT EXISTS vault_ledger_client_seq_idx ON vault_ledger (client_id, seq DESC);\nCREATE INDEX IF NOT EXISTS vault_ledger_capability_seq_idx ON vault_ledger (capability, seq DESC);\n\nCREATE OR REPLACE FUNCTION vault_ledger_append_only() RETURNS trigger\nLANGUAGE plpgsql AS $$\nBEGIN\n  RAISE EXCEPTION 'vault_ledger is append-only (% refused)', TG_OP;\nEND;\n$$;\n\nDROP TRIGGER IF EXISTS vault_ledger_no_update_delete ON vault_ledger;\nCREATE TRIGGER vault_ledger_no_update_delete\n  BEFORE UPDATE OR DELETE ON vault_ledger\n  FOR EACH ROW EXECUTE FUNCTION vault_ledger_append_only();\n\nDROP TRIGGER IF EXISTS vault_ledger_no_truncate ON vault_ledger;\nCREATE TRIGGER vault_ledger_no_truncate\n  BEFORE TRUNCATE ON vault_ledger\n  FOR EACH STATEMENT EXECUTE FUNCTION vault_ledger_append_only();\n";
var _0004_vault_approvals_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n-- ECHO Vault v2: request-bound, single-use approvals (src/lib/vault/v2/approvals.ts).\n-- No secret material lives here: the request is stored only as its sha256\n-- digest, and the summary is sanitized human text. The HMAC key that signs\n-- Telegram callback data is server-side env only.\ncreate table if not exists vault_approvals (\n  id             text primary key check (id ~ '^[A-Za-z0-9_-]{24}$'),\n  request_digest text not null check (request_digest ~ '^[0-9a-f]{64}$'),\n  client_id      text not null check (length(client_id) between 1 and 200),\n  capability     text not null check (length(capability) between 1 and 128),\n  resource       text not null check (length(resource) between 1 and 512),\n  summary        text not null default '' check (length(summary) <= 500),\n  status         text not null default 'pending'\n                 check (status in ('pending', 'approved', 'denied', 'expired', 'consumed')),\n  created_at     timestamptz not null default now(),\n  expires_at     timestamptz not null,\n  decided_at     timestamptz,\n  decided_by     text,\n  consumed_at    timestamptz\n);\n\ncreate index if not exists vault_approvals_status_expires_idx\n  on vault_approvals (status, expires_at);\n";
var _0005_vault_entries_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n--\n-- ECHO Vault v2 credential entries + credential cards (src/lib/vault/v2/cards.ts).\n--\n-- METADATA ONLY. No secret value is ever stored here: the secret lives in the\n-- canonical vault backend under the per-entry key derived from `id`. What this\n-- table keeps about the secret is the first 8 hex chars of its sha256 and its\n-- length. Card tokens are stored only as sha256 hex.\n--\n-- Many entries per site: identity is (site, lower(account), kind) among\n-- non-deleted rows, so a second account for a site can never overwrite another.\n-- At most one default per site: partial unique index on (site) where is_default.\n\ncreate table if not exists vault_entries (\n  id               text primary key check (id ~ '^ve_[0-9a-f]{32}$'),\n  site             text not null check (length(site) between 1 and 253 and site = lower(site)),\n  account          text not null check (length(account) between 1 and 254),\n  purpose          text not null default 'general' check (length(purpose) between 1 and 64),\n  label            text not null check (length(label) between 1 and 600),\n  kind             text not null check (kind in ('password', 'api_key', 'oauth_token', 'operator_secret')),\n  is_default       boolean not null default false,\n  status           text not null default 'active' check (status in ('active', 'needs_reentry', 'deleted')),\n  fingerprint      text not null check (fingerprint ~ '^[0-9a-f]{8}$'),\n  secret_length    integer not null check (secret_length between 1 and 4096),\n  reentry_reason   text check (reentry_reason is null or length(reentry_reason) <= 300),\n  created_at       timestamptz not null default now(),\n  updated_at       timestamptz not null default now(),\n  last_used_at     timestamptz,\n  last_verified_at timestamptz,\n  deleted_at       timestamptz,\n  constraint vault_entries_deleted_not_default check (not (is_default and status = 'deleted'))\n);\n\ncreate unique index if not exists vault_entries_identity_uidx\n  on vault_entries (site, lower(account), kind) where status <> 'deleted';\n\ncreate unique index if not exists vault_entries_one_default_uidx\n  on vault_entries (site) where is_default;\n\ncreate index if not exists vault_entries_site_status_idx\n  on vault_entries (site, status);\n\n-- Move the default to p_id atomically (the shared Sql surface has no\n-- multi-statement transactions; a function body runs inside the calling\n-- statement's transaction). Serialized per site with an advisory lock; the\n-- partial unique index is the backstop. Returns false when the entry does not\n-- exist or is deleted.\ncreate or replace function vault_entries_set_default(p_id text) returns boolean\nlanguage plpgsql as $$\ndeclare\n  v_site text;\nbegin\n  select site into v_site from vault_entries where id = p_id and status <> 'deleted';\n  if v_site is null then\n    return false;\n  end if;\n  perform pg_advisory_xact_lock(hashtext('vault_entries:' || v_site));\n  update vault_entries set is_default = false\n   where site = v_site and is_default and id <> p_id;\n  update vault_entries set is_default = true, updated_at = now()\n   where id = p_id and status <> 'deleted' and not is_default;\n  return exists (select 1 from vault_entries where id = p_id and is_default);\nend;\n$$;\n\n-- Credential cards: a pending request for the operator to type a secret.\n-- token_hash = sha256 hex of the single-use URL token (the token itself is\n-- only ever sent to the operator). status: pending -> claimed -> completed,\n-- or -> expired. `claimed` is the in-flight state of one POST.\ncreate table if not exists vault_cards (\n  id           text primary key check (id ~ '^vc_[0-9a-f]{32}$'),\n  token_hash   text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),\n  client_id    text not null check (length(client_id) between 1 and 200),\n  client_name  text not null default '' check (length(client_name) <= 120),\n  site         text not null check (length(site) between 1 and 253),\n  account      text check (account is null or length(account) between 1 and 254),\n  purpose      text check (purpose is null or length(purpose) between 1 and 64),\n  kind         text not null check (kind in ('password', 'api_key', 'oauth_token', 'operator_secret')),\n  reason       text not null default '' check (length(reason) <= 300),\n  entry_id     text references vault_entries (id),\n  is_reentry   boolean not null default false,\n  status       text not null default 'pending' check (status in ('pending', 'claimed', 'completed', 'expired')),\n  created_at   timestamptz not null default now(),\n  expires_at   timestamptz not null,\n  completed_at timestamptz,\n  constraint vault_cards_reentry_has_entry check (not is_reentry or entry_id is not null)\n);\n\ncreate index if not exists vault_cards_client_status_idx\n  on vault_cards (client_id, status, expires_at);\n";
var _0006_vault_entry_grants_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n-- ECHO Vault v2 entry consent grants (src/lib/vault/v2/entry-grants.ts).\n--\n-- One row = the owner approved, on Telegram, that this client may repeat ONE\n-- read-only (GET/HEAD) request — to this exact host, at this path or under it —\n-- without being asked again, until it expires or its uses run out. Non-GET uses\n-- never consult this table: they need a fresh approval every time. A client may\n-- hold several narrow grants for one entry, so the primary key is the full\n-- (client_id, entry_id, host, path_prefix).\n-- Metadata only: no secret, no request content. Revoking deletes the row(s)\n-- (revokeEntryGrant); the approval that created it stays in vault_approvals and\n-- the ledger.\ncreate table if not exists vault_entry_grants (\n  client_id      text not null check (length(client_id) between 1 and 200),\n  entry_id       text not null check (entry_id ~ '^ve_[0-9a-f]{32}$'),\n  host           text not null check (length(host) between 1 and 253),\n  path_prefix    text not null check (length(path_prefix) between 1 and 1024),\n  approval_id    text not null check (approval_id ~ '^[A-Za-z0-9_-]{24}$'),\n  granted_at     timestamptz not null default now(),\n  expires_at     timestamptz not null,\n  max_uses       integer null check (max_uses is null or max_uses >= 0),\n  uses_remaining integer null check (uses_remaining is null or uses_remaining >= 0),\n  check (expires_at > granted_at),\n  primary key (client_id, entry_id, host, path_prefix)\n);\n\ncreate index if not exists vault_entry_grants_entry_idx\n  on vault_entry_grants (entry_id);\n";
var _0007_vault_entry_rotation_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n--\n-- ECHO Vault v2 entry rotation state (src/lib/vault/v2/cards.ts, rotation.ts).\n--\n-- METADATA ONLY. Nothing here is a secret:\n--   rotation_mode        'manual' (the owner re-enters the secret on a card) or\n--                        'auto' (a provider rotator rolls it, see rotation.ts).\n--   rotate_interval_days how often the secret should be rotated; null = no schedule.\n--   last_rotated_at      last successful rotation (card re-entry or auto-rotate).\n--   rotate_by            when the next rotation is due (last rotation, or creation,\n--                        plus the interval); null = never due.\n--   rotation_count       successful rotations so far.\n--   last_rotation_error  a SHORT CODE only (e.g. 'provider_http_403'). Never\n--                        provider response text, which could carry a secret.\n--   provider_token_id    the provider-side, NON-SECRET id needed to rotate\n--                        (e.g. a Cloudflare API token id). Never a token value.\n--\n-- Idempotent: every statement is safe to re-run.\n\nalter table vault_entries add column if not exists rotation_mode text not null default 'manual';\nalter table vault_entries add column if not exists rotate_interval_days integer null;\nalter table vault_entries add column if not exists last_rotated_at timestamptz null;\nalter table vault_entries add column if not exists rotate_by timestamptz null;\nalter table vault_entries add column if not exists rotation_count integer not null default 0;\nalter table vault_entries add column if not exists last_rotation_error text null;\nalter table vault_entries add column if not exists provider_token_id text null;\n\ndo $$\nbegin\n  if not exists (select 1 from pg_constraint where conname = 'vault_entries_rotation_mode_check') then\n    alter table vault_entries add constraint vault_entries_rotation_mode_check\n      check (rotation_mode in ('manual', 'auto'));\n  end if;\n  if not exists (select 1 from pg_constraint where conname = 'vault_entries_rotate_interval_check') then\n    alter table vault_entries add constraint vault_entries_rotate_interval_check\n      check (rotate_interval_days is null or rotate_interval_days between 1 and 3650);\n  end if;\n  if not exists (select 1 from pg_constraint where conname = 'vault_entries_rotation_count_check') then\n    alter table vault_entries add constraint vault_entries_rotation_count_check\n      check (rotation_count >= 0);\n  end if;\n  if not exists (select 1 from pg_constraint where conname = 'vault_entries_rotation_error_check') then\n    alter table vault_entries add constraint vault_entries_rotation_error_check\n      check (last_rotation_error is null or last_rotation_error ~ '^[a-z0-9_]{1,64}$');\n  end if;\n  if not exists (select 1 from pg_constraint where conname = 'vault_entries_provider_token_id_check') then\n    alter table vault_entries add constraint vault_entries_provider_token_id_check\n      check (provider_token_id is null or provider_token_id ~ '^[A-Za-z0-9._:-]{1,128}$');\n  end if;\nend;\n$$;\n\ncreate index if not exists vault_entries_rotate_by_idx\n  on vault_entries (rotate_by) where status = 'active' and rotate_by is not null;\n";
var _0008_vault_ledger_anchors_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n--\n-- Vault v2 ledger anchors (src/lib/vault/v2/ledger-anchor.ts): a local INDEX of\n-- every ledger head that was published outside the database. The proof is the\n-- external message itself (channel 'telegram': the owner's chat; external_id is\n-- the Telegram message id) — this table only says which messages to look for.\n-- Metadata only: a sequence number, a sha256 chain hash, a row count, an\n-- optional HMAC. Never a secret value and nothing from a ledger row's payload.\n--\n-- Append-only like vault_ledger: triggers refuse UPDATE / DELETE / TRUNCATE.\n-- A privileged writer who disables them can drop index rows, but cannot unsend\n-- the external message; verify against the message, not against this table.\n\nCREATE TABLE IF NOT EXISTS vault_ledger_anchors (\n  seq          BIGINT      NOT NULL CHECK (seq >= 1),\n  hash         TEXT        NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),\n  row_count    BIGINT      NOT NULL CHECK (row_count >= 1),\n  anchored_at  TIMESTAMPTZ NOT NULL,\n  channel      TEXT        NOT NULL CHECK (channel ~ '^[a-z][a-z0-9_-]{0,31}$'),\n  external_id  TEXT        NOT NULL CHECK (length(external_id) BETWEEN 1 AND 128),\n  mac          TEXT        NULL CHECK (mac IS NULL OR mac ~ '^[0-9a-f]{64}$'),\n  PRIMARY KEY (seq, channel)\n);\n\nCREATE OR REPLACE FUNCTION vault_ledger_anchors_append_only() RETURNS trigger\nLANGUAGE plpgsql AS $$\nBEGIN\n  RAISE EXCEPTION 'vault_ledger_anchors is append-only (% refused)', TG_OP;\nEND;\n$$;\n\nDROP TRIGGER IF EXISTS vault_ledger_anchors_no_update_delete ON vault_ledger_anchors;\nCREATE TRIGGER vault_ledger_anchors_no_update_delete\n  BEFORE UPDATE OR DELETE ON vault_ledger_anchors\n  FOR EACH ROW EXECUTE FUNCTION vault_ledger_anchors_append_only();\n\nDROP TRIGGER IF EXISTS vault_ledger_anchors_no_truncate ON vault_ledger_anchors;\nCREATE TRIGGER vault_ledger_anchors_no_truncate\n  BEFORE TRUNCATE ON vault_ledger_anchors\n  FOR EACH STATEMENT EXECUTE FUNCTION vault_ledger_anchors_append_only();\n";
var _0009_vault_digest_state_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n-- ECHO Vault v2 daily audit digest state (src/lib/vault/v2/digest.ts).\n--\n-- One row per digest window [window_from, window_to) that was claimed for\n-- sending. It exists for one purpose: the same window is never sent twice.\n--   status 'sending' = a runner claimed the window and is building/sending it\n--                      (a claim older than 10 minutes is treated as a crashed\n--                      runner and may be re-claimed);\n--   status 'sent'    = Telegram accepted the message (message_id recorded).\n-- A failed send deletes its claim, so the window stays unsent and is retried.\n-- Metadata only: no digest text, no ledger content, no secret.\ncreate table if not exists vault_digest_state (\n  window_from text not null check (window_from ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$'),\n  window_to   text not null check (window_to   ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$'),\n  status      text not null check (status in ('sending', 'sent')),\n  claimed_at  timestamptz not null,\n  sent_at     timestamptz null,\n  message_id  bigint null,\n  check (window_from < window_to),\n  check ((status = 'sent') = (sent_at is not null)),\n  primary key (window_from, window_to)\n);\n";
var _0010_vault_rate_limits_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n-- ECHO Vault v2 shared rate-limit state (src/lib/vault/v2/rate-limit-store.ts).\n--\n-- One row per rate-limit key. `hits` holds the epoch-millisecond timestamps of\n-- the events still inside that key's sliding window (oldest first), so an exact\n-- sliding-window count survives restarts and is shared by every server instance.\n--\n-- Why one row per key instead of an events table: recording a hit is ONE\n-- statement, `insert … on conflict (key) do update … where <in-window count> <\n-- <limit>`. ON CONFLICT DO UPDATE takes the row lock and re-evaluates its WHERE\n-- against the latest committed row, so concurrent hits from several processes\n-- are serialized per key and \"count, then record only if under the limit\" is\n-- atomic without a transaction or advisory lock. An events table counted in the\n-- same statement would read a snapshot taken before a concurrent insert\n-- committed and could admit more than the limit.\n--\n-- `key` is `<namespace>:<sha256 hex>` — never a token, code, secret or raw\n-- identifier (the constraint below makes any other shape unstorable).\n-- `expires_at` is the latest hit plus its window; rows past it hold no live\n-- event and are deleted by the store's opportunistic prune.\n-- Metadata only: no secret, no request content.\ncreate table if not exists vault_rate_limits (\n  key        text primary key check (key ~ '^[a-z0-9_.-]{1,40}:[0-9a-f]{64}$'),\n  hits       bigint[] not null check (cardinality(hits) between 1 and 10000),\n  expires_at timestamptz not null\n);\n\ncreate index if not exists vault_rate_limits_expires_idx\n  on vault_rate_limits (expires_at);\n";
var _0011_vault_owner_console_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n--\n-- ECHO Vault v2 owner console (src/lib/vault/v2/owner-console*.ts,\n-- docs/ops/owner-console.md): passkeys, WebAuthn challenges, console sessions\n-- and the one-time enrollment bootstrap code.\n--\n-- What is stored, and what never is:\n--   - Passkeys: the credential id, the PUBLIC key (COSE, base64url), the\n--     signature counter and the transports. Passkey private material never\n--     reaches the server and has no column here.\n--   - Challenges, session tokens and the bootstrap code: sha256 hex ONLY. The\n--     raw value exists in the browser (cookie / ceremony) or in the one stdio\n--     tool result that minted it, never in a row.\n--   - No vault secret, no request content.\n--\n-- Times are epoch milliseconds (bigint) taken from the application clock, like\n-- vault_rate_limits, so tests can inject a clock and both stores agree.\n\ncreate table if not exists vault_console_passkeys (\n  -- base64url. (Length is a separate check: Postgres regex bounds stop at 255.)\n  credential_id text   primary key check (credential_id ~ '^[A-Za-z0-9_-]+$' and length(credential_id) between 16 and 1366),\n  public_key    text   not null check (public_key ~ '^[A-Za-z0-9_-]+$' and length(public_key) between 32 and 8192),\n  counter       bigint not null check (counter between 0 and 4294967295),\n  transports    text   not null default '' check (transports ~ '^([a-z][a-z-]{1,15}(,[a-z][a-z-]{1,15}){0,7})?$'),\n  label         text   not null check (length(label) between 1 and 64),\n  created_at    bigint not null check (created_at > 0),\n  last_used_at  bigint null check (last_used_at is null or last_used_at > 0),\n  -- Set when a correctly signed assertion carried a signature counter that did\n  -- not advance (possible cloned authenticator). The assertion is refused.\n  flagged_at    bigint null check (flagged_at is null or flagged_at > 0),\n  flag_reason   text   null check (flag_reason is null or flag_reason in ('counter_regression')),\n  check ((flagged_at is null) = (flag_reason is null))\n);\n\n-- One row per outstanding WebAuthn challenge. Single use: verification deletes\n-- the row before it checks the response.\ncreate table if not exists vault_console_challenges (\n  challenge_hash text   primary key check (challenge_hash ~ '^[0-9a-f]{64}$'),\n  purpose        text   not null check (purpose in ('enroll', 'login', 'stepup', 'add_passkey')),\n  -- The console session a step-up / add-passkey challenge is bound to.\n  session_id     text   null check (session_id is null or session_id ~ '^[0-9a-f]{32}$'),\n  created_at     bigint not null check (created_at > 0),\n  expires_at     bigint not null,\n  check (expires_at > created_at),\n  check ((purpose in ('stepup', 'add_passkey')) = (session_id is not null))\n);\n\ncreate index if not exists vault_console_challenges_expires_idx\n  on vault_console_challenges (expires_at);\n\ncreate table if not exists vault_console_sessions (\n  id                  text   primary key check (id ~ '^[0-9a-f]{32}$'),\n  token_hash          text   not null unique check (token_hash ~ '^[0-9a-f]{64}$'),\n  credential_id       text   not null references vault_console_passkeys (credential_id) on delete cascade,\n  created_at          bigint not null check (created_at > 0),\n  last_seen_at        bigint not null,\n  absolute_expires_at bigint not null,\n  -- Time of the newest WebAuthn assertion completed for this session.\n  step_up_at          bigint null,\n  revoked_at          bigint null,\n  user_agent          text   not null default '' check (length(user_agent) <= 200),\n  check (last_seen_at >= created_at),\n  check (absolute_expires_at > created_at)\n);\n\ncreate index if not exists vault_console_sessions_credential_idx\n  on vault_console_sessions (credential_id);\n\n-- At most ONE bootstrap code exists: a singleton row that minting overwrites.\ncreate table if not exists vault_console_bootstrap (\n  id          smallint primary key check (id = 1),\n  code_hash   text     not null check (code_hash ~ '^[0-9a-f]{64}$'),\n  minted_by   text     not null check (minted_by ~ '^local:[a-z0-9][a-z0-9._-]{0,63}$'),\n  created_at  bigint   not null check (created_at > 0),\n  expires_at  bigint   not null,\n  consumed_at bigint   null,\n  check (expires_at > created_at)\n);\n";
var _0012_vault_cookie_entries_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n--\n-- ECHO Vault v2 `cookie` entries (src/lib/vault/v2/cards.ts, cookie-jar.ts).\n--\n-- A cookie entry's secret is the canonical cookie-jar JSON. Like every other\n-- secret it lives ONLY in the canonical vault backend; this migration adds no\n-- column that can hold a cookie value.\n--\n--   kind            'cookie' joins the allowed kinds of vault_entries and vault_cards.\n--   secret_length   stays 1..4096 for every other kind; a cookie jar may be up to\n--                   32768 characters (cookie-jar.ts MAX_COOKIE_JAR_CHARS).\n--   cookie_meta     METADATA ONLY, cookie entries only: JSON text\n--                   {count, names[], domains[], truncated, expires_at, session_cookies}.\n--                   Cookie NAMES and domains, never a value.\n--\n-- Idempotent: every statement is safe to re-run.\n\nalter table vault_entries add column if not exists cookie_meta text null;\n\nalter table vault_entries drop constraint if exists vault_entries_kind_check;\nalter table vault_entries add constraint vault_entries_kind_check\n  check (kind in ('password', 'api_key', 'oauth_token', 'operator_secret', 'cookie'));\n\nalter table vault_entries drop constraint if exists vault_entries_secret_length_check;\nalter table vault_entries add constraint vault_entries_secret_length_check\n  check (secret_length between 1 and 4096 or (kind = 'cookie' and secret_length between 1 and 32768));\n\nalter table vault_entries drop constraint if exists vault_entries_cookie_meta_check;\nalter table vault_entries add constraint vault_entries_cookie_meta_check\n  check (cookie_meta is null or (kind = 'cookie' and length(cookie_meta) <= 16384));\n\nalter table vault_cards drop constraint if exists vault_cards_kind_check;\nalter table vault_cards add constraint vault_cards_kind_check\n  check (kind in ('password', 'api_key', 'oauth_token', 'operator_secret', 'cookie'));\n";
var _0013_vault_injectors_default = "-- library-first: echo.functions.search → no existing impl found (2026-11-14)\n--\n-- ECHO Vault v2 browser injector channel (src/lib/vault/v2/injector.ts,\n-- docs/ops/injector-contract.md, docs/ops/injector-channel.md).\n--\n-- What is stored, and what never is:\n--   - Injectors: an id, a display name, the injector's PUBLIC P-256 ECDH key\n--     (canonical JWK: crv, kty, x, y — no private member can be stored, see the\n--     check) and sha256(injector token). The raw `ein_` token exists in the one\n--     enrollment result and in the injector; never in a row.\n--   - Inject tickets: sha256(ticket) and what the ticket is bound to (entry id,\n--     mode, target origin, injector, approval, requesting client). The raw\n--     `eit_` ticket exists in the one tool result that minted it.\n--   - No vault secret, no cookie value, no ciphertext, no derived key.\n--\n-- Times are epoch milliseconds (bigint) from the application clock, like\n-- vault_rate_limits and the console tables, so tests can inject a clock and\n-- both stores agree.\n--\n-- Idempotent: every statement is safe to re-run.\n\ncreate table if not exists vault_injectors (\n  id             text   primary key check (id ~ '^inj_[0-9a-f]{16}$'),\n  name           text   not null check (length(name) between 1 and 64),\n  -- Canonical public JWK, members in this exact order. A JWK with a private\n  -- member (\"d\") or any other member cannot match.\n  public_key_jwk text   not null check (\n    public_key_jwk ~ '^\\{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"[A-Za-z0-9_-]{43}\",\"y\":\"[A-Za-z0-9_-]{43}\"\\}$'\n  ),\n  token_sha256   text   not null unique check (token_sha256 ~ '^[0-9a-f]{64}$'),\n  created_at     bigint not null check (created_at > 0),\n  revoked_at     bigint null check (revoked_at is null or revoked_at >= created_at),\n  last_used_at   bigint null check (last_used_at is null or last_used_at >= created_at)\n);\n\ncreate table if not exists vault_inject_tickets (\n  sha256        text   primary key check (sha256 ~ '^[0-9a-f]{64}$'),\n  entry_id      text   not null check (entry_id ~ '^ve_[0-9a-f]{32}$'),\n  mode          text   not null check (mode in ('cookies', 'field')),\n  -- https://<lower-case host>, nothing else. (Length is a separate check: Postgres regex bounds stop at 255.)\n  target_origin text   not null check (\n    target_origin ~ '^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$' and length(target_origin) <= 261\n  ),\n  injector_id   text   not null references vault_injectors (id),\n  -- One approval mints at most one ticket.\n  approval_id   text   not null unique check (length(approval_id) between 1 and 256),\n  client_id     text   not null check (length(client_id) between 1 and 200),\n  created_at    bigint not null check (created_at > 0),\n  expires_at    bigint not null,\n  -- Set once, by the first redeem attempt of the bound injector (the burn).\n  redeemed_at   bigint null,\n  -- Set once, by the injector's report.\n  result        text   null check (result is null or result in ('injected', 'failed')),\n  check (expires_at > created_at),\n  check (redeemed_at is null or redeemed_at >= created_at),\n  check (result is null or redeemed_at is not null)\n);\n\ncreate index if not exists vault_inject_tickets_expires_idx\n  on vault_inject_tickets (expires_at);\ncreate index if not exists vault_inject_tickets_injector_idx\n  on vault_inject_tickets (injector_id);\n";
/**
* Migration bookkeeping shared by the two appliers — `scripts/migrate.mjs`
* (deploy, `readdir`) and `src/lib/db.ts` (PGLite preview, `import.meta.glob`).
*
* Applied files are keyed by BASENAME, so the same file applies once no matter
* which directory it is globbed from. That is what makes the auth schema safe to
* copy from `migrations/auth/` into `migrations/` when an app turns sign-in on:
* a database that already has `0001_auth.sql` will not re-run it.
*
* Neither applier descends into subdirectories, so `migrations/auth/*.sql` is
* out of scope for both until it is copied up.
*/
/**
* The `_migrations` key for a migration path (or bare filename).
* @param {string} path
* @returns {string}
*/
function migrationName(path) {
	return path.split("/").pop() ?? path;
}
/**
* @param {string} path
* @returns {boolean}
*/
function isMigrationFile(path) {
	return path.endsWith(".sql");
}
/**
* Migrations in `paths` that are not yet in `applied`, in apply order.
* Non-`.sql` entries (a `readdir` also yields `migrations/auth/`) are dropped.
* @param {Iterable<string>} paths
* @param {Iterable<string>} applied
* @returns {Array<{ name: string, path: string }>}
*/
function pendingMigrations(paths, applied) {
	const done = new Set(applied);
	return [...paths].filter(isMigrationFile).map((path) => ({
		name: migrationName(path),
		path
	})).sort((a, b) => a.name.localeCompare(b.name)).filter(({ name }) => !done.has(name));
}
var rawDatabaseUrl = typeof process !== "undefined" ? process.env.DATABASE_URL : void 0;
var databaseUrl = rawDatabaseUrl && rawDatabaseUrl.trim() ? rawDatabaseUrl : void 0;
/**
* Active backend: real **Neon** when `DATABASE_URL` is set (deployed / configured
* sandbox), otherwise a local embedded **PGLite** (Postgres compiled to WASM) so
* the app has a working database even with nothing configured — the live preview
* included. Swap in Neon later by just setting `DATABASE_URL`; no code changes.
*/
var dbSource = databaseUrl ? "neon" : "pglite";
/**
* Init state lives on globalThis as promises: dev HMR creates new instances of
* this module, and two instances racing module-level state would open a second
* pool or run two concurrent PGLite migration passes (whose duplicate
* `_migrations` insert rejects — and would get memoized, poisoning every later
* `getSql()`). A failed init clears its slot so the next call retries.
*/
var globalRef = globalThis;
/**
* Result-type parity: Postgres sends every value as text plus a type OID — the
* JS value is the DRIVER's parsing choice, and pg and PGLite disagree (pg:
* int8 -> string, date -> local-midnight Date; PGLite: int8 -> BigInt, which
* JSON.stringify rejects, date -> UTC Date). Normalize both so preview and
* production return identical, JSON-safe shapes:
*   int8/bigint (incl. count(*)) -> number (past 2^53 loses precision — cast
*                                   `::text` if you ever need huge integers)
*   date                         -> 'YYYY-MM-DD' string
*   interval                     -> Postgres interval text
* numeric already comes back as a string on both (arbitrary precision).
*/
var OID_INT8 = 20;
var OID_DATE = 1082;
var OID_INTERVAL = 1186;
var identity = (v) => v;
/** Wrap a query runner in the tagged-template + `.query()` `Sql` surface. */
function toSql(run) {
	const sql = (async (strings, ...values) => {
		let text = strings[0];
		for (let i = 0; i < values.length; i += 1) text += `$${i + 1}${strings[i + 1]}`;
		return run(text, values);
	});
	sql.query = (text, params = []) => run(text, params);
	return sql;
}
function createNeonSql() {
	globalRef.__pgSqlPromise__ ??= (async () => {
		const { Pool, types } = await import("../_libs/pg.mjs").then((n) => n.t);
		types.setTypeParser(OID_INT8, Number);
		types.setTypeParser(OID_DATE, identity);
		types.setTypeParser(OID_INTERVAL, identity);
		const pool = new Pool({ connectionString: databaseUrl });
		return toSql(async (text, params) => {
			return (await pool.query(text, params)).rows;
		});
	})().catch((err) => {
		globalRef.__pgSqlPromise__ = void 0;
		throw err;
	});
	return globalRef.__pgSqlPromise__;
}
/**
* True when this module was transformed by Vite (dev server or a build).
* Vite defines `import.meta.env` and rewrites `import.meta.glob(...)` calls at
* transform time; under plain `node` (the stdio MCP transport, `node --test`)
* neither exists, so migrations are read from disk instead.
*/
var underVite = true;
/**
* Where the embedded PGLite keeps its files, or null for an in-memory database.
*   - `ECHO_VAULT_DATA_DIR` set  → `<that dir>/pglite` (any runtime).
*   - plain node, unset          → `<repo>/.vault-data/pglite` (gitignored), so
*     the stdio transport's ledger, approvals, entries and grants survive
*     restarts. Resolved from this file, not the cwd an MCP client spawned us in.
*   - Vite dev/preview, unset    → in-memory (the template's preview contract).
*   - `node --test`, unset       → in-memory, so a test can never write into the
*     operator's real data directory.
*/
async function pgliteDataDir() {
	const configured = process.env.ECHO_VAULT_DATA_DIR?.trim();
	if (!configured && underVite) return null;
	const { resolve, join, dirname } = await import("node:path");
	const { fileURLToPath } = await import("node:url");
	return join(configured ? resolve(configured) : join(dirname(fileURLToPath(import.meta.url)), "..", "..", ".vault-data"), "pglite");
}
/**
* PGLite is single-process: two processes opening one data directory corrupt
* it. Take a pid lock next to the directory; a lock left by a dead process is
* replaced. A second live process fails with a clear, catchable error.
*/
async function lockDataDir(dir) {
	const { mkdirSync, openSync, writeSync, closeSync, readFileSync, rmSync } = await import("node:fs");
	const { dirname } = await import("node:path");
	mkdirSync(dirname(dir), {
		recursive: true,
		mode: 448
	});
	const lockPath = `${dir}.lock`;
	for (let attempt = 0; attempt < 2; attempt += 1) try {
		const fd = openSync(lockPath, "wx", 384);
		writeSync(fd, String(process.pid));
		closeSync(fd);
		process.once("exit", () => {
			try {
				rmSync(lockPath, { force: true });
			} catch {}
		});
		return;
	} catch (err) {
		if (err.code !== "EEXIST") throw err;
		let owner = NaN;
		try {
			owner = Number(readFileSync(lockPath, "utf8").trim());
		} catch {}
		let alive = false;
		if (Number.isInteger(owner) && owner > 0 && owner !== process.pid) try {
			process.kill(owner, 0);
			alive = true;
		} catch (probe) {
			alive = probe.code === "EPERM";
		}
		if (alive) throw Object.assign(/* @__PURE__ */ new Error(`vault_data_dir_in_use: ${dir} is open in process ${owner}. Run one local vault process at a time, or set DATABASE_URL so several processes share one Postgres database.`), { code: "vault_data_dir_in_use" });
		rmSync(lockPath, { force: true });
	}
	throw Object.assign(/* @__PURE__ */ new Error("vault_data_dir_lock_failed"), { code: "vault_data_dir_lock_failed" });
}
/** `migrations/*.sql` (top level only), keyed by path. */
async function loadMigrations() {
	return /* #__PURE__ */ Object.assign({
		"/migrations/0002_vault_oauth.sql": _0002_vault_oauth_default,
		"/migrations/0003_vault_ledger.sql": _0003_vault_ledger_default,
		"/migrations/0004_vault_approvals.sql": _0004_vault_approvals_default,
		"/migrations/0005_vault_entries.sql": _0005_vault_entries_default,
		"/migrations/0006_vault_entry_grants.sql": _0006_vault_entry_grants_default,
		"/migrations/0007_vault_entry_rotation.sql": _0007_vault_entry_rotation_default,
		"/migrations/0008_vault_ledger_anchors.sql": _0008_vault_ledger_anchors_default,
		"/migrations/0009_vault_digest_state.sql": _0009_vault_digest_state_default,
		"/migrations/0010_vault_rate_limits.sql": _0010_vault_rate_limits_default,
		"/migrations/0011_vault_owner_console.sql": _0011_vault_owner_console_default,
		"/migrations/0012_vault_cookie_entries.sql": _0012_vault_cookie_entries_default,
		"/migrations/0013_vault_injectors.sql": _0013_vault_injectors_default
	});
}
async function createPgliteSql() {
	globalRef.__pgliteInstance__ ??= (async () => {
		const { PGlite } = await import("../_libs/electric-sql__pglite.mjs").then((n) => n.t);
		const dataDir = await pgliteDataDir();
		if (dataDir) await lockDataDir(dataDir);
		const options = { parsers: {
			[OID_INT8]: Number,
			[OID_DATE]: identity,
			[OID_INTERVAL]: identity
		} };
		const pg = dataDir ? new PGlite(dataDir, options) : new PGlite(options);
		await pg.waitReady;
		await pg.exec("create table if not exists _migrations (name text primary key, applied_at timestamptz not null default now())");
		return pg;
	})().catch((err) => {
		globalRef.__pgliteInstance__ = void 0;
		throw err;
	});
	const pg = await globalRef.__pgliteInstance__;
	const migrate = async () => {
		const migrations = await loadMigrations();
		const done = (await pg.query("select name from _migrations")).rows.map((r) => r.name);
		for (const { name, path } of pendingMigrations(Object.keys(migrations), done)) await pg.transaction(async (tx) => {
			await tx.exec(migrations[path]);
			await tx.query("insert into _migrations (name) values ($1)", [name]);
		});
	};
	const pass = (globalRef.__pgliteMigrateChain__ ?? Promise.resolve()).catch(() => void 0).then(migrate);
	globalRef.__pgliteMigrateChain__ = pass;
	await pass;
	return toSql(async (text, params) => {
		return (await pg.query(text, params)).rows;
	});
}
var sqlPromise = null;
async function createSql() {
	if (typeof window !== "undefined") throw new Error("@/lib/db is server-only — call getSql() from a createServerFn handler or a server route loader, never from client code.");
	return dbSource === "neon" ? createNeonSql() : createPgliteSql();
}
/**
* Get the shared, **server-only** SQL client. Neon when `DATABASE_URL` is set,
* otherwise the local PGLite fallback. Memoized — safe to call per request.
*
* Schema comes from `migrations/*.sql`, auto-applied before the first query on
* both backends — define tables there, never inline in server functions.
*/
function getSql() {
	sqlPromise ??= createSql().catch((err) => {
		sqlPromise = null;
		throw err;
	});
	return sqlPromise;
}
/**
* Finish DB bootstrap before the server handles traffic.
*
* - **PGLite** (preview / no `DATABASE_URL`): open the embedded DB and apply
*   `migrations/*.sql`. Idempotent — concurrent callers share one promise.
* - **Neon**: no-op (pool is created lazily on first query).
*
* Vite `configureServer` awaits this at dev startup; production imports of this
* module under Vite kick it off immediately (see bottom of file).
*/
function ensureDbReady() {
	if (dbSource !== "pglite") return Promise.resolve();
	return getSql().then(() => void 0);
}
var globalBoot = globalThis;
if (typeof window === "undefined" && dbSource === "pglite" && underVite) globalBoot.__pgBootstrapPromise__ ??= ensureDbReady().catch((err) => {
	globalBoot.__pgBootstrapPromise__ = void 0;
	console.error("[db] PGLite bootstrap failed:", err);
});
//#endregion
export { getSql };
