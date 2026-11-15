-- library-first: echo.functions.search → no existing impl found (2026-11-14)
--
-- ECHO Vault v2 owner console (src/lib/vault/v2/owner-console*.ts,
-- docs/ops/owner-console.md): passkeys, WebAuthn challenges, console sessions
-- and the one-time enrollment bootstrap code.
--
-- What is stored, and what never is:
--   - Passkeys: the credential id, the PUBLIC key (COSE, base64url), the
--     signature counter and the transports. Passkey private material never
--     reaches the server and has no column here.
--   - Challenges, session tokens and the bootstrap code: sha256 hex ONLY. The
--     raw value exists in the browser (cookie / ceremony) or in the one stdio
--     tool result that minted it, never in a row.
--   - No vault secret, no request content.
--
-- Times are epoch milliseconds (bigint) taken from the application clock, like
-- vault_rate_limits, so tests can inject a clock and both stores agree.

create table if not exists vault_console_passkeys (
  -- base64url. (Length is a separate check: Postgres regex bounds stop at 255.)
  credential_id text   primary key check (credential_id ~ '^[A-Za-z0-9_-]+$' and length(credential_id) between 16 and 1366),
  public_key    text   not null check (public_key ~ '^[A-Za-z0-9_-]+$' and length(public_key) between 32 and 8192),
  counter       bigint not null check (counter between 0 and 4294967295),
  transports    text   not null default '' check (transports ~ '^([a-z][a-z-]{1,15}(,[a-z][a-z-]{1,15}){0,7})?$'),
  label         text   not null check (length(label) between 1 and 64),
  created_at    bigint not null check (created_at > 0),
  last_used_at  bigint null check (last_used_at is null or last_used_at > 0),
  -- Set when a correctly signed assertion carried a signature counter that did
  -- not advance (possible cloned authenticator). The assertion is refused.
  flagged_at    bigint null check (flagged_at is null or flagged_at > 0),
  flag_reason   text   null check (flag_reason is null or flag_reason in ('counter_regression')),
  check ((flagged_at is null) = (flag_reason is null))
);

-- One row per outstanding WebAuthn challenge. Single use: verification deletes
-- the row before it checks the response.
create table if not exists vault_console_challenges (
  challenge_hash text   primary key check (challenge_hash ~ '^[0-9a-f]{64}$'),
  purpose        text   not null check (purpose in ('enroll', 'login', 'stepup', 'add_passkey')),
  -- The console session a step-up / add-passkey challenge is bound to.
  session_id     text   null check (session_id is null or session_id ~ '^[0-9a-f]{32}$'),
  created_at     bigint not null check (created_at > 0),
  expires_at     bigint not null,
  check (expires_at > created_at),
  check ((purpose in ('stepup', 'add_passkey')) = (session_id is not null))
);

create index if not exists vault_console_challenges_expires_idx
  on vault_console_challenges (expires_at);

create table if not exists vault_console_sessions (
  id                  text   primary key check (id ~ '^[0-9a-f]{32}$'),
  token_hash          text   not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  credential_id       text   not null references vault_console_passkeys (credential_id) on delete cascade,
  created_at          bigint not null check (created_at > 0),
  last_seen_at        bigint not null,
  absolute_expires_at bigint not null,
  -- Time of the newest WebAuthn assertion completed for this session.
  step_up_at          bigint null,
  revoked_at          bigint null,
  user_agent          text   not null default '' check (length(user_agent) <= 200),
  check (last_seen_at >= created_at),
  check (absolute_expires_at > created_at)
);

create index if not exists vault_console_sessions_credential_idx
  on vault_console_sessions (credential_id);

-- At most ONE bootstrap code exists: a singleton row that minting overwrites.
create table if not exists vault_console_bootstrap (
  id          smallint primary key check (id = 1),
  code_hash   text     not null check (code_hash ~ '^[0-9a-f]{64}$'),
  minted_by   text     not null check (minted_by ~ '^local:[a-z0-9][a-z0-9._-]{0,63}$'),
  created_at  bigint   not null check (created_at > 0),
  expires_at  bigint   not null,
  consumed_at bigint   null,
  check (expires_at > created_at)
);
