-- library-first: echo.functions.search → no existing impl found (2026-11-14)
-- ECHO Vault v2 — OAuth 2.1 authorization server state for the remote MCP endpoint.
--
-- Invariant: no raw bearer material is stored. Authorization codes, access /
-- refresh tokens and pending-authorization handles are stored ONLY as
-- lowercase sha256 hex; the CHECK constraints below reject anything else, so a
-- code path that tried to persist a raw "eva_…"/"evr_…"/"evc_…" value fails
-- loudly instead of leaking it into a dump.
--
-- All timestamps are epoch milliseconds (bigint) supplied by the application
-- clock. Applied by scripts/migrate.mjs (Postgres) and src/lib/db.ts (PGlite).

create table if not exists vault_oauth_clients (
  client_id        text primary key check (client_id ~ '^oc_[A-Za-z0-9_-]{16,64}$'),
  client_name      text not null check (char_length(client_name) between 1 and 100),
  redirect_uris    jsonb not null,
  requested_scopes jsonb not null default '[]'::jsonb,
  granted_scopes   jsonb not null default '[]'::jsonb,
  status           text not null check (status in ('registered', 'approved', 'denied', 'revoked')),
  created_at       bigint not null,
  approved_at      bigint,
  revoked_at       bigint
);

create table if not exists vault_oauth_pending (
  id_hash        text primary key check (id_hash ~ '^[0-9a-f]{64}$'),
  client_id      text not null references vault_oauth_clients (client_id) on delete cascade,
  redirect_uri   text not null,
  code_challenge text not null,
  scopes         jsonb not null,
  resource       text not null,
  state          text,
  approval_id    text not null,
  is_new_client  boolean not null,
  status         text not null check (status in ('pending', 'completed', 'denied', 'expired')),
  created_at     bigint not null,
  expires_at     bigint not null
);

create index if not exists vault_oauth_pending_client_idx on vault_oauth_pending (client_id);
create index if not exists vault_oauth_pending_status_idx on vault_oauth_pending (status, expires_at);

create table if not exists vault_oauth_codes (
  code_hash      text primary key check (code_hash ~ '^[0-9a-f]{64}$'),
  client_id      text not null references vault_oauth_clients (client_id) on delete cascade,
  redirect_uri   text not null,
  code_challenge text not null,
  scopes         jsonb not null,
  resource       text not null,
  family_id      text not null,
  created_at     bigint not null,
  expires_at     bigint not null,
  used_at        bigint
);

create table if not exists vault_oauth_tokens (
  token_hash text primary key check (token_hash ~ '^[0-9a-f]{64}$'),
  kind       text not null check (kind in ('access', 'refresh')),
  client_id  text not null references vault_oauth_clients (client_id) on delete cascade,
  family_id  text not null,
  scopes     jsonb not null,
  resource   text not null,
  created_at bigint not null,
  expires_at bigint not null,
  used_at    bigint,
  revoked_at bigint
);

create index if not exists vault_oauth_tokens_family_idx on vault_oauth_tokens (family_id);
create index if not exists vault_oauth_tokens_client_idx on vault_oauth_tokens (client_id);
create index if not exists vault_oauth_tokens_expires_idx on vault_oauth_tokens (expires_at);
