-- library-first: echo.functions.search → no existing impl found (2026-11-14)
--
-- ECHO Vault v2 credential entries + credential cards (src/lib/vault/v2/cards.ts).
--
-- METADATA ONLY. No secret value is ever stored here: the secret lives in the
-- canonical vault backend under the per-entry key derived from `id`. What this
-- table keeps about the secret is the first 8 hex chars of its sha256 and its
-- length. Card tokens are stored only as sha256 hex.
--
-- Many entries per site: identity is (site, lower(account), kind) among
-- non-deleted rows, so a second account for a site can never overwrite another.
-- At most one default per site: partial unique index on (site) where is_default.

create table if not exists vault_entries (
  id               text primary key check (id ~ '^ve_[0-9a-f]{32}$'),
  site             text not null check (length(site) between 1 and 253 and site = lower(site)),
  account          text not null check (length(account) between 1 and 254),
  purpose          text not null default 'general' check (length(purpose) between 1 and 64),
  label            text not null check (length(label) between 1 and 600),
  kind             text not null check (kind in ('password', 'api_key', 'oauth_token', 'operator_secret')),
  is_default       boolean not null default false,
  status           text not null default 'active' check (status in ('active', 'needs_reentry', 'deleted')),
  fingerprint      text not null check (fingerprint ~ '^[0-9a-f]{8}$'),
  secret_length    integer not null check (secret_length between 1 and 4096),
  reentry_reason   text check (reentry_reason is null or length(reentry_reason) <= 300),
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  last_used_at     timestamptz,
  last_verified_at timestamptz,
  deleted_at       timestamptz,
  constraint vault_entries_deleted_not_default check (not (is_default and status = 'deleted'))
);

create unique index if not exists vault_entries_identity_uidx
  on vault_entries (site, lower(account), kind) where status <> 'deleted';

create unique index if not exists vault_entries_one_default_uidx
  on vault_entries (site) where is_default;

create index if not exists vault_entries_site_status_idx
  on vault_entries (site, status);

-- Move the default to p_id atomically (the shared Sql surface has no
-- multi-statement transactions; a function body runs inside the calling
-- statement's transaction). Serialized per site with an advisory lock; the
-- partial unique index is the backstop. Returns false when the entry does not
-- exist or is deleted.
create or replace function vault_entries_set_default(p_id text) returns boolean
language plpgsql as $$
declare
  v_site text;
begin
  select site into v_site from vault_entries where id = p_id and status <> 'deleted';
  if v_site is null then
    return false;
  end if;
  perform pg_advisory_xact_lock(hashtext('vault_entries:' || v_site));
  update vault_entries set is_default = false
   where site = v_site and is_default and id <> p_id;
  update vault_entries set is_default = true, updated_at = now()
   where id = p_id and status <> 'deleted' and not is_default;
  return exists (select 1 from vault_entries where id = p_id and is_default);
end;
$$;

-- Credential cards: a pending request for the operator to type a secret.
-- token_hash = sha256 hex of the single-use URL token (the token itself is
-- only ever sent to the operator). status: pending -> claimed -> completed,
-- or -> expired. `claimed` is the in-flight state of one POST.
create table if not exists vault_cards (
  id           text primary key check (id ~ '^vc_[0-9a-f]{32}$'),
  token_hash   text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  client_id    text not null check (length(client_id) between 1 and 200),
  client_name  text not null default '' check (length(client_name) <= 120),
  site         text not null check (length(site) between 1 and 253),
  account      text check (account is null or length(account) between 1 and 254),
  purpose      text check (purpose is null or length(purpose) between 1 and 64),
  kind         text not null check (kind in ('password', 'api_key', 'oauth_token', 'operator_secret')),
  reason       text not null default '' check (length(reason) <= 300),
  entry_id     text references vault_entries (id),
  is_reentry   boolean not null default false,
  status       text not null default 'pending' check (status in ('pending', 'claimed', 'completed', 'expired')),
  created_at   timestamptz not null default now(),
  expires_at   timestamptz not null,
  completed_at timestamptz,
  constraint vault_cards_reentry_has_entry check (not is_reentry or entry_id is not null)
);

create index if not exists vault_cards_client_status_idx
  on vault_cards (client_id, status, expires_at);
