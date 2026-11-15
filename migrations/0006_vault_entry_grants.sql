-- library-first: echo.functions.search → no existing impl found (2026-11-14)
-- ECHO Vault v2 entry consent grants (src/lib/vault/v2/entry-grants.ts).
--
-- One row = the owner approved, on Telegram, that this client may repeat ONE
-- read-only (GET/HEAD) request — to this exact host, at this path or under it —
-- without being asked again, until it expires or its uses run out. Non-GET uses
-- never consult this table: they need a fresh approval every time. A client may
-- hold several narrow grants for one entry, so the primary key is the full
-- (client_id, entry_id, host, path_prefix).
-- Metadata only: no secret, no request content. Revoking deletes the row(s)
-- (revokeEntryGrant); the approval that created it stays in vault_approvals and
-- the ledger.
create table if not exists vault_entry_grants (
  client_id      text not null check (length(client_id) between 1 and 200),
  entry_id       text not null check (entry_id ~ '^ve_[0-9a-f]{32}$'),
  host           text not null check (length(host) between 1 and 253),
  path_prefix    text not null check (length(path_prefix) between 1 and 1024),
  approval_id    text not null check (approval_id ~ '^[A-Za-z0-9_-]{24}$'),
  granted_at     timestamptz not null default now(),
  expires_at     timestamptz not null,
  max_uses       integer null check (max_uses is null or max_uses >= 0),
  uses_remaining integer null check (uses_remaining is null or uses_remaining >= 0),
  check (expires_at > granted_at),
  primary key (client_id, entry_id, host, path_prefix)
);

create index if not exists vault_entry_grants_entry_idx
  on vault_entry_grants (entry_id);
