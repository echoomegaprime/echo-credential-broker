-- library-first: echo.functions.search → no existing impl found (2026-11-14)
-- ECHO Vault v2 shared rate-limit state (src/lib/vault/v2/rate-limit-store.ts).
--
-- One row per rate-limit key. `hits` holds the epoch-millisecond timestamps of
-- the events still inside that key's sliding window (oldest first), so an exact
-- sliding-window count survives restarts and is shared by every server instance.
--
-- Why one row per key instead of an events table: recording a hit is ONE
-- statement, `insert … on conflict (key) do update … where <in-window count> <
-- <limit>`. ON CONFLICT DO UPDATE takes the row lock and re-evaluates its WHERE
-- against the latest committed row, so concurrent hits from several processes
-- are serialized per key and "count, then record only if under the limit" is
-- atomic without a transaction or advisory lock. An events table counted in the
-- same statement would read a snapshot taken before a concurrent insert
-- committed and could admit more than the limit.
--
-- `key` is `<namespace>:<sha256 hex>` — never a token, code, secret or raw
-- identifier (the constraint below makes any other shape unstorable).
-- `expires_at` is the latest hit plus its window; rows past it hold no live
-- event and are deleted by the store's opportunistic prune.
-- Metadata only: no secret, no request content.
create table if not exists vault_rate_limits (
  key        text primary key check (key ~ '^[a-z0-9_.-]{1,40}:[0-9a-f]{64}$'),
  hits       bigint[] not null check (cardinality(hits) between 1 and 10000),
  expires_at timestamptz not null
);

create index if not exists vault_rate_limits_expires_idx
  on vault_rate_limits (expires_at);
