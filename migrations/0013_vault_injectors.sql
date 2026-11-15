-- library-first: echo.functions.search → no existing impl found (2026-11-14)
--
-- ECHO Vault v2 browser injector channel (src/lib/vault/v2/injector.ts,
-- docs/ops/injector-contract.md, docs/ops/injector-channel.md).
--
-- What is stored, and what never is:
--   - Injectors: an id, a display name, the injector's PUBLIC P-256 ECDH key
--     (canonical JWK: crv, kty, x, y — no private member can be stored, see the
--     check) and sha256(injector token). The raw `ein_` token exists in the one
--     enrollment result and in the injector; never in a row.
--   - Inject tickets: sha256(ticket) and what the ticket is bound to (entry id,
--     mode, target origin, injector, approval, requesting client). The raw
--     `eit_` ticket exists in the one tool result that minted it.
--   - No vault secret, no cookie value, no ciphertext, no derived key.
--
-- Times are epoch milliseconds (bigint) from the application clock, like
-- vault_rate_limits and the console tables, so tests can inject a clock and
-- both stores agree.
--
-- Idempotent: every statement is safe to re-run.

create table if not exists vault_injectors (
  id             text   primary key check (id ~ '^inj_[0-9a-f]{16}$'),
  name           text   not null check (length(name) between 1 and 64),
  -- Canonical public JWK, members in this exact order. A JWK with a private
  -- member ("d") or any other member cannot match.
  public_key_jwk text   not null check (
    public_key_jwk ~ '^\{"crv":"P-256","kty":"EC","x":"[A-Za-z0-9_-]{43}","y":"[A-Za-z0-9_-]{43}"\}$'
  ),
  token_sha256   text   not null unique check (token_sha256 ~ '^[0-9a-f]{64}$'),
  created_at     bigint not null check (created_at > 0),
  revoked_at     bigint null check (revoked_at is null or revoked_at >= created_at),
  last_used_at   bigint null check (last_used_at is null or last_used_at >= created_at)
);

create table if not exists vault_inject_tickets (
  sha256        text   primary key check (sha256 ~ '^[0-9a-f]{64}$'),
  entry_id      text   not null check (entry_id ~ '^ve_[0-9a-f]{32}$'),
  mode          text   not null check (mode in ('cookies', 'field')),
  -- https://<lower-case host>, nothing else. (Length is a separate check: Postgres regex bounds stop at 255.)
  target_origin text   not null check (
    target_origin ~ '^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$' and length(target_origin) <= 261
  ),
  injector_id   text   not null references vault_injectors (id),
  -- One approval mints at most one ticket.
  approval_id   text   not null unique check (length(approval_id) between 1 and 256),
  client_id     text   not null check (length(client_id) between 1 and 200),
  created_at    bigint not null check (created_at > 0),
  expires_at    bigint not null,
  -- Set once, by the first redeem attempt of the bound injector (the burn).
  redeemed_at   bigint null,
  -- Set once, by the injector's report.
  result        text   null check (result is null or result in ('injected', 'failed')),
  check (expires_at > created_at),
  check (redeemed_at is null or redeemed_at >= created_at),
  check (result is null or redeemed_at is not null)
);

create index if not exists vault_inject_tickets_expires_idx
  on vault_inject_tickets (expires_at);
create index if not exists vault_inject_tickets_injector_idx
  on vault_inject_tickets (injector_id);
