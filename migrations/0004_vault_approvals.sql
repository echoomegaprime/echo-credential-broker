-- library-first: echo.functions.search → no existing impl found (2026-11-14)
-- ECHO Vault v2: request-bound, single-use approvals (src/lib/vault/v2/approvals.ts).
-- No secret material lives here: the request is stored only as its sha256
-- digest, and the summary is sanitized human text. The HMAC key that signs
-- Telegram callback data is server-side env only.
create table if not exists vault_approvals (
  id             text primary key check (id ~ '^[A-Za-z0-9_-]{24}$'),
  request_digest text not null check (request_digest ~ '^[0-9a-f]{64}$'),
  client_id      text not null check (length(client_id) between 1 and 200),
  capability     text not null check (length(capability) between 1 and 128),
  resource       text not null check (length(resource) between 1 and 512),
  summary        text not null default '' check (length(summary) <= 500),
  status         text not null default 'pending'
                 check (status in ('pending', 'approved', 'denied', 'expired', 'consumed')),
  created_at     timestamptz not null default now(),
  expires_at     timestamptz not null,
  decided_at     timestamptz,
  decided_by     text,
  consumed_at    timestamptz
);

create index if not exists vault_approvals_status_expires_idx
  on vault_approvals (status, expires_at);
