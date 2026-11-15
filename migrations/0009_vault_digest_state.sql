-- library-first: echo.functions.search → no existing impl found (2026-11-14)
-- ECHO Vault v2 daily audit digest state (src/lib/vault/v2/digest.ts).
--
-- One row per digest window [window_from, window_to) that was claimed for
-- sending. It exists for one purpose: the same window is never sent twice.
--   status 'sending' = a runner claimed the window and is building/sending it
--                      (a claim older than 10 minutes is treated as a crashed
--                      runner and may be re-claimed);
--   status 'sent'    = Telegram accepted the message (message_id recorded).
-- A failed send deletes its claim, so the window stays unsent and is retried.
-- Metadata only: no digest text, no ledger content, no secret.
create table if not exists vault_digest_state (
  window_from text not null check (window_from ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'),
  window_to   text not null check (window_to   ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'),
  status      text not null check (status in ('sending', 'sent')),
  claimed_at  timestamptz not null,
  sent_at     timestamptz null,
  message_id  bigint null,
  check (window_from < window_to),
  check ((status = 'sent') = (sent_at is not null)),
  primary key (window_from, window_to)
);
