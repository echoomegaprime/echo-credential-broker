-- library-first: echo.functions.search → no existing impl found (2026-11-14)
--
-- ECHO Vault v2 `cookie` entries (src/lib/vault/v2/cards.ts, cookie-jar.ts).
--
-- A cookie entry's secret is the canonical cookie-jar JSON. Like every other
-- secret it lives ONLY in the canonical vault backend; this migration adds no
-- column that can hold a cookie value.
--
--   kind            'cookie' joins the allowed kinds of vault_entries and vault_cards.
--   secret_length   stays 1..4096 for every other kind; a cookie jar may be up to
--                   32768 characters (cookie-jar.ts MAX_COOKIE_JAR_CHARS).
--   cookie_meta     METADATA ONLY, cookie entries only: JSON text
--                   {count, names[], domains[], truncated, expires_at, session_cookies}.
--                   Cookie NAMES and domains, never a value.
--
-- Idempotent: every statement is safe to re-run.

alter table vault_entries add column if not exists cookie_meta text null;

alter table vault_entries drop constraint if exists vault_entries_kind_check;
alter table vault_entries add constraint vault_entries_kind_check
  check (kind in ('password', 'api_key', 'oauth_token', 'operator_secret', 'cookie'));

alter table vault_entries drop constraint if exists vault_entries_secret_length_check;
alter table vault_entries add constraint vault_entries_secret_length_check
  check (secret_length between 1 and 4096 or (kind = 'cookie' and secret_length between 1 and 32768));

alter table vault_entries drop constraint if exists vault_entries_cookie_meta_check;
alter table vault_entries add constraint vault_entries_cookie_meta_check
  check (cookie_meta is null or (kind = 'cookie' and length(cookie_meta) <= 16384));

alter table vault_cards drop constraint if exists vault_cards_kind_check;
alter table vault_cards add constraint vault_cards_kind_check
  check (kind in ('password', 'api_key', 'oauth_token', 'operator_secret', 'cookie'));
