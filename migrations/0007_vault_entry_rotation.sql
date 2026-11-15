-- library-first: echo.functions.search → no existing impl found (2026-11-14)
--
-- ECHO Vault v2 entry rotation state (src/lib/vault/v2/cards.ts, rotation.ts).
--
-- METADATA ONLY. Nothing here is a secret:
--   rotation_mode        'manual' (the owner re-enters the secret on a card) or
--                        'auto' (a provider rotator rolls it, see rotation.ts).
--   rotate_interval_days how often the secret should be rotated; null = no schedule.
--   last_rotated_at      last successful rotation (card re-entry or auto-rotate).
--   rotate_by            when the next rotation is due (last rotation, or creation,
--                        plus the interval); null = never due.
--   rotation_count       successful rotations so far.
--   last_rotation_error  a SHORT CODE only (e.g. 'provider_http_403'). Never
--                        provider response text, which could carry a secret.
--   provider_token_id    the provider-side, NON-SECRET id needed to rotate
--                        (e.g. a Cloudflare API token id). Never a token value.
--
-- Idempotent: every statement is safe to re-run.

alter table vault_entries add column if not exists rotation_mode text not null default 'manual';
alter table vault_entries add column if not exists rotate_interval_days integer null;
alter table vault_entries add column if not exists last_rotated_at timestamptz null;
alter table vault_entries add column if not exists rotate_by timestamptz null;
alter table vault_entries add column if not exists rotation_count integer not null default 0;
alter table vault_entries add column if not exists last_rotation_error text null;
alter table vault_entries add column if not exists provider_token_id text null;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'vault_entries_rotation_mode_check') then
    alter table vault_entries add constraint vault_entries_rotation_mode_check
      check (rotation_mode in ('manual', 'auto'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'vault_entries_rotate_interval_check') then
    alter table vault_entries add constraint vault_entries_rotate_interval_check
      check (rotate_interval_days is null or rotate_interval_days between 1 and 3650);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'vault_entries_rotation_count_check') then
    alter table vault_entries add constraint vault_entries_rotation_count_check
      check (rotation_count >= 0);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'vault_entries_rotation_error_check') then
    alter table vault_entries add constraint vault_entries_rotation_error_check
      check (last_rotation_error is null or last_rotation_error ~ '^[a-z0-9_]{1,64}$');
  end if;
  if not exists (select 1 from pg_constraint where conname = 'vault_entries_provider_token_id_check') then
    alter table vault_entries add constraint vault_entries_provider_token_id_check
      check (provider_token_id is null or provider_token_id ~ '^[A-Za-z0-9._:-]{1,128}$');
  end if;
end;
$$;

create index if not exists vault_entries_rotate_by_idx
  on vault_entries (rotate_by) where status = 'active' and rotate_by is not null;
