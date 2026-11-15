-- library-first: echo.functions.search → no existing impl found (2026-11-14)
--
-- Vault v2 ledger anchors (src/lib/vault/v2/ledger-anchor.ts): a local INDEX of
-- every ledger head that was published outside the database. The proof is the
-- external message itself (channel 'telegram': the owner's chat; external_id is
-- the Telegram message id) — this table only says which messages to look for.
-- Metadata only: a sequence number, a sha256 chain hash, a row count, an
-- optional HMAC. Never a secret value and nothing from a ledger row's payload.
--
-- Append-only like vault_ledger: triggers refuse UPDATE / DELETE / TRUNCATE.
-- A privileged writer who disables them can drop index rows, but cannot unsend
-- the external message; verify against the message, not against this table.

CREATE TABLE IF NOT EXISTS vault_ledger_anchors (
  seq          BIGINT      NOT NULL CHECK (seq >= 1),
  hash         TEXT        NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  row_count    BIGINT      NOT NULL CHECK (row_count >= 1),
  anchored_at  TIMESTAMPTZ NOT NULL,
  channel      TEXT        NOT NULL CHECK (channel ~ '^[a-z][a-z0-9_-]{0,31}$'),
  external_id  TEXT        NOT NULL CHECK (length(external_id) BETWEEN 1 AND 128),
  mac          TEXT        NULL CHECK (mac IS NULL OR mac ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (seq, channel)
);

CREATE OR REPLACE FUNCTION vault_ledger_anchors_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'vault_ledger_anchors is append-only (% refused)', TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS vault_ledger_anchors_no_update_delete ON vault_ledger_anchors;
CREATE TRIGGER vault_ledger_anchors_no_update_delete
  BEFORE UPDATE OR DELETE ON vault_ledger_anchors
  FOR EACH ROW EXECUTE FUNCTION vault_ledger_anchors_append_only();

DROP TRIGGER IF EXISTS vault_ledger_anchors_no_truncate ON vault_ledger_anchors;
CREATE TRIGGER vault_ledger_anchors_no_truncate
  BEFORE TRUNCATE ON vault_ledger_anchors
  FOR EACH STATEMENT EXECUTE FUNCTION vault_ledger_anchors_append_only();
