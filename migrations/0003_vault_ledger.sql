-- library-first: echo.functions.search → no existing impl found (2026-11-14)
--
-- Vault v2 ledger (src/lib/vault/v2/ledger.ts): append-only, hash-chained
-- audit of every capability request. Metadata only — never a secret value;
-- credential_ref is a vault:// reference.
--
-- Integrity layers:
--   1. seq PRIMARY KEY + UNIQUE prev_hash: two writers can never both append
--      after the same predecessor, so the chain cannot fork. ledger.ts appends
--      with a single compare-and-append INSERT ... SELECT ... ON CONFLICT DO
--      NOTHING and retries from the new head when it loses a race.
--   2. Triggers refuse UPDATE / DELETE / TRUNCATE.
--   3. verifyLedger() recomputes every hash (and the optional HMAC from
--      ECHO_VAULT_LEDGER_HMAC_KEY), so a privileged writer who disables (2)
--      is still detected at the first edited seq.
-- Every column except hmac is covered by the hash; hmac covers the hash.

CREATE TABLE IF NOT EXISTS vault_ledger (
  seq            BIGINT   PRIMARY KEY CHECK (seq >= 1),
  id             TEXT     NOT NULL UNIQUE,
  ts             TEXT     NOT NULL,
  prev_hash      TEXT     NOT NULL UNIQUE CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  hash           TEXT     NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$'),
  hmac           TEXT     NULL CHECK (hmac IS NULL OR hmac ~ '^[0-9a-f]{64}$'),
  client_id      TEXT     NOT NULL,
  capability     TEXT     NOT NULL,
  resource       TEXT     NOT NULL,
  decision       TEXT     NOT NULL CHECK (decision IN ('allow', 'escalate', 'deny')),
  tier           SMALLINT NOT NULL CHECK (tier BETWEEN 0 AND 3),
  result         TEXT     NOT NULL CHECK (result IN ('ok', 'error', 'denied', 'pending_approval', 'committing')),
  approval_id    TEXT     NULL,
  credential_ref TEXT     NULL CHECK (credential_ref IS NULL OR credential_ref ~ '^vault://[a-z0-9-]+/[A-Za-z0-9._-]+$'),
  http_status    INTEGER  NULL CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
  error          TEXT     NULL,
  duration_ms    BIGINT   NULL CHECK (duration_ms IS NULL OR duration_ms >= 0),
  task           TEXT     NULL CHECK (task IS NULL OR length(task) <= 300),
  credential_path TEXT    NULL CHECK (credential_path IS NULL OR credential_path IN ('installation', 'pat_fallback')),
  fallback_reason TEXT    NULL CHECK (fallback_reason IS NULL OR length(fallback_reason) <= 200)
);

CREATE INDEX IF NOT EXISTS vault_ledger_client_seq_idx ON vault_ledger (client_id, seq DESC);
CREATE INDEX IF NOT EXISTS vault_ledger_capability_seq_idx ON vault_ledger (capability, seq DESC);

CREATE OR REPLACE FUNCTION vault_ledger_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'vault_ledger is append-only (% refused)', TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS vault_ledger_no_update_delete ON vault_ledger;
CREATE TRIGGER vault_ledger_no_update_delete
  BEFORE UPDATE OR DELETE ON vault_ledger
  FOR EACH ROW EXECUTE FUNCTION vault_ledger_append_only();

DROP TRIGGER IF EXISTS vault_ledger_no_truncate ON vault_ledger;
CREATE TRIGGER vault_ledger_no_truncate
  BEFORE TRUNCATE ON vault_ledger
  FOR EACH STATEMENT EXECUTE FUNCTION vault_ledger_append_only();
