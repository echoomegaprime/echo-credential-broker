# Ledger anchoring (ops)

The audit ledger (`vault_ledger`) is a hash chain. `audit_verify` proves the
chain is internally consistent, but someone with database access can still

- delete the newest N rows (the remaining prefix is a valid chain), or
- rebuild the whole chain from scratch,

and the chain alone will still verify. Anchoring publishes the chain head
**outside the database**: one Telegram message to the owner's chat (the same
bot and chat as approvals). Compare the ledger with that message and both
attacks show.

Only a sequence number, the sha256 chain hash, a row count and a timestamp are
sent. Nothing from a ledger row's payload, and never a secret.

## The message

The whole message text is one line:

```
ECHO-VAULT-ANCHOR v1 seq=<n> hash=<64 hex> rows=<n> at=<ISO-8601 UTC, ms> mac=<64 hex>
ECHO-VAULT-ANCHOR v1 seq=<n> hash=<64 hex> rows=<n> at=<ISO-8601 UTC, ms> unsigned
```

- `seq` / `hash`: the newest ledger row at the time (`vault_ledger.seq`, `.hash`).
- `rows`: number of ledger rows at the time (equals `seq` in an intact chain).
- `mac`: HMAC-SHA256 under `ECHO_VAULT_ANCHOR_KEY` over the line **up to, not
  including, ` mac=`**. Without the key the line ends in the word `unsigned`.
- The Telegram message id is the receipt; it is stored as `external_id` in
  `vault_ledger_anchors`.

If verification fails, an alert is sent instead and **no anchor is recorded**:

```
ECHO-VAULT-ANCHOR ALERT v1 reason=<code> seq=<n> at=<ISO>
ECHO Vault: the audit ledger failed verification. No anchor was recorded. …
```

`reason` is one of `seq_gap`, `prev_hash_mismatch`, `hash_mismatch`,
`hmac_missing`, `hmac_mismatch` (the chain itself is broken at `seq`),
`truncated`, `rewritten` (the ledger no longer matches the newest recorded
anchor, whose seq is given), or `chain_invalid`.

## Environment variables

| Variable | Required | Meaning |
| --- | --- | --- |
| `ECHO_VAULT_ANCHOR_KEY` | recommended | **New.** HMAC key for the anchor line, at least 32 characters. Server-only; never store it in the database. Unset: anchors are sent `unsigned`. Shorter than 32 characters: anchoring fails closed (`anchor_key_too_short`). |
| `TELEGRAM_BOT_TOKEN` | yes | Existing. The approvals bot. |
| `ECHO_VAULT_APPROVER_TELEGRAM_ID` | yes | Existing. The owner's Telegram user id = the private chat the anchor goes to. |
| `ECHO_VAULT_LEDGER_HMAC_KEY` | optional | Existing. If the ledger uses it, the runner needs it too (it verifies the chain before anchoring). |
| `DATABASE_URL` / `ECHO_VAULT_DATA_DIR` | as deployed | Existing. The runner must point at the same database as the server. |

Generate a key: `openssl rand -base64 48`. Use a key different from the ledger
and approval HMAC keys. After setting or changing the key, the newest recorded
anchor no longer verifies under it (`anchor_mac_invalid` in `audit_verify`)
until the next anchor is taken — make any vault call so the head moves, then
run `admin_anchor_now`.

Apply `migrations/0008_vault_ledger_anchors.sql` (`vault_ledger_anchors`,
append-only like the ledger) with the usual migration step before the first run.

## Schedule

Run hourly. Everything after the newest anchor is unprotected against
truncation, so the interval is the exposure window; hourly keeps it small
without flooding the chat (an unchanged head sends nothing).

```
node --experimental-strip-types scripts/vault-anchor.ts
```

Prints one JSON object and exits 0 for `anchored`, `unchanged`, `empty`; exits
1 for anything else (`ledger_unverified`, `ledger_truncated`,
`ledger_rewritten`, `telegram_*`, `anchor_key_too_short`, `anchor_record_failed`, …).
Alert on a non-zero exit as well: if Telegram is down the alert message cannot
be delivered either.

cron (Linux):

```
7 * * * * cd /opt/echo-credential-broker && /usr/bin/env $(grep -v '^#' .env | xargs) node --experimental-strip-types scripts/vault-anchor.ts >> /var/log/echo-vault-anchor.log 2>&1
```

Task Scheduler (Windows, PowerShell 7), hourly:

```
$action  = New-ScheduledTaskAction -Execute "node.exe" -Argument "--experimental-strip-types scripts/vault-anchor.ts" -WorkingDirectory "C:\echo-credential-broker"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName "ECHO Vault ledger anchor" -Action $action -Trigger $trigger
```

(the task's account must have the environment variables above). From the local
stdio MCP client the owner can also call `admin_anchor_now` at any time.

## Verifying

Day to day: `audit_verify` now returns `anchor: { seq, anchored_at, verdict }`
for the newest recorded anchor (`anchor: null` when nothing was anchored yet).
That uses the local index in the same database, so it is a convenience, not
the proof. The proof is the Telegram message.

From a Telegram message — copy the message text, then either

```
node --experimental-strip-types scripts/vault-anchor.ts --verify "ECHO-VAULT-ANCHOR v1 seq=… "
```

or call the owner-only tool `admin_verify_anchor { line }` from the local stdio
client. Verdicts:

| Verdict | Meaning |
| --- | --- |
| `ok` | The ledger still has the anchored row with the anchored hash, and at least as many rows. |
| `truncated` | The ledger ends before the anchored seq (or has fewer rows than were anchored), and the anchor is authentic: its mac verified, or it matches a local anchor record. Rows were deleted. |
| `rewritten` | The row at the anchored seq has a different hash, or is gone while later rows exist. History was changed or the chain was rebuilt. |
| `anchor_mac_invalid` | A key is configured and the line's mac is missing or wrong: the line was edited, was signed with another key, or is unsigned. |
| `anchor_ahead_of_ledger` | The ledger ends before the anchored seq, but the anchor could not be authenticated (unsigned or no key configured, and no local record). Either truncation, or the line belongs to another vault / was made up. Treat as a failure until explained. |

By hand, with no vault code at all:

1. Check the mac (skip for `unsigned`):

   ```
   printf '%s' 'ECHO-VAULT-ANCHOR v1 seq=128 hash=<hash> rows=128 at=2026-11-14T10:00:00.000Z' \
     | openssl dgst -sha256 -hmac "$ECHO_VAULT_ANCHOR_KEY"
   ```

   The output must equal the `mac=` value.
2. Check the row: `SELECT hash FROM vault_ledger WHERE seq = 128;` must return
   exactly the anchored `hash`. A different hash, or no row while
   `max(seq) > 128`: rewritten. No row and `max(seq) < 128`: truncated.
3. Check the count: `SELECT count(*), max(seq) FROM vault_ledger;` — both must
   be `>= 128`.
4. Check the chat: anchor `seq` values must never go down from one message to
   the next. A lower seq after a higher one means the ledger **and** the local
   anchor index were both cut back before that run.

Verify against the **newest** message you have, and occasionally an old one.

## What this does and does not cover

- Covered: tail truncation and rewrite/rebuild of anything at or before the
  newest anchor, by someone with database access only.
- Not covered: rows appended and removed again between two anchors (the
  exposure window is the schedule interval).
- The local `vault_ledger_anchors` table is in the same database. A privileged
  writer can disable its triggers and delete index rows; the runner would then
  anchor the shortened ledger without an alert. Step 4 above catches that from
  the chat history.
- Unsigned anchors are only as trustworthy as the chat they are read from.
  Set `ECHO_VAULT_ANCHOR_KEY`.
- Someone who controls the Telegram account (or the bot token) can delete or
  edit bot messages. With a key they cannot forge a line that verifies, but
  they can make the newest anchors disappear, leaving only older ones to check
  against. Someone who holds database access, the anchor key **and** the
  Telegram chat can replace history undetectably; keep an occasional copy of
  an anchor line somewhere else (forward it, or note it down) if that matters.
