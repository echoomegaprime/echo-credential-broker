# Daily audit digest

One Telegram message per day that tells the owner what the vault broker did:
who used it, what was refused, what was approved, and whether the audit ledger
is still intact. Code: `src/lib/vault/v2/digest.ts`. Runner:
`scripts/vault-digest.ts`. State table: `migrations/0009_vault_digest_state.sql`.

## What it contains

The digest is built only from ledger rows, entry metadata and consent grants.
It never contains a secret, a request body, a `vault://` reference, or a full
approval id. Free-text `task` appears only as a label of at most 48 characters
on a tier-2 mutation. Every copied string is scrubbed again with the ledger's
redaction rules before the message is sent.

In order (most important first):

| Section | Meaning |
| --- | --- |
| Ledger chain | The `verifyLedger()` verdict: `OK (N rows verified)`, `BROKEN at seq N`, or `NOT VERIFIED`. Always present, also on a quiet day. |
| Anomalies | See below. Omitted when there are none. |
| Totals | Actions in the window and the count per result: ok, error, denied, pending approval, committing. Approvals requested / granted / denied / expired. |
| Clients | Per client: actions, denied, errors, distinct entries used. Most active first (12 shown). |
| Tier-2 mutations | Approved hard-to-undo actions that ran: time, client, capability, resource, short task label (10 shown). |
| Top denied reasons | The five most frequent denial reasons. |
| Needs re-entry | Labels of entries flagged `needs_reentry` in the window. |
| Consent grants | Grants created in the window and grants usable right now. |
| Extra sections | Plug-in sections (`extraSections`), after everything above. |

Anomalies:

- **Ledger chain broken** — the hash chain no longer verifies.
- **Authorized mutation never reported** — a `committing` row (the owner
  approved a mutation and the broker recorded that it was about to run) with no
  later `ok`/`error` row for the same approval. Rows younger than two minutes
  are not reported yet.
- **Ledger unavailable** — rows whose error is `ledger_unavailable`.
- **Denial burst** — one client was denied at least N times in the window.
- **New client** — a client id that appears in the ledger for the first time.

A day with no ledger rows produces a four-line message ending in
`No activity in this window.`

Telegram allows 4096 characters. A longer digest is cut at a line boundary and
ends with `…truncated`; the structured digest from `admin_digest_now` is never
cut.

### How the numbers are derived

- A row belongs to the window when `from <= timestamp < to` (UTC).
- Approvals are counted from ledger rows, not from the approvals table:
  *requested* = prompts created; *granted* = approvals a request actually ran
  under; *denied* / *expired* = refused retries. An approval the owner denied
  that the client never retried shows only as *requested*. OAuth connection
  approvals are not ledger rows and are not counted.
- *Grants created* counts grants still on record; a grant created and revoked
  inside the window is not counted.
- *Needs re-entry* uses the entry's `updated_at`; an entry flagged earlier and
  still unresolved is not repeated every day.

## Environment variables

| Variable | Required | Meaning |
| --- | --- | --- |
| `ECHO_VAULT_DIGEST_DENIAL_BURST` | no | **New.** Denials by one client in the window that count as a burst. Positive integer, default `10`. Anything else falls back to 10. |
| `TELEGRAM_BOT_TOKEN` | yes | Existing. The bot that sends the message. |
| `ECHO_VAULT_APPROVER_TELEGRAM_ID` | yes | Existing. The owner's Telegram id; the digest goes to that private chat. |
| `DATABASE_URL` | prod | Existing. Without it the runner uses the embedded PGLite database under `ECHO_VAULT_DATA_DIR`. |
| `ECHO_VAULT_LEDGER_HMAC_KEY` | if the ledger uses it | Existing. Set it for the runner too; without it the digest's chain check verifies the hashes but skips the per-row HMAC. |

The runner must see the same database and the same ledger HMAC key as the
broker.

## Running it

```
node --experimental-strip-types scripts/vault-digest.ts
node --experimental-strip-types scripts/vault-digest.ts --from 2026-11-13
node --experimental-strip-types scripts/vault-digest.ts --from 2026-11-13T06:00:00Z --to 2026-11-13T18:00:00Z
```

- No arguments: the previous full UTC day.
- `--from` only: the 24 hours starting there. `--to` only: the 24 hours ending there.
- Dates are `YYYY-MM-DD` (UTC midnight) or an ISO time with `Z` or an offset.
  A time without a zone is refused.

It prints one JSON line and nothing else on stdout (logs go to stderr):

```
{"sent":true,"message_id":1234,"window":{"from":"2026-11-13T00:00:00.000Z","to":"2026-11-14T00:00:00.000Z"},"recorded":true}
{"sent":false,"reason":"already_sent","window":{...}}
{"sent":false,"reason":"telegram_failed","window":{...},"detail":"telegram_http_429"}
```

| Exit code | When |
| --- | --- |
| 0 | Sent, or `already_sent`. |
| 1 | Everything else: `telegram_failed`, `in_progress`, `build_failed`, `state_unavailable`, `invalid_window`, `usage`, `internal_error`. |

### Once per window

Each window is sent at most once. The runner claims the window in
`vault_digest_state` before building, marks it `sent` after Telegram accepts
the message, and deletes the claim if the build or the send fails — so a failed
run can simply be retried. A claim left by a crashed runner blocks retries with
`in_progress` for 10 minutes, then is taken over. If the state table cannot be
reached, nothing is sent (`state_unavailable`).

Because of this it is safe to schedule the runner more than once a day (for
example hourly) as a retry mechanism: extra runs answer `already_sent`.

`"recorded": false` on a successful send means Telegram accepted the message
but the database write failed afterwards. The window then stays claimed for 10
minutes; a run after that would send it a second time. Fix the database before
the next scheduled run, or mark the row by hand:

```sql
update vault_digest_state set status = 'sent', sent_at = now()
 where window_from = '2026-11-13T00:00:00.000Z' and window_to = '2026-11-14T00:00:00.000Z';
```

To deliberately re-send a window, delete its row first.

## Schedule examples

Run shortly after 00:00 UTC so the previous day is complete.

### cron (Linux)

```
# /etc/cron.d/echo-vault-digest — cron.d files accept CRON_TZ on most distributions
CRON_TZ=UTC
10 0 * * *  vault  cd /opt/echo-credential-broker && /usr/bin/node --experimental-strip-types scripts/vault-digest.ts >> /var/log/echo-vault-digest.log 2>&1
# optional retry: harmless when the window was already sent
10 1-6 * * *  vault  cd /opt/echo-credential-broker && /usr/bin/node --experimental-strip-types scripts/vault-digest.ts >> /var/log/echo-vault-digest.log 2>&1
```

If your cron has no `CRON_TZ`, convert 00:10 UTC to the server's local time.
The environment variables must be available to the cron user (for example an
`EnvironmentFile` wrapper script that exports them and then runs the command).

### Windows Task Scheduler

Task Scheduler triggers use local time, so convert 00:10 UTC (18:10 in
US Central Standard Time, 19:10 during daylight time) or leave the hourly retry
below to absorb the shift.

```powershell
$action  = New-ScheduledTaskAction -Execute "node.exe" `
             -Argument "--experimental-strip-types scripts\vault-digest.ts" `
             -WorkingDirectory "C:\echo\echo-credential-broker"
$trigger = New-ScheduledTaskTrigger -Daily -At 6:15PM
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
             -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName "ECHO Vault daily digest" `
  -Action $action -Trigger $trigger -Settings $settings
```

`-RestartCount` retries a run that exited 1. Set the environment variables for
the account the task runs as (System Properties, or a small `.cmd` wrapper that
sets them and then calls `node`). To check the last run:

```powershell
Get-ScheduledTaskInfo -TaskName "ECHO Vault daily digest" | Select LastRunTime, LastTaskResult
```

`LastTaskResult` 0 means sent or already sent.

## On demand: `admin_digest_now`

Owner-only MCP tool, available to the local stdio identity only. OAuth and
workload clients are refused (`tier3_human_only`), like every `admin_*` tool.

| Argument | Meaning |
| --- | --- |
| `from`, `to` | Optional window, same formats as the runner. Default: previous UTC day. |
| `send` | `true` also sends it on Telegram, under the same once-per-window rule. Default `false`. |

It returns `{ digest, text }` (the structured digest and the formatted
message) plus `send` (the runner's status object) when `send` is true. Each call
is itself recorded in the ledger as `vault.admin.digest`.

## Adding a section

`DigestDeps.extraSections` takes functions
`(window, deps) => Promise<{ title, lines }>`. They run after the built-in
sections and are rendered last, in order. Titles and lines are redacted and
clipped (10 sections, 20 lines each, 200 characters per line). A section that
throws is replaced by "Section unavailable" and never blocks the digest.

## Cost

Each digest reads the whole ledger once (to know which clients are new) and
verifies the whole chain once. On a very large ledger this is the slow part.
