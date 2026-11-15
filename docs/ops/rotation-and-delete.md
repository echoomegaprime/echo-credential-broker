# Vault v2: rotation and real delete

Operator notes for `src/lib/vault/v2/rotation.ts`, the rotation columns on
`vault_entries` (`migrations/0007_vault_entry_rotation.sql`) and the owner-only
admin tools. The invariant is unchanged: agents may **use** credentials, never
**read** them. Nothing described here returns, logs or ledgers a secret value.

## Environment variables

None are added. The runner uses the existing database and vault settings
(`DATABASE_URL` or `ECHO_VAULT_DATA_DIR`, and the gate vault configuration).

## Rotation state

Every entry carries (metadata only):

| Field | Meaning |
| --- | --- |
| `rotation_mode` | `manual` (default): the owner re-enters the secret on a card. `auto`: a provider rotator rolls it. |
| `rotate_interval_days` | 1..3650, or null for no schedule. |
| `last_rotated_at` | Last successful rotation. |
| `rotate_by` | Last rotation (or creation, if never rotated) + interval. Null = never due. |
| `rotation_count` | Successful rotations. |
| `last_rotation_error` | Short code of the last failed attempt. Cleared by a success. Never provider text. |
| `provider_token_id` | The provider's non-secret token ID. Never a token value (a value equal to the entry's own secret, or secret-shaped, is refused). |

A completed card **re-entry** of an existing entry counts as a manual rotation:
`last_rotated_at` = now, `rotation_count` + 1, `rotate_by` recomputed,
`last_rotation_error` cleared. A failed attempt never moves `rotate_by`.

Agents do not see these fields (`entry_list` / `entry_find` views are unchanged).

## Owner tools (local stdio identity only)

All four are `vault.admin.*` capabilities: tier 3, refused for every OAuth and
workload client. The agent-facing `credential_rotate` / `credential_revoke`
remain tier-3 stubs.

| Tool | Arguments | Result |
| --- | --- | --- |
| `admin_set_rotation` | `entry_id`, `mode`, `interval_days?`, `provider_token_id?` | `{ entry, auto_supported }` |
| `admin_rotate_entry` | `entry_id` | `{ entry, provider, warnings }` |
| `admin_rotation_due` | none | `{ entries }` |
| `admin_purge_entry` | `entry_id`, `confirm` = `PURGE <entry_id>` exactly | `{ purged, entry_id, site, account, secret_disposal, grants_removed, cards_removed }` |

Omitting `interval_days` or `provider_token_id` keeps the current value.
`mode: "auto"` needs an interval and is refused (`rotation_unsupported`) unless
a rotator supports the entry, so an entry never sits in `auto` with nothing able
to rotate it.

## Auto-rotation: Cloudflare API tokens

The one rotator shipped. An entry qualifies when its site is `cloudflare.com`
(or a subdomain), its kind is `api_key`, and `provider_token_id` is the token's
32-hex ID (dashboard: My Profile → API Tokens; it is not the token value).

Request made, verified on 2026-11-14 against the Cloudflare API reference
("User → API Tokens → Roll Token",
<https://developers.cloudflare.com/api/resources/user/subresources/tokens/subresources/value/methods/update/>):

```
PUT https://api.cloudflare.com/client/v4/user/tokens/{token_id}/value
Authorization: Bearer <current token>
Content-Type: application/json

{}
```

A 200 answers `{ "success": true, "result": "<new token value>" }`. Rolling
invalidates the previous value immediately and keeps the same permissions.

Requirements and limits:

- The token must be able to roll itself: it needs the **API Tokens Write**
  permission (User → API Tokens → Edit). Without it Cloudflare answers 403 and
  the entry records `provider_http_403`; the old token keeps working.
- Only **user-owned** tokens. Account-owned tokens
  (`/accounts/{account_id}/tokens/{token_id}/value`) are not implemented.
- Anything else stays `manual`: set an interval and it shows up in
  `admin_rotation_due` and in the runner's `needs_manual_rotation` count.

### Order of operations

1. Read the current secret (the same internal path `entry_use` uses).
2. Call the provider. A failure here keeps the old secret.
3. `put` the new secret into the vault — **before** any metadata changes.
   Retried 5 times with backoff (250 ms, doubling).
4. Update the metadata (fingerprint, length, rotation fields).
5. Ledger row.

One ledger row per attempt: capability `vault.entry.rotate`, result `ok` or
`error` with the short code. (Run through `admin_rotate_entry`, the gateway adds
its own `vault.admin.entries.rotate` row.)

### Error codes (`last_rotation_error`, ledger `error`)

| Code | Old token still valid? | What to do |
| --- | --- | --- |
| `provider_http_<status>` | Yes | Fix the cause (403: missing API Tokens Write; 401: the stored token is already invalid — re-enter it). |
| `provider_unreachable` | Almost certainly. If the request reached Cloudflare before the connection dropped, the token may have rolled; the next use would then get a 401 and the entry is flagged for re-entry. | Retry; if uses start failing, re-enter. |
| `rotation_unsupported` | Yes | No rotator matches the site, kind or token ID. |
| `entry_needs_reentry`, `entry_secret_missing`, `vault_unavailable` | Yes | Nothing was sent to the provider. |
| `rotation_in_progress` | Yes | Another rotation of this entry is running in this process. |
| `provider_returned_same_secret`, `rotator_failed` | Yes / unknown | Investigate the rotator. |
| **`rotated_but_not_stored`** | **No** | See below. |

Warnings (the rotation succeeded and the new secret is stored):
`metadata_update_failed` (fingerprint and schedule are stale; the entry still
works and will be picked up as due again) and `ledger_unavailable`.

### Worst case: `rotated_but_not_stored`

The provider has already rolled the token — the old value is dead — and the new
value could not be stored (every vault `put` attempt failed, or the provider
answered 2xx with nothing usable). The new value is **not** written anywhere
else: it is dropped. The broker then:

- logs `vault_entry_rotation_SECRET_LOST` at error level,
- flags the entry `needs_reentry`, so nothing keeps using the dead token,
- sets `last_rotation_error = rotated_but_not_stored` and writes a ledger
  `error` row with that code.

Recovery: roll the token again in the Cloudflare dashboard and type the new
value on a re-entry card (`entry_request_card` with the `entry_id`).

## Runner

```
node --experimental-strip-types scripts/vault-rotate-due.ts
```

Rotates every due `auto` entry that a rotator supports. stdout is one JSON line
of counts only:

```
{"due":2,"rotated":1,"failed":0,"warned":0,"needs_manual_rotation":1}
```

Exit code 1 when any rotation failed or finished with a warning, or when the run
could not start (`{"error":"<code>"}`); otherwise 0. Entry ids and codes are in
the stderr log and the ledger. Ledger rows from the runner carry
`client_id = local:rotate-due`.

Schedule it daily. cron:

```
17 4 * * *  cd /path/to/echo-credential-broker && node --experimental-strip-types scripts/vault-rotate-due.ts >> /var/log/vault-rotate.log 2>&1
```

Windows Task Scheduler: action `node`, arguments
`--experimental-strip-types scripts\vault-rotate-due.ts`, "Start in" the repo
directory.

Run it as the same user and with the same environment as the broker, so both
see the same database. Do not run two copies at once against one database: the
in-progress guard is per process.

## Real delete (purge)

`deleteEntry` (soft delete) is the reversible step: the row is marked `deleted`
and the secret is untouched. `admin_purge_entry` is the irreversible one and
works on active, flagged or soft-deleted entries.

Order:

1. Mark the entry deleted (no further uses). The row still points at the secret.
2. Destroy the secret. If the vault backend has a `delete`, call it and confirm
   the key is gone. The canonical gate vault has **no** delete, so there the
   stored value is **overwritten** with 64 random bytes (base64url) and read
   back to confirm the overwrite took.
3. Ledger row: capability `vault.entry.purge`, entry ref and
   `entry:<site>/<account>` — never the secret. If the ledger is down the purge
   stops here with `ledger_unavailable` and the row is kept.
4. Remove the entry's consent grants, its cards and the row.

A crash at any point leaves either a row that still points at the secret, or no
usable secret at all. Success is never reported before the secret is destroyed.
A failed purge (`vault_unavailable`, `purge_secret_not_destroyed`,
`ledger_unavailable`, `purge_cleanup_failed`) is safe to run again.

Limits to know about:

- With the gate vault, the key `echo_vault_entry_<id>` remains, holding random
  filler. Removing the key itself is a Vault A operation.
- The overwrite replaces the **current** value. If Vault A keeps earlier
  versions of a key, those are outside this broker's reach; this has not been
  verified against Vault A. Where it matters, revoke the credential at the
  provider as well — that is what actually kills a secret.
- Purge does not revoke anything at the provider.
- Ledger rows about the entry are kept (they hold no secret).
