# Importing existing credentials

Cards are for one credential at a time. This is for the first load: every
credential already sitting in files on a node becomes a vault entry, without
anyone typing it and without the value appearing in any output.

It runs **on the node that holds the files**, as the vault's user, with the
vault's environment. Each node imports its own files.

## What it does

1. **Scan** (`scripts/credential-scan.mjs`) walks the roots you give it and
   writes a manifest of references: path, line, detector, the variable name, the
   length and a keyed fingerprint. No values.
2. **Preview** (`scripts/vault-import.ts`, no `--apply`) turns the manifest into
   a plan, reads each secret back to confirm it is still there, and writes a
   report. Nothing is stored.
3. **Import** (`--apply`) stores each secret in the vault backend, records the
   entry and writes one ledger row per entry (capability `vault.entry.import`).

A secret is read from its file and handed to the vault backend inside one
process. It is registered for redaction first. It is never printed, logged,
written to the report or returned.

## Run it

On the vault host (FORGE), from the app directory:

```bash
cd /mnt/storage/echo-vault-v2/app
set -a && . /home/forge/echo-vault-v2.env && set +a   # the env file the service unit loads
NODE=/home/forge/.nvm/versions/node/v22.23.1/bin/node  # the node the service runs on (22.6 or newer)
mkdir -p ~/vault-import && chmod 700 ~/vault-import

$NODE scripts/credential-scan.mjs --root /home/forge --out ~/vault-import/scan.json

$NODE --experimental-strip-types scripts/vault-import.ts \
  --manifest ~/vault-import/scan.json --report ~/vault-import/preview.json

$NODE --experimental-strip-types scripts/vault-import.ts \
  --manifest ~/vault-import/scan.json --report ~/vault-import/report.json --apply
```

Those paths are FORGE's. Elsewhere, use the `EnvironmentFile` and the node binary from
`systemctl cat echo-vault-v2.service`.

| Option | Effect |
| --- | --- |
| `--apply` | Store the entries. Without it the run is a preview. |
| `--include-generic` | Also import `KEY=value` findings whose variable name names a known service (for example `TWILIO_AUTH_TOKEN`). Off by default because these are guesses. |
| `--only-site <site>` | Repeatable. Import these sites only. |
| `--hmac-key-file <file>` | The node key the manifest was written with, if not the default `~/.echo-vault-scan/hmac.key`. |

## What you see

stdout is one line of counts:

```json
{"ok":true,"dry_run":false,"planned":41,"imported":38,"exists":0,"already_stored":2,"source_unreadable":1,...}
```

The report file (mode 0600, stays on the node) lists every planned entry with
its label, status and `path:line`, and every finding that was not imported with
the reason. It holds no secret value.

| Status | Meaning |
| --- | --- |
| `imported` | Stored. The entry is active. |
| `would_import` | Preview only: this would be stored. |
| `exists` | An entry with this site, account and kind is already there. |
| `already_stored` | Another entry of the same site and kind already holds this exact secret. |
| `source_unreadable` | The file or line no longer holds the secret the scan recorded. Scan again. |
| `secret_out_of_range` | Shorter than 8 or longer than 4096 characters. |
| `vault_unavailable` | The vault backend could not be reached. Nothing was stored for this entry. |
| `store_failed` | The entry row could not be written; the secret was taken back out of the backend. |

| Skipped finding | Why |
| --- | --- |
| `private_key_file` | A private key file, not a token. Not imported. |
| `vault_own_token` | One of the vault's own tokens. |
| `jwt_unattributed` | A JWT with no service attached; usually short-lived. |
| `url_credentials` | A password inside a URL. Enter it on a card with its real site and account. |
| `generic_not_requested` | A `KEY=value` guess; pass `--include-generic`. |
| `unknown_provider` | A `KEY=value` guess whose name does not identify a service. Use a card. |
| `provider_not_selected` | Outside `--only-site`. |

## Naming

- **Site** is the provider the scanner recognised (`github.com`, `google.com`, ...).
- **Account** is the variable the secret was assigned to, lower-cased
  (`YOUTUBE_API_KEY` → `youtube_api_key`). With no variable it is
  `imported-<8 hex>`.
- **Purpose** is `import <node>/<file>`.
- **Kind** is `api_key`.

Rename an entry afterwards from the owner console. The same secret found in
several files is one entry; the report lists every place it was found.

## Running it twice

Safe. Existing identities are `exists`, an identical secret is `already_stored`,
and one failed entry does not stop the rest.

## What it does not do

- It does not change or delete the source files. The credentials are still on
  disk afterwards; removing them is a separate, deliberate step.
- It does not grant any client the use of an imported entry. `entry_use` still
  needs the owner's consent per entry, host and path, exactly as for a
  card-entered entry.
- It does not import passwords, cookies, private keys or URL credentials. Those
  go through a card.
