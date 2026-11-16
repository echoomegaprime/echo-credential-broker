# `entry_transfer`: hand a stored credential to another service

`entry_transfer` lets an agent copy one stored credential into another service
without ever seeing it. Example: store your xAI API key as a secret inside
your ElevenLabs workspace, by calling ElevenLabs' API.

Code: `src/lib/vault/v2/entry-transfer.ts` (argument checks, body building) and
`entryTransferPlan` in `src/lib/vault/v2/gateway.ts`. Tests:
`src/lib/vault/v2/entry-transfer.test.ts`.

## What it does

It uses two entries in one request:

- The **destination** entry authenticates one HTTPS request to its own site
  (the site or `api.<site>`), the same way `entry_use` would.
- The **source** entry's secret is put into one field of the JSON body. The
  agent marks that field with the placeholder `{{vault:source}}`; the broker
  replaces it server-side just before sending.

The agent gets back the HTTP status and the response body, with both secrets
redacted. It never gets a response header.

## Input

```
entry_transfer {
  from_site: "x.ai", from_account: "<label>",
  to_site: "elevenlabs.io", to_account: "<label>",
  method: "POST", host: "api.elevenlabs.io", url_path: "/v1/convai/secrets",
  to_auth: { scheme: "header", name: "xi-api-key" },
  body: { type: "new", name: "XAI_API_KEY", value: "{{vault:source}}" },
  task: "Store the xAI key as an ElevenLabs agent secret for the Bree agent"
}
```

> The ElevenLabs endpoint path and body shape in this example are
> **illustrative**. Check them against ElevenLabs' current API reference
> before use. The broker does not know any service's API; it sends what the
> agent asks for, once you approve it.

| Argument | Meaning |
| --- | --- |
| `from_site`, `from_account`, `from_kind` | The source entry (the credential being handed over). Must be an `api_key` or `oauth_token` entry. `from_account` defaults to the site's default entry. |
| `to_site`, `to_account`, `to_kind` | The destination entry (the service that receives it). Must be `api_key`, `oauth_token` or `password`. |
| `method` | `POST`, `PUT` or `PATCH`. |
| `host` | Exactly the destination site or `api.<site>`. Default: the site. |
| `url_path` | Path and query on the destination, starting with `/`. |
| `body` | A JSON object. Exactly one string field, at any depth (arrays included), must have the value `{{vault:source}}`. |
| `to_auth` | Optional. Omit it and the destination secret is sent as `entry_use` sends it (`api_key` / `oauth_token`: bearer token in the Authorization header; `password`: HTTP Basic with the account). `{ "scheme": "header", "name": "<header-name>" }` sends it as that request header **instead of** the Authorization header (only for `api_key` / `oauth_token` destinations). |
| `task` | What the agent is doing and why. Shown to you and recorded. |

The source and the destination must be different entries.

## What you approve

Every call needs your approval on Telegram. There is no standing grant: a
second, identical call asks again. The first call returns `approval_required`;
the agent calls again with the same arguments plus `approval_id`.

The prompt's summary line reads:

```
TRANSFER the secret of "x.ai — <label> — <purpose>" into POST https://api.elevenlabs.io/v1/convai/secrets, JSON field value, authenticated as "elevenlabs.io — <label> — <purpose>", sent in header xi-api-key. elevenlabs.io will receive and may store this secret. Task: Store the xAI key as an ElevenLabs agent secret for the Bree agent
```

The prompt's `Action` line is `vault.entry.transfer` and its `Resource` line
names both entries. The JSON field is shown as a path (`value`,
`config.keys[0].secret`). The rest of the body is not shown; it is bound to
the approval by its hash.

The approval is tied to both entries, the method, host and path, the body
(with the placeholder still in it), the field, the auth header and the task.
Changing any of them needs a new approval.

## What the destination holds afterwards

After a successful transfer the destination service has a copy of the source
secret, and may keep it. From then on that copy is outside the vault:

- Rotating or deleting the source entry here does not change the copy. Rotate
  the key at its issuer and transfer it again, or delete it at the destination.
- Anyone who can read stored secrets in the destination account can read it.
  That includes an agent, **if** the destination's API returns secret values
  and you approve an `entry_use` read of that endpoint. Values the broker has
  loaded since it started are redacted from responses; after a restart, a
  value it has not loaded again is not. Before you approve a transfer, check
  that the destination does not hand stored secrets back through its API.

## What is recorded

- Ledger, capability `vault.entry.transfer`: `pending_approval`, then (after
  your decision, which has its own `vault.approval.decide` row) `committing`,
  written before anything is sent, then one row per entry. Each of those two
  rows carries that entry's `vault://entry/…`
  reference, both entry ids, the method, host and path, the JSON field and the
  HTTP status. No body, no secret.
- A transfer that ran therefore shows as two tier-2 rows in the daily digest
  (one per entry used).
- Both entries' last-used time is updated.
- If the destination entry cannot be used, or the request fails, the source
  entry's row is an error (`transfer_failed: <code>`), never `ok`.

## Results and errors

| Result | Meaning |
| --- | --- |
| `ok`, `status`, `body` | The request was sent. Check `status`: a 4xx/5xx other than 401/403 is returned as is. |
| `site_rejected_credential` | The destination answered 401. The **destination** entry is flagged for re-entry. The source entry is never flagged by the destination's answer. |
| `site_forbidden` | The destination answered 403. Neither entry is flagged. |
| `invalid_arguments` | Bad placeholder use, body not a JSON object, bad `to_auth`, method not POST/PUT/PATCH, same entry on both sides. Nothing was sent and no approval was asked for. |
| `entry_kind_not_transferable` / `entry_kind_not_usable` | The source / destination entry is of a kind that cannot be used here. |
| `hostname_not_allowed` | `host` is not the destination site or `api.<site>`, or is not reachable through the broker. |
| `missing_scope` | The client lacks `vault.write`. Neither entry is looked up. |
| `entry_use_failed`, `entry_needs_reentry`, … | An entry could not be used or the request failed. `failed_entry` says which side; `request_sent` is `true` (a response was read), `false` (nothing left the broker) or `"unknown"` (the connection was opened but no response was read: a timeout, a disconnect or an oversized answer). Treat `"unknown"` as "the destination may hold the secret": check there before retrying. |

## Limits

- JSON bodies only. No form bodies, no query-string or header placement of
  the source secret.
- One placeholder: the entire value of exactly one string field. Not part of a
  longer string (`"Bearer {{vault:source}}"` is refused), not an object key.
- `POST`, `PUT` or `PATCH` only.
- Per-call approval, always.
- Source entries: `api_key` and `oauth_token`. Cookie, password and
  operator-secret entries cannot be transferred.
- Same transport rules as `entry_use`: HTTPS only, DNS-pinned
  ([dns-pinning.md](./dns-pinning.md)), no redirects followed, 256 KiB request
  and 1 MiB response limits, 12 s timeout.
- Redaction of the response covers the source secret as sent, URL-encoded,
  base64 (padded or not), base64url and JSON-escaped, and the destination
  secret as `entry_use` covers it. A destination that returns the secret
  transformed in some other way (hex, truncated, split) is not caught.
