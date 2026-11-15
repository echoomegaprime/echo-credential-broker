# Vault v2 ⇄ Lyra consent bridge: the second approval decider

Purpose: let **Lyra's consent bridge** — the service that already relays ECHO-side
consent prompts to Lyra — decide the two approval kinds that are pure consent
prompts, without impersonating the owner:

- **connection approvals** (`vault.client.authorize`, created by the OAuth
  `/authorize` flow in bootstrap.ts), and
- **first-use approvals** (`vault.entry.use.read`, the gateway's one-time
  per-(client, entry) consent before a first entry read).

The invariant, stated precisely for this channel: **a bridge decision is never
recorded as the owner.** The owner's path (Telegram callback → per-approval
HMAC MAC → approver's Telegram id) is untouched and stays the only way to
decide everything else. A bridge decision is written to the hash-chained audit
ledger — before it takes effect, exactly like an owner decision — under
`client_id` **`service:lyra-consent-bridge`** with capability
`vault.approval.decide`, and the approval record's `decided_by` carries the
same value. Owner decisions read `owner:telegram` / the approver's Telegram
id. The two are distinguishable in the ledger forever.

## Endpoint

```
POST /api/internal/approvals/decide
Authorization: Bearer <<redacted>
Content-Type: application/json

{ "approval_id": "<24-char id>", "action": "approve" | "deny" }
```

Responses (all `Cache-Control: no-store`, errors are `{ "ok": false, "error" }`
and nothing else):

| Case                                   | Status | Body / error code                                        |
| -------------------------------------- | ------ | -------------------------------------------------------- |
| decided                                | 200    | `{ ok: true, approval_id, status, decided_by }`          |
| missing / wrong token, or token unset  | 401    | `unauthorized` (the two cases are not distinguished)     |
| non-loopback origin (see below)        | 403    | `not_loopback`                                           |
| approval kind out of scope             | 403    | `out_of_scope` — no state change, no ledger row          |
| unknown approval id                    | 404    | `not_found`                                              |
| already decided                        | 409    | `not_pending`                                            |
| expired                                | 410    | `expired`                                                |
| malformed body / action                | 400    | `invalid_request`                                        |
| body over 4096 bytes                   | 413    | `request_too_large`                                      |
| ledger unavailable (nothing decided)   | 503    | `ledger_unavailable` — retrying is safe                  |
| non-POST                               | 405    | `method_not_allowed`                                     |

The endpoint decides **only** the two approval kinds above. It cannot create
or list approvals, read or write entries, or touch secrets — an approval id
for anything else (every tier-2 escalation, `vault.entry.inject`, …) is
refused `out_of_scope` and remains for the owner, still decidable by the
owner afterwards.

## Authentication and origin

Two independent controls, both fail closed:

1. **Service token.** `ECHO_VAULT_BRIDGE_DECIDER_TOKEN` (32+ characters),
   generated at deploy time, compared in constant time. It is registered for
   log redaction and never appears in a response. Unset or too short on the
   server → every call is 401. This token is a *separate* credential: it is
   not the owner's approval HMAC key, not a Telegram secret, not an OAuth or
   workload token, and none of those authenticate here.
2. **Loopback only.** The handler refuses any request whose URL host is not
   `localhost` / `127.0.0.1` / `[::1]`, and any request carrying proxy/tunnel
   forwarding headers (`cf-connecting-ip`, `cf-ray`, `x-forwarded-for`,
   `forwarded`). Route handlers in this stack see only a fetch `Request`, so
   this is the strongest origin check available at this layer — treat the
   token as the primary control and, at deploy time, keep
   `/api/internal/*` out of the public tunnel's ingress rules as well.

## Deploy checklist (owner/lead)

- [ ] Generate the token: `openssl rand -base64 48 | tr -d '+/=' | cut -c1-48`
- [ ] Set `ECHO_VAULT_BRIDGE_DECIDER_TOKEN` in the vault service's env file
      (same file as `ECHO_VAULT_APPROVAL_HMAC_KEY`) and restart the service.
- [ ] Hand the same value to the lyra-consent-bridge configuration on FORGE
      through the usual secret channel — never in chat, a ticket, or git.
- [ ] Confirm the public tunnel has no ingress rule exposing `/api/internal/*`.
- [ ] Smoke test from the vault host itself:
      `curl -sS -X POST http://127.0.0.1:<port>/api/internal/approvals/decide -H "Authorization: Bearer <redacted>" -d '{"approval_id":"AAAAAAAAAAAAAAAAAAAAAAAA","action":"approve"}'`
      → `404 not_found` (auth + loopback passed; the id does not exist).
      From any non-loopback host the same call must answer `403 not_loopback`.

## Revocation

Unset `ECHO_VAULT_BRIDGE_DECIDER_TOKEN` and restart the service: the endpoint
fails closed (401 for every call) and only the owner's Telegram path can
decide. Past bridge decisions remain on the ledger under
`service:lyra-consent-bridge`; nothing about them changes.
