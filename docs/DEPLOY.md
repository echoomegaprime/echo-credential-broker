# Deploy checklist — Echo Vault v2

Work top to bottom. Nothing here needs a secret pasted into a chat.

## 1. Database

- [ ] Create a Postgres database and set `DATABASE_URL`.
      The deployed server needs it: without it the built server has no working database, and OAuth, approvals, cards and the ledger fail.
- [ ] `npm run build` applies `migrations/*.sql`. To apply them on their own: `npm run db:migrate`.

  | Migration | What it adds |
  | --- | --- |
  | 0002 | OAuth clients, pending authorizations, tokens |
  | 0003 | Hash-chained ledger |
  | 0004 | Approvals |
  | 0005 | Entries and cards |
  | 0006 | Entry consent grants |
  | 0007 | Entry rotation state ([ops/rotation-and-delete.md](./ops/rotation-and-delete.md)) |
  | 0008 | Ledger anchor index ([ops/ledger-anchor.md](./ops/ledger-anchor.md)) |
  | 0009 | Digest sent-window state ([ops/daily-digest.md](./ops/daily-digest.md)) |
  | 0010 | Shared rate-limit state ([ops/rate-limits.md](./ops/rate-limits.md)) |
  | 0011 | Owner console: passkeys, challenges, sessions, bootstrap code ([ops/owner-console.md](./ops/owner-console.md)) |
  | 0012 | `cookie` entries: kind, jar metadata, length limit ([ops/cookie-entries.md](./ops/cookie-entries.md)) |
  | 0013 | Browser injector channel: injectors (public key, token hash) and inject tickets (hashes only) ([ops/injector-channel.md](./ops/injector-channel.md)) |

## 2. Telegram bot

- [ ] Create a bot with @BotFather. Put its token in `TELEGRAM_BOT_TOKEN`.
- [ ] Send the bot any message from your own account (a bot cannot message you first).
- [ ] Find your numeric user id (for example with @userinfobot). Put it in `ECHO_VAULT_APPROVER_TELEGRAM_ID`. Only this account can approve.
- [ ] Generate two random values and set them:
      `ECHO_VAULT_APPROVAL_HMAC_KEY` (32+ characters) and
      `ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET` (16–256 characters from `A-Z a-z 0-9 _ -`).
      For example: `openssl rand -base64 48 | tr -d '+/=' | cut -c1-48`.

## 3. Server environment

- [ ] `ECHO_VAULT_PUBLIC_URL` = the public https origin, no path (for example `https://credbroker.echo-op.com`).
- [ ] `ECHO_SDK_API_KEY` (and `ECHO_SDK_GATE_URL` if not the default) so the broker can reach the canonical vault.
- [ ] `ECHO_VAULT_LEDGER_HMAC_KEY` (32+ characters). Set it before the first request; keep it out of the database.
- [ ] `ECHO_VAULT_ANCHOR_KEY` (32+ characters) so ledger anchors are signed. Keep it out of the database.
- [ ] Leave `ECHO_VAULT_CONSOLE` (the legacy read-only page) unset on a public host.
- [ ] Owner console: `ECHO_VAULT_CONSOLE_ORIGIN` = the exact https origin the owner will open (for example `https://credbroker.echo-op.com`). Its hostname becomes the passkey RP ID, so choose it once. Leave it unset to keep `/console` off (503). Never set `ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST` on a deployed server.
- [ ] Optional: `ECHO_VAULT_DIGEST_DENIAL_BURST` (default 10).
- [ ] Optional: `ECHO_VAULT_POLICY_FILE`, `ECHO_VAULT_WORKLOAD_TOKENS_FILE`, the `ECHO_VAULT_GITHUB_*` variables. See `.env.example`.
- [ ] Optional consent-grant tuning: `ECHO_VAULT_GRANT_TTL_MS` (grant lifetime, default `86400000` = 24 h) and `ECHO_VAULT_GRANT_MAX_USES` (un-prompted reads per grant, default `500`; `unlimited` for no cap).
- [ ] Deploy (`npm run build`, then start the server the way your host does). On your own Node box: [ops/self-host.md](./ops/self-host.md).

## 4. Point Telegram at the server

- [ ] Register the webhook, with the secret (run where the two variables are set):

  ```bash
  curl -sS "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setWebhook" \
    -H 'content-type: application/json' \
    -d "{\"url\":\"https://YOUR-HOST/api/telegram/webhook\",\"secret_token\":\"${ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET}\",\"allowed_updates\":[\"callback_query\"],\"drop_pending_updates\":true}"
  ```

- [ ] Check it: `curl -sS "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getWebhookInfo"` shows the URL and no `last_error_message`.

## 5. Check the server

- [ ] `curl -i -X POST https://YOUR-HOST/api/mcp -d '{}'` → `401` with `WWW-Authenticate: Bearer resource_metadata="https://YOUR-HOST/.well-known/oauth-protected-resource"`.
- [ ] `curl https://YOUR-HOST/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server` → JSON with your origin.
- [ ] `curl -i -X POST https://YOUR-HOST/api/mcp -H 'x-echo-agent: claude' -d '{}'` → still `401`.

## 6. Connect the first client

- [ ] In Claude (Settings → Connectors → Add custom connector), ChatGPT or Grok, add `https://YOUR-HOST/api/mcp`.
- [ ] The browser shows "Approve this connection on your phone". Telegram shows the client's redirect host, the name it gave itself, and the scopes it wants. Approve only if all three are what you expect.
- [ ] In the client, call `vault_status`, then `entry_list`.
- [ ] Ask the client to request a card (`entry_request_card`). Open the link from Telegram, type the secret, then have the client call `entry_use`. Approve the first use on Telegram.
- [ ] Call `audit_verify` (needs `audit.read`) → `ok: true`.

## 7. Owner console

Full procedure: [ops/owner-console.md](./ops/owner-console.md).

- [ ] `curl -i https://YOUR-HOST/console/login` → `200` with a `Content-Security-Policy` header (a `503` means `ECHO_VAULT_CONSOLE_ORIGIN` is unset or malformed).
- [ ] On the vault host, over local stdio, call `admin_console_bootstrap`. The code in the result is valid for 15 minutes, once.
- [ ] Open `https://YOUR-HOST/console/enroll`, type the code and register a passkey. Sign in at `/console/login`.
- [ ] Add a second passkey on another device (Security page).
- [ ] If a proxy sits in front of the server, add a per-address rate limit for `/console/login/*` and `/console/enroll/*` there.

## 8. Scheduled runners

Each prints one JSON object and exits non-zero on failure. They need the same database and Telegram variables as the server.

- [ ] `npm run vault:anchor` hourly — [ops/ledger-anchor.md](./ops/ledger-anchor.md)
- [ ] `npm run vault:digest` daily — [ops/daily-digest.md](./ops/daily-digest.md)
- [ ] `npm run vault:rotate-due` daily — [ops/rotation-and-delete.md](./ops/rotation-and-delete.md)

Background reading: [ops/rate-limits.md](./ops/rate-limits.md), [ops/dns-pinning.md](./ops/dns-pinning.md), [ops/test-coverage.md](./ops/test-coverage.md).

## 9. Server-side services (optional)

- [ ] For each service, generate a token `ewk_` + 43 or more URL-safe characters. Give the token to the service only.
- [ ] Put its SHA-256 in the file named by `ECHO_VAULT_WORKLOAD_TOKENS_FILE`:
      `[{"sha256":"<64 hex>","client_id":"workload:<name>","name":"<display>","scopes":["vault.read"]}]`
- [ ] The service calls `POST /api/rest/tool` with `Authorization: Bearer ewk_…` and body `{"tool":"…","arguments":{…}}`.
      Services that used to send `x-echo-agent` (the SDK gate's HTTP handler) must be switched to a workload token; the header no longer does anything.

## Day two

- The **owner console** (`/console`, passkey sign-in) manages clients, grants, entries, the ledger and the digest. Its actions are ledgered under `owner:<id>`.
- From the **stdio transport (owner only)**, the same admin tools work as before: `admin_list_clients`, `admin_set_client_scopes`, `admin_revoke_client`, `admin_list_grants`, `admin_revoke_grant`, `admin_list_entries` and the rotation, anchor and digest tools. They are tier 3 and refused for every OAuth and workload client, and are fully ledgered under `local:<name>`. Stdio is also the break-glass path when every passkey is lost.
- The same operations are also plain functions: `revokeClient(client_id)` / `setClientScopes` (`src/lib/vault/v2/identity.ts`), and `revokeEntryGrant(client_id, entry_id, store?, host?, path_prefix?)` / `listEntryGrants` (`src/lib/vault/v2/entry-grants.ts`). A consent grant is now scoped to one host + path and expires; `admin_revoke_grant` (or `revokeEntryGrant`) with `host`/`path_prefix` removes one narrow grant, or all grants for the pair when omitted.
- The remote owner UI is the console above; there is no other one.
