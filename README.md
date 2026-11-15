# Echo Vault — credential broker MCP (v2)

**Agents may USE credentials. Agents may NEVER READ credentials.**

Agents ask for actions, not secrets. A client connects with OAuth, each tool call is judged by a policy engine, risky calls wait for the owner's tap on Telegram, the broker performs the action with the credential injected server-side, and every call lands in a hash-chained ledger. No tool, log line, ledger row or Telegram message carries a secret value.

Repo: [echoomegaprime/echo-credential-broker](https://github.com/echoomegaprime/echo-credential-broker)

## How a call is handled

```
client ──Bearer token──▶ /api/mcp ─▶ dispatchTool ─▶ policy ─┬─ deny      → ledger, refuse
(stdio: local process)                                       ├─ escalate  → Telegram approval, then retry with approval_id
                                                             └─ allow     → run with injected credential → ledger
```

There is no self-asserted caller any more: `x-echo-agent` and similar headers are ignored.

## Tiers

| Tier | Meaning | What happens | Examples |
| --- | --- | --- | --- |
| 0 | Read | Runs if the client holds the scope | `vault_list`, `github_get_file`, `entry_list`, `audit_list`, GET via `provider_request` |
| 1 | Reversible write, in scope | Runs if the client holds the scope | `github_create_branch`, file write on an `agent/*` branch, `github_create_draft_pr`, `entry_request_card` |
| 2 | Hard to undo, or unknown | `approval_required` → owner approves that exact request on Telegram → call again with `approval_id` (single use, 10 minutes) | `github_repo_transfer`, file write on any other branch, any non-GET via `provider_request` / `credential_use` / `entry_use` |
| 3 | Human only | Always refused (admin tools: allowed only for the local stdio owner) | reveal / rotate / revoke a secret, Stripe writes, any `get_secret`-like tool name, the `admin_*` tools for any remote client |

Scopes are `<namespace>.<read|write>`: `github.*`, `cloudflare.*`, `openai.*`, `xai.*`, `stripe.read`, `vault.read`, `vault.write`, `audit.read`. No scope implies another. The owner can tighten policy per client with `ECHO_VAULT_POLICY_FILE` (rules can only make things stricter).

## Credential entries and cards

A site can have several accounts (for example `github.com — echoomegaprime` and `github.com — bmcii1976`). Each is an **entry**: metadata in the database, the secret only in the canonical vault.

1. An agent that needs a credential calls `entry_request_card`. It gets a `card_id`, nothing else.
2. The owner gets a single-use link on Telegram (30 minutes), opens it and types the secret. It goes straight to the vault.
3. The agent calls `entry_use` with `{site, account, method, url_path, task}`. The broker makes one HTTPS request to that entry's own site (the site or `api.<site>`), injects the secret, and returns the status and a redacted body.
   - First read-only use of an entry by a client at a given host and path: one Telegram approval, remembered as a **narrow grant** scoped to that entry, host and path (and anything under it). Later GET/HEAD to that host at that path or under it run without a prompt, until the grant expires (`ECHO_VAULT_GRANT_TTL_MS`, default 24 h) or its uses run out (`ECHO_VAULT_GRANT_MAX_USES`, default 500). A sibling path, a different host, an expired or spent grant each prompt again. Revoke with `revokeEntryGrant(client_id, entry_id)` or the `admin_revoke_grant` tool.
   - Any other method: approved per request, every time; it never consults or creates a grant.
   - `api_key` / `oauth_token` entries are sent as a bearer token; `password` entries as HTTP Basic with the account name. There is no form login, cookie session or 2FA handling.
   - A **401** from the site flags that one entry for re-entry (`site_rejected_credential`); request a new card with its `entry_id`. A **403** returns `site_forbidden` and leaves the entry active (it is a scope/rate problem, not a bad credential).

The owner, on the stdio transport only, has admin tools: `admin_list_clients`, `admin_set_client_scopes`, `admin_revoke_client`, `admin_list_grants`, `admin_revoke_grant`, `admin_list_entries`. Every remote client is refused (tier 3).

## Connect a client (remote, OAuth)

1. Add `https://<your-host>/api/mcp` as a remote MCP server / custom connector in Claude, ChatGPT or Grok. No header, no API key.
2. The client discovers `/.well-known/oauth-protected-resource`, registers itself and opens the authorize page.
3. Approve the connection on Telegram. The first approval fixes the client's scopes.
4. The client now has a one-hour access token (refresh rotates). Revoke a client with `revokeClient(client_id)`.

Server-side services use a workload token instead (`ECHO_VAULT_WORKLOAD_TOKENS_FILE`) on `/api/mcp` or `/api/rest/tool`.

## Run locally (stdio)

```bash
git clone https://github.com/echoomegaprime/echo-credential-broker.git
cd echo-credential-broker
npm install
cp .env.example .env
npm run mcp      # stdio MCP; state persists in .vault-data/
npm run dev      # HTTP server on :8080
npm test         # all tests, no network
```

The stdio process is trusted as far as the OS user who started it. Its scopes come from `ECHO_VAULT_LOCAL_SCOPES` (default: read-only). Run one stdio process per data directory, or set `DATABASE_URL`.

## Environment

| Variable | Needed for | Purpose |
| --- | --- | --- |
| `ECHO_SDK_API_KEY` | everything | Server-only key for the canonical vault gate |
| `ECHO_SDK_GATE_URL` | optional | Vault gate URL |
| `DATABASE_URL` | deployed server | Postgres for OAuth clients, approvals, entries, grants and the ledger |
| `ECHO_VAULT_DATA_DIR` | optional | Directory for the embedded database when `DATABASE_URL` is unset (default `.vault-data` under plain node) |
| `ECHO_VAULT_PUBLIC_URL` | OAuth, cards | Public https origin of this server |
| `TELEGRAM_BOT_TOKEN` | approvals, cards | Bot that messages the owner |
| `ECHO_VAULT_APPROVER_TELEGRAM_ID` | approvals, cards | The owner's numeric Telegram user id |
| `ECHO_VAULT_APPROVAL_HMAC_KEY` | approvals | ≥ 32 chars; signs the Approve / Deny buttons |
| `ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET` | approvals | Secret Telegram echoes on every webhook call |
| `ECHO_VAULT_LEDGER_HMAC_KEY` | recommended | ≥ 32 chars; set before the first ledger row |
| `ECHO_VAULT_GRANT_TTL_MS` | optional | Lifetime of an entry consent grant in ms (default `86400000` = 24 h) |
| `ECHO_VAULT_GRANT_MAX_USES` | optional | Max un-prompted reads per consent grant (default `500`; `unlimited` for no cap) |
| `ECHO_VAULT_POLICY_FILE` | optional | JSON rules per client (allowlists, rate limits, raised tiers) |
| `ECHO_VAULT_WORKLOAD_TOKENS_FILE` | optional | Hashed tokens for server-side services |
| `ECHO_VAULT_LOCAL_SCOPES` | stdio | Comma list of scopes for the local client |
| `ECHO_AGENT` | stdio | Name of the local client in the ledger (`local:<name>`); grants nothing |
| `ECHO_VAULT_GITHUB_APP_ID_REF`, `ECHO_VAULT_GITHUB_APP_KEY_REF`, `ECHO_VAULT_GITHUB_INSTALLATIONS` | optional | GitHub App for short-lived installation tokens |
| `ECHO_VAULT_OAUTH_MAX_CLIENTS`, `ECHO_VAULT_OAUTH_MAX_PENDING` | optional | Registration limits |
| `ECHO_VAULT_CONSOLE` | optional | `local` enables the read-only web console. Only on a private host |
| `ECHO_VAULT_MIGRATIONS_DIR`, `ECHO_VAULT_DEBUG` | optional | Migrations path override; debug logging |

Deployment checklist: [docs/DEPLOY.md](./docs/DEPLOY.md). Client setup: [docs/INSTALL.md](./docs/INSTALL.md). Security rules: [SECURITY.md](./SECURITY.md).

## Stack

TanStack Start · Vite · Postgres / PGlite · MCP JSON-RPC (`/api/mcp` Streamable HTTP + stdio).

Echo Prime Technologies.
