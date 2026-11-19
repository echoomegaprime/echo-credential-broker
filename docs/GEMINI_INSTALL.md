# Install Echo Vault for Gemini

Repo: [echoomegaprime/echo-credential-broker](https://github.com/echoomegaprime/echo-credential-broker)
Live broker: `https://credbroker.echo-op.com` — MCP endpoint `https://credbroker.echo-op.com/api/mcp`

Same broker as Grok, GPT, and Claude (see [INSTALL.md](./INSTALL.md)). Secrets stay in the
canonical vault. Chat never sees one: agents may **use** credentials, they may **never read**
them. There is no `get_secret`-style tool, and none will be added.

> **Status: UNTESTED on the Gemini side.** The broker side of everything below is live and
> verified (metadata, persistent registration, owner approval flow — the same flow other
> seats connected with). The Gemini-side steps are correct against Gemini CLI / Gemini Apps
> as documented, but no Gemini client has completed a live connection yet. The Gemini seat
> runs the first live connect.

## How identity works (read this before debugging auth)

There is **no caller header**. The broker deliberately ignores self-asserted headers such as
`x-echo-agent` — a header anyone can type proves nothing, and the test suite enforces that
ignoring it (`src/lib/vault/v2/identity.ts`). Identity comes only from credentials the
broker issued:

- **Remote (HTTP):** the OAuth 2.1 access token. The token resolves to the client that
  registered via Dynamic Client Registration (RFC 7591); the `client_name` given at
  registration is the identity the owner sees and the ledger records. Register as a name
  that says who you are (e.g. `gemini-cli`, `gemini-apps`).
- **Local (stdio):** the OS process boundary. `ECHO_AGENT` in the server env only *names*
  the local client in the ledger (`local:gemini-cli`); it grants nothing. Scopes come from
  `ECHO_VAULT_LOCAL_SCOPES` and default to read-only.

### Why Gemini will not hit an "unknown client" error

The `invalid_request` / unknown-client failure mode — a `client_id` the authorization
server no longer recognizes — happens when registered clients are kept in process memory
and wiped on restart. That cannot happen here:

- Registered clients, authorization codes, and tokens are stored in SQL
  (`vault_oauth_clients`, `vault_oauth_pending`, `vault_oauth_codes`, `vault_oauth_tokens`;
  migration `migrations/0002_vault_oauth.sql`). The production store is `SqlOAuthStore`
  (`src/lib/vault/v2/oauth-store.ts`); the in-memory store exists only in tests and dev.
- Only token/code *hashes* are persisted (sha256, enforced by CHECK constraints), so the
  database can never be replayed as a credential.
- Metadata is served at `/.well-known/oauth-authorization-server` (RFC 8414) and
  `/.well-known/oauth-protected-resource` (RFC 9728), advertising the registration
  endpoint and `S256` PKCE — the only code-challenge method and the only token-endpoint
  auth method (`none`, public clients) the broker accepts.
- Real scopes are `vault.read`, `vault.write`, `audit.read` plus the provider scopes
  (`github.*`, `cloudflare.*`, `openai.*`, `stripe.read`, `xai.*`). There is no
  `vault:use` scope; a client asking for one is rejected at registration/authorize time.

One approval wrinkle: a newly registered client starts unapproved. The first authorize
request raises a `vault.client.authorize` approval and the **owner approves the client on
Telegram** (name, redirect host, and requested scopes are shown). Until then the flow
waits — that pause is the design, not an error.

## 1. Gemini CLI

Merge [`public/install/gemini_cli.json`](../public/install/gemini_cli.json) into
`~/.gemini/settings.json`. It contains two servers; enable either or both:

- `echo-vault-remote` — the live broker over HTTPS with OAuth. Nothing to clone.
- `echo-vault-local` — the stdio server from a local clone (`npm run mcp`,
  `scripts/mcp-stdio.ts`). Replace the `cwd` placeholder with your clone path, same
  convention as `public/install/claude_desktop.json`. The stdio server also needs the
  broker's normal local configuration (see `.env.example`); without `ECHO_SDK_API_KEY`
  it starts but every tool call fails closed.

```json
{
  "mcpServers": {
    "echo-vault-remote": {
      "httpUrl": "https://credbroker.echo-op.com/api/mcp",
      "oauth": { "enabled": true }
    },
    "echo-vault-local": {
      "command": "node",
      "args": ["--experimental-strip-types", "scripts/mcp-stdio.ts"],
      "cwd": "/ABSOLUTE/PATH/TO/echo-credential-broker",
      "env": { "ECHO_AGENT": "gemini-cli" }
    }
  }
}
```

Then:

1. Restart Gemini CLI.
2. Run `/mcp` — `echo-vault-remote` and/or `echo-vault-local` should list as servers.
3. Run `/mcp auth` for the remote server and complete the OAuth flow. On first connect
   the owner gets the Telegram approval described above; approve it, then finish the
   consent in the browser.
4. Probe with `vault_status`, then `entry_list`. You should see status and entry
   metadata — never a token value.

## 2. Gemini Apps (Developer Mode)

1. Open Gemini Apps → Developer Mode → **Choose an app** → **+ Create new**.
2. Enter the MCP endpoint: `https://credbroker.echo-op.com/api/mcp`.
3. Complete the OAuth consent once. Gemini registers itself as a client (DCR); the owner
   approves that client on Telegram on first connect, as above.
4. In Developer Mode, check the **Event Log** and **Tool Schemas** tabs: Gemini should
   discover the vault tools and receive clean JSON-RPC 200 responses — no
   `invalid_request` errors, and no tool that returns a secret.

Optional pre-check with MCP Inspector against the same URL:
`npx @modelcontextprotocol/inspector https://credbroker.echo-op.com/api/mcp` —
`initialize` and `tools/list` should succeed after the OAuth flow, tool names are
snake_case, and calling a tool with a `vault://` handle returns redacted output only.

## 3. Verification checks (broker side, runnable today)

Metadata — both must return HTTP 200 with the registration endpoint and S256:

```bash
curl -s https://credbroker.echo-op.com/.well-known/oauth-authorization-server | jq .
curl -s https://credbroker.echo-op.com/.well-known/oauth-protected-resource | jq .
```

Expect `registration_endpoint: "https://credbroker.echo-op.com/api/oauth/register"` and
`"code_challenge_methods_supported": ["S256"]` in the first document.

No-header invariant — a self-asserted agent header alone must still be rejected:

```bash
curl -i -X POST https://credbroker.echo-op.com/api/mcp -H 'x-echo-agent: gemini' -d '{}'
# → 401
```

Registration persistence — the property that rules out the unknown-client error. On a
dev instance: `POST /api/oauth/register` a test client, restart the server, then start
`/api/oauth/authorize` with that `client_id` — it must be recognized (owner-approval
flow), not rejected as unknown. In production this is already proven by design (SQL
store) and by other seats' clients surviving broker restarts.

## Troubleshooting

- **Flow stalls after consent:** the client is waiting on the owner's Telegram approval
  (`vault.client.authorize`). Ask the owner; do not re-register in a loop — duplicate
  clients just create more approvals.
- **`invalid_client` / unknown client at the token endpoint:** the `client_id` was never
  registered against this broker, or the client was revoked/denied in the owner console.
  Re-register once and complete the approval.
- **Tools list but every call fails closed (local stdio):** `ECHO_SDK_API_KEY` is not
  configured for the stdio process. It warns about this on stderr at startup.
