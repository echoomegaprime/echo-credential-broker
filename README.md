# Echo Vault — credential broker MCP

**Agents may USE credentials. Agents may NEVER READ credentials.**

Opaque `vault://` handles. AES-GCM at rest. Fail-closed. No `get_secret` tool. stdout/MCP redaction armed.

Repo: [echoomegaprime/echo-credential-broker](https://github.com/echoomegaprime/echo-credential-broker)

## Install on Grok, GPT, Claude

Full steps → **[docs/INSTALL.md](./docs/INSTALL.md)**

| Client | Fast path |
| --- | --- |
| **Grok** | [Install GitHub app](https://github.com/apps/grok-by-xai/installations/new) · connector URL `/api/mcp` · header `x-echo-agent: grok` |
| **GPT** | [Install Codex connector](https://github.com/apps/chatgpt-codex-connector/installations/new) · import `public/install/chatgpt.openapi.json` |
| **Claude** | [Install Claude app](https://github.com/apps/claude/installations/new) · Desktop: merge `public/install/claude_desktop.json` · Code: `.mcp.json` |

```bash
git clone https://github.com/echoomegaprime/echo-credential-broker.git
cd echo-credential-broker
npm install
cp .env.example .env
npm run dev    # console + HTTP MCP
npm run mcp    # stdio MCP for Claude Desktop / Claude Code / Grok
```

## Tools (never return secrets)

`vault_status` · `vault_list` · `vault_metadata` · `credential_health` · `credential_use` · `provider_request` · `github_get_user` · `github_get_repository` · `github_get_file` · `github_list_repositories` · `github_create_branch` · `github_create_or_update_file` · `cloudflare_zone_get` · `openai_account_status` · `stripe_balance` · `xai_account_status` · `audit_list` · `credential_rotate` · `credential_revoke`

Allowlisted hosts only: `api.github.com`, `api.cloudflare.com`, `api.openai.com`, `api.stripe.com`, `api.x.ai`.

## Stack

TanStack Start · Vite · AES-256-GCM vault · MCP JSON-RPC (`/api/mcp` + stdio).

Echo Prime Technologies.
