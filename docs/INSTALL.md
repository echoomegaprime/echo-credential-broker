# Install Echo Vault on Grok, GPT, and Claude

Repo: [echoomegaprime/echo-credential-broker](https://github.com/echoomegaprime/echo-credential-broker)

Clone once. Same broker, three clients. Secrets stay in the canonical vault. Chat never sees one.

Remote clients authenticate with OAuth: add the URL, and approve the connection on Telegram when asked. There is no caller header.

```bash
git clone https://github.com/echoomegaprime/echo-credential-broker.git
cd echo-credential-broker
npm install
cp .env.example .env   # fill keys locally — do not paste them into any model
```

## 1. Grok (xAI)

### GitHub app (code access to this repo)

1. Open [Grok (by xAI)](https://github.com/apps/grok-by-xai/installations/new)
2. Grant **echoomegaprime/echo-credential-broker**
3. In Grok: connect GitHub if it is not already on this account

### MCP (use vault tools in chat)

**Local stdio** (Grok Desktop / MCP config):

```json
{
  "mcpServers": {
    "echo-credential-broker": {
      "command": "node",
      "args": ["--experimental-strip-types", "scripts/mcp-stdio.ts"],
      "cwd": "/ABSOLUTE/PATH/TO/echo-credential-broker",
      "env": { "ECHO_AGENT": "grok-desktop" }
    }
  }
}
```

**Remote HTTP** (Grok custom connector):

- URL: `https://YOUR-HOST/api/mcp`
- Authentication: OAuth (the connector registers itself; approve it on Telegram)
- Reference: [public/install/grok.json](../public/install/grok.json)

Probe: `vault_status` then `entry_list`. You should see metadata, never a token.

## 2. GPT (ChatGPT / Codex)

### Private ECHO Vault plugin

The ChatGPT plugin package lives in [plugins/echo-vault](../plugins/echo-vault/).
Connect it to the hosted broker and approve the ChatGPT client on Telegram.
The plugin requests `vault.read`. Check the connection with `vault_status`.
Use `vault_find` to locate a named account and `credential_health` to check a supported provider using its opaque reference.

### GitHub app (code access)

1. Open [ChatGPT Codex Connector](https://github.com/apps/chatgpt-codex-connector/installations/new)
2. Grant **echoomegaprime/echo-credential-broker**

### Custom GPT Action

1. ChatGPT → GPTs → create / edit → **Actions**
2. Import OpenAPI from `public/install/chatgpt.openapi.json`
3. Server URL = your deployed origin
4. Auth: OAuth (authorization and token URLs are in the OpenAPI file)

### ChatGPT MCP / Developer Mode

- Connector URL: `https://YOUR-HOST/api/mcp`
- Authentication: OAuth; approve the connection on Telegram

Codex CLI (project root):

```bash
# uses .mcp.json in this repo
codex mcp list
```

## 3. Claude (Desktop, Code, Cowork)

### GitHub app (code access)

1. Open [Claude](https://github.com/apps/claude/installations/new)
2. Grant **echoomegaprime/echo-credential-broker**

### Claude Desktop

Edit `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "echo-credential-broker": {
      "command": "node",
      "args": ["--experimental-strip-types", "scripts/mcp-stdio.ts"],
      "cwd": "/ABSOLUTE/PATH/TO/echo-credential-broker",
      "env": { "ECHO_AGENT": "claude-desktop" }
    }
  }
}
```

Restart Claude Desktop. Tools appear as **echo-credential-broker**.

### Claude Code

From the cloned repo:

```bash
claude mcp add echo-credential-broker --env ECHO_AGENT=claude-code -- node --experimental-strip-types scripts/mcp-stdio.ts
```

Or rely on the committed [`.mcp.json`](../.mcp.json).

### Claude.ai / remote MCP

- URL: `https://YOUR-HOST/api/mcp` (Settings → Connectors → Add custom connector)
- Authentication: OAuth; approve the connection on Telegram

## Local (stdio) clients

`ECHO_AGENT` is only the name the local client gets in the ledger (`local:<name>`). It grants nothing. What a local client may do is set by `ECHO_VAULT_LOCAL_SCOPES` (comma list; default read-only: `github.read,cloudflare.read,vault.read`). Tier 2 actions still ask on Telegram.

State (ledger, approvals, entries, grants) is kept in `.vault-data/` unless `DATABASE_URL` or `ECHO_VAULT_DATA_DIR` is set. Only one process can open that directory at a time; to run Claude Desktop and Claude Code side by side, point both at one Postgres with `DATABASE_URL`.

## Run

```bash
npm run dev      # HTTP server: /api/mcp, OAuth, cards, Telegram webhook
npm run mcp      # stdio MCP for desktop clients
npm test         # all tests; no network, no real vault
```

Server setup (Telegram bot, webhook, env): [DEPLOY.md](./DEPLOY.md).

Forbidden on purpose: `get_secret`, `get_token`, `read_credential`, `export_vault`, and anything else that would return a secret.
