# Install Echo Vault on Grok, GPT, and Claude

Repo: [echoomegaprime/echo-credential-broker](https://github.com/echoomegaprime/echo-credential-broker)

Clone once. Same broker, three clients. Secrets stay in env / the broker process. Chat never sees a PAT.

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
      "env": { "ECHO_AGENT": "grok" }
    }
  }
}
```

**Remote HTTP** (Grok custom connector):

- URL: `https://YOUR-HOST/api/mcp`
- Header: `x-echo-agent: grok`
- Copy [public/install/grok.json](../public/install/grok.json)

Probe: `vault_status` then `vault_list`. You should see `vault://` refs, never a token.

## 2. GPT (ChatGPT / Codex)

### GitHub app (code access)

1. Open [ChatGPT Codex Connector](https://github.com/apps/chatgpt-codex-connector/installations/new)
2. Grant **echoomegaprime/echo-credential-broker**

### Custom GPT Action

1. ChatGPT → GPTs → create / edit → **Actions**
2. Import OpenAPI from `public/install/chatgpt.openapi.json`
3. Server URL = your deployed origin
4. Auth: API key header `x-echo-agent` = `chatgpt`

### ChatGPT MCP / Developer Mode

- Connector URL: `https://YOUR-HOST/api/mcp`
- Header: `x-echo-agent: chatgpt`

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
      "env": { "ECHO_AGENT": "claude" }
    }
  }
}
```

Restart Claude Desktop. Tools appear as **echo-credential-broker**.

### Claude Code

From the cloned repo:

```bash
claude mcp add echo-credential-broker --env ECHO_AGENT=claude -- node --experimental-strip-types scripts/mcp-stdio.ts
```

Or rely on the committed [`.mcp.json`](../.mcp.json).

### Claude.ai / remote MCP

- URL: `https://YOUR-HOST/api/mcp`
- Header: `x-echo-agent: claude`

## Run the console

```bash
npm run dev      # HTTP console + POST /api/mcp
npm run mcp      # stdio MCP for desktop clients
npm test         # leak-probe + policy tests
```

Caller allowlist: `grok`, `chatgpt`, `claude`, `echo`, `echo-agent`, `echo-github-autonomy`, `vault-console`.

Forbidden on purpose: `get_secret`, `get_token`, `read_credential`, `export_vault`.
