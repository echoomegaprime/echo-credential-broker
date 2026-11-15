# Connectors — Grok, GPT, Claude

This repo is the shared source for Echo Vault. Chat clients are interchangeable. Raw secrets never leave the broker.

## GitHub apps (code)

| Model | Connector | Action |
| --- | --- | --- |
| Grok | [Grok (by xAI)](https://github.com/apps/grok-by-xai) | [Install](https://github.com/apps/grok-by-xai/installations/new) on `echo-credential-broker` |
| ChatGPT / Codex | [ChatGPT Codex Connector](https://github.com/apps/chatgpt-codex-connector) | [Install](https://github.com/apps/chatgpt-codex-connector/installations/new) on `echo-credential-broker` |
| Claude | [Claude](https://github.com/apps/claude) | [Install](https://github.com/apps/claude/installations/new) on `echo-credential-broker` |

## Runtime MCP (use credentials, never read them)

| Client | Transport | How it is identified |
| --- | --- | --- |
| Grok, ChatGPT, Claude.ai (remote) | HTTP `/api/mcp` | OAuth 2.1 access token; you approve the client on Telegram |
| Claude Desktop / Code, Codex CLI (local) | stdio `npm run mcp` | The local OS process; `ECHO_AGENT` only names it in the ledger |
| Server-side services | HTTP `/api/rest/tool` or `/api/mcp` | Workload token listed (hashed) in `ECHO_VAULT_WORKLOAD_TOKENS_FILE` |

Install walkthrough: [INSTALL.md](./INSTALL.md)
