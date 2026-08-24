# Connectors — Grok, GPT, Claude

This repo is the shared source for Echo Vault. Chat clients are interchangeable. Raw secrets never leave the broker.

## GitHub apps (code)

| Model | Connector | Action |
| --- | --- | --- |
| Grok | [Grok (by xAI)](https://github.com/apps/grok-by-xai) | [Install](https://github.com/apps/grok-by-xai/installations/new) on `echo-credential-broker` |
| ChatGPT / Codex | [ChatGPT Codex Connector](https://github.com/apps/chatgpt-codex-connector) | [Install](https://github.com/apps/chatgpt-codex-connector/installations/new) on `echo-credential-broker` |
| Claude | [Claude](https://github.com/apps/claude) | [Install](https://github.com/apps/claude/installations/new) on `echo-credential-broker` |

## Runtime MCP (use credentials, never read them)

| Client | Transport | Caller header / env |
| --- | --- | --- |
| Grok | HTTP `/api/mcp` or stdio | `x-echo-agent: grok` / `ECHO_AGENT=grok` |
| GPT | Custom GPT Action + MCP | `x-echo-agent: chatgpt` |
| Claude Desktop / Code | stdio `npm run mcp` | `ECHO_AGENT=claude` |

Install walkthrough: [INSTALL.md](./INSTALL.md)
