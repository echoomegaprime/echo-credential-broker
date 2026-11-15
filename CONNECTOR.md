# Echo Vault — connector

Invariant: **Agents may USE credentials. Agents may NEVER READ credentials.**

```
You → Grok / GPT / Claude
        → OAuth access token (you approve the client on Telegram)
        → Echo Vault MCP  (/api/mcp, or stdio for a local client)
        → policy → approval if needed → action with the credential injected
        → site or provider API
```

There is no `get_secret`, and no caller header: a client is who its token says it is.

Full steps: [docs/INSTALL.md](./docs/INSTALL.md)
