# Echo Vault — connector

Invariant: **Agents may USE credentials. Agents may NEVER READ credentials.**

```
You → Grok / GPT / Claude
        → Echo Vault MCP  (/api/mcp or stdio)
        → vault://github/echoomegaprime  (opaque handle)
        → allowlisted provider (api.github.com, …)
```

There is no `get_secret`. Callers send `x-echo-agent: grok|chatgpt|claude`.

Full steps: [docs/INSTALL.md](./docs/INSTALL.md)
