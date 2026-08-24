# Security

Invariant: **Agents may USE credentials. Agents may NEVER READ credentials.**

- Never commit `.env`, connector token files, or PATs.
- Never add a `get_secret` / `read_credential` tool.
- Caller allowlist is fail-closed (`grok`, `chatgpt`, `claude`, `echo`, …).
- Provider calls are HTTPS-only to allowlisted hosts. Localhost and link-local are blocked.
- Responses, logs, and MCP payloads pass through redaction before they leave the process.
