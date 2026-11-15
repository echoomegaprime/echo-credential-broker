# Security

Invariant: **Agents may USE credentials. Agents may NEVER READ credentials.**

- Never commit `.env`, connector token files, or PATs.
- Never add a `get_secret` / `read_credential` tool.
- Provider calls are HTTPS-only to allowlisted hosts. Localhost, private and link-local addresses are blocked.
- Responses, logs, and MCP payloads pass through redaction before they leave the process.

## v2 rules

- **Identity is authenticated, never asserted.** Remote callers present an OAuth access token issued after the owner approved the client, or a workload token whose hash the owner listed. `x-echo-agent`, `x-echo-caller` and every other caller-supplied identity are ignored. The stdio transport is trusted only as far as the OS user who started it; never bridge it to a network socket.
- **One gateway.** Every tool call on every transport goes through `dispatchTool` (`src/lib/vault/v2/gateway.ts`): policy, approval, action, ledger. Do not add a second path that executes a tool.
- **Tiers.** 0 read · 1 reversible write · 2 needs the owner's approval of that exact request · 3 never by an agent. A request the broker cannot classify (any non-GET through the generic proxy or `entry_use`) is tier 2.
- **Approvals are request-bound and single-use.** An approval covers one client, one capability, one resource and one set of parameters, for ten minutes, once. Only the configured Telegram user can decide.
- **Consent for entries (least privilege).** A read-only use runs without a prompt only under a matching grant scoped to that exact entry, host and request path (or a path under it). The first such read needs an approval, which creates a narrow grant that expires (`ECHO_VAULT_GRANT_TTL_MS`, default 24 h) and is use-capped (`ECHO_VAULT_GRANT_MAX_USES`, default 500). A sibling path, a different host, an expired or spent grant each re-prompt. Grants are revocable (`revokeEntryGrant` / `admin_revoke_grant`). Writes are approved every time and never consult or create a grant.
- **A 401 flags an entry, a 403 does not.** A 401 from the site means the credential was rejected: the entry is flagged for re-entry (`site_rejected_credential`). A 403 is a scope/rate problem, not a bad login: it returns `site_forbidden` and the entry stays active.
- **Owner-only admin tools.** `admin_list_clients`, `admin_set_client_scopes`, `admin_revoke_client`, `admin_list_grants`, `admin_revoke_grant`, `admin_list_entries` are tier 3 and allowed ONLY for the local stdio identity (the owner's own machine). Every remote OAuth/workload caller is denied. They are fully ledgered and never return a secret value.
- **An approved mutation is recorded before it runs.** For a mutating tool, the authorization is appended to the ledger as a `committing` row before the side-effect; if that cannot be written, the action does not run. The outcome is recorded afterwards as usual.
- **Secrets are typed by a human, on a card.** A card link is single-use, expires in 30 minutes and is sent only to the owner. Secrets are stored only in the canonical vault; the database holds metadata.
- **`entry_use` sends a secret only to its own site** (the site or `api.<site>`), over HTTPS, without following redirects, and returns a redacted body and no response headers.
- **Everything is ledgered.** Allowed, denied, pending and failed calls are appended to a hash-chained ledger (`audit_verify`). A result that cannot be ledgered is withheld. Set `ECHO_VAULT_LEDGER_HMAC_KEY`.
- **No reveal.** Nothing in this process returns a secret value — not a tool, not the web console. The console is off unless `ECHO_VAULT_CONSOLE=local`, is read-only, and must never be enabled on a publicly reachable host.
- **Fail closed.** Unknown tool, unknown capability, missing scope, unreadable policy file, unreachable approver, unwritable ledger: refuse.
