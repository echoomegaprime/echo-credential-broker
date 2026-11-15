# Vault v2 tool test coverage

Audit date: 2026-11-14. Scope: every tool in `TOOL_DEFINITIONS`
(`src/lib/vault/v2/gateway.ts`, 33 tools).

"Offline" means a test dispatches the tool through `dispatchTool` (directly, or
through the MCP / REST handlers that call it) with fakes and no network. A test
that only mentions the tool name, or tests the function underneath it, does not
count. "Live" means an opt-in test that runs the tool against the real provider.

- **yes** — the tool runs to a result (success and failure paths).
- **denial only** — the tool is dispatched, but only ever refused before it runs
  (missing scope, bad arguments, tier 3, approval prompt).
- **no** — never dispatched.

## Coverage table

| Tool | Offline before | Offline after | Live before | Live after |
| --- | --- | --- | --- | --- |
| vault_status | yes | yes | no | no |
| vault_list | yes | yes | no | no |
| vault_find | no | yes | no | no |
| vault_metadata | denial only | yes | no | no |
| credential_health | yes (fail-closed path) | yes (fail-closed path) | yes | yes |
| github_get_user | denial only | yes | no | yes |
| github_get_repository | denial only | yes | yes | yes |
| github_get_file | no | yes | no | no |
| github_list_repositories | no | yes | no | yes |
| github_create_branch | no | yes | no | no (write) |
| github_create_or_update_file | yes | yes | no | no (write) |
| github_create_draft_pr | no | yes | no | no (write) |
| github_repo_transfer | yes | yes | no | no (write) |
| cloudflare_zone_get | no | yes | no | yes |
| openai_account_status | no | yes | no | yes |
| xai_account_status | no | yes | no | yes |
| stripe_balance | no | yes | no | yes |
| credential_use | denial only | yes | no | no |
| provider_request | denial only | yes | no | yes (GET only) |
| entry_list | yes | yes | no | no |
| entry_request_card | yes | yes | no | no |
| entry_card_status | yes | yes | no | no |
| entry_use | yes | yes | no | no |
| approval_status | yes | yes | no | no |
| audit_list | yes | yes | no | no |
| audit_verify | yes | yes | no | no |
| admin_list_clients | yes | yes | no | no |
| admin_set_client_scopes | yes | yes | no | no |
| admin_revoke_client | yes | yes | no | no |
| admin_list_grants | yes | yes | no | no |
| admin_revoke_grant | yes | yes | no | no |
| admin_list_entries | yes | yes | no | no |
| credential_rotate | yes (always refused) | yes (always refused) | no | no |
| credential_revoke | yes (always refused) | yes (always refused) | no | no |

Where the "before" tests live: `src/lib/vault/v2/gateway.test.ts` and
`src/lib/vault/acceptance.test.ts` (the only live block before this change:
`credential_health` and `github_get_repository`).

Totals: offline "yes" went from 19 of 33 to 33 of 33. Live went from 2 tools to 8.

## New test files

### `src/lib/vault/v2/provider-tools.test.ts` (offline)

Runs with `npm run test:vault`. The vault is a `FakeVaultBackend`; the provider
is `globalThis.fetch`, replaced for that file's process by a recorder. For
`github_get_user`, `github_get_repository`, `github_get_file`,
`github_list_repositories`, `github_create_branch`, `cloudflare_zone_get`,
`openai_account_status`, `xai_account_status`, `stripe_balance`,
`credential_use` and `provider_request` it checks:

- the request sent: method, exact URL, `Authorization: Bearer <credential>`,
  `Accept`, GitHub's API version header, body, and `redirect: "error"`;
- the result shape on success;
- provider 401, 403, 429, 500, 503, a network error and a non-JSON 2xx body:
  a stable error code, no stack trace, no credential;
- capability, tier and scope against the policy registry;
- one ledger row per call with the right capability, decision, tier, result,
  credential reference and HTTP status;
- a provider body that echoes the credential is redacted (success, error and
  plain-text bodies);
- a client without the scope is denied with no network call; so is a missing
  credential, and another provider's `vault://` reference.

It also covers `github_create_draft_pr`, `vault_find`, `vault_metadata`, the
generic proxy's write path (scope, approval, single use, body binding, Stripe
tier 3) and its path checks (absolute URLs, traversal, other hosts).

### `src/lib/vault/v2/provider-tools.live.test.ts` (live, opt-in, read-only)

Also matched by the `test:vault` glob. With no opt-in every live test reports
as skipped and the file makes no network call; its last test asserts that.

A live test runs only when **all** of these are set:

| Variable | Meaning |
| --- | --- |
| `ECHO_VAULT_LIVE_TESTS=1` | Master switch (same one `acceptance.test.ts` uses). |
| `ECHO_SDK_API_KEY` | Vault gate credential. Only its presence is checked. |
| `ECHO_VAULT_LIVE_GITHUB=1` | `github_get_user`, `github_list_repositories`, `provider_request GET /rate_limit` |
| `ECHO_VAULT_LIVE_CLOUDFLARE=1` | `cloudflare_zone_get` |
| `ECHO_VAULT_LIVE_OPENAI=1` | `openai_account_status` |
| `ECHO_VAULT_LIVE_XAI=1` | `xai_account_status` |
| `ECHO_VAULT_LIVE_STRIPE=1` | `stripe_balance` |

Only the exact value `1` opts in. One provider's switch never enables another.

Optional, none of them secret:

| Variable | Meaning |
| --- | --- |
| `ECHO_VAULT_LIVE_<PROVIDER>_REF` | A `vault://<provider>/<account>` reference to use instead of the tool's default. |
| `ECHO_VAULT_LIVE_CLOUDFLARE_ZONE_ID` | Zone to read. Without it the test lists one zone with `provider_request GET /client/v4/zones?per_page=1` and reads that. |

Example (GitHub only):

```sh
ECHO_VAULT_LIVE_TESTS=1 ECHO_VAULT_LIVE_GITHUB=1 \
  node --experimental-strip-types --test src/lib/vault/v2/provider-tools.live.test.ts
```

What the live tests guarantee:

- **Read-only.** Only the seven tools above are dispatched, each client holds
  `<provider>.read` and nothing else, and every provider request is a GET.
- **The credential is never shown.** It is read by the vault's own path (the
  default `CredentialStore`). The test resolves the value in process only to
  assert it is absent from the tool result, the ledger rows and everything
  logged; assertion messages are fixed text.
- Each test asserts an `ok` result, a plausible shape, and one ledger row per call.

The live suite has not been run as part of this change (no opt-in was set).

## Fixes made while writing these tests

1. **Provider 4xx/5xx was reported as success** (`gateway.ts`, `fromV1`).
   `cloudflare_zone_get`, `openai_account_status`, `xai_account_status`,
   `stripe_balance`, `github_create_branch`, `credential_use` and
   `provider_request` returned `ok: true` with `data.status: 401` while the
   ledger row for the same call said `error`. They now return `ok: false` with
   `provider_rejected_credential` (401), `provider_forbidden` (403),
   `provider_rate_limited` (429), `provider_unavailable` (5xx) or
   `provider_http_error` (other 4xx), plus `status`, the provider's redacted
   error `body` and `credential_ref`. MCP `isError` follows.
2. **GitHub readers turned an error into empty data** (`providers.ts`). On a
   404 or 401, `github_get_repository` returned `ok: true` with
   `{"visibility":"public"}`, `github_get_file` returned `{}`,
   `github_list_repositories` returned an empty list, and the ledger recorded
   `ok`. They now return the provider error from fix 1.
3. **Non-JSON 2xx bodies** (`providers.ts`). The typed tools now return
   `provider_malformed_response` instead of passing an HTML page or truncated
   JSON through as a successful result.
4. **Redaction broke JSON bodies** (`http.ts`). The response text was redacted
   before it was parsed. A body containing a string such as
   `Authorization: Bearer …` lost the rest of the document to the greedy
   `Authorization:` rule and came back as text. It is now parsed first and
   redacted leaf by leaf.

Endpoints and auth schemes were checked against the providers' documentation
before changing anything; none was wrong: GitHub (`/user`, `/user/repos`,
`/repos/{owner}/{repo}`, `…/contents/{path}`, `…/git/refs`, bearer token,
`X-GitHub-Api-Version: 2022-11-28`), Cloudflare (`GET /client/v4/zones/{zone_id}`,
bearer API token), OpenAI and xAI (`GET /v1/models`, bearer), Stripe
(`GET /v1/balance`, bearer accepted alongside HTTP Basic).

## Known gaps and limitations (not changed)

- **Cloudflare default reference name.** The default is
  `vault://cloudflare/global_api_key`, but the broker sends
  `Authorization: Bearer`, which Cloudflare accepts for API *tokens* only. A
  Global API Key needs `X-Auth-Email` and `X-Auth-Key`. If the stored value is
  a real Global API Key, `cloudflare_zone_get` will fail live. Run the
  Cloudflare live test to find out.
- **HEAD.** `credential_use` and `provider_request` publish `HEAD` and classify
  it as a read, but the v1 broker's method allowlist has no `HEAD`, so it
  returns `operation_not_allowed`. A test pins this.
- **Base64 echo.** A provider body containing the base64 of the credential is
  not redacted for `vault://` credentials (only the raw value is registered).
  No provider is known to do this.
- **`github_get_user` error codes.** Every failure, including 5xx and network
  errors, is reported as `credential_unavailable` with `detail: http_<status>`,
  and the ledger row has no `http_status`.
- **Ledger `http_status` on success** is missing for `github_get_user`,
  `github_get_repository`, `github_get_file` and `github_list_repositories`
  (their results are reshaped and drop the status).
- **`pathPrefix`** in `PROVIDER_POLICIES` (for example Cloudflare `/client/v4/`)
  is not enforced by the generic proxy; the host allowlist is.
- **Pass-through tools and non-JSON bodies.** `credential_use`,
  `provider_request` and `github_create_branch` return a 2xx non-JSON body as
  text rather than an error, because a generic proxy can legitimately receive
  text or an empty body.
- **Timeouts** (12–15 s per provider) are not exercised.
- **Write tools have no live test**, by design.
- `credential_health` has no offline success-path test through `dispatchTool`
  (its live test covers it).
