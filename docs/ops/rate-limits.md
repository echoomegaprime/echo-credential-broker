# Vault v2 rate limits

Rate-limit state is shared and durable: it lives in the database
(`vault_rate_limits`, `migrations/0010_vault_rate_limits.sql`), so a limit holds
across every server instance on the same database and survives a restart.
Nothing is counted in process memory in production.

Code: `src/lib/vault/v2/rate-limit-store.ts` (store), `policy-engine.ts`
(`SlidingWindowRateLimiter`, `enforceRateLimits`), `oauth-server.ts`
(`FailureRateLimiter`).

## Limits

| Limit | Applies to | Threshold | Window | When exceeded |
| --- | --- | --- | --- | --- |
| Policy `max_per_hour` | Each (policy rule, client) pair, for allowed and escalated requests matching the rule. Only exists when a rule in `ECHO_VAULT_POLICY_FILE` sets `max_per_hour`; there is no built-in default. | the rule's `max_per_hour` (values above 10 000 are enforced as 10 000) | sliding 1 hour | tool result `{ ok: false, error: "rate_limited" }`, ledger row `deny` / `rate_limited` |
| Failed token attempts | Each OAuth `client_id` at `POST /api/oauth/token` (unknown client, bad/expired/reused code or refresh token, PKCE mismatch, …). All malformed `client_id` values share one bucket. | 10 failures | sliding 5 minutes | HTTP 429, `error: "temporarily_unavailable"`, `Retry-After` = seconds until the oldest failure leaves the window. A successful grant clears the client's failures. |

Thresholds, windows, error codes and `Retry-After` values are unchanged from the
previous in-process limiters.

Other caps in v2 are not sliding-window limiters and were already backed by the
database, so they needed no change:

| Cap | Where | Backing |
| --- | --- | --- |
| Registered OAuth clients (`ECHO_VAULT_OAUTH_MAX_CLIENTS`, default 256) → 429 | `oauth-server.ts` | row count in the OAuth store |
| Pending authorizations (`ECHO_VAULT_OAUTH_MAX_PENDING`, default 16) → 429 | `oauth-server.ts` | row count in the OAuth store |
| Pending cards per client (5) → `too_many_pending_cards` | `cards.ts` | `countOpen` on the card store |
| Consent-grant uses (`ECHO_VAULT_GRANT_MAX_USES`) | `entry-grants.ts` | `uses_remaining` column, atomic decrement |

Card links (single-use, one fill consumes the card) and Telegram approval
callbacks (HMAC-bound, one decision per approval) have no attempt counter.

## Storage

One row per key:

| Column | Meaning |
| --- | --- |
| `key` | `<namespace>:<sha256 hex>` — `policy:…` or `oauth.token:…` |
| `hits` | `bigint[]`, epoch-millisecond timestamps of the events still inside the window (at most 10 000) |
| `expires_at` | latest event + its window; after this the row holds nothing live |

- **Exact sliding window.** An event at `t` counts while `t > now - window`.
- **Atomic across processes.** Recording is one
  `insert … on conflict (key) do update … where <live count> < <limit>`
  statement. The row lock serializes concurrent hits on a key and the condition
  is checked against the latest committed row, so N parallel requests against a
  limit of L are admitted exactly min(N, L) times, whichever instances receive
  them.
- **Keys never contain a token, code, secret or raw identifier.** They are
  built only by `rateLimitKey(namespace, …parts)`, which hashes the parts
  (rule id + client id; client id). The store and a table constraint refuse any
  other key shape.
- **Pruning.** Expired timestamps are dropped from a row whenever it is hit.
  Rows whose every event has expired are deleted by an opportunistic sweep that
  runs on a hit at most once a minute per process; a failed sweep is logged
  (`rate_limit_prune_failed`) and does not fail the request. Table size is
  bounded by the number of keys active within their window.

Accuracy trade-offs:

- Time comes from the application clock, not the database. Instances whose
  clocks differ by *d* see window edges shifted by up to *d*.
- With several `max_per_hour` rules applying to one request, a request that
  loses a race for the last slot of a later rule is denied but keeps the slot it
  took from earlier rules. This only errs stricter.
- A rule without an `id` is keyed by its position (`rule[<index>]`). Reordering
  the policy file moves such a rule's counters; give limited rules a stable `id`.
- Each hit rewrites its row, so cost grows with the limit; that is why limits
  are capped at 10 000 events per key.

## Failure behaviour

When the store cannot be reached (database down, table missing):

| Path | Behaviour |
| --- | --- |
| Token endpoint, check before a grant | **Fail closed**: HTTP 503, `error: "temporarily_unavailable"`, `error_description` starting `rate_limit_unavailable`, `Retry-After: 5`. No code or refresh token is consumed. |
| Token endpoint, recording a failure | The attempt is refused as usual (`invalid_grant` / `invalid_client`); the missing count is logged. The next request fails closed at the check. |
| Token endpoint, clearing failures after a success | Tokens are still issued (the grant is already consumed); the old failures keep counting until they expire. |
| Policy `max_per_hour`, tier 1 and tier 2 | **Fail closed**: `{ ok: false, error: "rate_limit_unavailable" }`, ledger row `deny`. |
| Policy `max_per_hour`, tier 0 reads | **Fail closed** as well. |

Tier 0 fails closed because a `max_per_hour` rule is an explicit operator cap,
tier 0 includes credential-injecting reads (`vault.entry.use.read`,
`*.api.read`), and the ledger uses the same database, so serving uncounted
reads during an outage would buy little availability. Requests that no
`max_per_hour` rule applies to never touch the store and are unaffected.

Log events (no key, token or driver message is logged):
`rate_limit_store_error` (`op`, `store`, `error_class`),
`policy_rate_limit_unavailable`, `oauth_rate_limit_unavailable`,
`oauth_token_rate_limited`, `rate_limit_prune_failed`.

## Configuration

No new environment variables. The store follows the database selection used by
the other v2 stores: Postgres when `DATABASE_URL` is set, otherwise the embedded
PGLite (single process). Limits are shared across instances only when they
share a Postgres database. The migration is applied by `npm run db:migrate`
(deploy) or automatically on PGLite.

Related existing settings: `ECHO_VAULT_POLICY_FILE` (rules with
`max_per_hour`), `ECHO_VAULT_OAUTH_MAX_CLIENTS`, `ECHO_VAULT_OAUTH_MAX_PENDING`.

To clear a client's failed-attempt block by hand, delete its row; the key is
`oauth.token:` + sha256 of `JSON.stringify([client_id])`.
