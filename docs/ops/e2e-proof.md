# End-to-end proof — Echo Vault v2

The goal: a real agent requests a credential action through the governed door, the owner enters the credential once on a card, the action runs with the secret injected server-side, the agent never sees the secret, and the ledger shows the trail.

There are two things here.

- **The proof** needs you: a deployed server, real Telegram, and you typing on the card. `scripts/e2e/proof-client.mjs` is the agent.
- **The rehearsal** needs nobody: `npm run e2e:rehearsal` runs the same client against the real, unmodified server with stand-ins for the canonical vault, Telegram and you. It shows the code path works; it does not replace the proof.

Use a throwaway credential for the proof. The suggested target is `httpbin.org` with path `/bearer`: it answers `401` without a bearer token and `200` with any, so any made-up value works and nothing of value is at stake.

## The proof: your steps

### 1. Pick the host

The server must be reachable at a public `https` origin (Telegram only delivers webhooks to https), with a Postgres `DATABASE_URL`. The repository builds for Vercel; any host that can run it and give it environment variables works.

### 2. Create the environment

On the machine that holds the checkout, in a terminal:

```bash
node scripts/e2e/setup-env.mjs
```

It asks for the public origin, your numeric Telegram id, `TELEGRAM_BOT_TOKEN` and `ECHO_SDK_API_KEY` (both typed with no echo), and `DATABASE_URL` (no echo; press Enter to use an embedded data directory instead, which suits a single local process only). It generates `ECHO_VAULT_APPROVAL_HMAC_KEY`, `ECHO_VAULT_TELEGRAM_WEBHOOK_SECRET`, `ECHO_VAULT_LEDGER_HMAC_KEY` and `ECHO_VAULT_ANCHOR_KEY` itself and writes `.env` in the repository root with mode `0600`. It prints variable names, never a value, and refuses to replace an existing file without `--force`.

Before you run it, do the two Telegram steps from `docs/DEPLOY.md` §2: create the bot with @BotFather, and send the bot one message from your own account.

How the file is used:

| Command | Reads `.env` by itself? |
| --- | --- |
| `npm run dev`, `npm run preview`, the `vite build` half of `npm run build` | Yes. A variable already set in the shell wins. |
| `npm run db:migrate` (also the second half of `npm run build`), `npm run mcp`, `scripts/vault-*.ts` | No. Run `node --env-file=.env scripts/migrate.mjs`, or export first: `set -a; . ./.env; set +a`. |
| A Vercel deployment | No. Add each name to the project's environment variables (`vercel env add NAME production`), then redeploy. |

On a plain host, `npm run build` therefore skips the migrations unless the variables are exported first. Either let `setup-env.mjs` apply them when it offers to, or run `node --env-file=.env scripts/migrate.mjs`.

### 3. Start, register the webhook, check

`setup-env.mjs` offers each of these and prints only `PASS` or `FAIL`:

1. apply the migrations (only when `DATABASE_URL` was given);
2. register the Telegram webhook (the bot token goes into that one request to `api.telegram.org` and nowhere else);
3. the `docs/DEPLOY.md` §5 checks, once the server is up.

Start or deploy the server before answering yes to the third. To run the checks again later, with no secret involved:

```bash
node scripts/e2e/setup-env.mjs --verify https://YOUR-HOST
```

### 4. Run the proof client, from any machine

It needs Node 22 or newer and this repository's `scripts/` directory. It needs no secret and no `.env`.

```bash
node scripts/e2e/proof-client.mjs \
  --vault https://YOUR-HOST \
  --site httpbin.org --account proof --path /bearer \
  --out proof-transcript.json
```

It registers itself, then waits for you three times and tells you each time:

1. **Approve the connection** on Telegram. The message must name the redirect host `127.0.0.1:53682`, the client "ECHO Vault proof client" and the scopes `vault.read, vault.write, audit.read`. Approve only if all three match.
2. **Open the card link** the bot sends, and type the throwaway credential. The page shows a fingerprint and a length when it is stored, for example `3fa9c1d2 (44 characters)`. Note them if you want the stronger check below.
3. **Approve the first use** on Telegram. The message quotes the exact request: `GET https://httpbin.org/bearer`.

Then it lists the entry, reads the ledger, verifies the chain and prints a verdict. Exit code `0` means every step passed.

Options worth knowing: `--timeout-s` (how long it waits for each of your actions, default 900), `--show-body` (print the redacted body, not only its shape), `--reenter` (ask for a new card although the entry exists), `--auto` (skip the confirmation prompt).

Each run registers a new OAuth client. Revoke the ones you no longer want with `admin_revoke_client` from the stdio transport (`docs/DEPLOY.md`, "Day two").

### 5. The stronger secret check (optional)

The vault does not give an agent the entry's fingerprint or length. You have them, from the card page. Pass them to a second run and the client searches everything it receives for any substring with that fingerprint:

```bash
node scripts/e2e/proof-client.mjs --vault https://YOUR-HOST \
  --site httpbin.org --account proof --path /bearer \
  --fingerprint 3fa9c1d2:44
```

The fingerprint is the first 8 hex characters of the SHA-256 of the secret. It is not the secret. The entry already exists, so this run asks for no card. It is a new client, so you approve twice: the connection and its first use.

## Reading the verdict

```
steps passed: 11 of 11
entry_use: reached the site (200)
ledger rows observed for this run (client oc_…): 9
  seq   capability               decision  tier  result            http  approval
  3     vault.card.request       allow     1     ok                -     -
  6     vault.entry.use.read     escalate  0     pending_approval  -     c-lKWcHz…
  8     vault.entry.use.read     escalate  0     ok                200   c-lKWcHz…
chain verdict: intact (10 rows; anchor: none yet)
secret observed by client: NO
RESULT: PASS
```

- **`entry_use: reached the site (200)`**: the site accepted a request it rejects without a credential. The client sent none.
- **Ledger rows**: every tool call of this client, in order. The two `vault.entry.use.read` rows carry the same approval id: the request you approved is the request that ran. The id's first 8 characters are the `Ref:` on the Telegram message.
- **`chain verdict`**: the vault's own `audit_verify` over the whole ledger. `anchor: none yet` means no ledger head has been anchored externally so far; that is expected on a new server.
- **`secret observed by client: NO`** rests on a scan of every response body and header the client received: no value shaped like a provider token (the detectors of `scripts/credential-scan.mjs`), with the client's own OAuth tokens excluded; with `--fingerprint`, no substring with the entry's fingerprint; and the entry metadata the client was given has no fingerprint or length field.

## Reading the transcript

`proof-transcript.json` (mode `0600`) holds, per HTTP exchange, the request the client sent and the response it received, plus `steps`, `use`, `ledger_rows`, `chain`, `secret_scan` and `verdict`. The client's own access token, refresh token, authorization code, pending handle and PKCE verifier are replaced by `[MASKED:…]`. Nothing else is altered, so the file shows what an agent sees: for `httpbin.org/bearer` the body is `{"authenticated": true, "token": "[REDACTED_SECRET]"}`, the site's echo of the credential redacted by the server.

The transcript holds no credential, but it does hold ids and your host name. Treat it as internal.

## Reading the ledger yourself

From the stdio transport on the server host, `audit_list` and `audit_verify` return the same rows without going through the client. What a full run leaves:

| Capability | Meaning |
| --- | --- |
| `vault.status`, `vault.entry.list`, `vault.card.status`, `vault.approval.status`, `audit.read`, `audit.verify` | Reads by the client (tier 0). |
| `vault.card.request` | The client asked for a card. |
| `vault.entry.create` | You stored the credential through the card. Recorded under the requesting client, tier 2. |
| `vault.entry.use.read` → `pending_approval` | The first use was held for you. |
| `vault.entry.use.read` → `ok`, `http 200`, same approval id, `vault://entry/…` | The approved use ran. The reference names the entry; no value is recorded. |

Two things are not ledger rows today:

- **The connection approval** (`vault.client.authorize`). It is recorded in the `vault_approvals` table (status, `decided_by` = your Telegram id, time) and in the server log (`oauth_client_approved`), but not in the hash-chained ledger.
- **Your taps themselves.** The ledger records the request that was held and the request that ran, with the approval id; who decided and when is in `vault_approvals`.

## The rehearsal

```bash
npm run e2e:rehearsal          # under a minute; exit 0 only when every row passes
node scripts/e2e/rehearsal.mjs --keep   # keep the temp dir: transcript.json, data/, server.log
```

It starts the real server with `npm run dev` on a free loopback port, with PGlite in a temp directory and every variable from `docs/DEPLOY.md` §1–3 set to a value generated in memory. Nothing under `src/` is changed or switched into a test mode. Three things stand in for the outside world:

| Outside party | Stand-in | How the server reaches it |
| --- | --- | --- |
| Canonical vault (SDK gate) | `scripts/e2e/fake-gate.mjs`, in memory | `ECHO_SDK_GATE_URL`, a supported setting |
| Telegram | `scripts/e2e/fake-telegram.mjs` | `scripts/e2e/telegram-preload.mjs`, loaded with `NODE_OPTIONS=--import`, sends `fetch` calls for `https://api.telegram.org/` to the fake. It refuses any target that is not `http://127.0.0.1:<port>`. |
| The owner | `scripts/e2e/rehearsal.mjs` | Only public surfaces: it posts the `callback_query` update Telegram would send to `/api/telegram/webhook` with the secret header and the approver id, and it loads the card page and posts its form the way a browser does. |

The target site is not faked. The server's `entry_use` path refuses loopback and private addresses and pins DNS, by design, so the rehearsal sends a random throwaway value to the real `https://httpbin.org/bearer`. If that host cannot be reached, the rehearsal says so in capitals, asserts that `entry_use` fails closed with `entry_use_failed`, and proves no successful injected request.

### What the rehearsal proves

- The client completes discovery, registration, PKCE authorization, token exchange and MCP against the real HTTP routes.
- Approvals arrive as Telegram messages and are honoured only from the approver id with the right webhook secret. A wrong secret gets `401`; a tap from another id changes nothing.
- The card page takes the credential once, shows the right fingerprint, and the link is dead afterwards.
- The credential reaches the site: `httpbin.org/bearer` answers `200` to the vault and `401` to a request without one. The server logs one DNS-pinned connection to a public address.
- The site echoes the token and the client receives it redacted.
- The throwaway credential, in raw, URL-encoded, base64, base64url, hex and JSON-escaped form, appears in the owner's form post and in the fake vault's memory, and nowhere else: not in anything the client received or printed, the transcript, the server log, any Telegram payload, the fake gate's request log, the card page responses, any database row, or any file in the temp directory.
- None of the generated server keys appears in the log, transcript, Telegram payloads or database.
- The ledger, read straight from the database after the server stopped, links into one chain with an HMAC on every row and has the card request, the held use and the approved use with matching approval ids.

### What the rehearsal does not prove

- **Real Telegram.** No message is delivered, no real bot token is used, `setWebhook` is never called against Telegram, and Telegram's own retry and delivery behaviour is not exercised.
- **The real canonical vault.** The fake gate accepts the three calls the server makes and stores values in memory. Authentication, storage and `locate` behaviour of the real gate are not exercised.
- **A human.** Nobody reads the approval text before approving. The script approves whatever is asked, as long as there are exactly two approvals of the expected kinds.
- **The deployed build.** The rehearsal runs the Vite dev server with PGlite, not the Vercel build with Postgres, and plain `http` on loopback, not `https`.
- **The request as the site received it.** The connection to the site is TLS, so the rehearsal sees its effect (`200` instead of `401`, the redacted echo), not the bytes.
- **Outbound TLS on your host.** The server uses Node's trust store. The rehearsal passes `NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE` through when the machine it runs on sets them (a network that re-signs TLS needs that); it prints a line when it does.
