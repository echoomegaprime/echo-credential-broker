# Owner console

A passkey-gated web console for the vault's owner, served under `/console` by
the same server as `/api/mcp`. It replaces "stdio only" as the everyday way to
manage clients, consent grants, entries, the ledger and the digest. The local
stdio identity stays as the bootstrap and break-glass path.

Code: `src/lib/vault/v2/owner-console.ts` (ceremonies, sessions, step-up),
`owner-console-pages.ts` (HTTP, CSP, CSRF), `owner-console-store.ts` (storage),
`owner-identity.ts` (the `owner` identity and the bootstrap code). Routes:
`src/routes/console/index.ts` and `src/routes/console/$.ts`. Tables:
`migrations/0011_vault_owner_console.sql`.

**The console never shows a stored secret.** There is no reveal, copy or export
feature. It shows entry metadata (status, fingerprint, length, rotation state)
and nothing else. Secrets are still typed only on a credential card.

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `ECHO_VAULT_CONSOLE_ORIGIN` | to enable the console | The exact origin the owner opens, for example `https://vault.example.com` (scheme, host, optional port; no path, no trailing content, lower case). It is the expected WebAuthn origin, and its hostname is the WebAuthn RP ID. Unset or malformed: every `/console` URL answers `503`. |
| `ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST` | development only | Set to `1` to accept `http://localhost:<port>` as the origin. Without it an `http://localhost` origin is refused. Never set it on a deployed server. |

Rules worth knowing before you set it:

- Origin and RP ID come from this variable only. The request's `Host` header is
  never consulted, so a proxy or a DNS trick cannot change what the console
  expects.
- The RP ID is the hostname. Passkeys are bound to it: if you later move the
  console to another hostname, existing passkeys stop working and you bootstrap
  again (see Recovery).
- Only `https://` on a DNS name is accepted (no IP address), plus the
  `http://localhost` development exception above.
- The session cookie always carries `Secure`. Chrome and Firefox accept that on
  `http://localhost`; Safari does not, so use Chrome or Firefox for local work.
- The legacy read-only page at `/` (`ECHO_VAULT_CONSOLE=local`) is unrelated.
  It has no login, holds read scopes only, and can run no `admin_*` tool. Leave
  it off on a public host.

## Bootstrap: enrolling the first passkey

The first passkey can only be enrolled with a one-time code minted by the local
stdio identity, that is, by someone who can already run a process as the vault's
OS user on the vault host.

1. On the server, set `ECHO_VAULT_CONSOLE_ORIGIN`, apply migration 0011
   (`npm run db:migrate`, or let `npm run build` do it) and restart.
2. On the vault host, connect a local MCP client to the stdio server
   (`npm run mcp`, pointed at the same database as the web server) and call the
   tool `admin_console_bootstrap` with no arguments.
3. The result contains `bootstrap_code` (`evb_…`). It is shown once, in that
   result only. The server keeps its SHA-256, never the code. It is valid for
   15 minutes, works once, and minting again replaces it (there is never more
   than one).
4. In a browser on the device that will hold the passkey, open
   `https://<console origin>/console/enroll`, type the code, give the passkey a
   name and choose **Register passkey**. Your authenticator must verify you
   (PIN, fingerprint or face).
5. You are sent to `/console/login`. Sign in with the new passkey.
6. Recommended at once: open **Security** and add a second passkey on another
   device, so losing one device does not send you back to step 2.

The code is not a vault secret, but treat it like a password for 15 minutes:
whoever has it can enroll a passkey and become the owner. If you minted one and
will not use it, mint another and discard it, or just let it expire.

Embedded database note: with no `DATABASE_URL`, the stdio process and the web
server each open the PGlite directory. Run them against the same
`ECHO_VAULT_DATA_DIR` one at a time (stop the web server, mint, start it
again), or use Postgres.

## Enrollment rules

- First passkey: bootstrap code + a WebAuthn registration, as above. The code
  is consumed only when the registration verifies.
- More passkeys: from a signed-in session with a fresh step-up
  (**Security → Add a passkey**).
- Removing a passkey: signed-in session with a fresh step-up. The last passkey
  cannot be removed. Removing a passkey ends every session opened with it.
- There is no other path: no email, no password, no recovery link, and an owner
  session cannot mint a bootstrap code.
- At most 10 passkeys.

## WebAuthn details

- Library: `@simplewebauthn/server` 14.1.0 verifies every response;
  `@simplewebauthn/browser` 14.0.0 runs the ceremony in the page (its bundle is
  vendored verbatim into `owner-console-webauthn-bundle.ts` by
  `scripts/vendor-webauthn-browser.mjs` and inlined under a CSP nonce).
- User verification is required on every ceremony. Attestation is `none`.
  Passkeys are registered as discoverable credentials, and login sends no
  allow-list, so the server never tells an anonymous visitor which credential
  IDs exist.
- Stored per passkey: credential ID, public key, signature counter, transports,
  a label and timestamps. No private key material ever reaches the server.
- Challenges are 32 random bytes, stored as SHA-256, valid for 3 minutes and
  single use: the row is deleted before the response is checked. A step-up or
  add-passkey challenge is bound to the session that asked for it.
- Signature counter: an assertion whose counter did not advance is refused. If
  that was the only thing wrong with it (the signature is genuine), the passkey
  is flagged `counter_regression` on the Security page and in the ledger. It
  can mean a cloned authenticator. Remove the passkey and enroll a new one.

## Sessions, step-up and CSRF

- Session: a 256-bit random token in the cookie
  `__Secure-echo_vault_console` (`HttpOnly; Secure; SameSite=Strict;
  Path=/console`), stored as SHA-256. Idle timeout 15 minutes, absolute lifetime
  8 hours. **Sign out** revokes it server-side. Sessions are listed and can be
  revoked on the Security page.
- Why `__Secure-` and not `__Host-`: `__Host-` requires `Path=/`, which would
  send the owner's session token on every request to the origin (`/api/mcp`,
  `/card/…`, the app's own pages). The cookie is kept to `/console` instead.
- Step-up: destructive actions need a WebAuthn assertion completed for this
  session in the last 5 minutes. Signing in counts as one. Destructive means:
  purge or soft-delete an entry, rotate an entry now, set a rotation policy to
  `auto`, revoke a client, set a client's scopes, revoke all grants for a
  client and entry, add or remove a passkey. Without a fresh assertion the
  action is refused with `403` and the refusal is ledgered.
- CSRF, on every POST: `Sec-Fetch-Site: same-origin` must be present, `Origin`
  must be the configured origin, and behind a session the per-session CSRF
  token must be in the form (`csrf`) or the `x-csrf-token` header. `Origin:
  null` is accepted only together with `Sec-Fetch-Site: same-origin`, because
  browsers send `null` on same-origin form posts under
  `Referrer-Policy: no-referrer`.
- Rate limits (shared database store, keys hashed, fail closed when the store
  is unreachable): 5 wrong bootstrap codes per 15 minutes; 5 failed assertions
  per passkey per 15 minutes, with all unknown credentials sharing one bucket;
  30 anonymous login challenges per minute. A success clears the counter.

## Authorization

A signed-in session acts as the identity `owner:<first 12 hex of
sha256(credential id)>`, kind `owner`. Only the console session path can mint
it: the gateway accepts kind `owner` solely for the object that path created,
so no MCP, REST, OAuth or workload request can claim it. The gateway lets
`owner` (like the local stdio identity) through the tier-3 `admin_*` gate;
every OAuth and workload client is still refused with `tier3_human_only`.
`admin_console_bootstrap` stays local-only.

Every console action goes through `dispatchTool`, so policy, redaction and the
ledger apply as for any caller. Sign-in, failed sign-in, enrollment, sign-out,
step-up, passkey add/remove and session revocation are ledgered under
`vault.console.*`.

## Pages

| Page | What it does |
| --- | --- |
| `/console/enroll` | Bootstrap code + passkey registration |
| `/console/login` | Passkey sign-in |
| `/console` | Chain verdict, newest anchor verdict, counts, entries needing re-entry, rotation due |
| `/console/clients` | List OAuth clients, set scopes, revoke |
| `/console/grants` | List consent grants, revoke one, revoke all for a client and entry |
| `/console/entries` | List entries (status, fingerprint, length, rotation), set rotation policy, rotate now, send a re-entry card, soft delete, purge (typed `PURGE <entry_id>`) |
| `/console/audit` | Recent ledger rows with filters, verify chain, anchor now, verify a pasted anchor line |
| `/console/digest` | Preview the digest for a window, send it now |
| `/console/security` | Passkeys and sessions |

All pages are server-rendered with `Cache-Control: no-store`,
`Referrer-Policy: no-referrer`, `frame-ancestors 'none'` and a CSP of
`default-src 'none'` plus a per-response nonce. The platform's head injector
skips `/console` and `/card/`, so nothing third-party is added to them.

## Recovery: all passkeys lost

Bootstrap again. On the vault host call `admin_console_bootstrap` over stdio,
open `/console/enroll`, register a new passkey, sign in, then remove the lost
passkeys on the Security page (they stay enrolled until you do). Whoever can
run the stdio process as the vault's OS user can always do this, which is the
same trust the vault already places in that user.

If you believe a passkey or a session was stolen: sign in, remove the passkey
(this ends its sessions), revoke the remaining sessions you do not recognise,
and read `/console/audit` filtered by that passkey's `owner:…` ID.

## Threat model

| Threat | What stops it |
| --- | --- |
| A remote agent or OAuth client tries to use owner tools | Tier 3 for every OAuth/workload identity; `owner` cannot be asserted by a request |
| Phishing site asks for the passkey | WebAuthn binds the assertion to the origin and RP ID from the environment |
| Cross-site request with the owner's cookie | `SameSite=Strict`, `Sec-Fetch-Site` + `Origin` check, CSRF token |
| Stolen session cookie | `HttpOnly`, 15-minute idle and 8-hour absolute limits; destructive actions still need a fresh passkey assertion; revocable |
| Replay of a captured WebAuthn response | Challenges are single use and expire in 3 minutes |
| Cloned authenticator | Counter regression is refused and flagged |
| Guessing the bootstrap code | 192 random bits, 15 minutes, single use, 5 wrong guesses per 15 minutes |
| Database read access | Tokens, challenges and the code are stored as SHA-256 only; passkey rows hold public keys |
| Clickjacking, script injection | `frame-ancestors 'none'`, nonce-only CSP, every value escaped |
| The console leaking a secret | It has no access path to one: every vault read goes through `dispatchTool`, which returns metadata only |

Not covered, by design or by limits of this change:

- **Database write access** to the console tables is owner access (an attacker
  could insert a passkey row). Protect the database as you protect the vault.
- **The OS user that runs the vault** can mint a bootstrap code. That is the
  break-glass path.
- **Denial of service on sign-in.** The limits are global because the server
  has no trusted client address. Someone who floods `/console/login/options`
  or sends wrong bootstrap codes can lock those two functions for up to 15
  minutes at a time; someone who knows a passkey's credential ID can lock that
  passkey the same way. The stdio path is unaffected. Put a per-address rate
  limit at your proxy if this matters.
- **A flagged passkey is not disabled.** It is refused for that one assertion
  and reported; removing it is the owner's decision.
- **Malware on the owner's device** with an unlocked session can act as the
  owner, within the step-up window for destructive actions.

## What has been tested, and how

`src/lib/vault/v2/owner-console.test.ts` drives real WebAuthn ceremonies
against the unmocked verification library using a software authenticator
written in the test (P-256 keys from `node:crypto`). Storage is tested in
memory and on PGlite with the real migration. A hardware authenticator, a
platform passkey provider (iCloud Keychain, Google Password Manager, Windows
Hello) and Postgres itself have not been exercised by the automated suite.
