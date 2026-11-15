# Browser injector channel

The injector channel puts a stored credential into **your own browser** — the
session cookies of a `cookie` entry, or the password of a `password` entry typed
into a login field — without the credential ever reaching an agent, a tool
result, a log, the ledger, the database or a plaintext HTTP response.

It exists for sites you use in a browser yourself. `entry_use` covers the case
where the vault makes the request; this covers the case where *you* (or a
browser agent driving your browser) need to be signed in.

Scope: it delivers a credential to the owner's browser and does nothing else.
It does not disguise automated access and has nothing to do with a site's bot
or abuse detection.

Wire contract (what the extension is written against):
[injector-contract.md](./injector-contract.md).
Code: `src/lib/vault/v2/injector.ts` (registry, tickets, sealing),
`injector-http.ts` (the two endpoints), `gateway.ts` (`entry_inject`, the
`admin_*_injector` tools), `owner-console-pages.ts` (Security → Injectors).
Schema: `migrations/0013_vault_injectors.sql`.

## The invariant

Plaintext of a stored credential exists in two places only:

1. inside the vault process, for the moment it is read and sealed;
2. inside the enrolled injector (the extension's service worker), after it
   decrypted the blob with a private key that never leaves the browser.

Everything between them is ciphertext sealed to that injector's P-256 public
key (ECDH-ES with an ephemeral key → HKDF-SHA256 → AES-256-GCM, bound by AAD to
the ticket, the injector, the origin and the mode). Agents see a ticket id and
metadata.

## Parties and credentials

| Party | Has | Can |
| --- | --- | --- |
| Agent (OAuth `eva_` / workload `ewk_` token) | scope `vault.write` | ask for an injection; receives a ticket; cannot redeem it |
| Owner | Telegram, the passkey console, local stdio | approve each injection; enroll, list, revoke injectors |
| Injector (`ein_` token + P-256 private key in the browser) | one enrollment | redeem a ticket bound to it, decrypt, report; cannot call any tool |

The three token types do not cross: an `ein_` token is refused on `/api/mcp`
and `/api/rest/tool`; `eva_` and `ewk_` tokens are refused on
`/api/injector/*`.

## Owner steps

### 1. Generate the key in the extension

Open the extension's injector settings and create its key. The extension
generates a P-256 ECDH key pair with `extractable: false` and shows the
**public** key as a JWK (`kty`, `crv`, `x`, `y`). Copy that. There is no
private key to copy, and the vault refuses a JWK that contains one.

### 2. Enroll

Apply migration 0013 first. Then either:

- **Console:** Security → Injectors → "Enroll an injector". Give the browser a
  name, paste the public JWK, confirm with your passkey (enrolling needs a
  passkey confirmation from the last 5 minutes). The result page shows the
  injector id and the injector token.
- **Local stdio** (on the vault host): call `admin_enroll_injector` with
  `{ "name": "...", "public_key_jwk": { ... } }`.

The token (`ein_…`, result member `injector_token`) is shown **once** and
stored only as a SHA-256. Paste the id and the token into the extension, then
leave the page. If you lose it, revoke the injector and enroll again. Compare
the "public key thumbprint" in the list with the one the extension shows.

Remote clients cannot enroll, list or revoke injectors (tier 3).

### 3. Use

1. An agent calls `entry_inject` with `{ site, account?, target_origin, mode, injector_id?, task }`.
   `target_origin` must be exactly `https://<host>` where the host is the
   entry's site or a subdomain of it; `mode` is `cookies` (cookie entry) or
   `field` (password entry). A request that fails these rules is refused
   without bothering you.
2. You get a Telegram prompt naming the entry, the origin, the injector and the
   task. **Every injection asks.** There is no standing grant, and an approval
   covers exactly one request and mints at most one ticket.
3. After you approve, the agent's retry returns a ticket (`eit_…`, 120 s,
   single use, bound to that injector) and metadata — never the credential.
4. The agent hands the ticket to the extension. The extension redeems it at
   `POST /api/injector/redeem`, checks the AAD against what it asked for,
   decrypts in its service worker, sets the cookies for that origin (or types
   the password into the focused field), and reports the outcome.

### Revoke

Security → Injectors → Revoke, or `admin_revoke_injector`. The token stops
authenticating immediately, so tickets already minted for that injector can no
longer be redeemed. Revoke when a browser profile or machine is retired, lost
or suspected.

## What is recorded

| Ledger row | When | Client |
| --- | --- | --- |
| `vault.entry.inject` `pending_approval` | the agent asked | the agent |
| `vault.approval.decide` | you tapped | `owner:telegram` |
| `vault.entry.inject` `committing`, then `ok` | approved retry; the ticket exists only if the `ok` row was written | the agent |
| `vault.entry.inject.redeem` `ok` / `error` | each redeem attempt by an authenticated injector | `injector:<id>` |
| `vault.entry.inject.result` `ok` / `error` | the injector's report | `injector:<id>` |
| `vault.admin.injector.enroll` / `.list` / `.revoke` | owner actions | local or `owner:…` |

Each inject row carries the entry reference (`credential_ref`), the injector id
(the `#inj_…` suffix of `resource`) and the approval id. No row, log line or
SQL column holds a credential, a cookie value, a key, an `ein_` token or a raw
ticket: tokens and tickets are stored as SHA-256, and the CHECK constraints of
migration 0013 make any other shape unstorable.

Fail closed: no ticket without its mint row; no ciphertext leaves when the
redeem row cannot be written (the ticket is spent anyway); the redeem rate
limit (30 per injector per minute, shared database store) refuses when its
store is unreachable.

## Threat model

**A compromised relay** (the optional loopback forwarder between the agent side
and the extension, or anything else on the path, including a TLS-terminating
proxy):

- sees ciphertext, the ticket, the injector token if it forwards the redeem
  request, and metadata (entry label, origin, mode);
- cannot read the credential: the AES key is derived from an ECDH exchange with
  the injector's private key, which it does not have;
- cannot change the blob or re-target it: the ciphertext, IV and salt are
  authenticated, and the AAD binds ticket, injector, origin and mode — the
  extension refuses a blob whose AAD is not the one it asked for;
- can drop or delay traffic, or burn a ticket by redeeming it first with a
  token it relayed (denial of service; you would have to approve again).

**A compromised injector machine** (malware in the browser profile or on the
desktop):

- can read whatever the injector decrypts from then on, and already has the
  browser's own cookies — this channel does not make a compromised browser
  safe;
- still needs your Telegram approval for each credential: it cannot pull
  entries on its own, cannot list entries, cannot call tools, and is limited to
  tickets bound to that injector;
- may be able to *use* the non-extractable private key while it runs there,
  but the key cannot be exported through WebCrypto;
- response: revoke the injector, re-enter the credentials it received (the
  ledger's `vault.entry.inject.redeem` rows for that injector list exactly
  which entries, when, under which approval).

**A stolen `ein_` token** (without the private key):

- can call the two injector endpoints as that injector: redeem tickets bound
  to it and get **ciphertext it cannot open**, burn those tickets, and file
  false reports — denial of service and misleading result rows, no disclosure;
- cannot mint a ticket, call a tool, read the ledger, or touch another
  injector's tickets;
- response: revoke the injector and enroll again.

**A compromised agent** (or a prompt-injected one) holding `vault.write`:

- can ask for injections; each one reaches you as a prompt naming the origin;
  it never receives the credential, only a ticket it cannot redeem;
- cannot aim an entry at a foreign site: the origin must be the entry's own
  site or a subdomain, and cookies are filtered to those that domain-match it.
  Approving an injection into a subdomain you do not control would still hand
  that subdomain the matching cookies — read the origin in the prompt.

**The vault host or its database**: out of scope here as everywhere else — the
vault process reads the secret. The database alone holds hashes and public
keys, nothing that opens a credential.

## Limits and honest gaps

- The vault zeroes the byte buffers it controls (shared secret, plaintext
  bytes) and derives the AES key as a non-extractable key object, but the
  secret also exists as an immutable JavaScript string until garbage
  collection.
- The local stdio enrollment result is visible to whatever runs that stdio
  session on the vault host (the same trust as `admin_console_bootstrap`).
  Prefer the console when an assistant drives the stdio session.
- The vault does not store `SameSite`; injected cookies carry
  `sameSite: "unspecified"`.
- The domain filter uses the short public-suffix list of `cookie-jar.ts`, not
  the full Public Suffix List.
- Tested against a scripted injector only (`injector.test.ts`,
  `npm run e2e:rehearsal:inject`): a real key pair and the real decryption, but
  no real extension, `chrome.cookies`, CDP or browser.
