# Vault v2 ⇄ browser injector contract (v1)

Purpose: let a browser-side **injector** (the ShadowGlass extension's background service worker)
place a stored credential into the owner's own browser — session cookies via `chrome.cookies.set`,
or a password typed into a field via CDP — without the credential ever reaching an LLM agent, a
side panel, a log, the local relay in the clear, or a plaintext HTTP response.

The invariant, stated precisely for this channel: **plaintext exists only (a) inside the vault
process and (b) inside the enrolled injector's service worker memory for the duration of one
injection.** Everything on the wire is ciphertext sealed to the injector's public key. Agents see
ticket ids and metadata only.

## Parties
- **Agent** — any MCP client (OAuth identity). Can ask for an injection; never sees the secret.
- **Owner** — approves on Telegram; enrolls injectors from the console / stdio.
- **Injector** — an enrolled browser extension instance. Holds a non-extractable P-256 ECDH private
  key (WebCrypto, stored in IndexedDB) and an injector token.
- **Relay** — optional loopback forwarder (`127.0.0.1:9780`). Sees ciphertext only.

## Enrollment (owner only)
`admin_enroll_injector { name, public_key_jwk }` (local stdio or owner console; step-up in the console).
- `public_key_jwk`: P-256 ECDH public JWK (`kty:"EC", crv:"P-256", x, y`).
- Returns once: `{ injector_id: "inj_<16hex>", injector_token: "ein_<43 base64url>" }` (plus `name`,
  `key_thumbprint`, `status`, times). The vault stores `sha256(token)` only. `admin_list_injectors {}`,
  `admin_revoke_injector { injector_id }`.
  - **Resolved:** the result key is `injector_token`, not `token`. Every tool result passes through the
    vault's result redaction (gateway, MCP transport, JSON serializer), which blanks any member named
    `token`; a one-off hole through three redaction layers was judged worse than a different key name.
    The value and its use (`Authorization: Bearer ein_…`) are unchanged. The token is exactly
    `ein_` + 43 base64url characters (32 random bytes).
  - **Resolved:** `public_key_jwk` may be the object or its JSON text, and may carry the members a
    browser's `exportKey("jwk")` adds (`ext`, `key_ops`, `alg`, `use`, `kid`); only `kty, crv, x, y` are
    kept. A JWK with `d` is refused (`private_key_not_allowed`); any other member, curve or an off-curve
    point is `invalid_public_key`. The key is validated by importing it with WebCrypto. The list shows an
    RFC 7638 thumbprint (`key_thumbprint`, base64url sha256 of `{"crv":"P-256","kty":"EC","x":…,"y":…}`)
    so the owner can compare it with the extension.
- The token authenticates the injector on the two HTTP endpoints below: `Authorization: Bearer ein_…`.

## Agent tool: `entry_inject`
Input: `{ site, account?, target_origin, mode: "cookies" | "field", injector_id?, task }`
- `target_origin` must be `https://<host>` where host is the entry's site or a subdomain of it.
  - **Resolved:** the string must already be canonical — exactly `https://` + lower-case host; no port,
    path (not even a trailing `/`), query, fragment or credentials. Anything else is
    `invalid_target_origin`; a well-formed origin outside the entry's site is `target_origin_not_allowed`.
    The vault never normalizes it, so the `target_origin` in the tool result, in the redeem response and
    inside the AAD is byte-for-byte what the agent sent.
- `mode:"cookies"` requires an entry of kind `cookie`; `mode:"field"` requires kind `password`
  (the injector types it into a field the owner's page already shows).
  - **Resolved:** a mismatch is `mode_kind_mismatch`. Without `account`, the site's default entry *of the
    kind the mode needs* is used. The entry must be `active` (`entry_not_active` otherwise). All of these,
    and the injector checks below, are refused before any approval is requested.
- Policy: tier 2, capability `vault.entry.inject`. **Every** call needs the owner's Telegram
  approval (request-bound, single use) — there is no standing grant for injection. First call
  returns `approval_required` + `approval_id`; the retry with `approval_id` mints the ticket.
- Result (never a secret): `{ ticket: "eit_<32 base64url>", expires_at, injector_id, entry: { id, label, kind }, target_origin, mode }`.
- Ticket: random, stored as sha256, TTL 120 s, single use, bound to entry id, mode,
  target_origin, injector_id (if only one injector is enrolled it is implied) and approval id.
  - **Resolved:** the ticket is `eit_` + 32 base64url characters as written above, i.e. 24 random bytes =
    **192 bit**, not 256 (the two statements in the draft disagreed; the wire shape won).
  - **Resolved:** injector selection errors: `no_injector_enrolled` (none active), `injector_required`
    (several active and no `injector_id`), `injector_not_found` (unknown or revoked id).
  - **Resolved:** one approval mints at most one ticket: a retry with a consumed approval is
    `approval_already_consumed`, and the same request without `approval_id` asks the owner again.
- Ledger: `vault.entry.inject` pending_approval → `vault.approval.decide` → `vault.entry.inject` ok (ticket minted).
  - **Resolved:** the gateway also writes its usual intent row (`vault.entry.inject` `committing`) between
    the decision and the `ok` row, as for every approved mutation. If the `ok` row cannot be written no
    ticket exists (`ledger_unavailable`). The ledger has no injector column: every inject row's `resource`
    is `entry:<site>/<account>#<injector_id>`, with the entry ref in `credential_ref` and the approval in
    `approval_id`.

## Injector endpoint: `POST /api/injector/redeem`
Headers: `Authorization: Bearer ein_…`, `content-type: application/json`.
Body: `{ "ticket": "eit_…" }`
Success `200`:
```json
{
  "ok": true,
  "mode": "cookies",
  "target_origin": "https://example.com",
  "entry": { "id": "ve_…", "label": "example.com — work", "kind": "cookie" },
  "sealed": {
    "alg": "ECDH-ES+HKDF-SHA256+A256GCM",
    "epk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
    "salt": "<base64url 32 bytes>",
    "iv": "<base64url 12 bytes>",
    "ct": "<base64url ciphertext||tag>",
    "aad": "<base64url of UTF-8 `eit:${sha256hex(ticket)}|${injector_id}|${target_origin}|${mode}`>"
  }
}
```
- Key derivation: `Z = ECDH(epk_private, injector_public)`; `K = HKDF-SHA256(Z, salt, info="echo-vault-injector-v1", 32)`;
  `ct = AES-256-GCM(K, iv, plaintext, aad)`.
- Plaintext (UTF-8 JSON): for cookies `{"v":1,"cookies":[{"name","value","domain","path","secure","httpOnly","hostOnly","expires","sameSite"}]}`
  filtered to cookies that domain-match `target_origin`; for field `{"v":1,"username":"…","secret":"…"}`.
  - **Resolved (cookie fields):** `domain` is a lower-case host without a leading dot and is never empty
    (a cookie the vault stored as "bound to the entry's site" is emitted with that site and
    `hostOnly:true`); `hostOnly:false` means the domain and its subdomains. `expires` is epoch **seconds**
    (chrome.cookies' `expirationDate`) or `null` for a session cookie. `sameSite` is always
    `"unspecified"` — the vault does not store SameSite. The filter is the RFC 6265 domain match only
    (every path, unexpired cookies); a public-suffix domain never matches. `username` is the entry's account.
  - **Resolved:** when no stored cookie matches the origin the redeem fails (`503 unavailable`, ledger
    error `no_cookie_for_origin`) instead of sealing an empty list.
- Errors (no detail beyond the code): `401 invalid_injector`, `404 ticket_not_found`, `409 ticket_used`,
  `410 ticket_expired`, `403 ticket_wrong_injector`, `429 rate_limited`, `503 unavailable`.
  Every error body is exactly `{"ok":false,"error":"<code>"}`.
- A ticket is burned on the first redeem attempt that reaches a valid injector, success or not.
  - **Resolved (order and burn):** checks run in this order, first match wins —
    `401` (no/unknown/revoked `ein_` token, or any other token type) → `400 invalid_request` (body is not a
    JSON object) / `413 request_too_large` (body over 4096 bytes) / `405 method_not_allowed` → `429` (30
    redeems per injector per minute; `503` if the limiter's store is down) → `404` (malformed or unknown
    ticket) → `403` (ticket bound to another injector) → `409` (already redeemed) → `410` (expired) →
    **burn** → seal. "A valid injector" means the authenticated injector the ticket is bound to: none of
    the refusals above burns the ticket (so a wrong injector cannot destroy it, and a 429 can be retried).
    After the burn every failure — entry deleted or flagged for re-entry, entry kind changed, no cookie for
    the origin, vault unreachable, sealing failed, redeem ledger row not writable — is `503 unavailable`
    and the ticket stays spent; ask the agent for a new one. `400`, `405` and `413` are additions to the
    list above.
- Ledger: `vault.entry.inject.redeem` ok/error with entry ref, injector id, approval id. Rate-limited per injector (DB store).
- The response is `Cache-Control: no-store`. The vault never logs the plaintext or the derived key.
  - **Resolved:** no CORS header is sent (and `OPTIONS` is not answered): call the endpoints from the
    extension's service worker with a host permission for the vault origin, not from a page.
  - **Resolved:** refused redeems of an authenticated injector are ledgered too
    (`vault.entry.inject.redeem` `error` with the code).

## Injector endpoint: `POST /api/injector/report`
Body: `{ "ticket_sha256": "<hex>", "result": "injected" | "failed", "detail_code"?: "<short code>" }`
→ `{ ok: true }`. Writes a `vault.entry.inject.result` ledger row. Optional but the extension sends it.
- **Resolved:** same authentication and error shape as redeem. `detail_code` must match `^[a-z0-9_]{1,64}$`.
  One report per ticket, by the injector that redeemed it: `400 invalid_request`, `404 ticket_not_found`,
  `403 ticket_wrong_injector`, `409 ticket_not_redeemed`, `409 result_already_reported`,
  `429 rate_limited` (60 per injector per minute), `503 unavailable`.

## Capture (browser → vault), cookies
Uses the existing one-time card. An agent or the owner calls `entry_request_card { site, account, kind:"cookie", purpose }`;
the owner receives the card link on Telegram. The extension submits to the card's JSON endpoint (documented in
the vault's `docs/ops/cookie-entries.md`) with the cookies it read via `chrome.cookies.getAll` for that site.
The card link is the capability; it is single use.

## Injector behaviour (extension)
- Generate the ECDH key with `extractable:false`; export only the public JWK for enrollment.
- On `inject`: redeem → verify `aad` matches the ticket/origin/mode it asked for → decrypt in the service worker →
  for cookies: `chrome.cookies.set` each cookie for `target_origin` (never for a different registrable domain),
  then reload the tab; for field: CDP `Input.insertText` into the focused/selected field → zero the buffers →
  `report`. Never `console.log` a value; never post a value to the side panel, content script, relay or any model.
- The side panel shows entry labels, ticket status and results only.
