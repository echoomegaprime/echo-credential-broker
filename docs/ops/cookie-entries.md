# Cookie entries

A `cookie` entry stores one account's browser session for one site, so an agent
can make requests as that account without ever seeing a cookie value. It follows
the same model as every other entry kind: many accounts per site (identity is
site + account + kind, so a second account never overwrites the first), one
default per site, the secret only in the canonical vault, use through
`entry_use`, and a 401 flags that one entry for re-entry.

Every cookie **value** is a secret, exactly like a password. Cookie **names**
and domains are metadata: the owner sees them in the console; agents do not.

Code: `src/lib/vault/v2/cookie-jar.ts` (parsing, selection, merging — pure),
`cards.ts` (storage), `card-pages.ts` (card page and JSON submit),
`gateway.ts` (`entry_use`). Schema: `migrations/0012_vault_cookie_entries.sql`.

## Getting cookies in

An agent calls `entry_request_card` with `kind: "cookie"`. The owner gets the
usual single-use link (30 minutes). There are two ways to fill it.

### 1. Paste into the card page

The page shows a textarea. Three formats are accepted and detected
automatically:

| Format | Looks like | Scope of each cookie |
| --- | --- | --- |
| Cookie header | `sid=abc…; csrf=def…` (an optional leading `Cookie:` is fine) | none is known: bound host-only to the entry's site |
| JSON export | `[{"name":"sid","value":"…","domain":".example.com","path":"/","secure":true,"httpOnly":true,"hostOnly":false,"expirationDate":1790000000}]` as exported by browser devtools or a cookie extension; `{"cookies":[…]}` is also accepted | from `domain` / `hostOnly` / `path` |
| Netscape `cookies.txt` | seven tab-separated columns, `#HttpOnly_` prefix supported | from the domain and include-subdomains columns |

JSON details: `expirationDate`, `expires` or `expiry` may be epoch seconds,
epoch milliseconds or a date string; `session: true`, `0` or `-1` mean a session
cookie. Without `hostOnly`, a leading dot on `domain` makes it a domain cookie.
`sameSite` and other fields are ignored.

What is left out, and reported as counts on the success page:

- **Values shorter than 8 characters.** Redaction can only arm secrets of 8 or
  more characters, so a shorter value could not be kept out of a result if the
  site echoed it. Such cookies (`theme=dark`, `lang=en`) are not stored and not
  sent. A site that needs one of them for the session to work is not supported.
- **Cookies already expired.**
- **Cookies for other sites.** A whole-browser export can be pasted; only
  cookies whose domain is the entry's site, a subdomain of it, or a parent
  domain cookie that covers it are kept.

An invalid paste re-renders the form with a short code
(`invalid_cookie_value`, `invalid_cookie_json`, `public_suffix_domain`,
`no_usable_cookie`, …). Nothing that was typed is ever shown again.

Validation: names are RFC 6265 tokens (max 128 characters); values are printable
ASCII without `;`, with no control character, CR or LF and no leading or
trailing space (max 4096); paths start with `/` and contain no `;`, space or
control character. A cookie can therefore not inject a header or an attribute.
The same `(name, domain, path)` twice is refused (`duplicate_cookie`).

### 2. JSON submit (for a browser extension)

A program that holds the card link can submit the cookies directly. This is the
contract an extension is written against.

```
POST <card link>            the exact URL from Telegram: <ECHO_VAULT_PUBLIC_URL>/card/<token>
Content-Type: application/json
X-Echo-Vault-Card: submit

{
  "cookies": <array of cookie objects | string>,
  "account": "alice@example.com",
  "purpose": "general",
  "site": "example.com"
}
```

- `cookies` (required): an array of cookie objects (the JSON export format
  above, e.g. the result of `chrome.cookies.getAll({domain})`), or a string in
  any of the three formats.
- `account`, `purpose`, `site` (optional strings): same meaning as the form
  fields. `account` is required when the agent did not name one. All three are
  ignored for a re-entry card, which is bound to its existing entry.
- No cookie of this server, no CSRF field and no other credential is involved:
  the card page has none either. The one-time token in the URL is the
  capability.
- Body limit: 512 KiB. The cookie text itself is limited to 128 KiB, and the
  stored jar to 200 cookies and 32768 characters.

Responses are JSON, `Cache-Control: no-store`, and never carry a cookie value,
the token or any `Access-Control-Allow-*` header.

| Status | Body | Meaning |
| --- | --- | --- |
| 200 | `{"ok":true,"reentry":false,"entry":{"id","site","account","purpose","label","kind":"cookie","is_default"},"cookies":{"stored":N,"skipped":{"short_value":N,"expired":N,"other_site":N},"expires_at":"<ISO>"\|null}}` | Stored. The link is now dead. |
| 400 | `{"ok":false,"error":"invalid_json"\|"invalid_body","retryable":true}` | Body is not JSON, or `cookies` is not an array or string. |
| 400 | `{"ok":false,"error":"invalid_input","detail":"<code>","retryable":true}` | The cookies (or a field) were refused; `detail` is the parse code when there is one. The link is still usable. |
| 403 | `{"ok":false,"error":"card_header_required"}` | `X-Echo-Vault-Card: submit` is missing. |
| 404 | `{"ok":false,"error":"invalid_token"}` | Not a card link. |
| 409 | `{"ok":false,"error":"entry_exists","retryable":true}` | That site + account already has a cookie entry; ask the agent for a re-entry card instead. |
| 410 | `{"ok":false,"error":"expired"\|"already_used"\|"entry_gone"}` | The link is dead. |
| 413 | `{"ok":false,"error":"body_too_large","retryable":true}` | Over 512 KiB. |
| 415 | HTML page | The card is not a `cookie` card. JSON is accepted for cookie cards only. |
| 503 / 500 | `{"ok":false,"error":"vault_unavailable"\|"store_failed"\|"internal_error","retryable":true}` | Nothing was stored; retry. |

`retryable: true` means the card is still pending and the same link can be
posted to again until it expires.

**Why this request is exempt from the form's same-origin check, and what
replaces it.** The form POST must come from the card page itself
(`Sec-Fetch-Site: same-origin`, matching `Origin`). An extension is not that
page: it sends `Origin: chrome-extension://…`. So the JSON path does not look at
`Origin` or `Sec-Fetch-Site`. What it relies on instead:

1. The 256-bit single-use token in the URL, known only to whoever received the
   Telegram message. Same as the form.
2. No web page can send this request. `Content-Type: application/json` and the
   custom `X-Echo-Vault-Card` header each make it a non-simple CORS request; the
   browser must first send a preflight, the server answers `OPTIONS` without any
   CORS header, and the browser then refuses to send the POST. Either one alone
   is enough; both are required so that a browser quirk around one of them does
   not open the path. An extension with host permission for the vault origin, or
   any non-browser client, is not subject to CORS and can send it.
3. It is write-only. The response is metadata. There is no request that returns
   a stored value, to an extension or to anyone.

The card page's own CSP is unchanged (`default-src 'none'`, no script, hashed
inline style, `form-action 'self'`, `frame-ancestors 'none'`).

What the token holder can do with this path is exactly what they can do with
the form: store a secret for that one card, once.

## Stored form

The entry's secret is the canonical jar, compact JSON with a fixed key order:

```
{"v":1,"cookies":[{"name":"sid","value":"…","domain":"","path":"/","secure":false,"httpOnly":false,"hostOnly":true,"expires":null}]}
```

`domain` is lower-case without a leading dot; `""` means "the entry's site,
host-only" (the Cookie-header format). `expires` is epoch seconds or `null`.
The entry's fingerprint and length are computed over this string. In SQL the
entry row carries only `cookie_meta`: count, names, domains, earliest expiry.

## Using a cookie entry

`entry_use` works as for other kinds (`site`, optional `account` and `kind`,
`method`, `url_path`, `task`, optional `host`), with these differences:

- The request carries `Cookie: <selected cookies>` and **no** `Authorization`
  header. The `User-Agent` stays `Echo-Credential-Broker/2.0`.
- **Selection** (RFC 6265 §5.4): a host-only cookie needs the exact host; a
  domain cookie matches its domain and subdomains; the cookie path must
  path-match the request path (the query string is ignored); expired cookies
  are skipped; `Secure` is always satisfied because every request is https;
  longer paths first, then stored order.
- **Hosts.** The site, `api.<site>`, and additionally any subdomain of the site
  — but a subdomain is only reachable when a stored cookie applies to it: a
  domain cookie covering it, or a host-only cookie stored for exactly that host
  (from a JSON or cookies.txt export). Nothing outside the site is ever
  reachable.
- **`no_cookie_for_host`.** When no stored cookie applies to the host and path,
  the call fails with this error before any DNS lookup or connection. It is not
  a credential verdict; the entry stays active.
- Every cookie value is registered for redaction before the request, in its
  raw, URL-encoded, URL-decoded, base64 and base64url forms, together with the
  whole header. A site that echoes its request shows the agent `[REDACTED_…]`.
- The result is status, content type, redacted body and, for a 3xx, `location`.
  Response headers are never returned.
- A **401** flags the entry for re-entry (and its jar is left untouched). A
  **403** is `site_forbidden`. A **302/303 to a login page** is not treated as a
  verdict: status and `location` are passed through and the entry stays active.
  The agent or the owner decides whether the session is dead.

### Rotation

After each response (except a 401) the `Set-Cookie` headers are applied to the
jar per RFC 6265 §5.3:

- value and expiry are updated; `Max-Age` wins over `Expires`;
- `Max-Age <= 0` or a past `Expires` deletes the cookie;
- a `Domain` attribute is honoured only when the responding host belongs to that
  domain and it is not a public suffix; a cookie for another site, a sibling
  host or a superdomain is ignored;
- without `Domain` the cookie is host-only for the responding host; without
  `Path` it gets the request's default path;
- `__Secure-` cookies need `Secure`; `__Host-` cookies need `Secure`, no
  `Domain` and `Path=/`;
- a new value shorter than 8 characters cannot be stored; the cookie it would
  have replaced is removed rather than kept stale.

When the jar changed, the new jar is written to the vault and the entry's
fingerprint, length and jar metadata are updated, so the next use sends the
rotated session. The ledger gets a `vault.entry.cookie_refresh` row (`ok`, or
`error` with `cookie_jar_persist_failed` / `cookie_jar_too_large`). A failed
write-back does not fail the request that triggered it; the next use simply
sends the previous jar. A refresh is not counted as a rotation
(`rotation_count` is for owner re-entries).

### Public suffixes

There is no Public Suffix List in this repository. What is done: a cookie
domain with no dot (a bare TLD, `localhost`) is refused; IP literals are
refused; a short embedded list of common multi-label suffixes (`co.uk`,
`com.au`, `github.io`, `herokuapp.com`, … about 90 names) is refused, both when
pasting and when a response sets a cookie. What is not done: the full list. A
suffix that is not on the embedded list (say `k12.ca.us`) would be accepted as a
cookie domain. The containment that does not depend on the list is the host
rule above: a jar is never sent anywhere but its entry's site, `api.<site>` and
subdomains of that site.

## Owner console

`/console/entries` lists a cookie entry with kind `cookie`, the number of
cookies, their names, their domains (a leading dot marks a domain cookie) and
the earliest expiry. Long lists are cut to 50 names and 20 domains. Re-entry,
delete and purge work as for any entry; a re-entry card replaces the whole jar.

## Limits

| What | Limit |
| --- | --- |
| Cookies per entry | 200 |
| Stored jar (the entry's secret length) | 32768 characters; every other kind stays at 4096 |
| Pasted text | 128 KiB |
| Card POST body, cookie cards | 512 KiB (other kinds: 64 KiB) |
| Cookie name / value / path | 128 / 4096 / 1024 characters |
| Minimum cookie value | 8 characters |
| Cookies examined in one paste | 5000 |

## What it does not do

- **No JavaScript-driven login.** The broker does not run a browser. It cannot
  log in for you, execute a site's scripts, or obtain a session that is only
  created by script. The owner logs in in their own browser and hands over the
  resulting cookies.
- **No 2FA.** It does not answer one-time codes, prompts or passkey challenges.
  When a session expires, the owner logs in again and re-enters the cookies.
- **No anti-bot handling.** No User-Agent spoofing, header mimicry, TLS or
  browser fingerprint imitation, CAPTCHA solving or challenge-cookie harvesting.
  Requests identify themselves as `Echo-Credential-Broker/2.0`. A site that
  binds a session to the browser that created it, or blocks non-browser
  clients, will refuse these requests, and that is the expected outcome.
- **No redirect following.** A 3xx is returned with its `Location`; the agent
  makes the next request itself, on an allowed host.
- **No cookies shorter than 8 characters**, and no `SameSite` or
  third-party-context logic (every request is a direct, top-level style
  request to the entry's own site).
- **No per-request locking.** Two uses of the same entry at the same moment
  each merge their own response; the last write wins.

## Tests and proof

- `src/lib/vault/v2/cookie-jar.test.ts`: parsing, selection, merging.
- `src/lib/vault/v2/cookie-entries.test.ts`: card page, JSON submit, several
  accounts on one site, redaction, rotation, `no_cookie_for_host`, the
  migration, and a leak scan over results, ledger rows, logs, pages and stored
  rows for every cookie value (raw, URL-encoded, base64).
- `npm run e2e:rehearsal:cookie` (`scripts/e2e/rehearsal.mjs --cookie`): the
  whole proof against the real server with a cookie entry and
  `https://httpbin.org/cookies`, which echoes the cookies it received; the
  client must see them redacted. When httpbin is unreachable it asserts the
  fail-closed path only and says so.
