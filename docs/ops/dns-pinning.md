# DNS pinning for `entry_use`

`entry_use` injects a stored credential into one HTTPS request to the entry's
own site (`<site>` or `api.<site>`). This page describes what the broker
guarantees about *where* that request can go, and what it does not.

## The gap that was closed

Before, `siteRequest` (`src/lib/vault/v2/gateway.ts`) did:

1. resolve the host, reject if any address is private / link-local / blocked;
2. `fetch(url)`, which resolves the name **again**.

A DNS-rebinding attacker who controls the name's DNS answers lookup 1 with a
public address and lookup 2 with `127.0.0.1`, `169.254.169.254` or an RFC 1918
address. The check passes and the connection goes inside.

## The guarantee

For every `entry_use` request, in production (no `deps.fetch` injected):

1. **One lookup.** The hostname is resolved exactly once per request.
2. **All answers validated.** Every address must be an IP literal that is not
   blocked by `isBlockedHost` / `isPrivateOrLinkLocalIp`
   (`src/lib/vault/policy.ts`). One bad answer rejects the whole request with
   `hostname_not_allowed`; nothing is sent.
3. **Connection pinned.** The request is made by `pinnedFetch`
   (`src/lib/vault/v2/pinned-fetch.ts`) with `node:https` and a `lookup`
   function that can only return the validated addresses. Global `fetch` is
   not used, so there is no second resolution to poison.
4. **Peer address re-checked before any request byte.** After the TLS
   handshake, `socket.remoteAddress` must be one of the pinned addresses and
   must not be private. Only then are the request line, headers (including
   `Authorization`) and body written. Otherwise the socket is destroyed and
   the request fails with `hostname_not_allowed`.
5. **TLS is unchanged.** SNI and the `Host` header are the original hostname;
   the certificate is verified against that hostname with the normal trust
   store. Verification is never disabled.
6. **No connection reuse.** `agent: false`: each request gets a new socket, so
   a socket opened for an earlier (differently validated) request is never
   reused.
7. **No redirects.** A 3xx is returned to the caller with its `Location`; the
   credential is never replayed to another host.
8. **Bounded.** 12 s for connect + TLS + headers + body, and 1 MiB of response
   body (`ENTRY_USE_LIMITS`); past either the request is aborted
   (`request_timeout`, `response_too_large`).
9. **Errors are fixed codes.** `pinnedFetch` never builds an error message
   from request headers or bodies.

The connected address is logged (`vault_entry_use_connected`, with `entry_id`
and `host`). An IP address is not a secret. The ledger schema is unchanged.

## Addresses that are refused

IPv4: `0.0.0.0/8`, `10/8`, `100.64.0.0/10`, `127/8`, `169.254/16`,
`172.16/12`, `192.0.0.0/24`, `192.168/16`, `198.18.0.0/15`, `224.0.0.0/4`,
`240.0.0.0/4` (including broadcast), and non-canonical spellings (decimal,
hex, octal).

IPv6: `::`, `::1`, `::/96` (IPv4-compatible), `::ffff:0:0/96` (IPv4-mapped;
the dotted form is judged by its IPv4 address, any other spelling is refused),
`::ffff:0:0:0/96`, `64:ff9b::/96` NAT64 and `2002::/16` 6to4 when the embedded
IPv4 address is refused, `64:ff9b:1::/48`, `2001::/32` (Teredo), `fc00::/7`,
`fe80::/10`, `fec0::/10`, `ff00::/8`, and anything containing `:` that does
not parse as an IPv6 address. Addresses are parsed, not pattern-matched, so
expanded, zero-padded, upper-case and zoned spellings are covered.

## Limits: what this does not do

- **It does not decide which public host is the right one.** The host must
  still be the entry's `site` or `api.<site>`. If that name's DNS points at
  some other *public* address, the request goes there; TLS certificate
  verification is what stops a wrong server from reading it.
- **Only `entry_use` is pinned.** Other outbound calls that carry a credential
  use global `fetch` to a host fixed in code or operator configuration, with
  no address check:
  - `authorizedProviderFetch` (`src/lib/vault/http.ts`; used by
    `credential_use` / `provider_request` via `broker.ts`, and by
    `providers.ts`): `api.github.com`, `api.cloudflare.com`, `api.openai.com`,
    `api.stripe.com`, `api.x.ai`. Callers supply a path, never a host.
  - `githubCall` (`src/lib/vault/v2/github-app.ts`): `api.github.com`.
  - Telegram notifier (`src/lib/vault/v2/telegram.ts`): `api.telegram.org`.
  - Vault gate client (`src/lib/vault/gate-client.ts`): `ECHO_SDK_GATE_URL`
    (operator-set; may legitimately be a private address).
  These depend on DNS integrity for a well-known name plus TLS verification.
- **No proxy support.** `pinnedFetch` connects directly. If the deployment
  needs an egress proxy (`HTTPS_PROXY`), `entry_use` will not use it; and a
  proxy would resolve the name itself, which would move the rebinding problem
  to the proxy.
- **The resolver is trusted for the one lookup.** The broker uses the OS
  resolver (`dns.lookup`). An attacker who answers that single lookup with a
  public address they control gets the connection, but still needs a valid
  certificate for the hostname.
- **NAT64 / 6to4** addresses whose embedded IPv4 address is public are
  allowed, so IPv6-only hosts behind DNS64 keep working. A NAT64 gateway on a
  prefix other than `64:ff9b::/96` is not recognised as NAT64.
- **HTTP/1.1 only, no transparent decompression.** The request sends
  `accept-encoding: identity`.
- **`deps.fetch` bypasses pinning.** It exists for tests. Production wiring
  must not set it; nothing in `src/` outside tests does.
- **Test-only relaxations.** `pinnedFetch` has a `testOnly` option (extra CA,
  loopback allowance, replacement lookup) used by
  `pinned-fetch.test.ts`. `siteRequest` never passes it, and a gateway test
  asserts that.

## Operating notes

- `hostname_not_allowed` in an `entry_use_failed` detail means the name
  resolved to (or the socket reached) a refused address. Check the site's DNS
  from the broker host: `getent ahosts <host>`.
- `site_request_failed` means connect or TLS failed; the Node error code
  (for example `ECONNREFUSED`, `CERT_HAS_EXPIRED`) is on the error's `detail`
  field inside the broker but is not returned to the agent.
- A name with both A and AAAA records is pinned to all of them; Node picks
  one (happy eyeballs). The log line shows which.
