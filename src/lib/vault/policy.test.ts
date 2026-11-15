import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  assertSafeDestination,
  buildProviderUrl,
  isAllowedHostForProvider,
  canonicalIp,
  isBlockedHost,
  isPrivateOrLinkLocalIp,
  normalizeResourcePath,
} from "./policy.ts";

describe("policy", () => {
  it("allows only the GitHub API host", () => {
    assert.equal(isAllowedHostForProvider("github", "api.github.com"), true);
    assert.equal(isAllowedHostForProvider("github", "github.com"), false);
    assert.equal(isAllowedHostForProvider("github", "evil.example"), false);
  });

  it("blocks metadata services, localhost, and private IPs", () => {
    assert.equal(isBlockedHost("169.254.169.254"), true);
    assert.equal(isBlockedHost("localhost"), true);
    assert.equal(isBlockedHost("127.0.0.1"), true);
    assert.equal(isBlockedHost("metadata.google.internal"), true);
    assert.equal(isBlockedHost("10.0.0.5"), true);
    assert.equal(isBlockedHost("192.168.1.1"), true);
  });

  it("rejects absolute URLs and parent-path tricks as resources", () => {
    assert.throws(() => normalizeResourcePath("https://evil.example/steal"));
    assert.throws(() => normalizeResourcePath("//evil.example/steal"));
    assert.throws(() => normalizeResourcePath("/../../etc/passwd"));
  });

  it("refuses to send a credential to an unapproved hostname", () => {
    assert.throws(() =>
      assertSafeDestination(new URL("https://evil.example/"), "github"),
    );
    assert.throws(() =>
      assertSafeDestination(new URL("https://169.254.169.254/latest"), "github"),
    );
    assert.throws(() =>
      assertSafeDestination(new URL("http://api.github.com/user"), "github"),
    );
  });

  it("builds HTTPS GitHub URLs from paths only", () => {
    const url = buildProviderUrl("github", "/user");
    assert.equal(url.href, "https://api.github.com/user");
  });
});

describe("isPrivateOrLinkLocalIp: every address a credential must never be sent to", () => {
  const blocked: Array<[string, string]> = [
    // IPv4
    ["0.0.0.0", "0.0.0.0/8 unspecified"],
    ["0.1.2.3", "0.0.0.0/8"],
    ["127.0.0.1", "loopback"],
    ["127.255.255.254", "loopback /8"],
    ["10.0.0.5", "RFC 1918"],
    ["172.16.0.1", "RFC 1918"],
    ["172.31.255.255", "RFC 1918"],
    ["192.168.1.1", "RFC 1918"],
    ["169.254.169.254", "link-local / cloud metadata"],
    ["100.64.0.1", "CGNAT low edge"],
    ["100.127.255.255", "CGNAT high edge"],
    ["192.0.0.8", "192.0.0.0/24 protocol assignments"],
    ["198.18.0.1", "198.18.0.0/15 benchmarking"],
    ["198.19.255.255", "198.18.0.0/15 benchmarking"],
    ["224.0.0.1", "multicast"],
    ["239.255.255.250", "multicast"],
    ["240.0.0.1", "reserved"],
    ["255.255.255.255", "broadcast"],
    // IPv6 loopback / unspecified, in every spelling
    ["::1", "loopback"],
    ["[::1]", "bracketed loopback"],
    ["0:0:0:0:0:0:0:1", "expanded loopback"],
    ["0000:0000:0000:0000:0000:0000:0000:0001", "zero-padded loopback"],
    ["::", "unspecified"],
    ["0:0:0:0:0:0:0:0", "expanded unspecified"],
    // IPv4 inside IPv6
    ["::ffff:127.0.0.1", "IPv4-mapped loopback"],
    ["::FFFF:127.0.0.1", "IPv4-mapped loopback, upper case"],
    ["::ffff:169.254.169.254", "IPv4-mapped metadata"],
    ["::ffff:7f00:1", "IPv4-mapped loopback, hex form"],
    ["0:0:0:0:0:ffff:7f00:1", "IPv4-mapped loopback, expanded hex form"],
    ["0:0:0:0:0:ffff:10.0.0.1", "IPv4-mapped private, expanded dotted form"],
    ["::ffff:0:7f00:1", "IPv4-translated"],
    ["::7f00:1", "IPv4-compatible loopback"],
    ["::127.0.0.1", "IPv4-compatible loopback, dotted"],
    ["64:ff9b::7f00:1", "NAT64 → 127.0.0.1"],
    ["64:ff9b::127.0.0.1", "NAT64 → 127.0.0.1, dotted"],
    ["64:ff9b::a9fe:a9fe", "NAT64 → 169.254.169.254"],
    ["64:ff9b::a00:5", "NAT64 → 10.0.0.5"],
    ["64:FF9B::c0a8:101", "NAT64 → 192.168.1.1, upper case"],
    ["64:ff9b:1::1", "local-use NAT64 64:ff9b:1::/48"],
    ["2002:7f00:1::1", "6to4 → 127.0.0.1"],
    ["2002:a9fe:a9fe::1", "6to4 → 169.254.169.254"],
    ["2001:0:4136:e378:8000:63bf:3fff:fdd2", "Teredo"],
    // IPv6 scopes
    ["fe80::1", "link-local"],
    ["fe80::1%eth0", "link-local with zone"],
    ["febf:ffff::1", "link-local high edge of fe80::/10"],
    ["fec0::1", "site-local (deprecated)"],
    ["fc00::1", "unique local"],
    ["fd12:3456:789a::1", "unique local"],
    ["fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "unique local high edge"],
    ["ff02::1", "multicast"],
    ["ff0e::1", "multicast global scope"],
    // Not parseable as an address, and no hostname contains ":" → refused
    ["1::2::3", "malformed IPv6"],
    ["12345::1", "malformed IPv6"],
    ["::1:2:3:4:5:6:7:8", "too many groups"],
    ["example.com:443", "host:port is not a hostname"],
    // alternate IPv4 spellings (pre-existing rule, kept)
    ["2130706433", "decimal 127.0.0.1"],
    ["0x7f000001", "hex 127.0.0.1"],
    ["0177.0.0.1", "octal octet"],
  ];
  const allowed = [
    "8.8.8.8",
    "140.82.112.5",
    "100.63.255.255", // just below CGNAT
    "100.128.0.1", // just above CGNAT (was over-blocked)
    "172.15.255.255",
    "172.32.0.1",
    "169.253.0.1",
    "198.17.255.255",
    "198.20.0.1",
    "192.0.1.1",
    "223.255.255.255",
    "::ffff:8.8.8.8",
    "2606:4700::1111",
    "2001:4860:4860::8888", // 2001:4860::/32 is not Teredo (2001::/32)
    "2a00:1450:4001:81b::200e",
    "64:ff9b::808:808", // NAT64 → 8.8.8.8, a public address on an IPv6-only network
    "64:ff9b::8.8.8.8",
    "2002:808:808::1", // 6to4 → 8.8.8.8
    "fe7f::1", // just below fe80::/10
    "fbff::1", // just below fc00::/7
    "fe00::1", // below fe80::/10: not link-local
    // hostnames are never IP literals
    "github.com",
    "fdic.gov",
    "fcbarcelona.com",
    "fe80.example.com",
    "ff02.example",
  ];

  it("blocks loopback, private, link-local, CGNAT, multicast, reserved and IPv4-in-IPv6 forms", () => {
    for (const [ip, why] of blocked) {
      assert.equal(isPrivateOrLinkLocalIp(ip), true, `${ip} (${why})`);
      assert.equal(isBlockedHost(ip), true, `isBlockedHost ${ip} (${why})`);
    }
  });

  it("does not block public addresses or hostnames", () => {
    for (const ip of allowed) assert.equal(isPrivateOrLinkLocalIp(ip), false, ip);
  });

  it("canonicalIp gives one spelling per address and null for non-addresses", () => {
    assert.equal(canonicalIp("140.82.112.5"), "140.82.112.5");
    assert.equal(canonicalIp("::ffff:140.82.112.5"), "140.82.112.5");
    assert.equal(canonicalIp("::FFFF:8c52:7005"), "140.82.112.5");
    assert.equal(canonicalIp("2606:4700::1111"), canonicalIp("2606:4700:0:0:0:0:0:1111"));
    assert.equal(canonicalIp("[2606:4700::1111]"), "2606:4700:0:0:0:0:0:1111");
    assert.equal(canonicalIp("FE80::1%eth0"), "fe80:0:0:0:0:0:0:1");
    assert.notEqual(canonicalIp("2606:4700::1111"), canonicalIp("2606:4700::1112"));
    for (const bad of ["github.com", "", "256.1.1.1", "010.0.0.1", "1.2.3", "1::2::3", "localhost"]) {
      assert.equal(canonicalIp(bad), null, bad);
    }
  });
});
