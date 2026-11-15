import type { HttpMethod, ProviderId } from "./types.ts";

export interface ProviderPolicy {
  provider: ProviderId;
  hosts: readonly string[];
  methods: readonly HttpMethod[];
  pathPrefix: string;
  maxRequestBytes: number;
  maxResponseBytes: number;
  timeoutMs: number;
}

export const PROVIDER_POLICIES: Record<ProviderId, ProviderPolicy> = {
  github: {
    provider: "github",
    hosts: ["api.github.com"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    pathPrefix: "/",
    maxRequestBytes: 256 * 1024,
    maxResponseBytes: 1024 * 1024,
    timeoutMs: 12_000,
  },
  cloudflare: {
    provider: "cloudflare",
    hosts: ["api.cloudflare.com"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    pathPrefix: "/client/v4/",
    maxRequestBytes: 256 * 1024,
    maxResponseBytes: 1024 * 1024,
    timeoutMs: 12_000,
  },
  openai: {
    provider: "openai",
    hosts: ["api.openai.com"],
    methods: ["GET", "POST"],
    pathPrefix: "/v1/",
    maxRequestBytes: 256 * 1024,
    maxResponseBytes: 1024 * 1024,
    timeoutMs: 15_000,
  },
  stripe: {
    provider: "stripe",
    hosts: ["api.stripe.com"],
    methods: ["GET", "POST"],
    pathPrefix: "/v1/",
    maxRequestBytes: 256 * 1024,
    maxResponseBytes: 1024 * 1024,
    timeoutMs: 12_000,
  },
  xai: {
    provider: "xai",
    hosts: ["api.x.ai"],
    methods: ["GET", "POST"],
    pathPrefix: "/v1/",
    maxRequestBytes: 256 * 1024,
    maxResponseBytes: 1024 * 1024,
    timeoutMs: 15_000,
  },
};

const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
  "metadata.google.com",
  "instance-data",
]);

const BLOCKED_SUFFIXES = [".internal", ".local", ".localhost"];

export function isBlockedHost(hostname: string): boolean {
  const host = normalizeHost(hostname);
  if (!host) return true;
  if (BLOCKED_HOSTS.has(host)) return true;
  if (BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) return true;
  if (isPrivateOrLinkLocalIp(host)) return true;
  return false;
}

function normalizeHost(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/\.$/, "").replace(/^\[(.*)\]$/, "$1");
}

/**
 * Loopback, private, link-local, CGNAT, multicast, reserved and unspecified
 * addresses, IPv4 and IPv6 (including every way an IPv4 address can ride
 * inside an IPv6 one: IPv4-mapped, IPv4-compatible, NAT64, 6to4). Only IP
 * literals match: a hostname such as "fdic.gov" is not an fd00::/8 address.
 */
export function isPrivateOrLinkLocalIp(input: string): boolean {
  const host = normalizeHost(input);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return isPrivateIpv4(host);
  // Defense-in-depth: alternate IPv4 literal spellings (decimal/hex integer,
  // hex or octal octets) can encode a loopback/internal address while slipping
  // past the dotted-quad check above. A real DNS hostname is never all-numeric,
  // 0x-hex, nor carries an 0x/leading-zero octet, so refuse rather than decode.
  if (/^\d+$/.test(host) || /^0x[0-9a-f]+$/.test(host)) return true;
  if (host.includes(".") && !host.includes(":")) {
    const octets = host.split(".");
    if (octets.every((o) => /^(0x[0-9a-f]+|\d+)$/.test(o)) &&
        octets.some((o) => /^0x/.test(o) || (/^0\d/.test(o)))) {
      return true;
    }
  }
  if (!host.includes(":")) return false;
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(host);
  if (mapped) return isPrivateIpv4(mapped[1]);
  // A DNS hostname never contains ":", so anything left is an IPv6 literal or
  // garbage. Parse it properly (compressed, expanded, upper/lower case, zone
  // id, dotted tail) instead of pattern-matching one spelling; refuse what
  // does not parse.
  const groups = parseIpv6(host);
  if (!groups) return true;
  return isBlockedIpv6(groups);
}

/**
 * IPv6 literal → 8 hextets, or null when the text is not one. Accepts "::"
 * compression, a dotted IPv4 tail and a "%zone" suffix (ignored: the zone
 * selects an interface, not an address).
 */
function parseIpv6(input: string): number[] | null {
  const text = input.replace(/%[^%]*$/, "");
  if (!/^[0-9a-f:.]+$/.test(text) || !text.includes(":")) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const parseSide = (side: string): number[] | null => {
    if (side === "") return [];
    const out: number[] = [];
    const parts = side.split(":");
    for (let i = 0; i < parts.length; i += 1) {
      const part = parts[i];
      if (part.includes(".")) {
        if (i !== parts.length - 1) return null; // dotted quad only as the tail
        const o = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(part);
        if (!o) return null;
        const b = o.slice(1).map(Number);
        if (b.some((n) => n > 255)) return null;
        out.push((b[0] << 8) | b[1], (b[2] << 8) | b[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
        out.push(parseInt(part, 16));
      }
    }
    return out;
  };
  const head = parseSide(halves[0]);
  const tail = halves.length === 2 ? parseSide(halves[1]) : [];
  if (!head || !tail) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  // A dotted tail before "::" would be mid-address; "::" must stand for >= 1 group.
  if (halves[0].includes(".")) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 1) return null;
  return [...head, ...new Array<number>(missing).fill(0), ...tail];
}

function embeddedIpv4(hi: number, lo: number): string {
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

function isBlockedIpv6(g: readonly number[]): boolean {
  const zero = (from: number, to: number) => g.slice(from, to).every((n) => n === 0);
  // ::/96 — unspecified (::), loopback (::1) and the deprecated IPv4-compatible range.
  if (zero(0, 6)) return true;
  // ::ffff:0:0/96 IPv4-mapped in any spelling other than the canonical dotted
  // one handled by the caller, and ::ffff:0:0:0/96 IPv4-translated: refuse.
  if (zero(0, 5) && g[5] === 0xffff) return true;
  if (zero(0, 4) && g[4] === 0xffff && g[5] === 0) return true;
  // 64:ff9b::/96 well-known NAT64 prefix: the last 32 bits ARE an IPv4 address.
  if (g[0] === 0x64 && g[1] === 0xff9b && zero(2, 6)) return isPrivateIpv4(embeddedIpv4(g[6], g[7]));
  // 64:ff9b:1::/48 local-use NAT64 (RFC 8215): operator-local by definition.
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return true;
  // 2002::/16 6to4: bits 16..47 are the IPv4 address of the relay target.
  if (g[0] === 0x2002) return isPrivateIpv4(embeddedIpv4(g[1], g[2]));
  // 2001::/32 Teredo: tunnels to an obfuscated IPv4 endpoint.
  if (g[0] === 0x2001 && g[1] === 0) return true;
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local (deprecated)
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  return false;
}

/**
 * One comparable spelling per address, or null when the text is not an IP
 * literal: dotted quad for IPv4 and IPv4-mapped IPv6, eight lower-case
 * hextets for the rest. Used to compare a socket's remote address with the
 * addresses a request was pinned to.
 */
export function canonicalIp(input: string): string | null {
  const host = normalizeHost(input);
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (v4) {
    const octets = v4.slice(1);
    if (octets.some((o) => Number(o) > 255 || (o.length > 1 && o.startsWith("0")))) return null;
    return octets.map(Number).join(".");
  }
  const g = parseIpv6(host);
  if (!g) return null;
  if (g.slice(0, 5).every((n) => n === 0) && g[5] === 0xffff) return embeddedIpv4(g[6], g[7]);
  return g.map((n) => n.toString(16)).join(":");
}

function isPrivateIpv4(host: string): boolean {
  if (/^0\./.test(host)) return true; // 0.0.0.0/8 "this network"
  if (/^169\.254\./.test(host)) return true; // link-local, cloud metadata
  if (/^127\./.test(host)) return true;
  if (/^10\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host)) return true; // 100.64.0.0/10 CGNAT (100.64 – 100.127)
  if (/^192\.0\.0\./.test(host)) return true; // 192.0.0.0/24 IETF protocol assignments
  if (/^198\.1[89]\./.test(host)) return true; // 198.18.0.0/15 benchmarking
  if (/^(22[4-9]|23\d)\./.test(host)) return true; // 224.0.0.0/4 multicast
  if (/^(24\d|25[0-5])\./.test(host)) return true; // 240.0.0.0/4 reserved, incl. broadcast
  return false;
}

export function isAllowedHostForProvider(
  provider: ProviderId,
  hostname: string,
): boolean {
  if (isBlockedHost(hostname)) return false;
  const policy = PROVIDER_POLICIES[provider];
  return policy.hosts.includes(hostname.toLowerCase());
}

export function isAllowedMethod(
  provider: ProviderId,
  method: string,
): method is HttpMethod {
  const upper = method.toUpperCase();
  return (PROVIDER_POLICIES[provider].methods as readonly string[]).includes(
    upper,
  );
}

export function normalizeResourcePath(resource: string): string {
  const trimmed = resource.trim();
  if (!trimmed.startsWith("/")) {
    throw Object.assign(new Error("invalid_resource"), {
      code: "invalid_resource",
    });
  }
  if (trimmed.includes("://") || trimmed.startsWith("//")) {
    throw Object.assign(new Error("absolute_url_forbidden"), {
      code: "absolute_url_forbidden",
    });
  }
  if (trimmed.includes("\\") || trimmed.includes("\0")) {
    throw Object.assign(new Error("invalid_resource"), {
      code: "invalid_resource",
    });
  }
  const decoded = decodeURIComponent(trimmed);
  if (decoded.includes("://") || /(?:^|\/)\.\.(?:\/|$)/.test(decoded)) {
    throw Object.assign(new Error("invalid_resource"), {
      code: "invalid_resource",
    });
  }
  return trimmed.replace(/\/{2,}/g, "/");
}

export function buildProviderUrl(
  provider: ProviderId,
  resource: string,
): URL {
  const path = normalizeResourcePath(resource);
  const host = PROVIDER_POLICIES[provider].hosts[0];
  const url = new URL(`https://${host}${path}`);
  if (url.protocol !== "https:") {
    throw Object.assign(new Error("https_required"), { code: "https_required" });
  }
  if (!isAllowedHostForProvider(provider, url.hostname)) {
    throw Object.assign(new Error("hostname_not_allowed"), {
      code: "hostname_not_allowed",
    });
  }
  return url;
}

export function assertSafeDestination(url: URL, provider: ProviderId): void {
  if (url.protocol !== "https:") {
    throw Object.assign(new Error("https_required"), { code: "https_required" });
  }
  if (isBlockedHost(url.hostname) || isPrivateOrLinkLocalIp(url.hostname)) {
    throw Object.assign(new Error("hostname_not_allowed"), {
      code: "hostname_not_allowed",
    });
  }
  if (!isAllowedHostForProvider(provider, url.hostname)) {
    throw Object.assign(new Error("hostname_not_allowed"), {
      code: "hostname_not_allowed",
    });
  }
}

export const FORBIDDEN_FILE_PATHS = [
  ".env",
  "credentials.json",
  "tokens.json",
  ".pem",
  ".key",
  "github.token",
  "id_rsa",
  "id_ed25519",
];
