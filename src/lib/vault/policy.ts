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
 * Loopback, private, link-local, CGNAT and unspecified addresses, IPv4 and
 * IPv6 (including IPv4-mapped IPv6). Only IP literals match: a hostname such
 * as "fdic.gov" is not an fd00::/8 address.
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
  if (host === "::1" || host === "::") return true;
  if (/^::ffff:/.test(host)) return true; // hex-form mapped address: refuse rather than decode
  if (/^fe[89ab][0-9a-f]:/.test(host)) return true; // fe80::/10 link-local
  if (/^f[cd][0-9a-f]{2}:/.test(host)) return true; // fc00::/7 unique local
  return false;
}

function isPrivateIpv4(host: string): boolean {
  if (/^0\./.test(host)) return true;
  if (/^169\.254\./.test(host)) return true;
  if (/^127\./.test(host)) return true;
  if (/^10\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[0-2]\d)\./.test(host)) return true;
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
