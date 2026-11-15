// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * DNS-pinned HTTPS transport for requests that carry a credential.
 *
 * The problem it closes: "resolve the host, check the addresses, then
 * fetch(url)" resolves the name twice. A DNS-rebinding attacker answers the
 * first lookup (the one that is checked) with a public address and the second
 * (the one that is used) with 127.0.0.1, 169.254.169.254 or an RFC 1918
 * address, and the request, Authorization header included, goes inside.
 *
 * `pinnedFetch` never resolves anything. The caller hands it the addresses it
 * already validated; the connection is made through a `lookup` that can only
 * answer with those, and after the TLS handshake the socket's remote address
 * is checked again before a single request byte (headers included) is written.
 *
 *   - SNI and the Host header are the original hostname, so the certificate
 *     is verified against the hostname, exactly as with a normal request.
 *     TLS verification is never relaxed here.
 *   - Redirects are not followed: the 3xx and its Location go back to the
 *     caller untouched.
 *   - One fresh connection per request (`agent: false`): no pooled socket to
 *     an address validated for an earlier request can be reused.
 *   - A timeout covers connect + TLS + headers + body, and the body is
 *     streamed and abandoned past `maxResponseBytes`.
 *   - Every failure is a fixed code. No error text is built from request
 *     headers or bodies, so a secret cannot ride out in an exception.
 */
import https from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { canonicalIp, isPrivateOrLinkLocalIp } from "../policy.ts";

export interface PinnedRequestInit {
  method?: string;
  headers?: HeadersInit;
  body?: string | Uint8Array | null;
  signal?: AbortSignal | null;
  /** Accepted for fetch-compatibility. Redirects are never followed, whatever is passed. */
  redirect?: RequestRedirect;
}

export interface PinnedFetchOptions {
  /** The ONLY addresses the connection may go to. IP literals, already validated by the caller. */
  addresses: readonly string[];
  /** Whole-request deadline (connect, TLS, headers, body). Default 12 s. */
  timeoutMs?: number;
  /** Response body cap in bytes; past it the request fails with `response_too_large`. Default 1 MiB. */
  maxResponseBytes?: number;
  /** Told the address the socket actually connected to, after it passed the checks. */
  onConnect?: (address: string) => void;
  /**
   * TEST ONLY. Production callers must not set this: every field relaxes a
   * check so that a test can talk to a throwaway HTTPS server on loopback.
   */
  testOnly?: {
    /** Let pinned / connected addresses be loopback or private. */
    allowPrivateAddresses?: boolean;
    /** Extra trust anchor (the test's self-signed certificate). Verification itself stays on. */
    ca?: string | Buffer;
    /** Replace the pinned lookup, to simulate a resolver that answers outside the pinned set. */
    lookup?: LookupFunction;
  };
}

export type PinnedFetch = (url: URL | string, init: PinnedRequestInit, options: PinnedFetchOptions) => Promise<Response>;

const DEFAULT_TIMEOUT_MS = 12_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
/** Statuses for which the Response constructor refuses a body. */
const NULL_BODY_STATUS = new Set([204, 205, 304]);

/** An error whose message is a fixed code. `detail` is a Node error code (ECONNREFUSED, CERT_HAS_EXPIRED…), never free text. */
export class PinnedFetchError extends Error {
  readonly code: string;
  readonly detail?: string;
  constructor(code: string, detail?: string) {
    super(code);
    this.name = code === "request_timeout" ? "TimeoutError" : "PinnedFetchError";
    this.code = code;
    if (detail) this.detail = detail;
  }
}

function nodeErrorCode(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[A-Z0-9_]{1,64}$/.test(code) ? code : undefined;
}

/**
 * A `lookup` that ignores the hostname and answers only from `addresses`.
 * Exported for tests; `pinnedFetch` is the only production caller.
 */
export function pinnedLookup(addresses: readonly string[]): LookupFunction {
  const records = addresses.map((address) => ({ address, family: isIP(address) }));
  return (_hostname, options, callback) => {
    const wanted = typeof options === "object" && options !== null && (options.family === 4 || options.family === 6) ? options.family : 0;
    const usable = wanted ? records.filter((r) => r.family === wanted) : records;
    if (usable.length === 0) {
      callback(Object.assign(new Error("hostname_not_allowed"), { code: "ENOTFOUND" }), "", 0);
      return;
    }
    if (typeof options === "object" && options !== null && options.all) {
      (callback as unknown as (err: null, all: Array<{ address: string; family: number }>) => void)(null, usable.map((r) => ({ ...r })));
    } else {
      callback(null, usable[0].address, usable[0].family);
    }
  };
}

/**
 * One HTTPS request to `url`, connected only to one of `options.addresses`.
 * Resolves with a standard `Response` whose body is already bounded by
 * `maxResponseBytes`. Rejects with a `PinnedFetchError`:
 *   hostname_not_allowed  bad URL, an address that is not a public IP literal,
 *                         or a socket that connected outside the pinned set
 *   request_timeout       the deadline passed (name: "TimeoutError")
 *   response_too_large    the body exceeded the cap
 *   request_aborted       the caller's signal fired
 *   site_request_failed   connect / TLS / protocol failure (`detail` = Node code)
 */
export const pinnedFetch: PinnedFetch = async (input, init, options) => {
  let url: URL;
  try {
    url = input instanceof URL ? input : new URL(input);
  } catch {
    throw new PinnedFetchError("hostname_not_allowed");
  }
  if (url.protocol !== "https:" || url.username || url.password || !url.hostname) throw new PinnedFetchError("hostname_not_allowed");
  const hostname = url.hostname.replace(/^\[(.*)\]$/, "$1");
  const allowPrivate = options.testOnly?.allowPrivateAddresses === true;

  // The pinned set: IP literals only, none of them private (unless a test says so).
  const pinned = new Map<string, string>(); // canonical → as given
  for (const address of options.addresses) {
    const canonical = isIP(address) ? canonicalIp(address) : null;
    if (!canonical) throw new PinnedFetchError("hostname_not_allowed");
    if (!allowPrivate && isPrivateOrLinkLocalIp(address)) throw new PinnedFetchError("hostname_not_allowed");
    pinned.set(canonical, address);
  }
  if (pinned.size === 0) throw new PinnedFetchError("hostname_not_allowed");
  // Node skips `lookup` for an IP-literal host, so such a URL must itself be pinned.
  if (isIP(hostname)) {
    const literal = canonicalIp(hostname);
    if (!literal || !pinned.has(literal)) throw new PinnedFetchError("hostname_not_allowed");
  }

  const headers = new Headers(init.headers ?? undefined);
  headers.delete("host"); // Node writes Host from `host`; a caller must not be able to disagree with SNI
  headers.delete("content-length");
  headers.delete("transfer-encoding");
  headers.set("connection", "close");
  // No transparent decompression here (unlike fetch): ask for the bytes as they are.
  headers.set("accept-encoding", "identity");
  const method = (init.method ?? "GET").toUpperCase();
  const body = init.body === undefined || init.body === null ? null : typeof init.body === "string" ? Buffer.from(init.body, "utf8") : Buffer.from(init.body);
  if (body) headers.set("content-length", String(body.byteLength));
  const headerList: Record<string, string> = {};
  headers.forEach((value, name) => {
    headerList[name] = value;
  });

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const signal = init.signal ?? null;
  if (signal?.aborted) throw new PinnedFetchError(signal.reason instanceof Error && signal.reason.name === "TimeoutError" ? "request_timeout" : "request_aborted");

  return new Promise<Response>((resolve, reject) => {
    let settled = false;
    let req: ReturnType<typeof https.request> | null = null;
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    const fail = (error: PinnedFetchError) => {
      if (settled) return;
      settled = true;
      cleanup();
      req?.destroy();
      reject(error);
    };
    const succeed = (response: Response) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(response);
    };
    const onAbort = () => fail(new PinnedFetchError(signal?.reason instanceof Error && signal.reason.name === "TimeoutError" ? "request_timeout" : "request_aborted"));
    const timer = setTimeout(() => fail(new PinnedFetchError("request_timeout")), timeoutMs);
    signal?.addEventListener("abort", onAbort, { once: true });

    try {
      req = https.request({
        protocol: "https:",
        host: hostname, // → Host header and certificate identity
        servername: isIP(hostname) ? undefined : hostname, // SNI
        port: url.port ? Number(url.port) : 443,
        method,
        path: `${url.pathname}${url.search}`,
        headers: headerList,
        agent: false, // a fresh socket every time: nothing validated earlier is reused
        lookup: options.testOnly?.lookup ?? pinnedLookup([...pinned.values()]),
        ...(options.testOnly?.ca ? { ca: options.testOnly.ca } : {}),
      });
    } catch (err) {
      fail(new PinnedFetchError("site_request_failed", nodeErrorCode(err)));
      return;
    }
    const request = req;

    // Nothing is written until the handshake is done AND the peer address is
    // one we pinned. http.ClientRequest buffers headers until the first
    // write/end, so holding back end() holds back the Authorization header.
    request.once("socket", (socket) => {
      const verifyThenSend = () => {
        const remote = socket.remoteAddress ? canonicalIp(socket.remoteAddress) : null;
        if (!remote || !pinned.has(remote) || (!allowPrivate && isPrivateOrLinkLocalIp(remote))) {
          socket.destroy();
          fail(new PinnedFetchError("hostname_not_allowed"));
          return;
        }
        try {
          options.onConnect?.(remote);
        } catch {
          // an observer must not break the request
        }
        if (settled) return;
        request.end(body ?? undefined);
      };
      // `agent: false` means this socket was created for this request and is
      // still connecting. "secureConnect" fires only after the certificate
      // verified against `servername` (a failed verification destroys the
      // socket and surfaces as "error" instead).
      socket.once("secureConnect", verifyThenSend);
    });

    request.once("error", (err) => fail(new PinnedFetchError("site_request_failed", nodeErrorCode(err))));

    request.once("response", (res) => {
      const responseHeaders = new Headers();
      for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) {
        try {
          responseHeaders.append(res.rawHeaders[i], res.rawHeaders[i + 1]);
        } catch {
          // a header the Fetch API refuses to represent is dropped, not fatal
        }
      }
      const status = res.statusCode ?? 0;
      if (status < 200 || status > 599) {
        fail(new PinnedFetchError("site_request_failed", "BAD_STATUS"));
        return;
      }
      const declared = Number(res.headers["content-length"]);
      if (method !== "HEAD" && Number.isFinite(declared) && declared > maxBytes) {
        fail(new PinnedFetchError("response_too_large"));
        return;
      }
      const chunks: Buffer[] = [];
      let total = 0;
      res.on("data", (chunk: Buffer) => {
        total += chunk.byteLength;
        if (total > maxBytes) {
          fail(new PinnedFetchError("response_too_large")); // destroys the request, and with it the socket
          return;
        }
        chunks.push(chunk);
      });
      res.once("error", (err) => fail(new PinnedFetchError("site_request_failed", nodeErrorCode(err))));
      res.once("aborted", () => fail(new PinnedFetchError("site_request_failed", "ECONNRESET")));
      res.once("end", () => {
        const noBody = method === "HEAD" || NULL_BODY_STATUS.has(status) || total === 0;
        try {
          succeed(new Response(noBody ? null : Buffer.concat(chunks), { status, headers: responseHeaders }));
        } catch {
          fail(new PinnedFetchError("site_request_failed", "BAD_RESPONSE"));
        }
      });
    });
  });
};
