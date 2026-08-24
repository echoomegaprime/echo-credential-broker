import {
  assertSafeDestination,
  PROVIDER_POLICIES,
  type ProviderPolicy,
} from "./policy.ts";
import { redactString, sanitizeError } from "./redaction.ts";
import type { HttpMethod, ProviderId } from "./types.ts";

export interface BrokerRequest {
  provider: ProviderId;
  url: URL;
  method: HttpMethod;
  secret: string;
  headerName?: string;
  headerValuePrefix?: string;
  extraHeaders?: Record<string, string>;
  body?: unknown;
  accept?: string;
}

export interface BrokerHttpResult {
  status: number;
  ok: boolean;
  json: unknown;
  text: string | null;
}

function authorizationHeader(req: BrokerRequest): string {
  const prefix = req.headerValuePrefix ?? "Bearer ";
  return `${prefix}${req.secret}`;
}

export async function authorizedProviderFetch(
  req: BrokerRequest,
): Promise<BrokerHttpResult> {
  const policy: ProviderPolicy = PROVIDER_POLICIES[req.provider];
  assertSafeDestination(req.url, req.provider);

  if (req.body != null) {
    const serialized = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
    if (Buffer.byteLength(serialized) > policy.maxRequestBytes) {
      throw Object.assign(new Error("request_too_large"), {
        code: "request_too_large",
      });
    }
  }

  const headers = new Headers();
  headers.set(req.headerName ?? "Authorization", authorizationHeader(req));
  headers.set("User-Agent", "Echo-Credential-Broker/1.0");
  if (req.accept) headers.set("Accept", req.accept);
  if (req.body != null && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (req.extraHeaders) {
    for (const [k, v] of Object.entries(req.extraHeaders)) {
      if (k.toLowerCase() === "authorization") continue;
      headers.set(k, v);
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), policy.timeoutMs);
  try {
    const init: RequestInit = {
      method: req.method,
      headers,
      redirect: "error",
      signal: controller.signal,
    };
    if (req.body != null && req.method !== "GET") {
      init.body =
        typeof req.body === "string" ? req.body : JSON.stringify(req.body);
    }
    const res = await fetch(req.url, init);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.byteLength > policy.maxResponseBytes) {
      throw Object.assign(new Error("response_too_large"), {
        code: "response_too_large",
      });
    }
    const text = buf.toString("utf8");
    const redactedText = redactString(text);
    let json: unknown = null;
    const contentType = res.headers.get("content-type") ?? "";
    if (contentType.includes("json") || redactedText.startsWith("{") || redactedText.startsWith("[")) {
      try {
        json = JSON.parse(redactedText);
      } catch {
        json = null;
      }
    }
    return {
      status: res.status,
      ok: res.ok,
      json,
      text: json == null ? redactedText.slice(0, 4096) : null,
    };
  } catch (error) {
    throw sanitizeError(error);
  } finally {
    clearTimeout(timer);
  }
}

export function githubAuthHeaders(): Record<string, string> {
  return {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}
