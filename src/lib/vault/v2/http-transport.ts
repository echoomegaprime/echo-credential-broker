// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * HTTP transports for the vault: `/api/mcp` (MCP Streamable HTTP, JSON
 * responses) and `/api/rest/tool` (one flat POST per tool call, for services
 * that cannot speak JSON-RPC). The route files are thin wrappers around these
 * functions so the whole request path is testable without a server.
 *
 * Authentication (both routes): `Authorization: Bearer <token>` only.
 *   eva_…  OAuth access token issued by oauth-server.ts after the owner approved the client
 *   ewk_…  workload token whose SHA-256 is listed in ECHO_VAULT_WORKLOAD_TOKENS_FILE
 * `x-echo-agent`, `x-echo-caller` and every other self-asserted header are ignored.
 *
 * Unauthenticated requests get 401 with `WWW-Authenticate: Bearer
 * resource_metadata="…"` (MCP authorization spec, RFC 9728 §5.1), plus
 * `error="invalid_token"` when a credential was presented and rejected.
 */
import { log } from "../log.ts";
import { handleMcpRequest, MCP_SERVER_INFO } from "../mcp.ts";
import { redactValue, safeJson } from "../redaction.ts";
import { INVARIANT } from "../types.ts";
import { ensureV2Configured } from "./bootstrap.ts";
import type { ClientIdentity } from "./contracts.ts";
import { dispatchTool, listTools, type GatewayDeps } from "./gateway.ts";
import { authenticateRequest, wwwAuthenticateHeader } from "./identity.ts";
import { PROTECTED_RESOURCE_METADATA_PATH } from "./oauth-server.ts";
import { authenticateWorkload } from "./workload.ts";

export const MAX_TOOL_BODY_BYTES = 1024 * 1024;

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } as const;

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(safeJson(body), { status, headers: { ...JSON_HEADERS, ...extra } });
}

/** OAuth bearer first, then workload token. Null = not authenticated. */
export async function authenticateHttp(headers: Headers): Promise<ClientIdentity | null> {
  ensureV2Configured();
  return (await authenticateRequest(headers)) ?? authenticateWorkload(headers);
}

export function unauthorizedResponse(headers: Headers): Response {
  const presented = headers.has("authorization");
  return json(
    401,
    { error: presented ? "invalid_token" : "unauthorized", error_description: "Connect with OAuth: see the resource metadata named in WWW-Authenticate." },
    { "www-authenticate": presented ? wwwAuthenticateHeader({ error: "invalid_token" }) : wwwAuthenticateHeader() },
  );
}

async function readJsonBody(request: Request): Promise<{ ok: true; value: unknown } | { ok: false; response: Response }> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_TOOL_BODY_BYTES) return { ok: false, response: json(413, { error: "request_too_large" }) };
  let text: string;
  try {
    const buf = Buffer.from(await request.arrayBuffer());
    if (buf.byteLength > MAX_TOOL_BODY_BYTES) return { ok: false, response: json(413, { error: "request_too_large" }) };
    text = buf.toString("utf8");
  } catch {
    return { ok: false, response: json(400, { error: "invalid_body" }) };
  }
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, response: json(400, { error: "invalid_json_body" }) };
  }
}

/** GET /api/mcp. Unauthenticated callers learn the server name, the invariant and where to authenticate — not the tool list. */
export async function handleMcpGet(request: Request): Promise<Response> {
  if ((request.headers.get("accept") ?? "").includes("text/event-stream")) {
    // Streamable HTTP: this server does not offer a server-initiated SSE stream.
    return new Response(null, { status: 405, headers: { allow: "POST", "cache-control": "no-store" } });
  }
  const identity = await authenticateHttp(request.headers);
  const base = {
    name: MCP_SERVER_INFO.name,
    version: MCP_SERVER_INFO.version,
    invariant: INVARIANT,
    authentication: "oauth2",
    resource_metadata: PROTECTED_RESOURCE_METADATA_PATH,
  };
  if (!identity) return json(200, base);
  return json(200, { ...base, client_id: identity.client_id, scopes: identity.scopes, tools: listTools() });
}

/** POST /api/mcp: one JSON-RPC message per request. */
export async function handleMcpPost(request: Request, deps: GatewayDeps = {}): Promise<Response> {
  const identity = await authenticateHttp(request.headers);
  if (!identity) return unauthorizedResponse(request.headers);
  const body = await readJsonBody(request);
  if (!body.ok) return body.response;
  if (Array.isArray(body.value)) {
    return json(200, { jsonrpc: "2.0", id: null, error: { code: -32600, message: "batch_not_supported" } });
  }
  const result = await handleMcpRequest(body.value, identity, deps);
  if (result === null) return new Response(null, { status: 202, headers: { "cache-control": "no-store" } });
  return json(200, redactValue(result));
}

/**
 * POST /api/rest/tool — body {"tool": "<name>", "arguments": {...}} →
 * {"ok": true, "result": <tool result>}. Same authentication and the same
 * dispatchTool as MCP: a transport shim, not a second authority.
 */
export async function handleRestTool(request: Request, deps: GatewayDeps = {}): Promise<Response> {
  const identity = await authenticateHttp(request.headers);
  if (!identity) return unauthorizedResponse(request.headers);
  const body = await readJsonBody(request);
  if (!body.ok) return body.response;
  const { tool, arguments: args } = (body.value && typeof body.value === "object" ? body.value : {}) as {
    tool?: unknown;
    arguments?: unknown;
  };
  if (typeof tool !== "string" || !tool) return json(400, { ok: false, error: "tool_required" });
  const result = redactValue(await dispatchTool(identity, tool, args ?? {}, deps));
  log.info("rest_tool", { client_id: identity.client_id, tool: tool.slice(0, 64), ok: result.ok });
  return json(200, { ok: true, result });
}
