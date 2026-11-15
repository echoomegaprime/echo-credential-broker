// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * MCP JSON-RPC handler. Transport-agnostic: the caller (HTTP route or stdio
 * script) authenticates first and passes the resulting ClientIdentity. No
 * header, argument or environment value can name the caller from in here.
 * Every tools/call goes through v2/gateway.ts dispatchTool.
 */
import { redactValue, safeJson, sanitizeError } from "./redaction.ts";
import { INVARIANT } from "./types.ts";
import type { ClientIdentity } from "./v2/contracts.ts";
import { dispatchTool, listTools, type GatewayDeps } from "./v2/gateway.ts";

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
}

export const MCP_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"] as const;
export const MCP_SERVER_INFO = { name: "echo-credential-broker", version: "2.0.0" } as const;

const INSTRUCTIONS =
  `${INVARIANT} There is no tool that returns a secret. ` +
  "Tier 0 tools read; tier 1 tools make reversible writes; tier 2 tools return `approval_required` with an approval_id — " +
  "the owner approves on Telegram, then you call the same tool again with the same arguments plus approval_id. " +
  "To use a site credential, call entry_list then entry_use; if no entry exists, call entry_request_card and the owner types the secret on a private page.";

function rpcError(id: string | number | null, code: number, message: string) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

/**
 * Handle one JSON-RPC message for an authenticated client. Returns the
 * response object, or null for a notification (no id), which gets no response.
 */
export async function handleMcpRequest(body: unknown, identity: ClientIdentity, deps: GatewayDeps = {}): Promise<unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) return rpcError(null, -32600, "invalid_request");
  const req = body as JsonRpcRequest;
  const isNotification = req.id === undefined;
  const id = req.id ?? null;
  const method = typeof req.method === "string" ? req.method : "";
  if (isNotification) return null;
  if (!identity || typeof identity.client_id !== "string" || !identity.client_id) return rpcError(id, -32001, "unauthenticated");
  try {
    switch (method) {
      case "initialize": {
        const requested = (req.params as { protocolVersion?: unknown } | undefined)?.protocolVersion;
        const protocolVersion = (MCP_PROTOCOL_VERSIONS as readonly unknown[]).includes(requested)
          ? (requested as string)
          : MCP_PROTOCOL_VERSIONS[0];
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion,
            serverInfo: MCP_SERVER_INFO,
            capabilities: { tools: {} },
            instructions: INSTRUCTIONS,
          },
        };
      }
      case "tools/list":
        return { jsonrpc: "2.0", id, result: { tools: listTools() } };
      case "ping":
        return { jsonrpc: "2.0", id, result: {} };
      case "tools/call": {
        const params = (req.params ?? {}) as { name?: unknown; arguments?: unknown };
        const name = typeof params.name === "string" ? params.name : "";
        const payload = redactValue(await dispatchTool(identity, name, params.arguments ?? {}, deps));
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: safeJson(payload) }],
            isError: payload.ok === false,
            structuredContent: payload,
          },
        };
      }
      default:
        return rpcError(id, -32601, "method_not_found");
    }
  } catch (error) {
    return rpcError(id, -32603, sanitizeError(error).message.slice(0, 300));
  }
}
