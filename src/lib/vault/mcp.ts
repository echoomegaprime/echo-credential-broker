import { redactValue, safeJson, sanitizeError } from "./redaction.ts";
import { callTool, listTools } from "./tools.ts";
import { FORBIDDEN_TOOLS } from "./types.ts";
import { isApprovedCaller } from "./policy.ts";

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
}

export async function handleMcpRequest(
  body: unknown,
  caller: string,
): Promise<unknown> {
  const req = (body ?? {}) as JsonRpcRequest;
  const id = req.id ?? null;
  try {
    if (!isApprovedCaller(caller)) {
      return rpcError(id, -32001, "caller_not_allowed");
    }
    switch (req.method) {
      case "initialize":
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: "2024-11-05",
            serverInfo: {
              name: "echo-credential-broker",
              version: "1.0.0",
            },
            capabilities: { tools: {} },
            instructions:
              "Agents may USE credentials via vault:// references. Agents may NEVER READ credentials. There is no get_secret tool.",
          },
        };
      case "tools/list":
        return {
          jsonrpc: "2.0",
          id,
          result: { tools: listTools() },
        };
      case "ping":
        return { jsonrpc: "2.0", id, result: {} };
      case "tools/call": {
        const params = (req.params ?? {}) as {
          name?: string;
          arguments?: unknown;
        };
        const name = String(params.name ?? "");
        if ((FORBIDDEN_TOOLS as readonly string[]).includes(name)) {
          return rpcError(id, -32601, "tool_forbidden");
        }
        const result = await callTool(name, params.arguments ?? {}, { caller });
        const payload = redactValue(result);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: safeJson(payload),
              },
            ],
            isError: payload.ok === false,
            structuredContent: payload,
          },
        };
      }
      default:
        return rpcError(id, -32601, "method_not_found");
    }
  } catch (error) {
    const clean = sanitizeError(error);
    return rpcError(id, -32603, clean.message);
  }
}

function rpcError(id: string | number | null, code: number, message: string) {
  return {
    jsonrpc: "2.0",
    id,
    error: { code, message },
  };
}

export function callerFromHeaders(headers: Headers): string {
  return (
    headers.get("x-echo-agent") ||
    headers.get("x-echo-caller") ||
    "vault-console"
  );
}
