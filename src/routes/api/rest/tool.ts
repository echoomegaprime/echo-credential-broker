import { createFileRoute } from "@tanstack/react-router";

/**
 * Stateless REST wrapper around callTool() — for callers that cannot do the
 * MCP tools/call JSON-RPC envelope (the ECHO SDK gate's handler_kind='http'
 * dispatcher makes one bare httpx POST with a flat JSON body, no envelope).
 * Same tool registry, same policy (isApprovedCaller / FORBIDDEN_TOOLS), same
 * redaction — this is a transport shim, not a second authority boundary.
 *
 * Body: {"tool": "<name>", "arguments": {...}}
 * Auth: same as /api/mcp — x-echo-agent header must be an approved caller.
 */
export const Route = createFileRoute("/api/rest/tool")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { log } = await import("@/lib/vault/log.ts");
        const { callTool } = await import("@/lib/vault/tools.ts");
        const { FORBIDDEN_TOOLS } = await import("@/lib/vault/types.ts");
        const { isApprovedCaller } = await import("@/lib/vault/policy.ts");
        const { redactValue, safeJson } = await import("@/lib/vault/redaction.ts");
        const { callerFromHeaders } = await import("@/lib/vault/mcp.ts");

        const caller = callerFromHeaders(request.headers);
        if (!isApprovedCaller(caller)) {
          log.warn("rest_tool_caller_denied", { caller });
          return Response.json({ ok: false, error: "caller_not_allowed" }, { status: 403 });
        }

        let body: unknown = {};
        try {
          body = await request.json();
        } catch {
          return Response.json({ ok: false, error: "invalid_json_body" }, { status: 400 });
        }
        const { tool, arguments: args } = (body ?? {}) as { tool?: string; arguments?: unknown };
        const name = String(tool ?? "");
        if (!name) {
          return Response.json({ ok: false, error: "tool_required" }, { status: 400 });
        }
        if ((FORBIDDEN_TOOLS as readonly string[]).includes(name)) {
          log.warn("rest_tool_forbidden", { caller, tool: name });
          return Response.json({ ok: false, error: "tool_forbidden" }, { status: 403 });
        }

        try {
          const result = await callTool(name, args ?? {}, { caller });
          log.info("rest_tool_ok", { caller, tool: name });
          const payload = redactValue(result);
          return new Response(safeJson({ ok: true, result: payload }), {
            status: 200,
            headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
          });
        } catch (error) {
          log.error("rest_tool_error", { caller, tool: name, message: (error as Error).message });
          return Response.json({ ok: false, error: "internal_error" }, { status: 500 });
        }
      },
    },
  },
});
