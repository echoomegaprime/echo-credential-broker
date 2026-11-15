import { createFileRoute } from "@tanstack/react-router";

/**
 * Stateless REST wrapper around dispatchTool() — for callers that cannot do
 * the MCP JSON-RPC envelope (the ECHO SDK gate's handler_kind='http'
 * dispatcher makes one bare POST with a flat JSON body).
 *
 * Body: {"tool": "<name>", "arguments": {...}}
 * Auth: `Authorization: Bearer` — a workload token (ewk_…) or an OAuth access
 * token (eva_…). Same gateway, policy, approvals and ledger as /api/mcp.
 */
export const Route = createFileRoute("/api/rest/tool")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleRestTool } = await import("@/lib/vault/v2/http-transport.ts");
        return handleRestTool(request);
      },
    },
  },
});
