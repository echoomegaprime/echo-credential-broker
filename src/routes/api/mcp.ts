import { createFileRoute } from "@tanstack/react-router";

/**
 * MCP endpoint (Streamable HTTP, JSON responses). Authentication is an OAuth
 * bearer token or a workload token — see src/lib/vault/v2/http-transport.ts.
 * No self-asserted header is trusted.
 */
export const Route = createFileRoute("/api/mcp")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { handleMcpGet } = await import("@/lib/vault/v2/http-transport.ts");
        return handleMcpGet(request);
      },
      POST: async ({ request }) => {
        const { handleMcpPost } = await import("@/lib/vault/v2/http-transport.ts");
        return handleMcpPost(request);
      },
    },
  },
});
