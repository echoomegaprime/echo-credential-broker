import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/mcp")({
  server: {
    handlers: {
      GET: async () => {
        const { listTools } = await import("@/lib/vault/tools.ts");
        const { INVARIANT } = await import("@/lib/vault/types.ts");
        return Response.json({
          name: "echo-credential-broker",
          invariant: INVARIANT,
          tools: listTools(),
        });
      },
      POST: async ({ request }) => {
        const { handleMcpRequest, callerFromHeaders } = await import(
          "@/lib/vault/mcp.ts"
        );
        const { redactValue, safeJson } = await import("@/lib/vault/redaction.ts");
        let body: unknown = {};
        try {
          body = await request.json();
        } catch {
          body = {};
        }
        const caller = callerFromHeaders(request.headers);
        const result = await handleMcpRequest(body, caller);
        const payload = redactValue(result);
        return new Response(safeJson(payload), {
          status: 200,
          headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
          },
        });
      },
    },
  },
});
