// library-first: echo.functions.search → no existing impl found (2026-11-14)
import { createFileRoute } from "@tanstack/react-router";

/**
 * RFC 9728 §3.1 path form: a client that knows only the resource URL
 * `https://host/api/mcp` builds `/.well-known/oauth-protected-resource/api/mcp`.
 * Serves the same document as the root form (which this splat route also
 * matches, with an empty suffix). Any other suffix is 404: this server
 * protects exactly one resource.
 */
export const Route = createFileRoute("/.well-known/oauth-protected-resource/$")({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        const { ensureV2Configured } = await import("@/lib/vault/v2/bootstrap.ts");
        const { handleProtectedResourceMetadata, MCP_RESOURCE_PATH } = await import("@/lib/vault/v2/oauth-server.ts");
        ensureV2Configured();
        // An empty splat is the root form (this route also matches it).
        const suffix = `/${String(params._splat ?? "").replace(/\/+$/, "")}`;
        if (suffix !== "/" && suffix !== MCP_RESOURCE_PATH) {
          return new Response(JSON.stringify({ error: "not_found" }), {
            status: 404,
            headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
          });
        }
        return handleProtectedResourceMetadata(request);
      },
      OPTIONS: async ({ request }) => {
        const { handlePreflight } = await import("@/lib/vault/v2/oauth-server.ts");
        return handlePreflight(request);
      },
    },
  },
});
