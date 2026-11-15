// library-first: echo.functions.search → no existing impl found (2026-11-14)
import { createFileRoute } from "@tanstack/react-router";

/**
 * RFC 9728 protected-resource metadata for the MCP endpoint (`/api/mcp`).
 * 401s from /api/mcp point here via `WWW-Authenticate: Bearer resource_metadata="…"`.
 * See oauth-authorization-server.ts for why the directory is `[.]well-known`.
 */
export const Route = createFileRoute("/.well-known/oauth-protected-resource")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        (await import("@/lib/vault/v2/bootstrap.ts")).ensureV2Configured();
        const { handleProtectedResourceMetadata } = await import("@/lib/vault/v2/oauth-server.ts");
        return handleProtectedResourceMetadata(request);
      },
      OPTIONS: async ({ request }) => {
        const { handlePreflight } = await import("@/lib/vault/v2/oauth-server.ts");
        return handlePreflight(request);
      },
    },
  },
});
