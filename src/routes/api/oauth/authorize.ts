// library-first: echo.functions.search → no existing impl found (2026-11-14)
import { createFileRoute } from "@tanstack/react-router";

/**
 * OAuth 2.1 authorization endpoint (PKCE S256 only). Renders the
 * "Approve this connection on your phone" page, which polls this same route
 * with `?pending=…` until the owner decides, then 302s to the client.
 */
export const Route = createFileRoute("/api/oauth/authorize")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        (await import("@/lib/vault/v2/bootstrap.ts")).ensureV2Configured();
        const { handleAuthorize } = await import("@/lib/vault/v2/oauth-server.ts");
        return handleAuthorize(request);
      },
    },
  },
});
