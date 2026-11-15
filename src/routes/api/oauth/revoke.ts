// library-first: echo.functions.search → no existing impl found (2026-11-14)
import { createFileRoute } from "@tanstack/react-router";

/** RFC 7009 token revocation (access tokens; refresh tokens revoke their whole family). */
export const Route = createFileRoute("/api/oauth/revoke")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        (await import("@/lib/vault/v2/bootstrap.ts")).ensureV2Configured();
        const { handleRevoke } = await import("@/lib/vault/v2/oauth-server.ts");
        return handleRevoke(request);
      },
      OPTIONS: async ({ request }) => {
        const { handlePreflight } = await import("@/lib/vault/v2/oauth-server.ts");
        return handlePreflight(request);
      },
    },
  },
});
