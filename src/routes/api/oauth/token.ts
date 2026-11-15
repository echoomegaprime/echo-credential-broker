// library-first: echo.functions.search → no existing impl found (2026-11-14)
import { createFileRoute } from "@tanstack/react-router";

/** OAuth 2.1 token endpoint: authorization_code (+PKCE) and rotating refresh_token grants. */
export const Route = createFileRoute("/api/oauth/token")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        (await import("@/lib/vault/v2/bootstrap.ts")).ensureV2Configured();
        const { handleToken } = await import("@/lib/vault/v2/oauth-server.ts");
        return handleToken(request);
      },
      OPTIONS: async ({ request }) => {
        const { handlePreflight } = await import("@/lib/vault/v2/oauth-server.ts");
        return handlePreflight(request);
      },
    },
  },
});
