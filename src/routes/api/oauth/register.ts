// library-first: echo.functions.search → no existing impl found (2026-11-14)
import { createFileRoute } from "@tanstack/react-router";

/** RFC 7591 dynamic client registration (public clients; no scopes until the owner approves). */
export const Route = createFileRoute("/api/oauth/register")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        (await import("@/lib/vault/v2/bootstrap.ts")).ensureV2Configured();
        const { handleRegister } = await import("@/lib/vault/v2/oauth-server.ts");
        return handleRegister(request);
      },
      OPTIONS: async ({ request }) => {
        const { handlePreflight } = await import("@/lib/vault/v2/oauth-server.ts");
        return handlePreflight(request);
      },
    },
  },
});
