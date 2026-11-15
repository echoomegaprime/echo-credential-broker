// library-first: echo.functions.search → no existing impl found (2026-11-14)
import { createFileRoute } from "@tanstack/react-router";

/**
 * RFC 8414 authorization-server metadata for ECHO Vault v2.
 *
 * The directory is named `[.]well-known` because TanStack's route generator
 * skips any directory whose name starts with "." — the bracket escape yields
 * the literal URL path `/.well-known/oauth-authorization-server`.
 */
export const Route = createFileRoute("/.well-known/oauth-authorization-server")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        (await import("@/lib/vault/v2/bootstrap.ts")).ensureV2Configured();
        const { handleAuthorizationServerMetadata } = await import("@/lib/vault/v2/oauth-server.ts");
        return handleAuthorizationServerMetadata(request);
      },
      OPTIONS: async ({ request }) => {
        const { handlePreflight } = await import("@/lib/vault/v2/oauth-server.ts");
        return handlePreflight(request);
      },
    },
  },
});
