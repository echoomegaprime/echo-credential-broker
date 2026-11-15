// library-first: echo.functions.search → no existing impl found (2026-11-14)
import { createFileRoute } from "@tanstack/react-router";

/**
 * Vault v2 credential card: the operator opens the single-use link from
 * Telegram, types the secret, and it goes straight to the canonical vault.
 * GET renders the form (never consumes the token); POST stores the secret.
 * All logic — token check, CSRF, size limit, CSP, escaping — lives in
 * handleCardRequest. No secret ever appears in a response.
 */
export const Route = createFileRoute("/card/$token")({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        (await import("@/lib/vault/v2/bootstrap.ts")).ensureV2Configured();
        const { handleCardRequest } = await import("@/lib/vault/v2/card-pages.ts");
        return handleCardRequest(request, params.token);
      },
      POST: async ({ request, params }) => {
        (await import("@/lib/vault/v2/bootstrap.ts")).ensureV2Configured();
        const { handleCardRequest } = await import("@/lib/vault/v2/card-pages.ts");
        return handleCardRequest(request, params.token);
      },
    },
  },
});
