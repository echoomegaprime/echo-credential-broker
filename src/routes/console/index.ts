// library-first: echo.functions.search → no existing impl found (2026-11-14)
import { createFileRoute } from "@tanstack/react-router";

/**
 * Owner console overview (`/console`). All logic — configuration gate, passkey
 * session, CSRF, CSP, escaping — lives in handleConsoleRequest
 * (src/lib/vault/v2/owner-console-pages.ts). No secret ever appears in a response.
 */
async function handle(request: Request): Promise<Response> {
  (await import("@/lib/vault/v2/bootstrap.ts")).ensureV2Configured();
  const { handleConsoleRequest } = await import("@/lib/vault/v2/owner-console-pages.ts");
  return handleConsoleRequest(request);
}

export const Route = createFileRoute("/console/")({
  server: {
    handlers: {
      GET: ({ request }) => handle(request),
      POST: ({ request }) => handle(request),
    },
  },
});
