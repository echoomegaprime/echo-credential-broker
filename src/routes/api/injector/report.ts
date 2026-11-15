import { createFileRoute } from "@tanstack/react-router";

/**
 * Browser injector: report the outcome of an injection ("injected" | "failed").
 * `Authorization: Bearer ein_…` only — see src/lib/vault/v2/injector-http.ts.
 */
export const Route = createFileRoute("/api/injector/report")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleInjectorReport } = await import("@/lib/vault/v2/injector-http.ts");
        return handleInjectorReport(request);
      },
    },
  },
});
