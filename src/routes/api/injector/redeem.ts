import { createFileRoute } from "@tanstack/react-router";

/**
 * Browser injector: exchange a single-use ticket for the credential sealed to
 * the injector's public key. `Authorization: Bearer ein_…` only — see
 * src/lib/vault/v2/injector-http.ts and docs/ops/injector-contract.md.
 */
export const Route = createFileRoute("/api/injector/redeem")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleInjectorRedeem } = await import("@/lib/vault/v2/injector-http.ts");
        return handleInjectorRedeem(request);
      },
    },
  },
});
