// library-first: echo.functions.search → no existing impl found (2026-11-15)
import { createFileRoute } from "@tanstack/react-router";

/**
 * Second approval decider, for Lyra's consent bridge on the same host:
 * loopback-only + a dedicated service token. All logic — loopback check,
 * token auth, scope check, the decision and its ledger row — lives in
 * handleBridgeDecide / decideApprovalAsService. No secret ever appears in
 * the response. See docs/ops/bridge-decider.md.
 */
export const Route = createFileRoute("/api/internal/approvals/decide")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleBridgeDecide } = await import("@/lib/vault/v2/bridge-decider.ts");
        return handleBridgeDecide(request);
      },
    },
  },
});
