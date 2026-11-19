import { createFileRoute } from "@tanstack/react-router";

/**
 * Node import (begin): a fleet node pushes credentials it found on its own disks
 * into the vault after the owner approves that node. Write-only — see
 * src/lib/vault/v2/node-import.ts and docs/ops/credential-import.md.
 */
export const Route = createFileRoute("/api/import/begin")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleImportBegin } = await import("@/lib/vault/v2/node-import.ts");
        return handleImportBegin(request);
      },
    },
  },
});
