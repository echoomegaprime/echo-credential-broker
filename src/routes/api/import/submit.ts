import { createFileRoute } from "@tanstack/react-router";

/**
 * Node import (submit): a fleet node pushes credentials it found on its own disks
 * into the vault after the owner approves that node. Write-only — see
 * src/lib/vault/v2/node-import.ts and docs/ops/credential-import.md.
 */
export const Route = createFileRoute("/api/import/submit")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleImportSubmit } = await import("@/lib/vault/v2/node-import.ts");
        return handleImportSubmit(request);
      },
    },
  },
});
