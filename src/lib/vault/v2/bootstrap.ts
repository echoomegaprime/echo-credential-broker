// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Wires the v2 pieces together at runtime:
 *   - OAuth `/authorize` asks the owner on Telegram before any connection is granted.
 *
 * Call `ensureV2Configured()` at the top of every v2 route handler. It is idempotent.
 */
import type { CapabilityRequest } from "./contracts.ts";
import { createApproval, getApproval } from "./approvals.ts";
import {
  configureOAuth,
  type ClientApprovalRequest,
  type ClientApprovalStatus,
  type OwnerApprover,
} from "./oauth-server.ts";

const CLIENT_AUTHORIZE_CAPABILITY = "vault.client.authorize";

function clientApprovalSummary(r: ClientApprovalRequest): string {
  // client_name is self-asserted by the registering client, so the redirect host leads.
  const verb = r.is_new_client === false ? "Reconnect" : "New connection";
  const scopes = r.requested_scopes.length ? r.requested_scopes.join(", ") : "no scopes";
  return `${verb} from ${r.redirect_host} calling itself "${r.client_name}" wants: ${scopes}`;
}

/** OwnerApprover backed by the request-bound Telegram approvals. */
export const telegramOwnerApprover: OwnerApprover = {
  async requestClientApproval(r: ClientApprovalRequest): Promise<{ approval_id: string }> {
    const req: CapabilityRequest = {
      client: { client_id: r.client_id, name: r.client_name, kind: "oauth", scopes: [] },
      capability: CLIENT_AUTHORIZE_CAPABILITY,
      resource: `oauth:${r.redirect_host}`,
      params: { requested_scopes: [...r.requested_scopes].sort(), is_new_client: r.is_new_client !== false },
    };
    const record = await createApproval(req, clientApprovalSummary(r));
    return { approval_id: record.id };
  },

  async checkClientApproval(approvalId: string): Promise<ClientApprovalStatus> {
    const record = await getApproval(approvalId);
    if (!record || record.capability !== CLIENT_AUTHORIZE_CAPABILITY) return "denied";
    switch (record.status) {
      case "approved":
      case "consumed":
        return "approved";
      case "pending":
        return "pending";
      case "expired":
        return "expired";
      default:
        return "denied";
    }
  },
};

let configured = false;

export function ensureV2Configured(): void {
  if (configured) return;
  configureOAuth({ approver: telegramOwnerApprover });
  configured = true;
}
