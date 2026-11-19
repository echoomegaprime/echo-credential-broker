import { d as getApproval, s as createApproval } from "./approvals-vHr7W1Jg.mjs";
import { o as configureOAuth } from "./oauth-server-BJCUNFGm.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/bootstrap-DBXqHiC1.js
var CLIENT_AUTHORIZE_CAPABILITY = "vault.client.authorize";
function clientApprovalSummary(r) {
	const verb = r.is_new_client === false ? "Reconnect" : "New connection";
	const scopes = r.requested_scopes.length ? r.requested_scopes.join(", ") : "no scopes";
	return `${verb} from ${r.redirect_host} calling itself "${r.client_name}" wants: ${scopes}`;
}
/** OwnerApprover backed by the request-bound Telegram approvals. */
var telegramOwnerApprover = {
	async requestClientApproval(r) {
		const req = {
			client: {
				client_id: r.client_id,
				name: r.client_name,
				kind: "oauth",
				scopes: []
			},
			capability: CLIENT_AUTHORIZE_CAPABILITY,
			resource: `oauth:${r.redirect_host}`,
			params: {
				requested_scopes: [...r.requested_scopes].sort(),
				is_new_client: r.is_new_client !== false
			}
		};
		return { approval_id: (await createApproval(req, clientApprovalSummary(r))).id };
	},
	async checkClientApproval(approvalId) {
		const record = await getApproval(approvalId);
		if (!record || record.capability !== CLIENT_AUTHORIZE_CAPABILITY) return "denied";
		switch (record.status) {
			case "approved":
			case "consumed": return "approved";
			case "pending": return "pending";
			case "expired": return "expired";
			default: return "denied";
		}
	}
};
var configured = false;
function ensureV2Configured() {
	if (configured) return;
	configureOAuth({ approver: telegramOwnerApprover });
	configured = true;
}
//#endregion
export { ensureV2Configured };
