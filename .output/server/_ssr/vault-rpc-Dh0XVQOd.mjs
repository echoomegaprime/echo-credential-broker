import { n as TSS_SERVER_FUNCTION, t as createServerFn } from "./ssr.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/vault-rpc-Dh0XVQOd.js
var createServerRpc = (serverFnMeta, splitImportFn) => {
	const url = "/_serverFn/" + serverFnMeta.id;
	return Object.assign(splitImportFn, {
		url,
		serverFnMeta,
		[TSS_SERVER_FUNCTION]: true
	});
};
function asRpc(value) {
	return JSON.parse(JSON.stringify(value));
}
function parseArgs(raw) {
	if (raw && typeof raw === "object" && !Array.isArray(raw)) {
		const out = {};
		for (const [key, value] of Object.entries(raw)) if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") out[key] = value;
		return out;
	}
	if (typeof raw === "string") try {
		return parseArgs(JSON.parse(raw));
	} catch {
		return {};
	}
	return {};
}
/**
* Owner console RPCs. These are plain server functions: anyone who can reach
* the web port can call them, and there is no login in front of them. So:
*
*   - They are OFF unless `ECHO_VAULT_CONSOLE=local` is set. Set it only when
*     the port is reachable by the owner alone (localhost / a private LAN),
*     never on the public deployment.
*   - When on, every call goes through the same gateway as any agent
*     (dispatchTool) as the fixed identity `local:vault-console`, which holds
*     READ scopes only and is NOT a local/owner identity for the gateway.
*     Writes, approvals-required actions and tier-3 actions (every admin_*
*     tool) get the same answers an under-scoped agent would get. Owner
*     management lives in the passkey console under /console.
*   - There is no reveal. Reading a secret value is tier 3 ("never through
*     this broker"): use the canonical vault directly.
*/
var CONSOLE_SCOPES = [
	"github.read",
	"cloudflare.read",
	"openai.read",
	"stripe.read",
	"xai.read",
	"vault.read",
	"audit.read"
];
function consoleEnabled() {
	return process.env.ECHO_VAULT_CONSOLE?.trim().toLowerCase() === "local";
}
async function consoleCall(name, args) {
	if (!consoleEnabled()) return {
		ok: false,
		error: "console_disabled",
		detail: "Set ECHO_VAULT_CONSOLE=local on a private, owner-only host to enable the console."
	};
	const { dispatchTool } = await import("./gateway-iAPpU1jx.mjs").then((n) => n.n);
	return asRpc(await dispatchTool({
		client_id: "local:vault-console",
		name: "Vault console",
		kind: "workload",
		scopes: [...CONSOLE_SCOPES]
	}, name, args));
}
var rpcVaultStatus_createServerFn_handler = createServerRpc({
	id: "7de7d760af88b04ea9d4e820acb24cb8cdfcbc57d5ea27e3886c7c5e21152f89",
	name: "rpcVaultStatus",
	filename: "src/lib/vault-rpc.ts"
}, (opts) => rpcVaultStatus.__executeServer(opts));
var rpcVaultStatus = createServerFn({ method: "GET" }).handler(rpcVaultStatus_createServerFn_handler, async () => consoleCall("vault_status", {}));
var rpcVaultList_createServerFn_handler = createServerRpc({
	id: "f3b9d1532a52b5ed55e93854c737120df7ab25b75f43d753af8cdeb144f4e1b5",
	name: "rpcVaultList",
	filename: "src/lib/vault-rpc.ts"
}, (opts) => rpcVaultList.__executeServer(opts));
var rpcVaultList = createServerFn({ method: "GET" }).handler(rpcVaultList_createServerFn_handler, async () => consoleCall("vault_list", {}));
var rpcAuditList_createServerFn_handler = createServerRpc({
	id: "fd7f0c45e8a49f6617b6a6fa9c534dfe82c12897a1b2513a793eb7b2bad27c7d",
	name: "rpcAuditList",
	filename: "src/lib/vault-rpc.ts"
}, (opts) => rpcAuditList.__executeServer(opts));
var rpcAuditList = createServerFn({ method: "GET" }).handler(rpcAuditList_createServerFn_handler, async () => {
	const res = await consoleCall("audit_list", { limit: 50 });
	if (!res.ok) return res;
	return {
		ok: true,
		data: { records: (res.data?.records ?? []).map((r) => ({
			id: String(r.id ?? ""),
			timestamp: String(r.timestamp ?? ""),
			caller: String(r.client_id ?? ""),
			credential_ref: typeof r.credential_ref === "string" ? r.credential_ref : "",
			provider: String(r.capability ?? "").split(".")[0],
			operation: String(r.capability ?? ""),
			resource: String(r.resource ?? ""),
			http_status: typeof r.http_status === "number" ? r.http_status : null,
			duration_ms: typeof r.duration_ms === "number" ? r.duration_ms : 0,
			result: String(r.result ?? ""),
			error: typeof r.error === "string" ? r.error : void 0
		})) }
	};
});
var rpcListTools_createServerFn_handler = createServerRpc({
	id: "9f2c35a1dc0f94f879b7903158711646d9e84ed0a6ba962227effb9147eae5f0",
	name: "rpcListTools",
	filename: "src/lib/vault-rpc.ts"
}, (opts) => rpcListTools.__executeServer(opts));
var rpcListTools = createServerFn({ method: "GET" }).handler(rpcListTools_createServerFn_handler, async () => {
	if (!consoleEnabled()) return {
		ok: false,
		error: "console_disabled"
	};
	const { listTools } = await import("./gateway-iAPpU1jx.mjs").then((n) => n.n);
	return asRpc({
		ok: true,
		data: { tools: listTools().map((t) => ({
			name: t.name,
			description: t.description
		})) }
	});
});
var rpcRevealSecret_createServerFn_handler = createServerRpc({
	id: "f5a7b5df8d869f2e44c798107adc9abfe9fe44c57af389e2331420d7aeb85a64",
	name: "rpcRevealSecret",
	filename: "src/lib/vault-rpc.ts"
}, (opts) => rpcRevealSecret.__executeServer(opts));
var rpcRevealSecret = createServerFn({ method: "POST" }).validator((data) => ({ credential_ref: String(data.credential_ref) })).handler(rpcRevealSecret_createServerFn_handler, async () => {
	const { log } = await import("./log-BHJOU13W.mjs").then((n) => n.s).then((n) => n.n);
	log.warn("console_reveal_refused", { reason: "tier3_human_only" });
	return {
		ok: false,
		error: "reveal_disabled"
	};
});
var rpcCallTool_createServerFn_handler = createServerRpc({
	id: "5c20bb8e029b0ca180892b4f5efc9cb0c005ca569ee3c44cff4e51ed2db65653",
	name: "rpcCallTool",
	filename: "src/lib/vault-rpc.ts"
}, (opts) => rpcCallTool.__executeServer(opts));
var rpcCallTool = createServerFn({ method: "POST" }).validator((data) => ({
	name: String(data.name),
	arguments: data.arguments ?? {},
	argsJson: data.argsJson ?? ""
})).handler(rpcCallTool_createServerFn_handler, async ({ data }) => {
	const args = {
		...parseArgs(data.arguments),
		...parseArgs(data.argsJson)
	};
	return consoleCall(data.name, args);
});
//#endregion
export { rpcAuditList_createServerFn_handler, rpcCallTool_createServerFn_handler, rpcListTools_createServerFn_handler, rpcRevealSecret_createServerFn_handler, rpcVaultList_createServerFn_handler, rpcVaultStatus_createServerFn_handler };
