import { d as safeJson, f as sanitizeError, l as redactValue, n as INVARIANT, o as log } from "./log-BHJOU13W.mjs";
import { n as PROTECTED_RESOURCE_METADATA_PATH, r as SUPPORTED_SCOPES } from "./oauth-server-BJCUNFGm.mjs";
import { ensureV2Configured } from "./bootstrap-DBXqHiC1.mjs";
import { d as authenticateRequest, f as wwwAuthenticateHeader, r as listTools, t as dispatchTool } from "./gateway-iAPpU1jx.mjs";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
//#region node_modules/.nitro/vite/services/ssr/assets/http-transport-DIF0xnKu.js
/**
* MCP JSON-RPC handler. Transport-agnostic: the caller (HTTP route or stdio
* script) authenticates first and passes the resulting ClientIdentity. No
* header, argument or environment value can name the caller from in here.
* Every tools/call goes through v2/gateway.ts dispatchTool.
*/
var MCP_PROTOCOL_VERSIONS = [
	"2025-06-18",
	"2025-03-26",
	"2024-11-05"
];
var MCP_SERVER_INFO = {
	name: "echo-credential-broker",
	version: "2.0.0"
};
var INSTRUCTIONS = `${INVARIANT} There is no tool that returns a secret. Tier 0 tools read; tier 1 tools make reversible writes; tier 2 tools return \`approval_required\` with an approval_id — the owner approves on Telegram, then you call the same tool again with the same arguments plus approval_id. To use a site credential, call entry_list then entry_use; if no entry exists, call entry_request_card and the owner types the secret on a private page.`;
function rpcError(id, code, message) {
	return {
		jsonrpc: "2.0",
		id,
		error: {
			code,
			message
		}
	};
}
/**
* Handle one JSON-RPC message for an authenticated client. Returns the
* response object, or null for a notification (no id), which gets no response.
*/
async function handleMcpRequest(body, identity, deps = {}) {
	if (!body || typeof body !== "object" || Array.isArray(body)) return rpcError(null, -32600, "invalid_request");
	const req = body;
	const isNotification = req.id === void 0;
	const id = req.id ?? null;
	const method = typeof req.method === "string" ? req.method : "";
	if (isNotification) return null;
	if (!identity || typeof identity.client_id !== "string" || !identity.client_id) return rpcError(id, -32001, "unauthenticated");
	try {
		switch (method) {
			case "initialize": {
				const requested = req.params?.protocolVersion;
				return {
					jsonrpc: "2.0",
					id,
					result: {
						protocolVersion: MCP_PROTOCOL_VERSIONS.includes(requested) ? requested : MCP_PROTOCOL_VERSIONS[0],
						serverInfo: MCP_SERVER_INFO,
						capabilities: { tools: {} },
						instructions: INSTRUCTIONS
					}
				};
			}
			case "tools/list": return {
				jsonrpc: "2.0",
				id,
				result: { tools: listTools() }
			};
			case "ping": return {
				jsonrpc: "2.0",
				id,
				result: {}
			};
			case "tools/call": {
				const params = req.params ?? {};
				const name = typeof params.name === "string" ? params.name : "";
				const payload = redactValue(await dispatchTool(identity, name, params.arguments ?? {}, deps));
				return {
					jsonrpc: "2.0",
					id,
					result: {
						content: [{
							type: "text",
							text: safeJson(payload)
						}],
						isError: payload.ok === false,
						structuredContent: payload
					}
				};
			}
			default: return rpcError(id, -32601, "method_not_found");
		}
	} catch (error) {
		return rpcError(id, -32603, sanitizeError(error).message.slice(0, 300));
	}
}
/**
* Workload identities for server-side services on the owner's nodes (e.g. the
* ECHO SDK gate calling /api/rest/tool). These can't do an interactive OAuth
* flow, so each one gets its own long random token whose SHA-256 is listed in
* a root-owned file. The raw token lives only in that service's own
* file-mounted credential; this process stores and compares hashes only.
*
* File: path in env ECHO_VAULT_WORKLOAD_TOKENS_FILE, JSON array of
*   { "sha256": "<64 hex>", "client_id": "workload:<name>", "name": "<display>", "scopes": ["github.read", ...] }
* Token format presented by the service: `Authorization: Bearer ewk_<43+ url-safe chars>`.
* Unset env or unreadable/malformed file → no workload is accepted (fail closed).
*/
var TOKEN_PATTERN = /^ewk_[A-Za-z0-9_-]{43,256}$/;
var CLIENT_ID_PATTERN = /^workload:[a-z0-9][a-z0-9._-]{0,62}$/;
var cache = null;
function loadEntries(env) {
	const path = env.ECHO_VAULT_WORKLOAD_TOKENS_FILE?.trim();
	if (!path) return [];
	let mtimeMs;
	try {
		mtimeMs = statSync(path).mtimeMs;
	} catch {
		log.warn("workload_tokens_unreadable", {});
		return [];
	}
	if (cache && cache.path === path && cache.mtimeMs === mtimeMs) return cache.entries;
	let parsed;
	try {
		parsed = JSON.parse(readFileSync(path, "utf8"));
	} catch {
		log.warn("workload_tokens_malformed", {});
		cache = {
			path,
			mtimeMs,
			entries: []
		};
		return [];
	}
	const supported = new Set(SUPPORTED_SCOPES);
	const entries = [];
	if (Array.isArray(parsed)) for (const raw of parsed) {
		const r = raw;
		if (typeof r?.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(r.sha256) || typeof r.client_id !== "string" || !CLIENT_ID_PATTERN.test(r.client_id) || typeof r.name !== "string" || !Array.isArray(r.scopes)) {
			log.warn("workload_tokens_malformed_entry", {});
			cache = {
				path,
				mtimeMs,
				entries: []
			};
			return [];
		}
		entries.push({
			sha256: Buffer.from(r.sha256, "hex"),
			identity: {
				client_id: r.client_id,
				name: r.name.slice(0, 80),
				kind: "workload",
				scopes: r.scopes.filter((s) => typeof s === "string" && supported.has(s))
			}
		});
	}
	cache = {
		path,
		mtimeMs,
		entries
	};
	return entries;
}
/** Resolve `Authorization: Bearer ewk_…` to a workload identity, or null. */
function authenticateWorkload(headers, env = process.env) {
	const auth = headers.get("authorization") ?? "";
	const match = /^Bearer\s+(\S+)$/i.exec(auth.trim());
	if (!match || !TOKEN_PATTERN.test(match[1])) return null;
	const digest = createHash("sha256").update(match[1], "utf8").digest();
	let found = null;
	for (const entry of loadEntries(env)) if (timingSafeEqual(entry.sha256, digest)) found = entry.identity;
	return found ? {
		...found,
		scopes: [...found.scopes]
	} : null;
}
var JSON_HEADERS = {
	"content-type": "application/json; charset=utf-8",
	"cache-control": "no-store"
};
function json(status, body, extra = {}) {
	return new Response(safeJson(body), {
		status,
		headers: {
			...JSON_HEADERS,
			...extra
		}
	});
}
/** OAuth bearer first, then workload token. Null = not authenticated. */
async function authenticateHttp(headers) {
	ensureV2Configured();
	return await authenticateRequest(headers) ?? authenticateWorkload(headers);
}
function unauthorizedResponse(headers) {
	const presented = headers.has("authorization");
	return json(401, {
		error: presented ? "invalid_token" : "unauthorized",
		error_description: "Connect with OAuth: see the resource metadata named in WWW-Authenticate."
	}, { "www-authenticate": presented ? wwwAuthenticateHeader({ error: "invalid_token" }) : wwwAuthenticateHeader() });
}
async function readJsonBody(request) {
	const declared = Number(request.headers.get("content-length") ?? "0");
	if (Number.isFinite(declared) && declared > 1048576) return {
		ok: false,
		response: json(413, { error: "request_too_large" })
	};
	let text;
	try {
		const buf = Buffer.from(await request.arrayBuffer());
		if (buf.byteLength > 1048576) return {
			ok: false,
			response: json(413, { error: "request_too_large" })
		};
		text = buf.toString("utf8");
	} catch {
		return {
			ok: false,
			response: json(400, { error: "invalid_body" })
		};
	}
	try {
		return {
			ok: true,
			value: JSON.parse(text)
		};
	} catch {
		return {
			ok: false,
			response: json(400, { error: "invalid_json_body" })
		};
	}
}
/** GET /api/mcp. Unauthenticated callers learn the server name, the invariant and where to authenticate — not the tool list. */
async function handleMcpGet(request) {
	if ((request.headers.get("accept") ?? "").includes("text/event-stream")) return new Response(null, {
		status: 405,
		headers: {
			allow: "POST",
			"cache-control": "no-store"
		}
	});
	const identity = await authenticateHttp(request.headers);
	const base = {
		name: MCP_SERVER_INFO.name,
		version: MCP_SERVER_INFO.version,
		invariant: INVARIANT,
		authentication: "oauth2",
		resource_metadata: PROTECTED_RESOURCE_METADATA_PATH
	};
	if (!identity) return json(200, base);
	return json(200, {
		...base,
		client_id: identity.client_id,
		scopes: identity.scopes,
		tools: listTools()
	});
}
/** POST /api/mcp: one JSON-RPC message per request. */
async function handleMcpPost(request, deps = {}) {
	const identity = await authenticateHttp(request.headers);
	if (!identity) return unauthorizedResponse(request.headers);
	const body = await readJsonBody(request);
	if (!body.ok) return body.response;
	if (Array.isArray(body.value)) return json(200, {
		jsonrpc: "2.0",
		id: null,
		error: {
			code: -32600,
			message: "batch_not_supported"
		}
	});
	const result = await handleMcpRequest(body.value, identity, deps);
	if (result === null) return new Response(null, {
		status: 202,
		headers: { "cache-control": "no-store" }
	});
	return json(200, redactValue(result));
}
/**
* POST /api/rest/tool — body {"tool": "<name>", "arguments": {...}} →
* {"ok": true, "result": <tool result>}. Same authentication and the same
* dispatchTool as MCP: a transport shim, not a second authority.
*/
async function handleRestTool(request, deps = {}) {
	const identity = await authenticateHttp(request.headers);
	if (!identity) return unauthorizedResponse(request.headers);
	const body = await readJsonBody(request);
	if (!body.ok) return body.response;
	const { tool, arguments: args } = body.value && typeof body.value === "object" ? body.value : {};
	if (typeof tool !== "string" || !tool) return json(400, {
		ok: false,
		error: "tool_required"
	});
	const result = redactValue(await dispatchTool(identity, tool, args ?? {}, deps));
	log.info("rest_tool", {
		client_id: identity.client_id,
		tool: tool.slice(0, 64),
		ok: result.ok
	});
	return json(200, {
		ok: true,
		result
	});
}
//#endregion
export { handleMcpGet, handleMcpPost, handleRestTool };
