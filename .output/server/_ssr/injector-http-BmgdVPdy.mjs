import { o as log } from "./log-BHJOU13W.mjs";
import { ensureV2Configured } from "./bootstrap-DBXqHiC1.mjs";
import { b as reportResult, o as authenticateInjector, y as redeemTicket } from "./injector-BgOH-ggh.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/injector-http-BmgdVPdy.js
var HEADERS = {
	"content-type": "application/json; charset=utf-8",
	"cache-control": "no-store"
};
function json(status, body, extra = {}) {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			...HEADERS,
			...extra
		}
	});
}
var refuse = (status, error, extra = {}) => json(status, {
	ok: false,
	error
}, extra);
/** Method, authentication, then the size-capped JSON object body — in that order. */
async function prepare(request, deps) {
	ensureV2Configured();
	if (request.method.toUpperCase() !== "POST") return { response: refuse(405, "method_not_allowed", { allow: "POST" }) };
	let injector;
	try {
		injector = await authenticateInjector(request.headers, deps);
	} catch {
		log.error("vault_injector_auth_store_error", {});
		return { response: refuse(503, "unavailable") };
	}
	if (!injector) return { response: refuse(401, "invalid_injector") };
	const declared = Number(request.headers.get("content-length") ?? "0");
	if (Number.isFinite(declared) && declared > 4096) return { response: refuse(413, "request_too_large") };
	let value;
	try {
		const buf = Buffer.from(await request.arrayBuffer());
		if (buf.byteLength > 4096) return { response: refuse(413, "request_too_large") };
		value = JSON.parse(buf.toString("utf8"));
	} catch {
		return { response: refuse(400, "invalid_request") };
	}
	if (!value || typeof value !== "object" || Array.isArray(value)) return { response: refuse(400, "invalid_request") };
	return {
		injector,
		body: value
	};
}
/** POST /api/injector/redeem */
async function handleInjectorRedeem(request, deps = {}) {
	try {
		const p = await prepare(request, deps);
		if ("response" in p) return p.response;
		const out = await redeemTicket(p.injector, p.body.ticket, deps);
		return out.ok ? json(200, out) : refuse(out.status, out.error);
	} catch {
		return refuse(503, "unavailable");
	}
}
/** POST /api/injector/report */
async function handleInjectorReport(request, deps = {}) {
	try {
		const p = await prepare(request, deps);
		if ("response" in p) return p.response;
		const out = await reportResult(p.injector, p.body, deps);
		return out.ok ? json(200, { ok: true }) : refuse(out.status, out.error);
	} catch {
		return refuse(503, "unavailable");
	}
}
//#endregion
export { handleInjectorRedeem, handleInjectorReport };
