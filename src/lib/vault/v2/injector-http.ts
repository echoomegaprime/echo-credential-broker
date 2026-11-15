// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * HTTP surface of the browser injector channel (docs/ops/injector-contract.md):
 *
 *   POST /api/injector/redeem   { "ticket": "eit_…" }            → sealed credential
 *   POST /api/injector/report   { "ticket_sha256", "result", … } → { ok: true }
 *
 * Authentication: `Authorization: Bearer ein_…` ONLY (injector.ts,
 * authenticateInjector). An OAuth (`eva_`) or workload (`ewk_`) token is
 * refused here with 401 invalid_injector, and an `ein_` token authenticates
 * nothing on /api/mcp or /api/rest/tool (http-transport.ts never looks at it).
 * An injector therefore cannot call a tool, and an agent cannot redeem.
 *
 * Every response: `Cache-Control: no-store`, no CORS header (an extension's
 * service worker with host permission does not need one; a web page gets
 * none). Every error is `{ "ok": false, "error": "<short code>" }` and nothing
 * else. The success body of redeem is written with JSON.stringify directly —
 * not through the redaction layer — because it is ciphertext plus fixed
 * metadata, and a redaction pattern that happened to match base64url output
 * would corrupt the blob.
 */
import { log } from "../log.ts";
import { ensureV2Configured } from "./bootstrap.ts";
import { authenticateInjector, redeemTicket, reportResult, type InjectorDeps, type InjectorRecord } from "./injector.ts";

export const MAX_INJECTOR_BODY_BYTES = 4096;

const HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } as const;

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...HEADERS, ...extra } });
}

const refuse = (status: number, error: string, extra: Record<string, string> = {}): Response => json(status, { ok: false, error }, extra);

type Prepared = { injector: InjectorRecord; body: Record<string, unknown> } | { response: Response };

/** Method, authentication, then the size-capped JSON object body — in that order. */
async function prepare(request: Request, deps: InjectorDeps): Promise<Prepared> {
  ensureV2Configured();
  if (request.method.toUpperCase() !== "POST") return { response: refuse(405, "method_not_allowed", { allow: "POST" }) };
  let injector: InjectorRecord | null;
  try {
    injector = await authenticateInjector(request.headers, deps);
  } catch {
    log.error("vault_injector_auth_store_error", {});
    return { response: refuse(503, "unavailable") };
  }
  if (!injector) return { response: refuse(401, "invalid_injector") };
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_INJECTOR_BODY_BYTES) return { response: refuse(413, "request_too_large") };
  let value: unknown;
  try {
    const buf = Buffer.from(await request.arrayBuffer());
    if (buf.byteLength > MAX_INJECTOR_BODY_BYTES) return { response: refuse(413, "request_too_large") };
    value = JSON.parse(buf.toString("utf8"));
  } catch {
    return { response: refuse(400, "invalid_request") };
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return { response: refuse(400, "invalid_request") };
  return { injector, body: value as Record<string, unknown> };
}

/** POST /api/injector/redeem */
export async function handleInjectorRedeem(request: Request, deps: InjectorDeps = {}): Promise<Response> {
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
export async function handleInjectorReport(request: Request, deps: InjectorDeps = {}): Promise<Response> {
  try {
    const p = await prepare(request, deps);
    if ("response" in p) return p.response;
    const out = await reportResult(p.injector, p.body, deps);
    return out.ok ? json(200, { ok: true }) : refuse(out.status, out.error);
  } catch {
    return refuse(503, "unavailable");
  }
}
