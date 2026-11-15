// library-first: echo.functions.search → no existing impl found (2026-11-15)
/**
 * HTTP surface of the vault's second approval decider (docs/ops/bridge-decider.md):
 *
 *   POST /api/internal/approvals/decide
 *        { "approval_id": "…", "action": "approve" | "deny" }
 *     →  200 { "ok": true, "approval_id": "…", "status": "approved" | "denied",
 *              "decided_by": "service:lyra-consent-bridge" }
 *
 * Caller: Lyra's consent bridge, running on the same host as the vault. Two
 * independent controls, both fail closed:
 *   - Loopback only: the request URL's host must be a loopback host and the
 *     request must carry no proxy/tunnel forwarding headers — anything that
 *     arrived through the public tunnel is refused before auth is checked.
 *     (Route handlers in this stack see only a fetch `Request`, so this is
 *     the strongest origin check available at this layer; the token below is
 *     the primary control and deploy keeps the path unrouted publicly.)
 *   - A dedicated service token: `Authorization: Bearer <token>`, the token
 *     being ECHO_VAULT_BRIDGE_DECIDER_TOKEN, compared in constant time by
 *     decideApprovalAsService. Unset/short on the server → every call is 401.
 *
 * The decision itself is decideApprovalAsService (approvals.ts): only
 * connection (vault.client.authorize) and first-use (vault.entry.use.read)
 * approvals are decidable here, and every decision is written to the audit
 * ledger under client_id "service:lyra-consent-bridge" — never as the owner.
 * This path never touches the owner's Telegram identity or callback MACs.
 *
 * Every response is JSON with `Cache-Control: no-store`; every error is
 * `{ "ok": false, "error": "<short code>" }` and nothing else. The service
 * token never appears in a response (it is registered for log redaction).
 */
import { log } from "../log.ts";
import { ensureV2Configured } from "./bootstrap.ts";
import {
  BRIDGE_DECIDER_CLIENT_ID,
  decideApprovalAsService,
  type ApprovalAction,
  type ApprovalOptions,
  type ServiceDecideResult,
} from "./approvals.ts";

export const MAX_BRIDGE_BODY_BYTES = 4096;

const HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
} as const;

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...HEADERS, ...extra } });
}

const refuse = (status: number, error: string, extra: Record<string, string> = {}): Response =>
  json(status, { ok: false, error }, extra);

const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
const PROXY_HEADERS = ["cf-connecting-ip", "cf-ray", "x-forwarded-for", "forwarded"] as const;

/** True when the request demonstrably originated on this host (see header comment). */
function isLoopbackRequest(request: Request): boolean {
  let hostname: string;
  try {
    hostname = new URL(request.url).hostname;
  } catch {
    return false;
  }
  if (!LOOPBACK_HOSTNAMES.has(hostname)) return false;
  for (const h of PROXY_HEADERS) {
    if (request.headers.get(h)) return false;
  }
  return true;
}

function bearerToken(request: Request): string {
  const raw = (request.headers.get("authorization") ?? "").trim();
  const m = /^Bearer\s+(.+)$/i.exec(raw);
  return m ? m[1] : "";
}

const STATUS_BY_REASON: Readonly<Record<string, number>> = {
  invalid_action: 400,
  not_found: 404,
  out_of_scope: 403,
  expired: 410,
  not_pending: 409,
  ledger_unavailable: 503,
};

/** POST /api/internal/approvals/decide */
export async function handleBridgeDecide(
  request: Request,
  deps: ApprovalOptions = {},
): Promise<Response> {
  try {
    ensureV2Configured();
    if (request.method.toUpperCase() !== "POST")
      return refuse(405, "method_not_allowed", { allow: "POST" });
    if (!isLoopbackRequest(request)) {
      log.warn("vault_bridge_decide_rejected", { reason: "not_loopback" });
      return refuse(403, "not_loopback");
    }
    const declared = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(declared) && declared > MAX_BRIDGE_BODY_BYTES)
      return refuse(413, "request_too_large");
    let value: unknown;
    try {
      const buf = Buffer.from(await request.arrayBuffer());
      if (buf.byteLength > MAX_BRIDGE_BODY_BYTES) return refuse(413, "request_too_large");
      value = JSON.parse(buf.toString("utf8"));
    } catch {
      return refuse(400, "invalid_request");
    }
    if (!value || typeof value !== "object" || Array.isArray(value))
      return refuse(400, "invalid_request");
    const body = value as Record<string, unknown>;
    const id = typeof body.approval_id === "string" ? body.approval_id : "";
    const rawAction = body.action;
    const action: ApprovalAction | null =
      rawAction === "approve" || rawAction === "deny" ? rawAction : null;
    if (!id || !action) return refuse(400, "invalid_request");

    const result: ServiceDecideResult = await decideApprovalAsService(
      id,
      action,
      bearerToken(request),
      deps,
    );
    if (result.ok) {
      return json(200, {
        ok: true,
        approval_id: id,
        status: result.status,
        decided_by: BRIDGE_DECIDER_CLIENT_ID,
      });
    }
    // Do not distinguish "no token configured" from "wrong token" on the wire.
    if (result.reason === "unauthorized_service" || result.reason === "service_not_configured") {
      return refuse(401, "unauthorized");
    }
    return refuse(STATUS_BY_REASON[result.reason] ?? 400, result.reason);
  } catch {
    log.error("vault_bridge_decide_error", {});
    return refuse(503, "unavailable");
  }
}
