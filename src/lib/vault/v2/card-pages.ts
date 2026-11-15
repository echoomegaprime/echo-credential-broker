// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 credential-card page — framework-free Request → Response.
 *
 *   GET  /card/<token>   minimal form (never consumes the token)
 *   POST /card/<token>   stores the typed secret via cards.ts submitCard()
 *
 * The token in the URL is the capability (256 bits, single use, 30 minutes,
 * stored hashed). Pages are script-free under a strict CSP (hashed inline
 * style only), `no-store`, `frame-ancestors 'none'`, `no-referrer`, and every
 * dynamic value is HTML-escaped. The secret is never echoed: not on success,
 * not on a validation error (the form is re-rendered from the card's own
 * prefill, never from submitted values), not in a log line.
 *
 * CSRF, on top of the token: when the browser sends `Sec-Fetch-Site` it must
 * be `same-origin`; when it sends an `Origin` it must be this server's origin
 * (the request's or ECHO_VAULT_PUBLIC_URL's). Note `Referrer-Policy:
 * no-referrer` makes browsers send `Origin: null` on the form POST (Fetch
 * spec), so a `null` origin is accepted only together with
 * `Sec-Fetch-Site: same-origin`.
 */
import { createHash } from "node:crypto";
import { log } from "../log.ts";
import {
  lookupCard,
  MAX_SECRET_LENGTH,
  MIN_SECRET_LENGTH,
  submitCard,
  type CardsDeps,
  type CardSubmitFailure,
  type CardView,
  type EntryMetadata,
} from "./cards.ts";

export const MAX_CARD_BODY_BYTES = 64 * 1024;

export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/`/g, "&#96;");
}

const PAGE_STYLE =
  "body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#0f1115;color:#e8eaed}" +
  "main{max-width:30rem;margin:0 auto;padding:1.5rem}h1{font-size:1.25rem}" +
  "label{display:block;margin:.9rem 0 .25rem;font-weight:600}" +
  "input{box-sizing:border-box;width:100%;padding:.6rem;font:inherit;color:inherit;background:#1a1d24;" +
  "border:1px solid #3a3f4b;border-radius:.4rem}" +
  "button{margin-top:1.2rem;width:100%;padding:.7rem;font:inherit;font-weight:600;color:#0f1115;background:#8ab4f8;" +
  "border:0;border-radius:.4rem}" +
  "dl{margin:0}dt{margin-top:.6rem;color:#9aa0a6;font-size:.85rem}dd{margin:0;word-break:break-word}" +
  ".err{padding:.6rem;border:1px solid #f28b82;border-radius:.4rem;color:#f28b82}.muted{color:#9aa0a6;font-size:.85rem}";
const PAGE_STYLE_HASH = createHash("sha256").update(PAGE_STYLE, "utf8").digest("base64");

function csp(formAction: "'self'" | "'none'"): string {
  return (
    `default-src 'none'; style-src 'sha256-${PAGE_STYLE_HASH}'; img-src 'none'; ` +
    `base-uri 'none'; form-action ${formAction}; frame-ancestors 'none'`
  );
}

const BASE_HEADERS: Record<string, string> = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  pragma: "no-cache",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-robots-tag": "noindex, nofollow",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

/** `body` is trusted HTML built here with every dynamic value already escaped; `title` is escaped here. */
function page(status: number, title: string, body: string, opts: { form?: boolean; allow?: string } = {}): Response {
  const html =
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<meta name="robots" content="noindex,nofollow">` +
    `<title>${escapeHtml(title)}</title><style>${PAGE_STYLE}</style></head>` +
    `<body><main><h1>${escapeHtml(title)}</h1>${body}</main></body></html>`;
  const headers: Record<string, string> = {
    ...BASE_HEADERS,
    "content-security-policy": csp(opts.form ? "'self'" : "'none'"),
  };
  if (opts.allow) headers.allow = opts.allow;
  return new Response(html, { status, headers });
}

function messagePage(status: number, title: string, message: string, opts: { allow?: string } = {}): Response {
  return page(status, title, `<p>${escapeHtml(message)}</p>`, opts);
}

const DEAD_LINK = "This card link is invalid, expired or already used. Ask the agent to request a new card.";

function field(name: string, label: string, value: string | null, max: number, required: boolean): string {
  return (
    `<label for="f-${name}">${escapeHtml(label)}</label>` +
    `<input id="f-${name}" name="${name}" type="text" value="${escapeHtml(value ?? "")}" maxlength="${max}" ` +
    `autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"${required ? " required" : ""}>`
  );
}

function fixed(label: string, value: string): string {
  return `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`;
}

/** The entry form. Prefill comes from the card only — never from a submission. */
function formPage(status: number, card: CardView, error?: string): Response {
  const who = card.client_name ? `${card.client_name} (${card.client_id})` : card.client_id;
  const facts =
    `<dl>${fixed("Requested by", who)}${fixed("Reason", card.reason || "(none)")}${fixed("Kind", card.kind)}` +
    (card.reentry
      ? fixed("Site", card.site) + fixed("Account", card.account ?? "") + fixed("Purpose", card.purpose ?? "general")
      : "") +
    `${fixed("Link expires", card.expires_at)}</dl>`;
  const editable = card.reentry
    ? ""
    : field("site", "Site", card.site, 253, true) +
      field("account", "Account (username or email)", card.account, 254, true) +
      field("purpose", "Purpose tag", card.purpose ?? "general", 64, false);
  const body =
    (error ? `<p class="err" role="alert">${escapeHtml(error)}</p>` : "") +
    `<p>${card.reentry ? "Re-enter the secret for this existing entry. Only its secret is replaced." : "Type the credential. It goes straight to the vault; the requesting agent never sees it."}</p>` +
    facts +
    `<form method="post" autocomplete="off">${editable}` +
    `<label for="f-secret">Secret</label>` +
    `<input id="f-secret" name="secret" type="password" autocomplete="off" autocapitalize="off" autocorrect="off" ` +
    `spellcheck="false" minlength="${MIN_SECRET_LENGTH}" maxlength="${MAX_SECRET_LENGTH}" required>` +
    `<button type="submit">Store in vault</button></form>` +
    `<p class="muted">Single use. The secret is not shown again.</p>`;
  return page(status, card.reentry ? "Re-enter credential" : "Enter credential", body, { form: true });
}

function successPage(entry: EntryMetadata, reentry: boolean): Response {
  const body =
    `<p>${reentry ? "The secret was replaced." : "The credential was stored."} You can close this page.</p>` +
    `<dl>${fixed("Entry", entry.label)}${fixed("Kind", entry.kind)}` +
    `${fixed("Default for this site", entry.is_default ? "yes" : "no")}` +
    `${fixed("Fingerprint", `${entry.fingerprint} (${entry.secret_length} characters)`)}</dl>`;
  return page(200, "Stored in vault", body);
}

const FAILURE_STATUS: Record<CardSubmitFailure, number> = {
  invalid_token: 404,
  expired: 410,
  already_used: 410,
  invalid_input: 400,
  entry_exists: 409,
  entry_gone: 410,
  vault_unavailable: 503,
  store_failed: 500,
};

function originOf(value: string | undefined | null): string | null {
  if (!value) return null;
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

/** Same-origin check for POST. Headers that are absent are not required (non-browser clients). */
export function sameOriginPost(request: Request, env: NodeJS.ProcessEnv = process.env): boolean {
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site.toLowerCase() !== "same-origin") return false;
  const origin = request.headers.get("origin");
  if (origin === null) return true;
  if (origin === "null") return site !== null; // no-referrer pages POST with Origin: null
  const allowed = [originOf(request.url), originOf(env.ECHO_VAULT_PUBLIC_URL)].filter((o): o is string => o !== null);
  return allowed.includes(origin);
}

/** Read at most `limit` bytes; null when the body is larger (the rest is not buffered). */
async function readLimited(request: Request, limit: number): Promise<string | null> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > limit) return null;
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Entry point for GET/HEAD/POST /card/<token>. `deps` is the cards.ts wiring
 * (stores, vault backend, ledger, clock, env); production passes nothing.
 */
export async function handleCardRequest(
  request: Request,
  token: string | undefined,
  deps: CardsDeps = {},
): Promise<Response> {
  const method = request.method.toUpperCase();
  try {
    if (method === "GET" || method === "HEAD") {
      const found = await lookupCard(token ?? "", deps);
      if (found.state !== "pending") {
        return messagePage(found.state === "invalid" ? 404 : 410, "Card unavailable", DEAD_LINK);
      }
      return formPage(200, found.card);
    }
    if (method !== "POST") {
      return messagePage(405, "Method not allowed", "Use the form on this page.", { allow: "GET, HEAD, POST" });
    }

    if (!sameOriginPost(request, deps.env ?? process.env)) {
      log.warn("vault_card_post_rejected", { reason: "cross_origin" });
      return messagePage(403, "Request refused", "This form can only be submitted from its own page.");
    }
    const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
    if (contentType !== "application/x-www-form-urlencoded") {
      return messagePage(415, "Request refused", "Unsupported form encoding.");
    }
    const raw = await readLimited(request, MAX_CARD_BODY_BYTES);
    if (raw === null) {
      log.warn("vault_card_post_rejected", { reason: "body_too_large" });
      return messagePage(413, "Request refused", "The submission is too large.");
    }
    const form = new URLSearchParams(raw);
    const result = await submitCard(
      token ?? "",
      {
        site: form.get("site") ?? undefined,
        account: form.get("account") ?? undefined,
        purpose: form.get("purpose") ?? undefined,
        secret: form.get("secret") ?? "",
      },
      deps,
    );
    if (result.ok) return successPage(result.entry, result.reentry);
    const status = FAILURE_STATUS[result.code] ?? 400;
    if (result.card) return formPage(status, result.card, result.message);
    return messagePage(status, "Card unavailable", DEAD_LINK);
  } catch (err) {
    // Fixed code only: an unexpected error's text is never logged or rendered.
    log.error("vault_card_page_error", { code: err instanceof Error ? err.name : "unknown", method });
    return messagePage(500, "Something went wrong", "The card could not be processed. Nothing was stored by this request.");
  }
}
