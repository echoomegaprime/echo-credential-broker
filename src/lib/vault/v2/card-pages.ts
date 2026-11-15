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
 *
 * `cookie` cards (docs/ops/cookie-entries.md): the secret field is a textarea
 * for a pasted Cookie header / JSON export / cookies.txt, and the same URL also
 * accepts ONE other request shape, for a browser extension that holds the card
 * link:
 *
 *   POST /card/<token>
 *   content-type: application/json
 *   x-echo-vault-card: submit
 *   {"cookies": <array | string>, "account"?, "purpose"?, "site"?}
 *
 * It is write-only (the answer is JSON metadata: entry label, counts — never a
 * value, never the token) and single-use exactly like the form. The same-origin
 * check is NOT applied to it, because an extension is by definition not this
 * page; what replaces it is that no web page can send this request: both
 * `application/json` and the custom header make it a non-simple CORS request,
 * the preflight (OPTIONS) is answered 405 with no CORS header, and no response
 * here ever carries `Access-Control-Allow-*`. The capability is the unguessable
 * one-time token, as for the form. The HTML page's CSP is unchanged.
 */
import { createHash } from "node:crypto";
import { log } from "../log.ts";
import { MAX_COOKIE_INPUT_CHARS } from "./cookie-jar.ts";
import {
  lookupCard,
  MAX_SECRET_LENGTH,
  MIN_SECRET_LENGTH,
  submitCard,
  type CardsDeps,
  type CardSubmitFailure,
  type CardSubmitResult,
  type CardView,
  type EntryMetadata,
} from "./cards.ts";

export const MAX_CARD_BODY_BYTES = 64 * 1024;
/** Body cap for a `cookie` card (form or JSON): a 128 KiB paste, url-encoded at worst 3x, plus the other fields. */
export const MAX_COOKIE_CARD_BODY_BYTES = 512 * 1024;
/** The JSON submit must carry this header with this value (see the file header). */
export const CARD_JSON_HEADER = "x-echo-vault-card";
export const CARD_JSON_HEADER_VALUE = "submit";

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
  "input,textarea{box-sizing:border-box;width:100%;padding:.6rem;font:inherit;color:inherit;background:#1a1d24;" +
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
    (card.kind === "cookie"
      ? // Never prefilled, never re-filled: the textarea is always rendered empty.
        `<label for="f-secret">Cookies</label>` +
        `<p class="muted">Paste this account's cookies for the site in one of three formats: a Cookie header ` +
        `(name=value; name2=value2), a JSON array exported by browser devtools or a cookie extension, or a ` +
        `Netscape cookies.txt. Cookies for other sites are ignored.</p>` +
        `<textarea id="f-secret" name="secret" rows="8" autocomplete="off" autocapitalize="off" autocorrect="off" ` +
        `spellcheck="false" maxlength="${MAX_COOKIE_INPUT_CHARS}" required></textarea>`
      : `<label for="f-secret">Secret</label>` +
        `<input id="f-secret" name="secret" type="password" autocomplete="off" autocapitalize="off" autocorrect="off" ` +
        `spellcheck="false" minlength="${MIN_SECRET_LENGTH}" maxlength="${MAX_SECRET_LENGTH}" required>`) +
    `<button type="submit">Store in vault</button></form>` +
    `<p class="muted">Single use. The secret is not shown again.</p>`;
  return page(status, card.reentry ? "Re-enter credential" : "Enter credential", body, { form: true });
}

type CookieCounts = Extract<CardSubmitResult, { ok: true }>["cookies"];

function skippedText(counts: NonNullable<CookieCounts>): string {
  const s = counts.skipped;
  const parts = [
    s.short_value ? `${s.short_value} with a value shorter than 8 characters (cannot be protected by redaction)` : "",
    s.expired ? `${s.expired} already expired` : "",
    s.other_site ? `${s.other_site} for other sites` : "",
  ].filter(Boolean);
  return parts.length ? parts.join(", ") : "none";
}

function successPage(entry: EntryMetadata, reentry: boolean, cookies?: CookieCounts): Response {
  const body =
    `<p>${reentry ? "The secret was replaced." : "The credential was stored."} You can close this page.</p>` +
    `<dl>${fixed("Entry", entry.label)}${fixed("Kind", entry.kind)}` +
    `${fixed("Default for this site", entry.is_default ? "yes" : "no")}` +
    (cookies
      ? fixed("Cookies stored", String(cookies.stored)) +
        fixed("Cookies skipped", skippedText(cookies)) +
        fixed("Earliest expiry", entry.cookie_jar?.expires_at ?? "session cookies only")
      : "") +
    `${fixed("Fingerprint", `${entry.fingerprint} (${entry.secret_length} characters)`)}</dl>`;
  return page(200, "Stored in vault", body);
}

const JSON_HEADERS: Record<string, string> = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  pragma: "no-cache",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-robots-tag": "noindex, nofollow",
  "cross-origin-resource-policy": "same-origin",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
};

/** JSON answer of the cookie JSON submit. Fixed codes and metadata only; never a CORS header. */
function jsonAnswer(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function jsonFailure(status: number, error: string, extra: Record<string, unknown> = {}): Response {
  return jsonAnswer(status, { ok: false, error, ...extra });
}

/**
 * POST /card/<token> with `content-type: application/json` — the extension
 * path for `cookie` cards. See the file header for why it is exempt from the
 * same-origin check and what stands in its place.
 */
async function handleJsonSubmit(request: Request, token: string, deps: CardsDeps): Promise<Response> {
  const found = await lookupCard(token, deps);
  // JSON exists only for `cookie` cards. Any other pending card answers exactly as before this path existed.
  if (found.state === "pending" && found.card.kind !== "cookie") {
    return messagePage(415, "Request refused", "Unsupported form encoding.");
  }
  if ((request.headers.get(CARD_JSON_HEADER) ?? "").trim().toLowerCase() !== CARD_JSON_HEADER_VALUE) {
    log.warn("vault_card_post_rejected", { reason: "json_header_missing" });
    return jsonFailure(403, "card_header_required");
  }
  if (found.state !== "pending") {
    log.warn("vault_card_submit_rejected", { reason: found.state, card_id: "unknown" });
    return jsonFailure(found.state === "invalid" ? 404 : 410, found.state === "invalid" ? "invalid_token" : found.state === "expired" ? "expired" : "already_used");
  }
  const raw = await readLimited(request, MAX_COOKIE_CARD_BODY_BYTES);
  if (raw === null) {
    log.warn("vault_card_post_rejected", { reason: "body_too_large" });
    return jsonFailure(413, "body_too_large", { retryable: true });
  }
  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return jsonFailure(400, "invalid_json", { retryable: true });
  }
  const o = body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
  const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
  if (!o || !(Array.isArray(o.cookies) || typeof o.cookies === "string")) {
    return jsonFailure(400, "invalid_body", { retryable: true });
  }
  const result = await submitCard(
    token,
    { site: str(o.site), account: str(o.account), purpose: str(o.purpose), cookies: o.cookies },
    deps,
  );
  if (!result.ok) {
    const extra: Record<string, unknown> = { retryable: result.card !== undefined };
    if (result.detail) extra.detail = result.detail;
    return jsonFailure(FAILURE_STATUS[result.code] ?? 400, result.code, extra);
  }
  const e = result.entry;
  return jsonAnswer(200, {
    ok: true,
    reentry: result.reentry,
    entry: { id: e.id, site: e.site, account: e.account, purpose: e.purpose, label: e.label, kind: e.kind, is_default: e.is_default },
    cookies: { stored: result.cookies?.stored ?? 0, skipped: result.cookies?.skipped ?? null, expires_at: e.cookie_jar?.expires_at ?? null },
  });
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
export async function readLimited(request: Request, limit: number): Promise<string | null> {
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

    const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
    if (contentType === "application/json") {
      try {
        return await handleJsonSubmit(request, token ?? "", deps);
      } catch (err) {
        log.error("vault_card_page_error", { code: err instanceof Error ? err.name : "unknown", method });
        return jsonFailure(500, "internal_error", { retryable: true });
      }
    }
    if (!sameOriginPost(request, deps.env ?? process.env)) {
      log.warn("vault_card_post_rejected", { reason: "cross_origin" });
      return messagePage(403, "Request refused", "This form can only be submitted from its own page.");
    }
    if (contentType !== "application/x-www-form-urlencoded") {
      return messagePage(415, "Request refused", "Unsupported form encoding.");
    }
    // Only a pending `cookie` card gets the larger body cap; everything else keeps 64 KiB.
    const pending = await lookupCard(token ?? "", deps);
    const bodyLimit = pending.state === "pending" && pending.card.kind === "cookie" ? MAX_COOKIE_CARD_BODY_BYTES : MAX_CARD_BODY_BYTES;
    const raw = await readLimited(request, bodyLimit);
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
    if (result.ok) return successPage(result.entry, result.reentry, result.cookies);
    const status = FAILURE_STATUS[result.code] ?? 400;
    if (result.card) return formPage(status, result.card, result.message);
    return messagePage(status, "Card unavailable", DEAD_LINK);
  } catch (err) {
    // Fixed code only: an unexpected error's text is never logged or rendered.
    log.error("vault_card_page_error", { code: err instanceof Error ? err.name : "unknown", method });
    return messagePage(500, "Something went wrong", "The card could not be processed. Nothing was stored by this request.");
  }
}
