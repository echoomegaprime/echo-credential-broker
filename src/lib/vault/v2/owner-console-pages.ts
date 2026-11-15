// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Owner console HTTP surface — framework-free Request → Response, in the
 * style of card-pages.ts. The route files under src/routes/console are thin
 * wrappers around `handleConsoleRequest`.
 *
 * Every response: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`,
 * `frame-ancestors 'none'`, and a CSP of `default-src 'none'` plus a per-
 * response nonce for the one inline style and (only on pages that run a
 * WebAuthn ceremony) the one inline script. No inline event handlers, no
 * third-party origin, no images. Every dynamic value is HTML-escaped.
 *
 * No page, JSON body, header or log line here ever contains a vault secret:
 * the console has no reveal, copy or export feature, and all vault data it
 * shows comes out of dispatchTool (metadata only, already redacted).
 *
 * State-changing requests (every POST):
 *   1. `Sec-Fetch-Site: same-origin` must be present, and `Origin` must be the
 *      configured console origin. `Origin: null` is accepted only because (1)
 *      already holds — with `Referrer-Policy: no-referrer` browsers send
 *      `Origin: null` on same-origin form navigations (Fetch spec).
 *   2. Behind a session: the `SameSite=Strict` cookie plus the per-session
 *      CSRF token, in the `csrf` form field or the `x-csrf-token` header.
 * The expected origin is ECHO_VAULT_CONSOLE_ORIGIN — never the Host header.
 */
import { randomBytes } from "node:crypto";
import { log } from "../log.ts";
import { escapeHtml, readLimited } from "./card-pages.ts";
import type { GatewayResult } from "./gateway.ts";
import {
  authenticateSession,
  beginAddPasskey,
  beginEnroll,
  beginLogin,
  beginStepUp,
  consoleConfig,
  ConsoleError,
  csrfTokenMatches,
  finishAddPasskey,
  finishEnroll,
  finishLogin,
  finishStepUp,
  listPasskeys,
  listSessions,
  logout,
  recordView,
  removePasskey,
  revokeSession,
  runOwnerTool,
  SESSION_ABSOLUTE_MS,
  type ConsoleConfig,
  type ConsoleDeps,
  type ConsoleSession,
} from "./owner-console.ts";
import { WEBAUTHN_BROWSER_BUNDLE } from "./owner-console-webauthn-bundle.ts";
import { SUPPORTED_SCOPES } from "./oauth-server.ts";
import { RateLimitUnavailableError } from "./rate-limit-store.ts";

export const CONSOLE_BASE = "/console";
/**
 * `__Secure-`, not `__Host-`: the cookie is scoped to Path=/console so the
 * owner's session token is not sent to /api/mcp, /card or the app's other
 * routes, and `__Host-` requires Path=/. `__Secure-` still forces the Secure
 * attribute and a secure origin.
 */
export const CONSOLE_COOKIE = "__Secure-echo_vault_console";
export const MAX_CONSOLE_BODY_BYTES = 64 * 1024;

type Cfg = Extract<ConsoleConfig, { ok: true }>;

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

const STYLE =
  "body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#0f1115;color:#e8eaed}" +
  "a{color:#8ab4f8}a:focus,button:focus,input:focus,select:focus,summary:focus{outline:3px solid #fdd663;outline-offset:2px}" +
  "header{background:#171a21;border-bottom:1px solid #3a3f4b;padding:.6rem 1rem}" +
  "nav ul{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:.3rem 1rem;align-items:center}" +
  "nav form{margin:0}main{max-width:70rem;margin:0 auto;padding:1rem}h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.6rem}" +
  "table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #2a2e37;vertical-align:top;word-break:break-word}" +
  "th{color:#bdc1c6}label{display:block;margin:.6rem 0 .2rem;font-weight:600}" +
  "input,select{box-sizing:border-box;max-width:100%;padding:.45rem;font:inherit;color:inherit;background:#1a1d24;border:1px solid #5f6368;border-radius:.3rem}" +
  "input[type=text],input[type=password]{width:28rem}" +
  "button{margin-top:.6rem;padding:.5rem .9rem;font:inherit;font-weight:600;color:#0f1115;background:#8ab4f8;border:0;border-radius:.3rem;cursor:pointer}" +
  "button.danger{background:#f28b82}button.plain{background:#bdc1c6}button[disabled]{opacity:.6}" +
  "fieldset{border:1px solid #3a3f4b;border-radius:.4rem;margin:.8rem 0;padding:.4rem .8rem .8rem}legend{font-weight:600;padding:0 .3rem}" +
  ".inline{display:inline-block;margin-right:1rem;font-weight:400}.inline input{width:auto;margin-right:.3rem}" +
  ".ok{padding:.6rem;border:1px solid #81c995;border-radius:.4rem;color:#81c995}.err{padding:.6rem;border:1px solid #f28b82;border-radius:.4rem;color:#f28b82}" +
  ".muted{color:#bdc1c6;font-size:.88rem}.bad{color:#f28b82;font-weight:600}.good{color:#81c995;font-weight:600}" +
  "pre{white-space:pre-wrap;word-break:break-word;background:#171a21;padding:.8rem;border-radius:.4rem}" +
  "dl{margin:0;display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem}dt{color:#bdc1c6}dd{margin:0;word-break:break-word}" +
  ".skip{position:absolute;left:-999rem}.skip:focus{left:.5rem;top:.5rem;background:#0f1115;padding:.4rem}" +
  "details{margin:.4rem 0}summary{cursor:pointer}";

/** Glue for the three ceremonies. Reads everything from data-* attributes; talks only to this origin. */
const GLUE_SCRIPT =
  "(function(){var W=window.SimpleWebAuthnBrowser;" +
  "function post(u,b,c){var h={'content-type':'application/json'};if(c){h['x-csrf-token']=c;}" +
  "return fetch(u,{method:'POST',credentials:'same-origin',headers:h,body:JSON.stringify(b||{})})" +
  ".then(function(r){return r.json().catch(function(){return{ok:false,error:'bad_response'};});});}" +
  "function say(b,m,e){var o=document.getElementById(b.getAttribute('data-status'));if(o){o.textContent=m;o.className=e?'err':'muted';}}" +
  "function val(id){var e=document.getElementById(id);return e?e.value:undefined;}" +
  "function run(b){var k=b.getAttribute('data-webauthn'),base=b.getAttribute('data-base'),c=b.getAttribute('data-csrf')||'';" +
  "var x={};var code=val('f-code');if(code!==undefined){x.code=code.trim();}var label=val('f-label');if(label!==undefined){x.label=label;}" +
  "if(!W||!W.browserSupportsWebAuthn()){say(b,'This browser does not support passkeys.',true);return;}" +
  "b.disabled=true;say(b,'Waiting for your passkey\\u2026');" +
  "post(base+'/options',x,c).then(function(o){if(!o.ok){throw new Error(o.error||'failed');}" +
  "return k==='register'?W.startRegistration({optionsJSON:o.options}):W.startAuthentication({optionsJSON:o.options});})" +
  ".then(function(r){var y={response:r};for(var p in x){y[p]=x[p];}return post(base+'/verify',y,c);})" +
  ".then(function(v){if(!v.ok){throw new Error(v.error||'failed');}say(b,'Done.');window.location.assign(b.getAttribute('data-next')||'/console');})" +
  ".catch(function(e){b.disabled=false;say(b,'Failed: '+(e&&e.message?e.message:'error'),true);});}" +
  "var bs=document.querySelectorAll('[data-webauthn]');for(var i=0;i<bs.length;i++){(function(b){b.addEventListener('click',function(ev){ev.preventDefault();run(b);});})(bs[i]);}" +
  "})();";

const BASE_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  pragma: "no-cache",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-robots-tag": "noindex, nofollow",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

const CSP_TAIL = "img-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

interface Extra {
  cookie?: string;
  location?: string;
  allow?: string;
}

function withExtra(headers: Record<string, string>, extra: Extra): Headers {
  const h = new Headers(headers);
  if (extra.cookie) h.append("set-cookie", extra.cookie);
  if (extra.location) h.set("location", extra.location);
  if (extra.allow) h.set("allow", extra.allow);
  return h;
}

function json(status: number, body: unknown, extra: Extra = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: withExtra(
      { ...BASE_HEADERS, "content-type": "application/json; charset=utf-8", "content-security-policy": "default-src 'none'; frame-ancestors 'none'" },
      extra,
    ),
  });
}

function redirect(location: string, extra: Extra = {}): Response {
  return new Response(null, {
    status: 303,
    headers: withExtra({ ...BASE_HEADERS, "content-security-policy": "default-src 'none'; frame-ancestors 'none'" }, { ...extra, location }),
  });
}

interface Notice {
  ok: boolean;
  text: string;
  /** The refusal's error code, when there is one. */
  code?: string;
}

interface PageOpts {
  status?: number;
  title: string;
  /** Trusted HTML built here; every dynamic value already escaped. */
  body: string;
  /** Include the WebAuthn bundle + glue (nonce'd). */
  script?: boolean;
  session?: ConsoleSession;
  notice?: Notice;
  extra?: Extra;
}

const NAV: ReadonlyArray<readonly [string, string]> = [
  ["", "Overview"],
  ["/clients", "Clients"],
  ["/grants", "Consent grants"],
  ["/entries", "Entries"],
  ["/audit", "Audit"],
  ["/digest", "Digest"],
  ["/security", "Security"],
];

function page(o: PageOpts): Response {
  const nonce = randomBytes(18).toString("base64");
  const nav = o.session
    ? `<header><nav aria-label="Console"><ul>` +
      NAV.map(([path, label]) => `<li><a href="${CONSOLE_BASE}${path}">${escapeHtml(label)}</a></li>`).join("") +
      `<li><span class="muted">${escapeHtml(o.session.identity.client_id)}</span></li>` +
      `<li><form method="post" action="${CONSOLE_BASE}/logout">${csrfField(o.session)}<button class="plain" type="submit">Sign out</button></form></li>` +
      `</ul></nav></header>`
    : "";
  const notice = o.notice
    ? `<p class="${o.notice.ok ? "ok" : "err"}" role="${o.notice.ok ? "status" : "alert"}">${escapeHtml(o.notice.text)}</p>`
    : "";
  const script = o.script ? `<script nonce="${nonce}">${WEBAUTHN_BROWSER_BUNDLE}\n${GLUE_SCRIPT}</script>` : "";
  const html =
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">` +
    `<title>${escapeHtml(o.title)} — ECHO Vault console</title><style nonce="${nonce}">${STYLE}</style></head>` +
    `<body><a class="skip" href="#main">Skip to content</a>${nav}<main id="main"><h1>${escapeHtml(o.title)}</h1>${notice}${o.body}</main>${script}</body></html>`;
  const csp =
    `default-src 'none'; style-src 'nonce-${nonce}'; script-src ${o.script ? `'nonce-${nonce}'` : "'none'"}; ` +
    `connect-src ${o.script ? "'self'" : "'none'"}; ${CSP_TAIL}`;
  return new Response(html, {
    status: o.status ?? 200,
    headers: withExtra({ ...BASE_HEADERS, "content-type": "text/html; charset=utf-8", "content-security-policy": csp }, o.extra ?? {}),
  });
}

function message(status: number, title: string, text: string, extra: Extra = {}): Response {
  return page({ status, title, body: `<p>${escapeHtml(text)}</p>`, extra });
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function sessionCookie(token: string): string {
  return `${CONSOLE_COOKIE}=${token}; Path=${CONSOLE_BASE}; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}

const CLEAR_COOKIE = `${CONSOLE_COOKIE}=; Path=${CONSOLE_BASE}; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

/** Every value presented under the console cookie name (a tossed duplicate must not mask the real one). */
function cookieTokens(request: Request): string[] {
  const out: string[] = [];
  for (const part of (request.headers.get("cookie") ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === CONSOLE_COOKIE) out.push(part.slice(eq + 1).trim());
    if (out.length === 4) break;
  }
  return out;
}

async function sessionOf(request: Request, deps: ConsoleDeps): Promise<{ session: ConsoleSession; token: string } | null> {
  for (const token of cookieTokens(request)) {
    const session = await authenticateSession(token, deps);
    if (session) return { session, token };
  }
  return null;
}

/** Rule 1 of the module header. */
export function sameOriginConsolePost(request: Request, cfg: Cfg): boolean {
  if ((request.headers.get("sec-fetch-site") ?? "").toLowerCase() !== "same-origin") return false;
  const origin = request.headers.get("origin");
  return origin === cfg.origin || origin === "null";
}

type Body = { kind: "json"; value: Record<string, unknown> } | { kind: "form"; value: URLSearchParams };

async function readBody(request: Request): Promise<Body | "too_large" | "unsupported" | "invalid"> {
  const type = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (type !== "application/json" && type !== "application/x-www-form-urlencoded") return "unsupported";
  const raw = await readLimited(request, MAX_CONSOLE_BODY_BYTES);
  if (raw === null) return "too_large";
  if (type === "application/x-www-form-urlencoded") return { kind: "form", value: new URLSearchParams(raw) };
  try {
    const value = JSON.parse(raw === "" ? "{}" : raw) as unknown;
    if (typeof value !== "object" || value === null || Array.isArray(value)) return "invalid";
    return { kind: "json", value: value as Record<string, unknown> };
  } catch {
    return "invalid";
  }
}

function csrfField(s: ConsoleSession): string {
  return `<input type="hidden" name="csrf" value="${escapeHtml(s.csrf)}">`;
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

type Rec = Record<string, unknown>;

function dataOf(result: GatewayResult): Rec | null {
  return result.ok && typeof result.data === "object" && result.data !== null ? (result.data as Rec) : null;
}

function listOf(result: GatewayResult, key: string): Rec[] {
  const value = dataOf(result)?.[key];
  return Array.isArray(value) ? (value as Rec[]) : [];
}

const ERROR_TEXT: Record<string, string> = {
  step_up_required: "Confirm with your passkey first (valid for 5 minutes), then repeat the action.",
  confirmation_required: 'Type the confirmation exactly: "PURGE <entry_id>".',
  last_passkey: "The last passkey cannot be removed. Add another passkey first.",
  rate_limited: "Too many attempts. Wait and try again.",
  ledger_unavailable: "The audit ledger could not record this, so nothing was done.",
};

function failureText(result: Extract<GatewayResult, { ok: false }> | { ok: false; error: string }): string {
  const detail = "detail" in result && typeof result.detail === "string" ? ` — ${result.detail}` : "";
  return `${ERROR_TEXT[result.error] ?? `Refused: ${result.error}`}${ERROR_TEXT[result.error] ? "" : detail}`;
}

function noticeOf(result: GatewayResult | { ok: boolean; error?: string }, okText: string): Notice {
  if (result.ok) return { ok: true, text: okText };
  const failure = result as { ok: false; error: string };
  return { ok: false, text: failureText(failure), code: failure.error };
}

function unavailable(result: GatewayResult): string {
  return result.ok ? "" : `<p class="err" role="alert">${escapeHtml(failureText(result))}</p>`;
}

function table(caption: string, heads: string[], rows: string[][]): string {
  if (rows.length === 0) return `<p class="muted">${escapeHtml(caption)}: none.</p>`;
  return (
    `<table><caption class="skip">${escapeHtml(caption)}</caption><thead><tr>` +
    heads.map((h) => `<th scope="col">${escapeHtml(h)}</th>`).join("") +
    `</tr></thead><tbody>` +
    rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") +
    `</tbody></table>`
  );
}

const e = escapeHtml;
const txt = (v: unknown): string => e(v === null || v === undefined || v === "" ? "—" : String(v));

function postForm(s: ConsoleSession, action: string, inner: string, submit: string, cls = ""): string {
  return (
    `<form method="post" action="${CONSOLE_BASE}${action}" autocomplete="off">${csrfField(s)}${inner}` +
    `<button type="submit"${cls ? ` class="${cls}"` : ""}>${e(submit)}</button></form>`
  );
}

const hidden = (name: string, value: unknown): string => `<input type="hidden" name="${name}" value="${e(value)}">`;

let fieldSeq = 0;
function input(name: string, label: string, opts: { value?: unknown; type?: string; required?: boolean; max?: number } = {}): string {
  fieldSeq = (fieldSeq + 1) % 1_000_000;
  const id = `i-${name}-${fieldSeq}`;
  return (
    `<label for="${id}">${e(label)}</label><input id="${id}" name="${name}" type="${opts.type ?? "text"}" value="${e(opts.value ?? "")}"` +
    ` maxlength="${opts.max ?? 400}" autocomplete="off" autocapitalize="off" spellcheck="false"${opts.required ? " required" : ""}>`
  );
}

/** Step-up status + the button that runs the assertion. Shown on every page with a destructive form. */
function stepUpPanel(s: ConsoleSession, next: string): string {
  const fresh = s.stepUpRemainingMs > 0;
  return (
    `<fieldset><legend>Passkey confirmation</legend>` +
    `<p class="muted">Destructive actions need a passkey confirmation from the last 5 minutes. ` +
    (fresh ? `Confirmed: about ${Math.ceil(s.stepUpRemainingMs / 60_000)} min left.` : `<span class="bad">Not confirmed.</span>`) +
    `</p><button type="button" data-webauthn="auth" data-base="${CONSOLE_BASE}/stepup" data-csrf="${e(s.csrf)}" data-next="${e(next)}" data-status="stepup-status">` +
    `${fresh ? "Confirm again" : "Confirm with passkey"}</button><p id="stepup-status" class="muted" role="status" aria-live="polite"></p></fieldset>`
  );
}

// ---------------------------------------------------------------------------
// Pages behind a session
// ---------------------------------------------------------------------------

interface View {
  s: ConsoleSession;
  deps: ConsoleDeps;
  url: URL;
  notice?: Notice;
  status?: number;
}

const call = (v: View, tool: string, args: Rec = {}): Promise<GatewayResult> => runOwnerTool(v.s, tool, args, v.deps);

async function overviewPage(v: View): Promise<Response> {
  const [verify, entries, due, clients, grants] = await Promise.all([
    call(v, "audit_verify"),
    call(v, "admin_list_entries"),
    call(v, "admin_rotation_due"),
    call(v, "admin_list_clients"),
    call(v, "admin_list_grants"),
  ]);
  const chain = dataOf(verify);
  const anchor = chain && typeof chain.anchor === "object" && chain.anchor !== null ? (chain.anchor as Rec) : null;
  const allEntries = listOf(entries, "entries");
  const needs = allEntries.filter((x) => x.status === "needs_reentry");
  const dueList = listOf(due, "entries");
  const clientList = listOf(clients, "clients");
  const chainLine = !chain
    ? `<span class="bad">unavailable</span>`
    : chain.ok === true
      ? `<span class="good">intact</span> (${txt(chain.count)} rows)`
      : `<span class="bad">BROKEN at seq ${txt(chain.broken_at_seq)}: ${txt(chain.reason)}</span>`;
  const anchorLine = !chain
    ? `<span class="bad">unavailable</span>`
    : chain.anchor_error
      ? `<span class="bad">${txt(chain.anchor_error)}</span>`
      : !anchor
        ? "nothing anchored yet"
        : `<span class="${anchor.verdict === "ok" ? "good" : "bad"}">${txt(anchor.verdict)}</span>`;
  const body =
    unavailable(verify) +
    `<h2>Ledger</h2><dl><dt>Hash chain</dt><dd>${chainLine}</dd><dt>Newest anchor</dt><dd>${anchorLine}</dd></dl>` +
    `<h2>Counts</h2><dl>` +
    `<dt>Entries</dt><dd>${entries.ok ? `${allEntries.filter((x) => x.status !== "deleted").length} live, ${allEntries.filter((x) => x.status === "deleted").length} soft-deleted` : "unavailable"}</dd>` +
    `<dt>Clients</dt><dd>${clients.ok ? `${clientList.filter((x) => x.status === "approved").length} approved of ${clientList.length}` : "unavailable"}</dd>` +
    `<dt>Consent grants</dt><dd>${grants.ok ? listOf(grants, "grants").length : "unavailable"}</dd></dl>` +
    `<h2>Entries needing re-entry</h2>` +
    table("Entries needing re-entry", ["Entry", "Reason"], needs.map((x) => [txt(x.label), txt(x.reentry_reason)])) +
    `<h2>Rotation due</h2>` +
    table("Rotation due", ["Entry", "Mode", "Due"], dueList.map((x) => [txt(x.label), txt(x.rotation_mode), txt(x.rotate_by)]));
  return page({ title: "Overview", body, session: v.s, notice: v.notice, status: v.status });
}

async function clientsPage(v: View): Promise<Response> {
  const result = await call(v, "admin_list_clients");
  const rows = listOf(result, "clients").map((c) => {
    const granted = Array.isArray(c.granted_scopes) ? (c.granted_scopes as unknown[]).map(String) : [];
    const id = String(c.client_id ?? "");
    const boxes = SUPPORTED_SCOPES.map(
      (scope) =>
        `<label class="inline"><input type="checkbox" name="scope" value="${e(scope)}"${granted.includes(scope) ? " checked" : ""}>${e(scope)}</label>`,
    ).join("");
    const actions =
      c.status === "approved"
        ? `<details><summary>Manage ${txt(c.client_name)}</summary>` +
          postForm(v.s, "/clients/scopes", hidden("client_id", id) + `<fieldset><legend>Granted scopes</legend>${boxes}</fieldset>`, "Set scopes") +
          postForm(v.s, "/clients/revoke", hidden("client_id", id), "Revoke client", "danger") +
          `</details>`
        : "";
    return [
      `${txt(c.client_name)}<br><span class="muted">${txt(id)}</span>`,
      txt(c.status),
      txt(granted.join(", ")),
      txt(c.created_at),
      actions,
    ];
  });
  const body =
    stepUpPanel(v.s, `${CONSOLE_BASE}/clients`) + unavailable(result) + table("OAuth clients", ["Client", "Status", "Granted scopes", "Registered", "Actions"], rows);
  return page({ title: "Clients", body, session: v.s, notice: v.notice, status: v.status, script: true });
}

async function grantsPage(v: View): Promise<Response> {
  const result = await call(v, "admin_list_grants");
  const grants = listOf(result, "grants");
  const rows = grants.map((g) => [
    txt(g.client_id),
    txt(g.entry_id),
    txt(g.host),
    txt(g.path_prefix),
    txt(g.expires_at),
    txt(g.uses_remaining === null ? "unlimited" : g.uses_remaining),
    postForm(
      v.s,
      "/grants/revoke",
      hidden("client_id", g.client_id) + hidden("entry_id", g.entry_id) + hidden("host", g.host) + hidden("path_prefix", g.path_prefix),
      "Revoke this grant",
    ),
  ]);
  const pairs = [...new Map(grants.map((g) => [`${String(g.client_id)}\u0000${String(g.entry_id)}`, g])).values()];
  const pairForms = pairs
    .map((g) =>
      postForm(
        v.s,
        "/grants/revoke",
        hidden("client_id", g.client_id) + hidden("entry_id", g.entry_id) + hidden("all", "1") + `<p>${txt(g.client_id)} → ${txt(g.entry_id)}</p>`,
        "Revoke ALL grants for this pair",
        "danger",
      ),
    )
    .join("");
  const body =
    stepUpPanel(v.s, `${CONSOLE_BASE}/grants`) +
    unavailable(result) +
    table("Consent grants", ["Client", "Entry", "Host", "Path prefix", "Expires", "Uses left", "Action"], rows) +
    (pairs.length ? `<h2>Revoke all grants for a client and entry</h2>${pairForms}` : "");
  return page({ title: "Consent grants", body, session: v.s, notice: v.notice, status: v.status, script: true });
}

async function entriesPage(v: View): Promise<Response> {
  const result = await call(v, "admin_list_entries");
  const sections = listOf(result, "entries")
    .map((x) => {
      const id = String(x.id ?? "");
      const live = x.status !== "deleted";
      const rotation =
        `<fieldset><legend>Rotation policy</legend>` +
        `<label class="inline"><input type="radio" name="mode" value="manual"${x.rotation_mode !== "auto" ? " checked" : ""}>manual</label>` +
        `<label class="inline"><input type="radio" name="mode" value="auto"${x.rotation_mode === "auto" ? " checked" : ""}>auto (needs confirmation)</label>` +
        input("interval_days", "Rotate every N days (blank = keep)", { value: x.rotate_interval_days ?? "", max: 4 }) +
        input("provider_token_id", "Provider token ID — the non-secret ID, never the token (blank = keep)", { max: 64 }) +
        `</fieldset>`;
      return (
        `<section aria-label="${e(x.label)}"><h2>${txt(x.label)}</h2><dl>` +
        `<dt>Entry ID</dt><dd>${txt(id)}</dd><dt>Kind</dt><dd>${txt(x.kind)}</dd>` +
        `<dt>Status</dt><dd>${x.status === "active" ? txt(x.status) : `<span class="bad">${txt(x.status)}</span>`}${x.reentry_reason ? ` — ${txt(x.reentry_reason)}` : ""}</dd>` +
        `<dt>Fingerprint</dt><dd>${txt(x.fingerprint)}</dd><dt>Secret length</dt><dd>${txt(x.secret_length)} characters</dd>` +
        `<dt>Default for site</dt><dd>${x.is_default ? "yes" : "no"}</dd>` +
        `<dt>Rotation</dt><dd>${txt(x.rotation_mode)}, every ${txt(x.rotate_interval_days)} days, due ${txt(x.rotate_by)}, last ${txt(x.last_rotated_at)}, count ${txt(x.rotation_count)}` +
        `${x.last_rotation_error ? `, <span class="bad">last error ${txt(x.last_rotation_error)}</span>` : ""}</dd>` +
        `<dt>Last used</dt><dd>${txt(x.last_used_at)}</dd></dl>` +
        `<details><summary>Actions for ${txt(x.label)}</summary>` +
        (live
          ? postForm(v.s, "/entries/rotation", hidden("entry_id", id) + rotation, "Set rotation policy") +
            postForm(v.s, "/entries/rotate", hidden("entry_id", id), "Rotate now", "danger") +
            postForm(v.s, "/entries/reentry", hidden("entry_id", id), "Send a re-entry card to Telegram") +
            postForm(v.s, "/entries/delete", hidden("entry_id", id), "Soft delete", "danger")
          : "") +
        postForm(
          v.s,
          "/entries/purge",
          hidden("entry_id", id) + input("confirm", `Irreversible. Type: PURGE ${id}`, { required: true, max: 60 }),
          "Purge permanently",
          "danger",
        ) +
        `</details></section>`
      );
    })
    .join("");
  const body =
    `<p class="muted">Metadata only. The console cannot show, copy or export a stored secret.</p>` +
    stepUpPanel(v.s, `${CONSOLE_BASE}/entries`) +
    unavailable(result) +
    (sections || (result.ok ? `<p class="muted">No entries.</p>` : ""));
  return page({ title: "Entries", body, session: v.s, notice: v.notice, status: v.status, script: true });
}

async function auditPage(v: View, extra = ""): Promise<Response> {
  const q = v.url.searchParams;
  const clientId = (q.get("client_id") ?? "").slice(0, 200);
  const capability = (q.get("capability") ?? "").slice(0, 200);
  const limitRaw = Number(q.get("limit") ?? "100");
  const limit = Number.isInteger(limitRaw) && limitRaw >= 1 && limitRaw <= 1000 ? limitRaw : 100;
  const result = await call(v, "audit_list", { limit, ...(clientId ? { client_id: clientId } : {}), ...(capability ? { capability } : {}) });
  const rows = listOf(result, "records").map((r) => [
    txt(r.seq),
    txt(r.timestamp),
    txt(r.client_id),
    txt(r.capability),
    txt(r.resource),
    txt(r.decision),
    txt(r.tier),
    r.result === "ok" ? txt(r.result) : `<span class="bad">${txt(r.result)}</span>`,
    txt(r.error),
  ]);
  const body =
    extra +
    `<h2>Ledger checks</h2>` +
    postForm(v.s, "/audit/verify", "", "Verify hash chain") +
    postForm(v.s, "/audit/anchor", "", "Anchor head to Telegram now") +
    postForm(v.s, "/audit/verify-anchor", input("line", "Anchor line copied from Telegram", { required: true }), "Verify anchor line") +
    `<h2>Recent ledger rows</h2>` +
    `<form method="get" action="${CONSOLE_BASE}/audit">` +
    input("client_id", "Client ID (exact)", { value: clientId, max: 200 }) +
    input("capability", "Capability (exact)", { value: capability, max: 200 }) +
    input("limit", "Rows (1–1000)", { value: limit, max: 4 }) +
    `<button type="submit">Filter</button></form>` +
    unavailable(result) +
    table("Ledger rows", ["Seq", "Time", "Client", "Capability", "Resource", "Decision", "Tier", "Result", "Error"], rows);
  return page({ title: "Audit", body, session: v.s, notice: v.notice, status: v.status });
}

async function digestPage(v: View, send = false): Promise<Response> {
  const from = (v.url.searchParams.get("from") ?? "").slice(0, 40);
  const to = (v.url.searchParams.get("to") ?? "").slice(0, 40);
  const result = await call(v, "admin_digest_now", { ...(from ? { from } : {}), ...(to ? { to } : {}), ...(send ? { send: true } : {}) });
  const data = dataOf(result);
  const sent = data && typeof data.send === "object" && data.send !== null ? (data.send as Rec) : null;
  const window = data && typeof data.digest === "object" && data.digest !== null ? ((data.digest as Rec).window as Rec | undefined) : undefined;
  const body =
    `<form method="get" action="${CONSOLE_BASE}/digest">` +
    input("from", "From (YYYY-MM-DD, UTC; blank = previous full day)", { value: from, max: 40 }) +
    input("to", "To (exclusive; blank = one day)", { value: to, max: 40 }) +
    `<button type="submit">Preview</button></form>` +
    unavailable(result) +
    (sent ? `<p class="${sent.ok ? "ok" : "err"}" role="status">Send: ${txt(sent.ok ? (sent.status ?? "sent") : (sent.error ?? "failed"))}</p>` : "") +
    (data
      ? `<h2>Preview${window ? ` ${txt(window.from)} → ${txt(window.to)}` : ""}</h2><pre>${txt(data.text)}</pre>` +
        postForm(v.s, "/digest/send", hidden("from", from) + hidden("to", to), "Send this digest to Telegram now")
      : "");
  return page({ title: "Digest", body, session: v.s, notice: v.notice, status: v.status });
}

async function securityPage(v: View): Promise<Response> {
  await recordView(v.s, "security", v.deps);
  const [passkeys, sessions] = await Promise.all([listPasskeys(v.deps), listSessions(v.s, v.deps)]);
  const passkeyRows = passkeys.map((p) => [
    `${txt(p.label)}<br><span class="muted">${txt(p.owner_id)}</span>`,
    txt(p.transports.join(", ")),
    txt(p.created_at),
    txt(p.last_used_at),
    p.flagged_at ? `<span class="bad">${txt(p.flag_reason)} at ${txt(p.flagged_at)} — remove this passkey</span>` : "—",
    postForm(v.s, "/security/passkeys/remove", hidden("credential_id", p.credential_id), "Remove", "danger"),
  ]);
  const sessionRows = sessions.map((x) => [
    `${txt(x.id.slice(0, 8))}${x.current ? " (this session)" : ""}`,
    txt(x.owner_id),
    txt(x.created_at),
    txt(x.last_seen_at),
    txt(x.expires_at),
    txt(x.user_agent),
    postForm(v.s, "/security/sessions/revoke", hidden("session_id", x.id), x.current ? "Sign out" : "Revoke"),
  ]);
  const body =
    stepUpPanel(v.s, `${CONSOLE_BASE}/security`) +
    `<h2>Passkeys</h2>` +
    table("Passkeys", ["Passkey", "Transports", "Added", "Last used", "Flag", "Action"], passkeyRows) +
    `<fieldset><legend>Add a passkey</legend>` +
    `<label for="f-label">Name for the new passkey</label><input id="f-label" type="text" maxlength="64" autocomplete="off">` +
    `<button type="button" data-webauthn="register" data-base="${CONSOLE_BASE}/security/passkeys" data-csrf="${e(v.s.csrf)}" data-next="${CONSOLE_BASE}/security" data-status="add-status">Add passkey</button>` +
    `<p id="add-status" class="muted" role="status" aria-live="polite"></p></fieldset>` +
    `<h2>Sessions</h2>` +
    table("Sessions", ["Session", "Passkey", "Opened", "Last seen", "Expires", "Browser", "Action"], sessionRows) +
    `<p class="muted">Lost every passkey? Run admin_console_bootstrap over local stdio and enroll again at ${CONSOLE_BASE}/enroll.</p>`;
  return page({ title: "Security", body, session: v.s, notice: v.notice, status: v.status, script: true });
}

// ---------------------------------------------------------------------------
// Pages without a session
// ---------------------------------------------------------------------------

function loginPage(notice?: Notice, extra: Extra = {}): Response {
  const body =
    `<p>Sign in with the passkey you enrolled for this vault.</p>` +
    `<button type="button" data-webauthn="auth" data-base="${CONSOLE_BASE}/login" data-next="${CONSOLE_BASE}" data-status="login-status">Sign in with passkey</button>` +
    `<p id="login-status" class="muted" role="status" aria-live="polite"></p>` +
    `<p class="muted">No passkey yet, or lost them all? <a href="${CONSOLE_BASE}/enroll">Enroll with a bootstrap code</a>.</p>`;
  return page({ title: "Sign in", body, script: true, notice, extra });
}

function enrollPage(): Response {
  const body =
    `<p>Enrolling a passkey needs a one-time bootstrap code. Mint it on the vault host over local stdio ` +
    `(<code>admin_console_bootstrap</code>); it is valid for 15 minutes and works once.</p>` +
    `<label for="f-code">Bootstrap code</label><input id="f-code" type="password" maxlength="64" autocomplete="off" autocapitalize="off" spellcheck="false" required>` +
    `<label for="f-label">Name for this passkey</label><input id="f-label" type="text" maxlength="64" autocomplete="off">` +
    `<button type="button" data-webauthn="register" data-base="${CONSOLE_BASE}/enroll" data-next="${CONSOLE_BASE}/login" data-status="enroll-status">Register passkey</button>` +
    `<p id="enroll-status" class="muted" role="status" aria-live="polite"></p>` +
    `<p class="muted"><a href="${CONSOLE_BASE}/login">Back to sign in</a></p>`;
  return page({ title: "Enroll a passkey", body, script: true });
}

function disabledPage(cfg: Extract<ConsoleConfig, { ok: false }>): Response {
  const why =
    cfg.reason === "unset"
      ? "ECHO_VAULT_CONSOLE_ORIGIN is not set."
      : cfg.reason === "localhost_not_allowed"
        ? "ECHO_VAULT_CONSOLE_ORIGIN is an http://localhost origin and ECHO_VAULT_CONSOLE_ALLOW_LOCALHOST=1 is not set."
        : "ECHO_VAULT_CONSOLE_ORIGIN is not a bare https origin (https://host[:port]).";
  return message(503, "Owner console disabled", `${why} The console does not operate until the operator configures it. The local stdio interface is unaffected.`);
}

// ---------------------------------------------------------------------------
// POST actions behind a session
// ---------------------------------------------------------------------------

type Field = (name: string) => string;

interface Action {
  run(v: View, f: Field, form: URLSearchParams): Promise<Notice>;
  render(v: View): Promise<Response>;
}

const FORM_ACTIONS: Readonly<Record<string, Action>> = {
  "/clients/scopes": {
    run: async (v, f, form) =>
      noticeOf(await call(v, "admin_set_client_scopes", { client_id: f("client_id"), scopes: form.getAll("scope") }), "Scopes updated."),
    render: clientsPage,
  },
  "/clients/revoke": {
    run: async (v, f) => noticeOf(await call(v, "admin_revoke_client", { client_id: f("client_id") }), "Client revoked."),
    render: clientsPage,
  },
  "/grants/revoke": {
    run: async (v, f) => {
      const all = f("all") === "1";
      const args: Rec = { client_id: f("client_id"), entry_id: f("entry_id") };
      // One grant = host + path_prefix. A request without them is the "all for this pair" form.
      if (!all) {
        if (!f("host") || !f("path_prefix")) return { ok: false, text: "Refused: host and path_prefix are required to revoke one grant." };
        args.host = f("host");
        args.path_prefix = f("path_prefix");
      }
      return noticeOf(await call(v, "admin_revoke_grant", args), all ? "All grants for the pair revoked." : "Grant revoked.");
    },
    render: grantsPage,
  },
  "/entries/rotation": {
    run: async (v, f) => {
      const args: Rec = { entry_id: f("entry_id"), mode: f("mode") };
      if (f("interval_days")) args.interval_days = Number(f("interval_days"));
      if (f("provider_token_id")) args.provider_token_id = f("provider_token_id");
      return noticeOf(await call(v, "admin_set_rotation", args), "Rotation policy saved.");
    },
    render: entriesPage,
  },
  "/entries/rotate": {
    run: async (v, f) => noticeOf(await call(v, "admin_rotate_entry", { entry_id: f("entry_id") }), "Entry rotated. The new secret went straight to the vault."),
    render: entriesPage,
  },
  "/entries/reentry": {
    run: async (v, f) => noticeOf(await call(v, "admin_request_reentry", { entry_id: f("entry_id") }), "A single-use card link was sent to Telegram."),
    render: entriesPage,
  },
  "/entries/delete": {
    run: async (v, f) => noticeOf(await call(v, "admin_delete_entry", { entry_id: f("entry_id") }), "Entry soft-deleted."),
    render: entriesPage,
  },
  "/entries/purge": {
    run: async (v, f) => noticeOf(await call(v, "admin_purge_entry", { entry_id: f("entry_id"), confirm: f("confirm") }), "Entry purged."),
    render: entriesPage,
  },
  "/audit/verify": {
    run: async (v) => {
      const result = await call(v, "audit_verify");
      const d = dataOf(result);
      if (!d) return noticeOf(result, "");
      const anchor = typeof d.anchor === "object" && d.anchor !== null ? String((d.anchor as Rec).verdict) : d.anchor_error ? String(d.anchor_error) : "nothing anchored";
      return d.ok === true
        ? { ok: true, text: `Chain intact: ${String(d.count)} rows. Newest anchor: ${anchor}.` }
        : { ok: false, text: `Chain BROKEN at seq ${String(d.broken_at_seq)} (${String(d.reason)}). Newest anchor: ${anchor}.` };
    },
    render: (v) => auditPage(v),
  },
  "/audit/anchor": {
    run: async (v) => {
      const result = await call(v, "admin_anchor_now");
      const d = dataOf(result);
      return d ? { ok: true, text: `Anchor: ${String(d.status)}${d.seq !== undefined ? ` (seq ${String(d.seq)})` : ""}.` } : noticeOf(result, "");
    },
    render: (v) => auditPage(v),
  },
  "/audit/verify-anchor": {
    run: async (v, f) => {
      const result = await call(v, "admin_verify_anchor", { line: f("line").slice(0, 400) });
      const d = dataOf(result);
      if (!d) return noticeOf(result, "");
      return {
        ok: d.verdict === "ok",
        text: `Anchor verdict: ${String(d.verdict)} (mac checked: ${String(d.mac_checked)}, known locally: ${String(d.known_locally)}, ledger head seq ${String(d.head_seq)}).`,
      };
    },
    render: (v) => auditPage(v),
  },
  "/security/passkeys/remove": {
    run: async (v, f) => noticeOf(await removePasskey(v.s, f("credential_id"), v.deps), "Passkey removed."),
    render: securityPage,
  },
  "/security/sessions/revoke": {
    run: async (v, f) => noticeOf(await revokeSession(v.s, f("session_id"), v.deps), "Session revoked."),
    render: securityPage,
  },
};

const GET_PAGES: Readonly<Record<string, (v: View) => Promise<Response>>> = {
  "": overviewPage,
  "/clients": clientsPage,
  "/grants": grantsPage,
  "/entries": entriesPage,
  "/audit": (v) => auditPage(v),
  "/digest": (v) => digestPage(v),
  "/security": securityPage,
};

const JSON_ANON = new Set(["/login/options", "/login/verify", "/enroll/options", "/enroll/verify"]);
const JSON_SESSION = new Set(["/stepup/options", "/stepup/verify", "/security/passkeys/options", "/security/passkeys/verify"]);

const JSON_STATUS: Record<string, number> = { rate_limited: 429, step_up_required: 403, ledger_unavailable: 503 };

function jsonResult(result: { ok: boolean; error?: string }): Response {
  if (result.ok) return json(200, { ok: true });
  const error = result.error ?? "failed";
  return json(JSON_STATUS[error] ?? 400, { ok: false, error });
}

/** Route list (for docs and tests). */
export const CONSOLE_ROUTES: readonly string[] = [
  ...Object.keys(GET_PAGES).map((p) => `GET ${CONSOLE_BASE}${p}`),
  `GET ${CONSOLE_BASE}/login`,
  `GET ${CONSOLE_BASE}/enroll`,
  ...[...JSON_ANON, ...JSON_SESSION].map((p) => `POST ${CONSOLE_BASE}${p}`),
  ...Object.keys(FORM_ACTIONS).map((p) => `POST ${CONSOLE_BASE}${p}`),
  `POST ${CONSOLE_BASE}/digest/send`,
  `POST ${CONSOLE_BASE}/logout`,
];

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function handlePost(request: Request, path: string, url: URL, cfg: Cfg, deps: ConsoleDeps): Promise<Response> {
  const wantsJson = JSON_ANON.has(path) || JSON_SESSION.has(path);
  const refuse = (status: number, error: string, text: string): Response =>
    wantsJson ? json(status, { ok: false, error }) : message(status, "Request refused", text);

  const known = wantsJson || path === "/logout" || path === "/digest/send" || Object.prototype.hasOwnProperty.call(FORM_ACTIONS, path);
  if (!known) return message(404, "Not found", "No such console page.");
  if (!sameOriginConsolePost(request, cfg)) {
    log.warn("vault_console_post_rejected", { reason: "cross_origin", path });
    return refuse(403, "cross_origin", "This request did not come from the console's own pages.");
  }
  const body = await readBody(request);
  if (body === "unsupported") return refuse(415, "unsupported_media_type", "Unsupported request encoding.");
  if (body === "too_large") return refuse(413, "request_too_large", "The request is too large.");
  if (body === "invalid" || (body.kind === "json") !== wantsJson) return refuse(400, "invalid_body", "The request body is not valid.");

  if (JSON_ANON.has(path) && body.kind === "json") {
    const b = body.value;
    if (path === "/login/options") {
      const started = await beginLogin(deps);
      return started.ok ? json(200, { ok: true, options: started.options }) : jsonResult(started);
    }
    if (path === "/login/verify") {
      const done = await finishLogin(b.response, { userAgent: request.headers.get("user-agent") }, deps);
      return done.ok ? json(200, { ok: true }, { cookie: sessionCookie(done.token) }) : jsonResult(done);
    }
    if (path === "/enroll/options") {
      const started = await beginEnroll(b.code, deps);
      return started.ok ? json(200, { ok: true, options: started.options }) : jsonResult(started);
    }
    return jsonResult(await finishEnroll(b.code, b.response, b.label, deps));
  }

  const auth = await sessionOf(request, deps);
  if (!auth) return wantsJson ? json(401, { ok: false, error: "unauthenticated" }) : redirect(`${CONSOLE_BASE}/login`, { cookie: CLEAR_COOKIE });
  const presented = body.kind === "form" ? body.value.get("csrf") : request.headers.get("x-csrf-token");
  if (!csrfTokenMatches(auth.token, presented)) {
    log.warn("vault_console_post_rejected", { reason: "csrf", path });
    return refuse(403, "csrf", "The form's security token is missing or stale. Reload the page and try again.");
  }
  const s = auth.session;

  if (body.kind === "json") {
    const b = body.value;
    if (path === "/stepup/options") {
      const started = await beginStepUp(s, deps);
      return started.ok ? json(200, { ok: true, options: started.options }) : jsonResult(started);
    }
    if (path === "/stepup/verify") return jsonResult(await finishStepUp(s, b.response, deps));
    if (path === "/security/passkeys/options") {
      const started = await beginAddPasskey(s, deps);
      return started.ok ? json(200, { ok: true, options: started.options }) : jsonResult(started);
    }
    return jsonResult(await finishAddPasskey(s, b.response, b.label, deps));
  }

  const form = body.value;
  if (path === "/logout") {
    await logout(s, deps);
    return redirect(`${CONSOLE_BASE}/login`, { cookie: CLEAR_COOKIE });
  }
  const view: View = { s, deps, url };
  if (path === "/digest/send") {
    for (const k of ["from", "to"]) if (form.get(k)) url.searchParams.set(k, String(form.get(k)));
    return digestPage(view, true);
  }
  const action = FORM_ACTIONS[path];
  const notice = await action.run(view, (name) => (form.get(name) ?? "").trim(), form);
  // The action may have ended this session (own passkey removed, own session revoked).
  const again = await sessionOf(request, deps);
  if (!again) return redirect(`${CONSOLE_BASE}/login`, { cookie: CLEAR_COOKIE });
  return action.render({ s: again.session, deps, url, notice, status: notice.ok ? 200 : notice.code === "step_up_required" ? 403 : 400 });
}

/**
 * Entry point for every request under /console. `deps` is the test seam
 * (stores, clock, env, gateway wiring); production passes nothing.
 */
export async function handleConsoleRequest(request: Request, deps: ConsoleDeps = {}): Promise<Response> {
  const method = request.method.toUpperCase();
  let wantsJson = false;
  try {
    const cfg = consoleConfig(deps.env ?? process.env);
    if (!cfg.ok) return disabledPage(cfg);
    // Only the path and query are read from the request URL — never its host.
    const url = new URL(request.url);
    const full = url.pathname.replace(/\/+$/, "");
    if (full !== CONSOLE_BASE && !full.startsWith(`${CONSOLE_BASE}/`)) return message(404, "Not found", "No such console page.");
    const path = full.slice(CONSOLE_BASE.length);
    wantsJson = JSON_ANON.has(path) || JSON_SESSION.has(path);

    if (method === "POST") return await handlePost(request, path, url, cfg, deps);
    if (method !== "GET" && method !== "HEAD") return message(405, "Method not allowed", "Use the console's pages.", { allow: "GET, HEAD, POST" });

    if (path === "/enroll") return enrollPage();
    const auth = await sessionOf(request, deps);
    if (path === "/login") return auth ? redirect(CONSOLE_BASE) : loginPage();
    const render = Object.prototype.hasOwnProperty.call(GET_PAGES, path) ? GET_PAGES[path] : undefined;
    if (!render) return message(404, "Not found", "No such console page.");
    if (!auth) return redirect(`${CONSOLE_BASE}/login`, cookieTokens(request).length ? { cookie: CLEAR_COOKIE } : {});
    return await render({ s: auth.session, deps, url });
  } catch (err) {
    const limited = err instanceof RateLimitUnavailableError;
    const code = limited ? "rate_limit_unavailable" : err instanceof ConsoleError ? err.code : "internal_error";
    // Fixed codes only: an unexpected error's text is never logged or rendered.
    log.error("vault_console_page_error", { code, error_class: err instanceof Error ? err.name : "unknown", method });
    const status = limited || code === "ledger_unavailable" || code === "console_disabled" ? 503 : 500;
    if (wantsJson) return json(status, { ok: false, error: code });
    return message(status, status === 503 ? "Temporarily unavailable" : "Something went wrong", "The console could not process this request. Nothing was changed by it.");
  }
}
