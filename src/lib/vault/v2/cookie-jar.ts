// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Cookie jar for `cookie` entries — pure functions, no I/O, no logging.
 *
 * A cookie VALUE is a secret exactly like a password: nothing here ever puts a
 * value into an error (errors are fixed codes), and `describeJar` returns
 * names/domains/expiry only. Cookie NAMES and domains are metadata.
 *
 *   parseCookieInput   what the owner pastes (or an extension submits): a
 *                      Cookie header string, a JSON array of cookie objects, or
 *                      a Netscape cookies.txt → a validated jar
 *   serializeJar /     the canonical stored form (the entry's "secret"):
 *   parseStoredJar     {"v":1,"cookies":[{name,value,domain,path,secure,httpOnly,hostOnly,expires}]}
 *   cookieHeaderFor    RFC 6265 §5.4 selection for one request → "a=b; c=d" | null
 *   mergeSetCookie     RFC 6265 §5.2/§5.3 storage of a response's Set-Cookie headers
 *   describeJar        metadata only (count, names, domains, earliest expiry)
 *
 * Values shorter than 8 characters are NOT stored: redaction.ts can only arm
 * secrets of 8+ characters, so a shorter value could not be kept out of a
 * result if the site echoed it. Such cookies are skipped (and counted).
 *
 * Public suffixes: there is no Public Suffix List in this repo. What IS done:
 * a cookie domain with no dot (a bare TLD, "localhost") is refused, IP literals
 * are refused, and a small embedded list of well-known multi-label suffixes
 * (co.uk, com.au, github.io, …) is refused. What is NOT done: the full PSL.
 * The containment that does not depend on it is in gateway.ts: a jar is only
 * ever sent to the entry's own site, api.<site> or a subdomain of that site.
 */

export interface StoredCookie {
  name: string;
  value: string;
  /** Lower-case host without a leading dot. "" = bound host-only to the entry's site at use time. */
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  /** true: only the exact host. false: the domain and its subdomains. */
  hostOnly: boolean;
  /** Expiry in epoch SECONDS, or null for a session cookie. */
  expires: number | null;
}

export interface CookieJar {
  v: 1;
  cookies: StoredCookie[];
}

/** A fixed code. The message is the code: no submitted text ever rides in it. */
export class CookieInputError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "CookieInputError";
    this.code = code;
  }
}

export const MAX_COOKIES = 200;
/** Cookies examined in one paste before filtering (a whole-browser cookies.txt). */
export const MAX_RAW_COOKIES = 5000;
export const MAX_COOKIE_INPUT_CHARS = 128 * 1024;
/** Cap of the canonical stored JSON, i.e. the secret length limit of a `cookie` entry. */
export const MAX_COOKIE_JAR_CHARS = 32 * 1024;
export const MAX_COOKIE_NAME_CHARS = 128;
export const MAX_COOKIE_VALUE_CHARS = 4096;
export const MAX_COOKIE_PATH_CHARS = 1024;
/** redaction.ts arms only secrets of 8+ characters. */
export const MIN_COOKIE_VALUE_CHARS = 8;
const MAX_SET_COOKIE_CHARS = 8192;

const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/; // RFC 6265 cookie-name = RFC 2616 token
const VALUE_RE = /^[\x20-\x3a\x3c-\x7e]*$/; // printable ASCII without ";" — no CTL, CR, LF, NUL
const PATH_RE = /^\/[\x21-\x3a\x3c-\x7e]*$/;
const HOST_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** NOT the Public Suffix List — a short list of common multi-label suffixes. See the file header. */
const MULTI_LABEL_SUFFIXES = new Set(
  (
    "co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk sch.uk com.au net.au org.au edu.au gov.au id.au " +
    "co.nz net.nz org.nz govt.nz ac.nz co.jp ne.jp or.jp ac.jp go.jp com.br net.br org.br gov.br com.cn net.cn " +
    "org.cn gov.cn edu.cn co.in net.in org.in gov.in ac.in co.za org.za com.mx org.mx gob.mx com.ar com.tr " +
    "com.sg com.hk com.tw co.kr or.kr co.il com.ua com.pl co.id com.my com.ph com.vn co.th com.co com.pe " +
    "com.ve com.eg com.sa com.ng co.ke com.pk com.bd " +
    "github.io githubusercontent.com gitlab.io herokuapp.com vercel.app netlify.app pages.dev workers.dev " +
    "web.app firebaseapp.com appspot.com cloudfront.net azurewebsites.net blogspot.com s3.amazonaws.com " +
    "onrender.com fly.dev glitch.me repl.co ngrok.io ngrok-free.app r2.dev deno.dev surge.sh now.sh"
  ).split(" "),
);

/** True for a name no cookie may be scoped to: no dot (bare TLD / single label) or a listed suffix. */
export function isPublicSuffix(domain: string): boolean {
  return !domain.includes(".") || MULTI_LABEL_SUFFIXES.has(domain);
}

function isIpLike(host: string): boolean {
  return /^\d+$/.test(host.slice(host.lastIndexOf(".") + 1)) || host.includes(":");
}

/** RFC 6265 §5.1.3. `domain` has no leading dot. */
export function domainMatches(host: string, domain: string): boolean {
  if (!host || !domain) return false;
  if (host === domain) return true;
  return host.endsWith(`.${domain}`) && !isIpLike(host);
}

/** RFC 6265 §5.1.4. */
export function pathMatches(requestPath: string, cookiePath: string): boolean {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith("/") || requestPath.charAt(cookiePath.length) === "/";
}

function requestPathname(path: string | undefined): string {
  const p = (path ?? "/").split(/[?#]/)[0];
  return p.startsWith("/") ? p : "/";
}

/** RFC 6265 §5.1.4 default-path of a request path. */
function defaultPath(requestPath: string): string {
  const p = requestPathname(requestPath);
  const last = p.lastIndexOf("/");
  return last <= 0 ? "/" : p.slice(0, last);
}

function fail(code: string): never {
  throw new CookieInputError(code);
}

function checkName(name: unknown): string {
  if (typeof name !== "string" || name.length === 0 || name.length > MAX_COOKIE_NAME_CHARS || !TOKEN_RE.test(name)) {
    fail("invalid_cookie_name");
  }
  return name as string;
}

function checkValue(value: unknown): string {
  if (typeof value !== "string") fail("invalid_cookie_value");
  const v = value as string;
  if (v.length > MAX_COOKIE_VALUE_CHARS) fail("cookie_value_too_long");
  if (!VALUE_RE.test(v) || v !== v.trim()) fail("invalid_cookie_value");
  return v;
}

function checkPath(path: unknown): string {
  if (path === undefined || path === null || path === "") return "/";
  if (typeof path !== "string" || path.length > MAX_COOKIE_PATH_CHARS || !PATH_RE.test(path)) fail("invalid_cookie_path");
  return path as string;
}

/** "" (no domain) or a validated lower-case host without the leading dot. */
function checkDomain(domain: unknown): string {
  if (domain === undefined || domain === null || domain === "") return "";
  if (typeof domain !== "string") fail("invalid_cookie_domain");
  const d = (domain as string).trim().toLowerCase().replace(/^\./, "").replace(/\.$/, "");
  if (!HOST_RE.test(d) || isIpLike(d)) fail("invalid_cookie_domain");
  if (isPublicSuffix(d)) fail("public_suffix_domain");
  return d;
}

function checkExpiry(raw: unknown): number | null {
  if (raw === undefined || raw === null || raw === "") return null;
  let seconds: number;
  if (typeof raw === "number") seconds = raw;
  else if (typeof raw === "string") {
    const t = raw.trim();
    if (/^session$/i.test(t)) return null;
    seconds = /^-?\d+(\.\d+)?$/.test(t) ? Number(t) : Date.parse(t) / 1000;
  } else return fail("invalid_cookie_expiry");
  if (!Number.isFinite(seconds)) fail("invalid_cookie_expiry");
  if (seconds <= 0) return null; // 0 / -1: "session" in cookies.txt and in Puppeteer exports
  if (seconds > 1e11) seconds /= 1000; // milliseconds
  return Math.floor(seconds);
}

interface RawCookie {
  name: unknown;
  value: unknown;
  domain: unknown;
  path: unknown;
  secure: boolean;
  httpOnly: boolean;
  /** undefined: decide from the leading dot of `domain`. */
  hostOnly: boolean | undefined;
  expires: unknown;
}

function rawFromHeader(text: string): RawCookie[] {
  if (/[\r\n]/.test(text)) fail("invalid_cookie_header");
  const body = text.replace(/^cookie\s*:/i, "");
  const out: RawCookie[] = [];
  for (const part of body.split(";")) {
    const pair = part.trim();
    if (!pair) continue;
    const eq = pair.indexOf("=");
    if (eq <= 0) fail("invalid_cookie_header");
    out.push({
      name: pair.slice(0, eq).trim(),
      value: pair.slice(eq + 1).trim(),
      domain: "",
      path: "/",
      secure: false,
      httpOnly: false,
      hostOnly: true,
      expires: null,
    });
  }
  return out;
}

function rawFromJson(value: unknown): RawCookie[] {
  const list = Array.isArray(value)
    ? value
    : value && typeof value === "object" && Array.isArray((value as { cookies?: unknown }).cookies)
      ? ((value as { cookies: unknown[] }).cookies)
      : fail("invalid_cookie_json");
  return list.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) fail("invalid_cookie_json");
    const o = item as Record<string, unknown>;
    const session = o.session === true;
    return {
      name: o.name,
      value: o.value,
      domain: o.domain,
      path: o.path,
      secure: o.secure === true,
      httpOnly: o.httpOnly === true,
      hostOnly: typeof o.hostOnly === "boolean" ? o.hostOnly : undefined,
      expires: session ? null : (o.expirationDate ?? o.expires ?? o.expiry ?? null),
    };
  });
}

function rawFromNetscape(text: string): RawCookie[] {
  const out: RawCookie[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    let line = rawLine;
    let httpOnly = false;
    if (line.startsWith("#HttpOnly_")) {
      httpOnly = true;
      line = line.slice("#HttpOnly_".length);
    } else if (line.trim() === "" || line.startsWith("#")) continue;
    const f = line.split("\t");
    if (f.length < 6 || f.length > 7) fail("invalid_cookies_txt");
    const flag = f[1].trim().toUpperCase();
    const secure = f[3].trim().toUpperCase();
    if (!["TRUE", "FALSE"].includes(flag) || !["TRUE", "FALSE"].includes(secure) || !/^\d{1,16}$/.test(f[4].trim())) {
      fail("invalid_cookies_txt");
    }
    if (f[0].trim() === "") fail("invalid_cookie_domain");
    out.push({
      name: f[5],
      value: f[6] ?? "",
      domain: f[0].trim(),
      path: f[2],
      secure: secure === "TRUE",
      httpOnly,
      hostOnly: flag === "FALSE",
      expires: Number(f[4].trim()),
    });
  }
  return out;
}

function sameIdentity(a: StoredCookie, b: StoredCookie, site: string): boolean {
  return a.name === b.name && a.path === b.path && (a.domain || site) === (b.domain || site);
}

export interface ParseCookieOptions {
  /** The entry's site. Cookies scoped to unrelated domains are skipped; "" domains are bound to it at use time. */
  site?: string;
  /** Epoch ms; cookies already expired at this time are skipped. Default Date.now(). */
  now?: number;
}

export interface ParsedCookieInput {
  jar: CookieJar;
  format: "header" | "json" | "netscape";
  /** Cookies left out, by reason. Counts only. */
  skipped: { short_value: number; expired: number; other_site: number };
}

/**
 * Parse what the owner pasted. Accepts a string in any of the three formats, or
 * an already-decoded JSON array (the card page's JSON submit). Throws
 * CookieInputError with a short code; never includes input text in an error.
 */
export function parseCookieInput(input: unknown, opts: ParseCookieOptions = {}): ParsedCookieInput {
  const site = opts.site ?? "";
  const nowSec = Math.floor((opts.now ?? Date.now()) / 1000);
  let raw: RawCookie[];
  let format: ParsedCookieInput["format"];
  if (typeof input === "string") {
    if (input.length > MAX_COOKIE_INPUT_CHARS) fail("cookie_input_too_large");
    const text = (input.charCodeAt(0) === 0xfeff ? input.slice(1) : input).trim(); // drop a byte-order mark
    if (!text) fail("cookie_input_empty");
    if (text.includes("\u0000")) fail("invalid_cookie_value");
    if (text.startsWith("[") || text.startsWith("{")) {
      let decoded: unknown;
      try {
        decoded = JSON.parse(text);
      } catch {
        return fail("invalid_cookie_json");
      }
      raw = rawFromJson(decoded);
      format = "json";
    } else if (text.includes("\t") || /^# (Netscape )?HTTP Cookie File/im.test(text)) {
      raw = rawFromNetscape(text);
      format = "netscape";
    } else {
      raw = rawFromHeader(text);
      format = "header";
    }
  } else if (Array.isArray(input)) {
    if (input.length > MAX_RAW_COOKIES) fail("too_many_cookies");
    raw = rawFromJson(input);
    format = "json";
  } else {
    return fail("cookie_input_empty");
  }
  if (raw.length === 0) fail("cookie_input_empty");
  if (raw.length > MAX_RAW_COOKIES) fail("too_many_cookies");

  const skipped = { short_value: 0, expired: 0, other_site: 0 };
  const cookies: StoredCookie[] = [];
  for (const r of raw) {
    const leadingDot = typeof r.domain === "string" && r.domain.trim().startsWith(".");
    const domain = checkDomain(r.domain);
    const hostOnly = domain === "" ? true : (r.hostOnly ?? !leadingDot);
    if (site && domain) {
      const related = domain === site || domain.endsWith(`.${site}`) || (!hostOnly && site.endsWith(`.${domain}`));
      if (!related) {
        skipped.other_site += 1;
        continue;
      }
    }
    const cookie: StoredCookie = {
      name: checkName(r.name),
      value: checkValue(r.value),
      domain,
      path: checkPath(r.path),
      secure: r.secure,
      httpOnly: r.httpOnly,
      hostOnly,
      expires: checkExpiry(r.expires),
    };
    if (cookie.expires !== null && cookie.expires <= nowSec) {
      skipped.expired += 1;
      continue;
    }
    if (cookie.value.length < MIN_COOKIE_VALUE_CHARS) {
      skipped.short_value += 1;
      continue;
    }
    if (cookies.some((c) => sameIdentity(c, cookie, site))) fail("duplicate_cookie");
    cookies.push(cookie);
    if (cookies.length > MAX_COOKIES) fail("too_many_cookies");
  }
  if (cookies.length === 0) fail("no_usable_cookie");
  const jar: CookieJar = { v: 1, cookies };
  if (serializeJar(jar).length > MAX_COOKIE_JAR_CHARS) fail("cookie_jar_too_large");
  return { jar, format, skipped };
}

function canonicalCookie(c: StoredCookie): StoredCookie {
  // Fixed key order: this string is what the entry's fingerprint is computed over.
  return {
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path,
    secure: c.secure,
    httpOnly: c.httpOnly,
    hostOnly: c.hostOnly,
    expires: c.expires,
  };
}

/** The canonical stored form: compact JSON, fixed key order, cookies in jar order. */
export function serializeJar(jar: CookieJar): string {
  return JSON.stringify({ v: 1, cookies: jar.cookies.map(canonicalCookie) });
}

/** Strictly re-validate a stored jar. Throws CookieInputError("invalid_cookie_jar"). */
export function parseStoredJar(text: string): CookieJar {
  try {
    const o = JSON.parse(text) as { v?: unknown; cookies?: unknown };
    if (!o || o.v !== 1 || !Array.isArray(o.cookies) || o.cookies.length > MAX_COOKIES) throw new Error("shape");
    const cookies = o.cookies.map((raw): StoredCookie => {
      const c = raw as Record<string, unknown>;
      if (!c || typeof c !== "object") throw new Error("shape");
      const expires = c.expires === null ? null : c.expires;
      if (expires !== null && !(typeof expires === "number" && Number.isInteger(expires) && expires > 0)) throw new Error("shape");
      if ([c.secure, c.httpOnly, c.hostOnly].some((b) => typeof b !== "boolean")) throw new Error("shape");
      const domain = checkDomain(c.domain);
      if (domain !== c.domain || (domain === "" && c.hostOnly !== true)) throw new Error("shape");
      const value = checkValue(c.value);
      if (value.length < MIN_COOKIE_VALUE_CHARS) throw new Error("shape");
      const path = checkPath(c.path);
      if (path !== c.path) throw new Error("shape");
      return {
        name: checkName(c.name),
        value,
        domain,
        path,
        secure: c.secure as boolean,
        httpOnly: c.httpOnly as boolean,
        hostOnly: c.hostOnly as boolean,
        expires: expires as number | null,
      };
    });
    return { v: 1, cookies };
  } catch {
    throw new CookieInputError("invalid_cookie_jar");
  }
}

export interface CookieRequestContext {
  /** Request host, lower-case. */
  host: string;
  /** Request path (a query string is ignored). */
  path: string;
  /** Epoch ms. */
  now: number;
  /** The entry's site: what a cookie with domain "" is bound to (host-only). */
  site?: string;
}

function cookieApplies(c: StoredCookie, ctx: CookieRequestContext, pathname: string): boolean {
  if (c.expires !== null && c.expires * 1000 <= ctx.now) return false;
  const domain = c.domain || ctx.site || "";
  if (!domain) return false;
  if (c.hostOnly ? ctx.host !== domain : !domainMatches(ctx.host, domain) || isPublicSuffix(domain)) return false;
  return pathMatches(pathname, c.path);
}

/**
 * RFC 6265 §5.4: the Cookie header for one https request, or null when no
 * cookie matches. Host-only cookies need the exact host; domain cookies match
 * the domain and its subdomains (never a public suffix); the path must
 * path-match; expired cookies are skipped; `Secure` is always satisfied (the
 * broker only makes https requests); longer paths first, then jar order.
 */
export function cookieHeaderFor(jar: CookieJar, ctx: CookieRequestContext): string | null {
  const pathname = requestPathname(ctx.path);
  const host = ctx.host.toLowerCase();
  const picked = jar.cookies
    .map((c, i) => ({ c, i }))
    .filter(({ c }) => cookieApplies(c, { ...ctx, host }, pathname))
    .sort((a, b) => b.c.path.length - a.c.path.length || a.i - b.i);
  if (picked.length === 0) return null;
  return picked.map(({ c }) => `${c.name}=${c.value}`).join("; ");
}

interface SetCookie {
  name: string;
  value: string;
  domainAttr: string | null;
  pathAttr: string | null;
  secure: boolean;
  httpOnly: boolean;
  /** Epoch seconds; null = session; -Infinity = delete now. */
  expires: number | null;
}

/** RFC 6265 §5.2 (attribute parsing). Returns null for anything malformed: a response is never trusted. */
function parseSetCookie(header: string, nowSec: number): SetCookie | null {
  if (typeof header !== "string" || header.length > MAX_SET_COOKIE_CHARS || ["\r", "\n", "\u0000"].some((ch) => header.includes(ch))) return null;
  const parts = header.split(";");
  const pair = parts[0];
  const eq = pair.indexOf("=");
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  const value = pair.slice(eq + 1).trim();
  if (!name || name.length > MAX_COOKIE_NAME_CHARS || !TOKEN_RE.test(name)) return null;
  if (value.length > MAX_COOKIE_VALUE_CHARS || !VALUE_RE.test(value)) return null;
  const out: SetCookie = { name, value, domainAttr: null, pathAttr: null, secure: false, httpOnly: false, expires: null };
  let maxAge: number | null = null;
  let expiresAttr: number | null = null;
  for (const part of parts.slice(1)) {
    const i = part.indexOf("=");
    const key = (i < 0 ? part : part.slice(0, i)).trim().toLowerCase();
    const val = i < 0 ? "" : part.slice(i + 1).trim();
    if (key === "secure") out.secure = true;
    else if (key === "httponly") out.httpOnly = true;
    else if (key === "domain") {
      const d = val.toLowerCase().replace(/^\./, "").replace(/\.$/, "");
      if (d) out.domainAttr = d; // an empty Domain is ignored (§5.2.3)
    } else if (key === "path") out.pathAttr = val.startsWith("/") ? val : null;
    else if (key === "max-age") {
      if (/^-?\d{1,15}$/.test(val)) maxAge = Number(val);
    } else if (key === "expires") {
      const t = Date.parse(val);
      if (Number.isFinite(t)) expiresAttr = Math.floor(t / 1000);
    }
  }
  if (maxAge !== null) out.expires = maxAge <= 0 ? -Infinity : nowSec + maxAge; // Max-Age wins over Expires
  else if (expiresAttr !== null) out.expires = expiresAttr <= nowSec ? -Infinity : expiresAttr;
  return out;
}

/**
 * RFC 6265 §5.3: apply a response's Set-Cookie headers to the jar. Returns a
 * NEW jar and whether anything changed. Rules:
 *   - Domain attribute: honoured only when the request host domain-matches it
 *     and it is not a public suffix (a suffix equal to the host itself becomes
 *     host-only); otherwise the cookie is ignored — a response cannot set a
 *     cookie for another site or for a superdomain it does not belong to.
 *   - No Domain attribute: host-only for the request host.
 *   - Path attribute, or the request's default-path.
 *   - Max-Age <= 0 or a past Expires deletes the stored cookie.
 *   - `__Secure-` needs Secure; `__Host-` needs Secure, no Domain and Path=/.
 *   - A value shorter than 8 characters cannot be stored (see the file header):
 *     the stored cookie of that identity, now stale, is removed.
 * Date parsing uses Date.parse, not the RFC's own cookie-date algorithm.
 */
export function mergeSetCookie(
  jar: CookieJar,
  setCookieHeaders: readonly string[],
  ctx: CookieRequestContext,
): { jar: CookieJar; changed: boolean } {
  const site = ctx.site ?? "";
  const host = ctx.host.toLowerCase();
  const nowSec = Math.floor(ctx.now / 1000);
  const cookies = jar.cookies.map(canonicalCookie);
  let changed = false;
  for (const header of setCookieHeaders) {
    const sc = parseSetCookie(header, nowSec);
    if (!sc) continue;
    let domain = host;
    let hostOnly = true;
    if (sc.domainAttr !== null) {
      if (!HOST_RE.test(sc.domainAttr) || isIpLike(sc.domainAttr)) continue;
      if (isPublicSuffix(sc.domainAttr)) {
        if (sc.domainAttr !== host) continue;
      } else if (!domainMatches(host, sc.domainAttr)) continue;
      else hostOnly = false;
      domain = sc.domainAttr;
    }
    if (!HOST_RE.test(domain)) continue;
    const path = sc.pathAttr !== null && sc.pathAttr.length <= MAX_COOKIE_PATH_CHARS && PATH_RE.test(sc.pathAttr) ? sc.pathAttr : defaultPath(ctx.path);
    if (sc.name.startsWith("__Secure-") && !sc.secure) continue;
    if (sc.name.startsWith("__Host-") && (!sc.secure || sc.domainAttr !== null || path !== "/")) continue;

    const next: StoredCookie = {
      name: sc.name,
      value: sc.value,
      domain,
      path,
      secure: sc.secure,
      httpOnly: sc.httpOnly,
      hostOnly,
      expires: sc.expires === -Infinity ? null : sc.expires,
    };
    const at = cookies.findIndex((c) => sameIdentity(c, next, site));
    const remove = sc.expires === -Infinity || sc.value.length < MIN_COOKIE_VALUE_CHARS;
    if (remove) {
      if (at >= 0) {
        cookies.splice(at, 1);
        changed = true;
      }
      continue;
    }
    if (at >= 0) {
      const old = cookies[at];
      // A site-bound cookie ("" domain) stays site-bound when the site itself refreshes it host-only.
      if (old.domain === "" && next.hostOnly && next.domain === site) next.domain = "";
      if (JSON.stringify(old) !== JSON.stringify(next)) {
        cookies[at] = next;
        changed = true;
      }
    } else if (cookies.length < MAX_COOKIES) {
      cookies.push(next);
      changed = true;
    }
  }
  return { jar: { v: 1, cookies }, changed };
}

export const MAX_SUMMARY_NAMES = 50;
export const MAX_SUMMARY_DOMAINS = 20;

/** Metadata only. Never a value. */
export interface CookieJarSummary {
  count: number;
  /** Distinct cookie names, sorted; at most MAX_SUMMARY_NAMES. */
  names: string[];
  /** Distinct domains, sorted ("" is shown as the entry's site); at most MAX_SUMMARY_DOMAINS. */
  domains: string[];
  /** True when names or domains were cut to their caps. */
  truncated: boolean;
  /** Earliest expiry among cookies that expire (ISO), or null when all are session cookies. */
  expires_at: string | null;
  /** Cookies without an expiry. */
  session_cookies: number;
}

export function describeJar(jar: CookieJar, site = ""): CookieJarSummary {
  const names = [...new Set(jar.cookies.map((c) => c.name))].sort();
  const domains = [...new Set(jar.cookies.map((c) => (c.hostOnly ? "" : ".") + (c.domain || site || "(entry site)")))].sort();
  const expiries = jar.cookies.map((c) => c.expires).filter((e): e is number => e !== null);
  return {
    count: jar.cookies.length,
    names: names.slice(0, MAX_SUMMARY_NAMES),
    domains: domains.slice(0, MAX_SUMMARY_DOMAINS),
    truncated: names.length > MAX_SUMMARY_NAMES || domains.length > MAX_SUMMARY_DOMAINS,
    expires_at: expiries.length ? new Date(Math.min(...expiries) * 1000).toISOString() : null,
    session_cookies: jar.cookies.length - expiries.length,
  };
}

/**
 * Every form of the jar's values that must be armed for redaction before a
 * request: raw, URL-encoded, URL-decoded (a framework may echo the decoded
 * value), base64 and base64url. Only forms of 8+ characters (redaction's floor).
 */
export function jarRedactionForms(jar: CookieJar): string[] {
  const out = new Set<string>();
  for (const { value } of jar.cookies) {
    out.add(value);
    out.add(encodeURIComponent(value));
    out.add(new URLSearchParams({ v: value }).toString().slice(2));
    try {
      out.add(decodeURIComponent(value));
    } catch {
      // not percent-encoded
    }
    const bytes = Buffer.from(value, "utf8");
    out.add(bytes.toString("base64"));
    out.add(bytes.toString("base64url"));
  }
  return [...out].filter((v) => v.trim().length >= MIN_COOKIE_VALUE_CHARS);
}
