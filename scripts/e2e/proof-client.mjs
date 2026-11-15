#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * ECHO Vault v2 end-to-end proof client.
 *
 * A real MCP client with zero dependencies (Node >= 22). It talks only to the
 * vault's public HTTP surface, the way Claude or ChatGPT would:
 *
 *   discovery (RFC 9728 + RFC 8414) → dynamic client registration (RFC 7591)
 *   → authorization request with PKCE S256 → wait for the owner's approval
 *   → token exchange → MCP initialize + tools/list → vault_status
 *   → entry_request_card → wait until the owner typed the secret on the card
 *   → entry_use (GET) → owner approval → retry with approval_id
 *   → entry_list, audit_list, audit_verify → verdict.
 *
 * The client never holds the credential. It ends by scanning everything it
 * ever received for token shapes (the detectors of scripts/credential-scan.mjs)
 * and, with --fingerprint, for any substring whose SHA-256 prefix is the
 * entry's fingerprint.
 *
 * What it prints and writes: step results, ids, statuses and shapes. Its own
 * bearer / refresh tokens, authorization code, pending handle and PKCE verifier
 * are masked in the transcript and never printed.
 *
 *   node scripts/e2e/proof-client.mjs --vault https://vault.example \
 *     --site httpbin.org --account proof --path /bearer --out proof-transcript.json
 */
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { DETECTORS } from "../credential-scan.mjs";

export const CLIENT_NAME = "ECHO Vault proof client";
export const DEFAULT_SCOPES = "vault.read vault.write audit.read";
const REDIRECT_URI = "http://127.0.0.1:53682/callback";
const REQUEST_TIMEOUT_MS = 30_000;
const MCP_PROTOCOL_VERSION = "2025-06-18";
const ENTRY_KINDS = ["password", "api_key", "oauth_token"];

const USAGE = `ECHO Vault end-to-end proof client

  node scripts/e2e/proof-client.mjs --vault <origin> --site <domain> [options]

Required
  --vault <origin>       The vault's public origin, e.g. https://vault.example (http only for loopback).
  --site <domain>        Site of the credential entry. Pick a low-stakes target with a throwaway
                         value, e.g. httpbin.org with --path /bearer.

Options
  --account <name>       Account of the entry (default: proof).
  --kind <kind>          api_key | oauth_token | password (default: api_key).
  --path <path>          Path for the entry_use GET on the entry's own site (default: /).
  --scopes "<a b c>"     Scopes to request (default: "${DEFAULT_SCOPES}").
  --timeout-s <n>        How long to wait for each owner action (default: 900).
  --out <file>           Transcript JSON (default: ./e2e-proof-transcript.json, mode 0600).
  --auto                 No interactive prompt; pure polling.
  --show-body            Print the redacted body the site returned (default: its shape only).
  --reenter              Ask for a card even when the entry already exists and is active.
  --fingerprint-check    Also check that the vault withholds fingerprint / length metadata from this client.
  --fingerprint <h:len>  The entry's fingerprint and length as the OWNER sees them on the card's
                         "Stored in vault" page (8 hex characters, then the character count, e.g.
                         3fa9c1d2:44). Everything the client received is searched for a substring
                         with that SHA-256 prefix. Implies --fingerprint-check.
  --expect-use-error <c> Rehearsal only: pass the entry_use step when it fails with exactly this error.
  --help

Exit code 0 only when every step passed and no secret was observed.
`;

// ---------------------------------------------------------------- helpers (pure, exported for tests)

/** An expected failure with a message that is safe to print. Never carries a request body. */
export class ProofError extends Error {
  constructor(step, message) {
    super(message);
    this.name = "ProofError";
    this.step = step;
  }
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

export function sha256Hex(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** PKCE S256 challenge for a verifier (RFC 7636 §4.2). */
export function pkceChallenge(verifier) {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

/** True for https, or http to a loopback host. Tokens are never sent anywhere else. */
export function isSafeEndpoint(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.username || url.password) return false;
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}

/** Undo the HTML escaping the vault's pages apply to attribute values. */
export function unescapeHtml(text) {
  return String(text)
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#96;/g, "`")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

/** The polling URL of the "Approve this connection on your phone" page, or null. */
export function extractRefreshUrl(html) {
  const m = /<meta http-equiv="refresh" content="\d+;url=([^"]+)"/i.exec(String(html));
  return m ? unescapeHtml(m[1]) : null;
}

/** `resource_metadata` of a `WWW-Authenticate: Bearer …` header, or null. */
export function parseResourceMetadata(header) {
  const m = /resource_metadata="([^"]+)"/i.exec(String(header ?? ""));
  return m ? m[1] : null;
}

const VAULT_TOKEN_RE = /(?<![A-Za-z0-9])(ev[acpr])_[A-Za-z0-9_-]{43,}/g;

/**
 * Masks the client's own credentials in anything that is written or printed.
 * `register(label, value)` adds an exact value; vault-issued token shapes are
 * masked even when they were never registered.
 */
export class Masker {
  constructor() {
    this.values = [];
  }
  register(label, value) {
    if (typeof value === "string" && value.length >= 8) this.values.push({ label, value });
  }
  mask(text) {
    let out = String(text);
    for (const { label, value } of [...this.values].sort((a, b) => b.value.length - a.value.length)) {
      if (out.includes(value)) out = out.split(value).join(`[MASKED:${label}]`);
      const encoded = encodeURIComponent(value);
      if (encoded !== value && out.includes(encoded)) out = out.split(encoded).join(`[MASKED:${label}]`);
    }
    return out.replace(VAULT_TOKEN_RE, (_m, prefix) => `[MASKED:${prefix}_token]`);
  }
  maskValue(value) {
    if (value == null) return value;
    if (typeof value === "string") return this.mask(value);
    if (Array.isArray(value)) return value.map((v) => this.maskValue(v));
    if (typeof value === "object") {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = this.maskValue(v);
      return out;
    }
    return value;
  }
}

/** Keys, types and lengths of a value: what is safe to show without --show-body. */
export function bodyShape(value, depth = 0) {
  if (value === null) return "null";
  if (typeof value === "string") return `string(${value.length})`;
  if (typeof value !== "object") return typeof value;
  if (depth >= 4) return Array.isArray(value) ? `array(${value.length})` : "object";
  if (Array.isArray(value)) return value.length ? [`array(${value.length}) of`, bodyShape(value[0], depth + 1)] : "array(0)";
  const out = {};
  for (const [k, v] of Object.entries(value)) out[k] = bodyShape(v, depth + 1);
  return out;
}

/**
 * Token-shape findings in text. Returns [{ detector, length }] — never the match.
 * `ignore` holds exact values that are expected (the client's own tokens).
 */
export function scanTokenShapes(text, ignore = []) {
  let hay = String(text);
  for (const value of ignore) if (value) hay = hay.split(value).join(" ");
  const findings = [];
  for (const d of DETECTORS) {
    d.re.lastIndex = 0;
    let m;
    while ((m = d.re.exec(hay)) !== null) {
      const value = d.marker ? m[0] : (m[1] ?? m[0]);
      findings.push({ detector: d.id, length: value.length });
      if (m.index === d.re.lastIndex) d.re.lastIndex += 1;
    }
  }
  return findings;
}

/** Parse "3fa9c1d2:44" → { prefix, length }, or null. */
export function parseFingerprint(raw) {
  const m = /^([0-9a-f]{8}):([0-9]{1,4})$/i.exec(String(raw ?? "").trim());
  if (!m) return null;
  const length = Number(m[2]);
  return length >= 8 && length <= 4096 ? { prefix: m[1].toLowerCase(), length } : null;
}

/**
 * Number of substrings of exactly `fp.length` characters in `text` whose
 * SHA-256 starts with `fp.prefix`. The vault's entry fingerprint is the first
 * 8 hex characters of SHA-256(secret), so a hit means the secret itself is in
 * the text (a chance hit has probability 2^-32 per window).
 */
export function countFingerprintWindows(text, fp) {
  const s = String(text);
  let hits = 0;
  for (let i = 0; i + fp.length <= s.length; i += 1) {
    if (createHash("sha256").update(s.slice(i, i + fp.length), "utf8").digest("hex").startsWith(fp.prefix)) hits += 1;
  }
  return hits;
}

/** Every string leaf (and key) of a JSON value, plus nested JSON found in strings. */
export function stringLeaves(value, out = []) {
  if (typeof value === "string") {
    out.push(value);
    if (value.length > 1 && (value.startsWith("{") || value.startsWith("["))) {
      try {
        stringLeaves(JSON.parse(value), out);
      } catch {
        // not JSON
      }
    }
  } else if (Array.isArray(value)) {
    for (const v of value) stringLeaves(v, out);
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      out.push(k);
      stringLeaves(v, out);
    }
  }
  return out;
}

/** Paths of keys that would expose secret metadata to an agent (fingerprint, length, the value itself). */
export function forbiddenMetadataKeys(value, path = "$", out = []) {
  const FORBIDDEN = new Set(["fingerprint", "secret_length", "secret", "password", "key_fingerprint"]);
  if (Array.isArray(value)) value.forEach((v, i) => forbiddenMetadataKeys(v, `${path}[${i}]`, out));
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (FORBIDDEN.has(k.toLowerCase())) out.push(`${path}.${k}`);
      forbiddenMetadataKeys(v, `${path}.${k}`, out);
    }
  }
  return out;
}

const ERROR_HINTS = {
  missing_scope: "The owner granted fewer scopes than this step needs. Re-run and approve the scopes shown on Telegram.",
  approval_unavailable: "The vault could not create an approval: check TELEGRAM_BOT_TOKEN, ECHO_VAULT_APPROVER_TELEGRAM_ID and ECHO_VAULT_APPROVAL_HMAC_KEY on the server.",
  approver_not_configured: "ECHO_VAULT_APPROVER_TELEGRAM_ID is not set on the server.",
  public_url_not_configured: "ECHO_VAULT_PUBLIC_URL is not set to an https origin on the server.",
  card_notification_failed: "The vault could not send the card link on Telegram: check the bot token, and that the owner has messaged the bot once.",
  too_many_pending_cards: "This client already has 5 open cards. Wait for them to expire (30 minutes).",
  entry_not_found: "No entry for that site/account. Run without --expect-use-error so the card is requested first.",
  entry_secret_missing: "The canonical vault has no value for this entry. Ask for a re-entry card (--reenter).",
  vault_unavailable: "The server could not reach the canonical vault: check ECHO_SDK_API_KEY / ECHO_SDK_GATE_URL.",
  hostname_not_allowed: "The broker refuses that host (private, loopback or not the entry's own site).",
  dns_lookup_failed: "The server could not resolve the site's name.",
  site_rejected_credential: "The site answered 401: the stored value is not accepted there. The entry is now flagged for re-entry.",
  site_forbidden: "The site answered 403: the credential was accepted but this request is not allowed.",
  ledger_unavailable: "The action could not be recorded in the ledger, so the vault refused or withheld it.",
  rate_limited: "A policy rate limit was hit. Wait and retry.",
  rate_limit_unavailable: "The rate-limit store is unreachable; the vault fails closed.",
  approval_denied: "The owner denied the request on Telegram.",
  approval_expired: "The approval expired before the owner decided (10 minutes).",
  tier3_human_only: "That capability is reserved for the owner.",
};

function hint(code) {
  return ERROR_HINTS[code] ? ` ${ERROR_HINTS[code]}` : "";
}

// ---------------------------------------------------------------- the run

export function parseCli(argv) {
  const { values } = parseArgs({
    args: argv,
    allowPositionals: false,
    options: {
      vault: { type: "string" },
      site: { type: "string" },
      account: { type: "string", default: "proof" },
      kind: { type: "string", default: "api_key" },
      path: { type: "string", default: "/" },
      scopes: { type: "string", default: DEFAULT_SCOPES },
      "timeout-s": { type: "string", default: "900" },
      out: { type: "string", default: "e2e-proof-transcript.json" },
      auto: { type: "boolean", default: false },
      "show-body": { type: "boolean", default: false },
      reenter: { type: "boolean", default: false },
      "fingerprint-check": { type: "boolean", default: false },
      fingerprint: { type: "string" },
      "expect-use-error": { type: "string" },
      "poll-ms": { type: "string", default: "3000" },
      help: { type: "boolean", default: false },
    },
  });
  if (values.help) return { help: true };
  const problems = [];
  if (!values.vault) problems.push("--vault <origin> is required");
  else if (!isSafeEndpoint(values.vault) || new URL(values.vault).pathname !== "/" || new URL(values.vault).search) {
    problems.push("--vault must be an https origin without a path (http only for localhost / 127.0.0.1)");
  }
  if (!values.site) problems.push("--site <domain> is required (pick a low-stakes target, e.g. httpbin.org)");
  if (!ENTRY_KINDS.includes(values.kind)) problems.push(`--kind must be one of ${ENTRY_KINDS.join(", ")}`);
  if (!values.path.startsWith("/")) problems.push("--path must start with /");
  const timeoutS = Number(values["timeout-s"]);
  if (!Number.isFinite(timeoutS) || timeoutS < 5 || timeoutS > 86_400) problems.push("--timeout-s must be between 5 and 86400");
  const pollMs = Number(values["poll-ms"]);
  if (!Number.isFinite(pollMs) || pollMs < 200 || pollMs > 60_000) problems.push("--poll-ms must be between 200 and 60000");
  let fingerprint = null;
  if (values.fingerprint !== undefined) {
    fingerprint = parseFingerprint(values.fingerprint);
    if (!fingerprint) problems.push("--fingerprint must look like 3fa9c1d2:44 (8 hex characters, a colon, the length)");
  }
  if (problems.length) return { problems };
  return {
    vault: new URL(values.vault).origin,
    site: values.site.trim().toLowerCase(),
    account: values.account,
    kind: values.kind,
    path: values.path,
    scopes: values.scopes.split(/\s+/).filter(Boolean).join(" "),
    timeoutMs: timeoutS * 1000,
    pollMs,
    out: resolve(values.out),
    auto: values.auto,
    showBody: values["show-body"],
    reenter: values.reenter,
    fingerprintCheck: values["fingerprint-check"] || fingerprint !== null,
    fingerprint,
    expectUseError: values["expect-use-error"] ?? null,
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class ProofRun {
  constructor(opts, io = {}) {
    this.o = opts;
    this.print = io.print ?? ((line) => process.stdout.write(`${line}\n`));
    this.masker = new Masker();
    /** Transcript entries, masked at write time. */
    this.exchanges = [];
    /** Everything the client received, unmasked, in memory only: the corpus of the final scan. */
    this.received = [];
    /** The client's own credentials: expected in what it received, excluded from the scan. */
    this.own = [];
    this.steps = [];
    this.rpcId = 0;
    this.startedAt = new Date().toISOString();
    this.tokens = null;
    this.clientId = null;
    this.endpoints = null;
    this.useResult = null;
    this.ledgerRows = [];
    this.chain = null;
    this.metadataLeaks = [];
  }

  ownSecret(label, value) {
    this.masker.register(label, value);
    this.own.push(value);
  }

  /** One HTTP exchange. Records it; returns { status, headers, text, json }. Never throws an error that carries the body. */
  async http(step, method, url, { headers = {}, body, redirect = "follow" } = {}) {
    if (!isSafeEndpoint(url)) throw new ProofError(step, "refusing to call an endpoint that is neither https nor loopback http");
    const entry = {
      step,
      at: new Date().toISOString(),
      request: { method, url, headers: { ...headers }, body: body ?? null },
      response: null,
    };
    if (entry.request.headers.authorization) entry.request.headers.authorization = "Bearer [MASKED:access_token]";
    this.exchanges.push(entry);
    let res;
    try {
      res = await fetch(url, { method, headers, body, redirect, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    } catch (err) {
      const code = err?.name === "TimeoutError" ? "timed out" : (err?.cause?.code ?? err?.name ?? "network error");
      entry.response = { error: String(code) };
      throw new ProofError(step, `${method} ${new URL(url).pathname} failed: ${code}. Is the vault reachable at ${new URL(url).origin}?`);
    }
    let text = "";
    try {
      text = await res.text();
    } catch {
      text = "";
    }
    const kept = {};
    for (const name of ["content-type", "www-authenticate", "location", "retry-after", "cache-control"]) {
      const v = res.headers.get(name);
      if (v !== null) kept[name] = v;
    }
    let json;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      json = undefined;
    }
    entry.response = { status: res.status, headers: kept, body: json !== undefined ? json : text };
    this.received.push(text, ...Object.values(kept));
    return { status: res.status, headers: res.headers, text, json };
  }

  async step(id, title, fn) {
    const record = { id, title, ok: false, detail: "" };
    this.steps.push(record);
    try {
      const detail = await fn();
      record.ok = true;
      record.detail = detail ?? "";
      this.print(`[ ok ] ${id} ${title}${record.detail ? ` — ${this.masker.mask(record.detail)}` : ""}`);
    } catch (err) {
      record.detail = err instanceof ProofError ? err.message : `unexpected ${err?.name ?? "error"}`;
      this.print(`[FAIL] ${id} ${title} — ${this.masker.mask(record.detail)}`);
      throw err instanceof ProofError ? err : new ProofError(id, record.detail);
    }
  }

  oauthFailure(step, what, res) {
    const code = res.json?.error ?? `http ${res.status}`;
    const desc = typeof res.json?.error_description === "string" ? `: ${res.json.error_description}` : "";
    const extra =
      res.status === 503 && /not configured/.test(desc)
        ? " Set ECHO_VAULT_PUBLIC_URL (and the rest of docs/DEPLOY.md §3) on the server."
        : res.status === 429
          ? ` Retry after ${res.headers.get("retry-after") ?? "a while"}.`
          : "";
    return new ProofError(step, `${what} was refused (${code}${desc}).${extra}`);
  }

  // ---- 1. discovery
  async discover() {
    const v = this.o.vault;
    const probe = await this.http("discover", "POST", `${v}/api/mcp`, { headers: { "content-type": "application/json" }, body: "{}" });
    if (probe.status !== 401) throw new ProofError("discover", `POST /api/mcp without a token answered ${probe.status}, expected 401. Is this an ECHO Vault v2 server?`);
    const advertised = parseResourceMetadata(probe.headers.get("www-authenticate"));
    if (!advertised) {
      throw new ProofError("discover", "the 401 has no resource_metadata in WWW-Authenticate: ECHO_VAULT_PUBLIC_URL is probably unset on the server");
    }
    const prm = await this.http("discover", "GET", advertised);
    if (prm.status !== 200 || !prm.json) throw this.oauthFailure("discover", "Protected-resource metadata", prm);
    const issuer = Array.isArray(prm.json.authorization_servers) ? prm.json.authorization_servers[0] : null;
    if (typeof issuer !== "string") throw new ProofError("discover", "protected-resource metadata names no authorization server");
    if (prm.json.resource !== `${v}/api/mcp`) {
      throw new ProofError("discover", `the server says its resource is ${String(prm.json.resource).slice(0, 200)}, not ${v}/api/mcp: ECHO_VAULT_PUBLIC_URL does not match --vault`);
    }
    const asm = await this.http("discover", "GET", `${issuer.replace(/\/+$/, "")}/.well-known/oauth-authorization-server`);
    if (asm.status !== 200 || !asm.json) throw this.oauthFailure("discover", "Authorization-server metadata", asm);
    const m = asm.json;
    for (const key of ["authorization_endpoint", "token_endpoint", "registration_endpoint"]) {
      if (typeof m[key] !== "string" || !isSafeEndpoint(m[key])) throw new ProofError("discover", `authorization-server metadata has no usable ${key}`);
    }
    if (m.issuer !== issuer) throw new ProofError("discover", "issuer in the authorization-server metadata does not match the protected-resource metadata");
    if (!Array.isArray(m.code_challenge_methods_supported) || !m.code_challenge_methods_supported.includes("S256")) {
      throw new ProofError("discover", "the authorization server does not advertise PKCE S256");
    }
    this.endpoints = {
      resource: prm.json.resource,
      issuer,
      authorize: m.authorization_endpoint,
      token: m.token_endpoint,
      register: m.registration_endpoint,
    };
    return `resource ${this.endpoints.resource}, issuer ${issuer}, PKCE S256`;
  }

  // ---- 2. dynamic client registration
  async register() {
    const res = await this.http("register", "POST", this.endpoints.register, {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: CLIENT_NAME,
        redirect_uris: [REDIRECT_URI],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        scope: this.o.scopes,
      }),
    });
    if (res.status !== 201 || typeof res.json?.client_id !== "string") throw this.oauthFailure("register", "Client registration", res);
    this.clientId = res.json.client_id;
    return `client_id ${this.clientId}`;
  }

  // ---- 3. authorization request + owner approval
  async authorize() {
    const verifier = b64url(randomBytes(48));
    const state = b64url(randomBytes(18));
    this.ownSecret("pkce_verifier", verifier);
    this.verifier = verifier;
    const url = new URL(this.endpoints.authorize);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: REDIRECT_URI,
      code_challenge: pkceChallenge(verifier),
      code_challenge_method: "S256",
      state,
      scope: this.o.scopes,
      resource: this.endpoints.resource,
    }).toString();
    const first = await this.http("authorize", "GET", url.toString(), { redirect: "manual" });
    if (first.status !== 200) {
      const title = /<h1>([^<]{1,120})<\/h1>/.exec(first.text)?.[1] ?? `http ${first.status}`;
      const para = /<p>([^<]{1,300})<\/p>/.exec(first.text)?.[1] ?? "";
      throw new ProofError("authorize", `the authorization request was refused: ${unescapeHtml(title)}. ${unescapeHtml(para)}`.trim());
    }
    const refresh = extractRefreshUrl(first.text);
    if (!refresh || !refresh.startsWith(`${this.endpoints.authorize}?pending=`)) {
      throw new ProofError("authorize", "the waiting page has no polling link; the server did not start an owner approval");
    }
    this.ownSecret("pending_handle", new URL(refresh).searchParams.get("pending") ?? "");
    this.print("");
    this.print("       OWNER ACTION 1 of 3: approve the connection on Telegram.");
    this.print(`       The message names the redirect host 127.0.0.1:53682, the client "${CLIENT_NAME}"`);
    this.print(`       and the scopes: ${this.o.scopes}`);
    this.print("       (Nothing has to be opened in a browser: this client polls. The same waiting page is at");
    this.print(`        ${this.masker.mask(url.toString())} )`);
    this.print("");

    const deadline = Date.now() + this.o.timeoutMs;
    for (;;) {
      await sleep(this.o.pollMs);
      const poll = await this.http("authorize", "GET", refresh, { redirect: "manual" });
      if (poll.status === 302) {
        const location = poll.headers.get("location") ?? "";
        let back;
        try {
          back = new URL(location);
        } catch {
          throw new ProofError("authorize", "the server redirected to something that is not a URL");
        }
        if (`${back.origin}${back.pathname}` !== REDIRECT_URI) throw new ProofError("authorize", "the server redirected to a different redirect_uri");
        if (back.searchParams.get("error")) {
          throw new ProofError("authorize", `authorization failed: ${back.searchParams.get("error")} (${back.searchParams.get("error_description") ?? ""})`);
        }
        if (back.searchParams.get("state") !== state) throw new ProofError("authorize", "state mismatch on the authorization response");
        if (back.searchParams.get("iss") !== this.endpoints.issuer) throw new ProofError("authorize", "iss mismatch on the authorization response (RFC 9207)");
        const code = back.searchParams.get("code");
        if (!code) throw new ProofError("authorize", "the authorization response carries no code");
        this.ownSecret("authorization_code", code);
        this.code = code;
        return "owner approved; authorization code received (state and iss verified)";
      }
      if (poll.status === 403) throw new ProofError("authorize", "the owner DENIED the connection on Telegram");
      if (poll.status === 400) throw new ProofError("authorize", "the connection request expired or was already completed; run the client again");
      if (poll.status !== 200) throw new ProofError("authorize", `polling the approval answered ${poll.status}`);
      if (Date.now() > deadline) throw new ProofError("authorize", `no owner decision within ${this.o.timeoutMs / 1000}s (--timeout-s)`);
    }
  }

  // ---- 4. token exchange
  async exchange() {
    const res = await this.http("token", "POST", this.endpoints.token, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: this.code,
        code_verifier: this.verifier,
        client_id: this.clientId,
        redirect_uri: REDIRECT_URI,
        resource: this.endpoints.resource,
      }).toString(),
    });
    return this.acceptTokens("token", res);
  }

  acceptTokens(step, res) {
    const t = res.json;
    if (res.status !== 200 || typeof t?.access_token !== "string") throw this.oauthFailure(step, "Token request", res);
    this.ownSecret("access_token", t.access_token);
    if (typeof t.refresh_token === "string") this.ownSecret("refresh_token", t.refresh_token);
    this.tokens = { access: t.access_token, refresh: t.refresh_token ?? null, scope: typeof t.scope === "string" ? t.scope : "" };
    const granted = this.tokens.scope.split(" ").filter(Boolean);
    const missing = this.o.scopes.split(" ").filter((s) => !granted.includes(s));
    if (missing.length) throw new ProofError(step, `the token lacks scope(s) ${missing.join(", ")}; the proof needs all of: ${this.o.scopes}`);
    return `access token issued (${t.token_type ?? "Bearer"}, expires_in ${t.expires_in ?? "?"}s, scope "${this.tokens.scope}")`;
  }

  async refresh() {
    if (!this.tokens?.refresh) return false;
    const res = await this.http("token-refresh", "POST", this.endpoints.token, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: this.tokens.refresh, client_id: this.clientId }).toString(),
    });
    if (res.status !== 200) return false;
    this.acceptTokens("token-refresh", res);
    return true;
  }

  // ---- MCP
  async rpc(step, method, params, { notification = false } = {}) {
    const message = { jsonrpc: "2.0", method, ...(params !== undefined ? { params } : {}) };
    if (!notification) message.id = ++this.rpcId;
    const send = () =>
      this.http(step, "POST", this.endpoints.resource, {
        headers: {
          authorization: `Bearer ${this.tokens.access}`,
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "mcp-protocol-version": MCP_PROTOCOL_VERSION,
        },
        body: JSON.stringify(message),
      });
    let res = await send();
    if (res.status === 401 && (await this.refresh())) res = await send();
    if (notification) {
      if (res.status !== 202 && res.status !== 200) throw new ProofError(step, `${method} answered ${res.status}`);
      return null;
    }
    if (res.status === 401) throw new ProofError(step, "the vault rejected this client's access token (revoked, expired, or the client was revoked)");
    if (res.status !== 200 || !res.json) throw new ProofError(step, `${method} answered http ${res.status}`);
    if (res.json.error) throw new ProofError(step, `${method} failed: JSON-RPC ${res.json.error.code} ${String(res.json.error.message).slice(0, 200)}`);
    return res.json.result;
  }

  /** tools/call → the tool's structured payload ({ ok, data } or { ok:false, error, … }). */
  async tool(step, name, args) {
    const result = await this.rpc(step, "tools/call", { name, arguments: args });
    const payload = result?.structuredContent;
    if (!payload || typeof payload.ok !== "boolean") throw new ProofError(step, `${name} returned no structured result`);
    return payload;
  }

  toolFailure(step, name, payload) {
    const detail = typeof payload.detail === "string" ? ` (${payload.detail.slice(0, 240)})` : "";
    return new ProofError(step, `${name} failed: ${payload.error}${detail}.${hint(payload.error)}`);
  }

  async initialize() {
    const init = await this.rpc("initialize", "initialize", {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "echo-vault-proof-client", version: "1.0.0" },
    });
    await this.rpc("initialize", "notifications/initialized", undefined, { notification: true });
    const list = await this.rpc("initialize", "tools/list", {});
    const names = Array.isArray(list?.tools) ? list.tools.map((t) => t.name) : [];
    const needed = ["vault_status", "entry_request_card", "entry_card_status", "entry_use", "approval_status", "entry_list", "audit_list", "audit_verify"];
    const missing = needed.filter((n) => !names.includes(n));
    if (missing.length) throw new ProofError("initialize", `the server does not offer tool(s): ${missing.join(", ")}`);
    const revealing = names.filter((n) => /reveal|export|get_secret|read_secret|dump/i.test(n));
    if (revealing.length) throw new ProofError("initialize", `the server offers tool(s) that look like they return secrets: ${revealing.join(", ")}`);
    return `${init?.serverInfo?.name ?? "server"} ${init?.serverInfo?.version ?? ""}, protocol ${init?.protocolVersion}, ${names.length} tools, none returns a secret`;
  }

  async vaultStatus() {
    const p = await this.tool("vault_status", "vault_status", {});
    if (!p.ok) throw this.toolFailure("vault_status", "vault_status", p);
    return `ok (${Object.keys(p.data ?? {}).slice(0, 8).join(", ")})`;
  }

  async findEntry() {
    const p = await this.tool("entry_list", "entry_list", { site: this.o.site });
    if (!p.ok) throw this.toolFailure("entry_list", "entry_list", p);
    const entries = Array.isArray(p.data?.entries) ? p.data.entries : [];
    return entries.find((e) => e.account === this.o.account && e.kind === this.o.kind && e.status !== "deleted") ?? null;
  }

  // ---- 6 + 7. card
  async card() {
    const existing = await this.findEntry();
    if (existing && existing.status === "active" && !this.o.reenter) {
      this.entry = existing;
      return `entry ${existing.id} already exists and is active; no card needed (use --reenter to replace its secret)`;
    }
    const p = await this.tool("entry_request_card", "entry_request_card", {
      site: this.o.site,
      account: this.o.account,
      kind: this.o.kind,
      purpose: "e2e-proof",
      reason: `End-to-end proof: one GET ${this.o.path} on ${this.o.site}. Use a throwaway value.`,
    });
    if (!p.ok) throw this.toolFailure("entry_request_card", "entry_request_card", p);
    const cardId = p.data?.card_id;
    if (typeof cardId !== "string") throw new ProofError("entry_request_card", "the vault returned no card_id");
    const leaked = Object.keys(p.data).filter((k) => /token|url|link|secret/i.test(k));
    if (leaked.length) throw new ProofError("entry_request_card", `the card receipt carries field(s) an agent must not get: ${leaked.join(", ")}`);
    this.print("");
    this.print("       OWNER ACTION 2 of 3: open the single-use card link the bot just sent on Telegram");
    this.print(`       and type the credential for ${this.o.site} / ${this.o.account} (${this.o.kind}). This client never sees it.`);
    this.print(`       card ${cardId}, link expires ${p.data.expires_at}`);
    this.print("");
    const deadline = Date.now() + this.o.timeoutMs;
    for (;;) {
      await sleep(this.o.pollMs);
      const s = await this.tool("entry_card_status", "entry_card_status", { card_id: cardId });
      if (!s.ok) throw this.toolFailure("entry_card_status", "entry_card_status", s);
      if (s.data?.status === "completed") {
        this.entry = s.data.entry ?? { id: s.data.entry_id };
        return `card ${cardId} completed; entry ${s.data.entry_id} (${this.entry.label ?? "no label"}) status ${this.entry.status ?? "?"}`;
      }
      if (s.data?.status === "expired") throw new ProofError("entry_card_status", "the card expired (30 minutes) or could not be delivered; run the client again");
      if (Date.now() > deadline) throw new ProofError("entry_card_status", `the card was not completed within ${this.o.timeoutMs / 1000}s (--timeout-s)`);
    }
  }

  // ---- 8. entry_use
  async use() {
    const args = {
      site: this.o.site,
      account: this.o.account,
      kind: this.o.kind,
      method: "GET",
      url_path: this.o.path,
      task: "End-to-end proof: one read with the secret injected server-side.",
    };
    let p = await this.tool("entry_use", "entry_use", args);
    let approvalId = null;
    if (!p.ok && p.error === "approval_required") {
      approvalId = p.approval_id;
      if (typeof approvalId !== "string") throw new ProofError("entry_use", "approval_required came without an approval_id");
      this.print("");
      this.print("       OWNER ACTION 3 of 3: approve this client's first use of the entry on Telegram.");
      this.print(`       approval ${approvalId.slice(0, 8)}…, expires ${p.expires_at}`);
      this.print("");
      const deadline = Date.now() + this.o.timeoutMs;
      for (;;) {
        await sleep(this.o.pollMs);
        const s = await this.tool("approval_status", "approval_status", { approval_id: approvalId });
        if (!s.ok) throw this.toolFailure("approval_status", "approval_status", s);
        const status = s.data?.status;
        if (status === "approved") break;
        if (status === "denied") throw new ProofError("entry_use", "the owner DENIED the use on Telegram");
        if (status === "expired") throw new ProofError("entry_use", "the approval expired before the owner decided");
        if (status !== "pending") throw new ProofError("entry_use", `unexpected approval status: ${String(status).slice(0, 40)}`);
        if (Date.now() > deadline) throw new ProofError("entry_use", `no owner decision within ${this.o.timeoutMs / 1000}s (--timeout-s)`);
      }
      p = await this.tool("entry_use", "entry_use", { ...args, approval_id: approvalId });
    }
    this.useResult = { approval_id_prefix: approvalId ? approvalId.slice(0, 8) : null, ok: p.ok };
    if (!p.ok) {
      this.useResult.error = p.error;
      if (this.o.expectUseError && p.error === this.o.expectUseError) {
        this.print("       !!! entry_use DID NOT REACH THE SITE. It failed closed with the expected error:");
        this.print(`       !!! ${p.error}${typeof p.detail === "string" ? ` (${p.detail.slice(0, 200)})` : ""}`);
        this.useResult.expected_failure = true;
        return `FAILED CLOSED AS EXPECTED with ${p.error}: this run does NOT prove a successful injected request`;
      }
      throw this.toolFailure("entry_use", "entry_use", p);
    }
    if (this.o.expectUseError) throw new ProofError("entry_use", `expected entry_use to fail with ${this.o.expectUseError}, but it succeeded`);
    const d = p.data ?? {};
    this.useResult.status = d.status;
    this.useResult.content_type = d.content_type ?? null;
    this.useResult.body_shape = bodyShape(d.body);
    this.useResult.body_chars = d.body == null ? 0 : (typeof d.body === "string" ? d.body : JSON.stringify(d.body)).length;
    this.print(`       site answered ${d.status} (${d.content_type ?? "no content-type"}), body ${this.useResult.body_chars} characters`);
    this.print(`       body shape: ${JSON.stringify(this.useResult.body_shape)}`);
    if (this.o.showBody) this.print(`       redacted body: ${this.masker.mask(JSON.stringify(d.body))}`);
    if (typeof d.status !== "number" || d.status < 200 || d.status >= 400) {
      throw new ProofError("entry_use", `the request ran but the site answered ${d.status}; pick a --path that answers 2xx with this credential`);
    }
    return `GET https://${this.o.site}${this.o.path} → ${d.status}, secret injected server-side${approvalId ? `, approval ${approvalId.slice(0, 8)}…` : " (covered by an existing grant)"}`;
  }

  // ---- 9. evidence
  async evidence() {
    const entry = await this.findEntry();
    if (!entry) throw new ProofError("entry_list", "the entry is not in entry_list after the run");
    const audit = await this.tool("audit_list", "audit_list", { client_id: this.clientId, limit: 1000 });
    if (!audit.ok) throw this.toolFailure("audit_list", "audit_list", audit);
    const rows = Array.isArray(audit.data?.records) ? audit.data.records : [];
    // The client_id was registered by this run, so every row under it belongs to this run.
    this.ledgerRows = rows
      .sort((a, b) => a.seq - b.seq)
      .map((r) => ({
        seq: r.seq,
        timestamp: r.timestamp,
        capability: r.capability,
        resource: r.resource,
        decision: r.decision,
        tier: r.tier,
        result: r.result,
        approval_id_prefix: typeof r.approval_id === "string" ? r.approval_id.slice(0, 8) : null,
        credential_ref: r.credential_ref ?? null,
        http_status: r.http_status ?? null,
        error: r.error ?? null,
      }));
    const caps = new Set(this.ledgerRows.map((r) => r.capability));
    const needed = ["vault.status", "vault.entry.use.read"];
    if (!this.cardSkipped) needed.push("vault.card.request");
    const missing = needed.filter((c) => !caps.has(c));
    if (missing.length) throw new ProofError("audit_list", `the ledger has no row for: ${missing.join(", ")}`);
    if (!this.o.expectUseError) {
      const used = this.ledgerRows.find((r) => r.capability === "vault.entry.use.read" && r.result === "ok" && r.http_status === this.useResult.status);
      if (!used) throw new ProofError("audit_list", "the ledger has no successful vault.entry.use.read row matching the response status");
      if (this.useResult.approval_id_prefix && used.approval_id_prefix !== this.useResult.approval_id_prefix) {
        throw new ProofError("audit_list", "the ledger row of the use does not carry the approval id the owner approved");
      }
    }
    return `entry ${entry.id} listed (status ${entry.status}); ${this.ledgerRows.length} ledger rows for this client in this run`;
  }

  async verifyChain() {
    const p = await this.tool("audit_verify", "audit_verify", {});
    if (!p.ok) throw this.toolFailure("audit_verify", "audit_verify", p);
    const d = p.data ?? {};
    this.chain = { ok: d.ok === true, count: d.count ?? null, anchor: d.anchor?.verdict ?? (d.anchor === null ? "none yet" : "unknown"), anchor_error: d.anchor_error ?? null };
    if (d.ok !== true) throw new ProofError("audit_verify", `the ledger hash chain is NOT intact (${String(d.error ?? d.reason ?? "see transcript").slice(0, 120)})`);
    return `chain intact over ${d.count} rows; anchor: ${this.chain.anchor}`;
  }

  // ---- 10. secret scan over everything received
  scan() {
    const corpus = this.received.join("\n");
    const leaves = [];
    for (const text of this.received) {
      try {
        stringLeaves(JSON.parse(text), leaves);
      } catch {
        // not JSON: the raw text is already in the corpus
      }
    }
    const everything = `${corpus}\n${leaves.join("\n")}`;
    const shapes = scanTokenShapes(everything, this.own);
    const byDetector = {};
    for (const f of shapes) byDetector[f.detector] = (byDetector[f.detector] ?? 0) + 1;
    let fingerprintHits = null;
    if (this.o.fingerprint) {
      fingerprintHits = countFingerprintWindows(everything, this.o.fingerprint);
    }
    let metadata = null;
    if (this.o.fingerprintCheck) {
      const leaks = [];
      // Entry metadata as the vault hands it to this client: data.entry / data.entries of every tool result.
      // (A site's own response body is not vault metadata and is not judged by its key names.)
      for (const e of this.exchanges) {
        const data = e.response?.body?.result?.structuredContent?.data;
        if (!data || typeof data !== "object") continue;
        for (const key of ["entry", "entries"]) {
          if (data[key] !== undefined) leaks.push(...forbiddenMetadataKeys(data[key], `$.data.${key}`).map((p) => `${e.step}:${p}`));
        }
      }
      metadata = { withheld: leaks.length === 0, paths: leaks.slice(0, 20) };
    }
    return {
      bytes_scanned: Buffer.byteLength(everything, "utf8"),
      responses: this.exchanges.filter((e) => e.response && !e.response.error).length,
      token_shape_findings: shapes.length,
      token_shape_detectors: byDetector,
      fingerprint_window_hits: fingerprintHits,
      metadata,
      observed: shapes.length > 0 || (fingerprintHits ?? 0) > 0 || (metadata !== null && !metadata.withheld),
    };
  }

  transcript(scan, verdict) {
    return {
      tool: "echo-vault e2e proof-client",
      version: 1,
      started_at: this.startedAt,
      finished_at: new Date().toISOString(),
      vault: this.o.vault,
      target: { site: this.o.site, account: this.o.account, kind: this.o.kind, path: this.o.path },
      client_id: this.clientId,
      note: "The client's own access/refresh tokens, authorization code, pending handle and PKCE verifier are masked. Response bodies are otherwise exactly what the client received.",
      steps: this.steps,
      use: this.useResult,
      ledger_rows: this.ledgerRows,
      chain: this.chain,
      secret_scan: scan,
      verdict,
      exchanges: this.masker.maskValue(this.exchanges),
    };
  }

  async run() {
    const o = this.o;
    this.print(`ECHO Vault end-to-end proof — ${o.vault}`);
    this.print(`target: ${o.kind} entry ${o.site} / ${o.account}, GET https://${o.site}${o.path}`);
    this.print("");
    let failure = null;
    try {
      await this.step("01", "discover (401 challenge, RFC 9728, RFC 8414)", () => this.discover());
      await this.step("02", "dynamic client registration", () => this.register());
      await this.step("03", "authorization request (PKCE S256) + owner approval", () => this.authorize());
      await this.step("04", "token exchange", () => this.exchange());
      await this.step("05", "MCP initialize + tools/list", () => this.initialize());
      await this.step("06", "vault_status", () => this.vaultStatus());
      await this.step("07", "entry_request_card + owner types the secret", async () => {
        const detail = await this.card();
        this.cardSkipped = /no card needed/.test(detail);
        return detail;
      });
      await this.step("08", "entry_use (GET, secret injected server-side) + owner approval", () => this.use());
      await this.step("09", "entry_list + audit_list", () => this.evidence());
      await this.step("10", "audit_verify", () => this.verifyChain());
    } catch (err) {
      failure = err;
    }

    const scan = this.scan();
    const scanStep = { id: "11", title: "secret scan of everything the client received", ok: !scan.observed, detail: "" };
    scanStep.detail = scan.observed
      ? `${scan.token_shape_findings} token-shaped value(s) (${Object.keys(scan.token_shape_detectors).join(", ") || "none"}), fingerprint hits ${scan.fingerprint_window_hits ?? "n/a"}, metadata withheld ${scan.metadata ? scan.metadata.withheld : "n/a"}`
      : `${scan.bytes_scanned} bytes in ${scan.responses} responses: no token shape${scan.fingerprint_window_hits === null ? "" : ", no substring with the entry's fingerprint"}${scan.metadata ? ", fingerprint/length metadata withheld" : ""}`;
    this.steps.push(scanStep);
    this.print(`[${scanStep.ok ? " ok " : "FAIL"}] 11 ${scanStep.title} — ${scanStep.detail}`);

    const allPassed = failure === null && this.steps.every((s) => s.ok);
    const verdict = {
      passed: allPassed,
      steps_passed: this.steps.filter((s) => s.ok).length,
      steps_total: 11,
      steps_run: this.steps.length,
      chain: this.chain ? (this.chain.ok ? "intact" : "BROKEN") : "not checked",
      secret_observed_by_client: scan.observed ? "POSSIBLY — see secret_scan" : "NO",
      entry_use: this.useResult?.expected_failure ? `failed closed (${this.useResult.error})` : this.useResult?.ok ? `reached the site (${this.useResult.status})` : "not completed",
    };

    this.print("");
    this.print("================ VERDICT ================");
    this.print(`steps passed: ${verdict.steps_passed} of ${verdict.steps_total}${verdict.steps_run < verdict.steps_total ? ` (${verdict.steps_total - verdict.steps_run} not run)` : ""}`);
    for (const s of this.steps) this.print(`  ${s.ok ? "PASS" : "FAIL"}  ${s.id} ${s.title}`);
    this.print(`entry_use: ${verdict.entry_use}`);
    this.print(`ledger rows observed for this run (client ${this.clientId ?? "?"}): ${this.ledgerRows.length}`);
    if (this.ledgerRows.length) {
      this.print("  seq   capability               decision  tier  result            http  approval");
      for (const r of this.ledgerRows) {
        this.print(
          `  ${String(r.seq).padEnd(5)} ${String(r.capability).padEnd(24)} ${String(r.decision).padEnd(9)} ${String(r.tier).padEnd(5)} ${String(r.result).padEnd(17)} ${String(r.http_status ?? "-").padEnd(5)} ${r.approval_id_prefix ? `${r.approval_id_prefix}…` : "-"}`,
        );
      }
    }
    this.print(`chain verdict: ${verdict.chain}${this.chain ? ` (${this.chain.count} rows; anchor: ${this.chain.anchor})` : ""}`);
    this.print(`secret observed by client: ${verdict.secret_observed_by_client}`);
    this.print(`  basis: ${scan.bytes_scanned} bytes received in ${scan.responses} responses; token-shape detectors: ${scan.token_shape_findings} finding(s);`);
    this.print(
      `         fingerprint scan: ${scan.fingerprint_window_hits === null ? "not requested (--fingerprint)" : `${scan.fingerprint_window_hits} hit(s)`}; secret metadata withheld: ${scan.metadata ? (scan.metadata.withheld ? "yes" : `NO (${scan.metadata.paths.join(", ")})`) : "not checked (--fingerprint-check)"}`,
    );
    this.print(`RESULT: ${allPassed ? "PASS" : "FAIL"}${failure ? ` — ${this.masker.mask(failure.message)}` : ""}`);
    this.print("=========================================");

    try {
      writeFileSync(o.out, `${JSON.stringify(this.transcript(scan, verdict), null, 2)}\n`, { mode: 0o600 });
      chmodSync(o.out, 0o600);
      this.print(`transcript: ${o.out}`);
    } catch (err) {
      this.print(`transcript could not be written (${err?.code ?? "error"}): ${o.out}`);
      return 1;
    }
    return allPassed ? 0 : 1;
  }
}

export async function main(argv, io = {}) {
  let opts;
  try {
    opts = parseCli(argv);
  } catch (err) {
    process.stderr.write(`${err?.message ?? "invalid arguments"}\n\n${USAGE}`);
    return 2;
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (opts.problems) {
    process.stderr.write(`${opts.problems.map((p) => `error: ${p}`).join("\n")}\n\n${USAGE}`);
    return 2;
  }
  if (!opts.auto && process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    process.stdout.write(
      `This will register a client at ${opts.vault}, ask the owner for approval on Telegram (three actions),\n` +
        `and make one GET https://${opts.site}${opts.path} with the stored credential. Use a throwaway credential.\n`,
    );
    const answer = (await rl.question("Proceed? [y/N] ")).trim().toLowerCase();
    rl.close();
    if (answer !== "y" && answer !== "yes") {
      process.stdout.write("Cancelled. Nothing was sent.\n");
      return 2;
    }
  }
  return new ProofRun(opts, io).run();
}

function isMain() {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isMain()) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      // Never a stack, never a request body.
      process.stderr.write(`proof-client stopped: ${err instanceof ProofError ? err.message : `unexpected ${err?.name ?? "error"}`}\n`);
      process.exit(1);
    },
  );
}
