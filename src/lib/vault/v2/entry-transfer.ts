// library-first: echo.functions.search → no existing impl found (2026-11-16)
/**
 * entry_transfer ("opaque credential transfer"): the pure parts.
 *
 * The tool hands one entry's secret to another service: the DESTINATION entry
 * authenticates one HTTPS request to its own site, and the SOURCE entry's
 * secret replaces a placeholder in the JSON body. The agent never sees either
 * value. gateway.ts (entryTransferPlan) owns policy, approval, the two
 * useEntry calls and the request; this module only validates the agent's
 * arguments and builds the outgoing body.
 *
 * Nothing here logs, and no error message echoes body content: the body is
 * agent-supplied text that the owner has not seen yet.
 */
import { sanitizeDisplayText } from "./approvals.ts";
import type { EntryKind } from "./cards.ts";

export const TRANSFER_CAPABILITY = "vault.entry.transfer";
export const TRANSFER_PLACEHOLDER = "{{vault:source}}";
export const TRANSFER_METHODS = ["POST", "PUT", "PATCH"] as const;
/** Kinds whose secret is one opaque string another service can hold. */
export const TRANSFER_SOURCE_KINDS: readonly EntryKind[] = ["api_key", "oauth_token"];
/** Kinds that can authenticate the request to the destination (no cookie jar, no operator secret). */
export const TRANSFER_DESTINATION_KINDS: readonly EntryKind[] = ["api_key", "oauth_token", "password"];

const MAX_DEPTH = 32;
const MAX_KEY_DISPLAY = 40;
const MAX_PATH_DISPLAY = 120;
const PLAIN_KEY = /^[A-Za-z_$][A-Za-z0-9_$-]*$/;

/** A refusal of the agent's arguments. `message` is safe to return: it never contains body content. */
export class TransferInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransferInputError";
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/** One step of the placeholder's location, for the owner: `.key`, `["odd key"]` or `[3]`. Keys are sanitized and clipped. */
function segment(key: string | number, first: boolean): string {
  if (typeof key === "number") return `[${key}]`;
  const shown = sanitizeDisplayText(key, MAX_KEY_DISPLAY);
  if (PLAIN_KEY.test(key) && shown === key) return first ? shown : `.${shown}`;
  return `[${JSON.stringify(shown)}]`;
}

/**
 * Find the placeholder in a JSON body. It must be the ENTIRE value of exactly
 * one string field (any depth, arrays included): not part of a longer string,
 * not in a key, not zero times, not twice. Returns its location as a
 * dotted/indexed path (`value`, `config.keys[0].secret`).
 */
export function locatePlaceholder(body: unknown): { path: string } {
  if (!isPlainObject(body)) throw new TransferInputError("body must be a JSON object");
  const found: string[] = [];
  const walk = (value: unknown, path: string, depth: number): void => {
    if (depth > MAX_DEPTH) throw new TransferInputError("body is nested too deeply");
    if (typeof value === "string") {
      if (value === TRANSFER_PLACEHOLDER) found.push(path);
      else if (value.includes(TRANSFER_PLACEHOLDER)) {
        throw new TransferInputError(`${TRANSFER_PLACEHOLDER} must be the entire value of a string field, not part of a longer string`);
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, i) => walk(item, `${path}${segment(i, false)}`, depth + 1));
      return;
    }
    if (isPlainObject(value)) {
      for (const [key, child] of Object.entries(value)) {
        if (key.includes(TRANSFER_PLACEHOLDER)) throw new TransferInputError(`${TRANSFER_PLACEHOLDER} is not allowed in an object key`);
        walk(child, `${path}${segment(key, path === "")}`, depth + 1);
      }
    }
  };
  walk(body, "", 0);
  if (found.length === 0) throw new TransferInputError(`body must contain ${TRANSFER_PLACEHOLDER} as the value of one string field`);
  if (found.length > 1) throw new TransferInputError(`body must contain ${TRANSFER_PLACEHOLDER} exactly once`);
  const path = found[0];
  return { path: path.length > MAX_PATH_DISPLAY ? `${path.slice(0, MAX_PATH_DISPLAY - 1)}…` : path };
}

const HEADER_NAME = /^[a-z][a-z0-9-]{0,39}$/;
/** Headers the destination secret may never be sent as: they route, frame or already authenticate the request. */
const FORBIDDEN_HEADERS: ReadonlySet<string> = new Set([
  "host",
  "cookie",
  "set-cookie",
  "content-length",
  "content-type",
  "transfer-encoding",
  "connection",
  "authorization",
  "proxy-authorization",
  "te",
  "upgrade",
  "via",
  "forwarded",
]);
const FORBIDDEN_HEADER_PREFIXES = ["x-forwarded-", "sec-"] as const;

export type TransferAuth = { scheme: "default" } | { scheme: "header"; name: string };

/**
 * `to_auth`: absent (or `{scheme:"default"}`) → what entry_use does for the
 * entry kind. `{scheme:"header", name}` → the destination secret is sent as
 * that request header instead of the Authorization header. The name is
 * lower-cased and checked against a strict pattern and a deny list.
 */
export function parseTransferAuth(value: unknown): TransferAuth {
  if (value === undefined || value === null) return { scheme: "default" };
  if (!isPlainObject(value)) throw new TransferInputError("to_auth must be an object");
  for (const key of Object.keys(value)) {
    if (key !== "scheme" && key !== "name") throw new TransferInputError("to_auth: only scheme and name are allowed");
  }
  if (value.scheme === "default") {
    if (value.name !== undefined) throw new TransferInputError("to_auth: name is only for scheme \"header\"");
    return { scheme: "default" };
  }
  if (value.scheme !== "header") throw new TransferInputError("to_auth.scheme must be \"header\" (or omit to_auth)");
  if (typeof value.name !== "string") throw new TransferInputError("to_auth.name: a header name is required");
  const name = value.name.toLowerCase();
  if (!HEADER_NAME.test(name)) throw new TransferInputError("to_auth.name: not a valid header name (a letter, then letters, digits or hyphens; 40 at most)");
  if (FORBIDDEN_HEADERS.has(name) || FORBIDDEN_HEADER_PREFIXES.some((p) => name.startsWith(p))) {
    throw new TransferInputError("to_auth.name: that header cannot carry a credential");
  }
  return { scheme: "header", name };
}

/**
 * The outgoing body: `template` is the agent's body exactly as it was hashed
 * for the approval (JSON text with the placeholder still in it). The one
 * placeholder value becomes the secret; JSON.stringify does the escaping.
 * The result is a secret: it is sent, never logged, stored or returned.
 */
export function buildTransferBody(template: string, sourceSecret: string): string {
  return JSON.stringify(JSON.parse(template), (_key, value) => (value === TRANSFER_PLACEHOLDER ? sourceSecret : value));
}

/**
 * Other spellings of the transferred secret that a destination might echo
 * back: URL-encoded, base64 (padded and unpadded), base64url and JSON-escaped.
 * The caller arms each for redaction (redaction.ts matches literal strings
 * only). The secret itself is armed by cards.ts when it is loaded.
 */
export function transferRedactionForms(secret: string): string[] {
  const forms = new Set<string>();
  const add = (form: string) => {
    if (form !== secret && form.length > 0) forms.add(form);
  };
  add(encodeURIComponent(secret));
  const bytes = Buffer.from(secret, "utf8");
  const b64 = bytes.toString("base64");
  add(b64);
  add(b64.replace(/=+$/, ""));
  add(bytes.toString("base64url"));
  add(JSON.stringify(secret).slice(1, -1));
  return [...forms];
}
