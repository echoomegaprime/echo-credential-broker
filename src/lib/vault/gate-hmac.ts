// library-first: echo.functions.search → no existing impl found (2026-11-15)
/**
 * Request signing for the ECHO SDK gate.
 *
 * The gate refuses every capability of danger tier 2 or higher (`echo.vault.put` is tier 2)
 * with HTTP 423 `hmac_required_for_tier2_plus` unless the envelope carries
 * `auth: { hmac, nonce, ts }`. Contract, read from the gate's own source on 2026-11-15
 * (`routers/_auth_p4.py`: `_canonical_signed_form`, `hmac_sign`, `verify_hmac`):
 *
 *   canonical = "v1|" + api_key + "|" + capability + "|" + params_json + "|" + nonce + "|" + ts
 *   params_json = Python json.dumps(params, sort_keys=True, separators=(",", ":"))
 *   hmac        = HMAC-SHA256(key = bytes.fromhex(secret_hmac), canonical) as lowercase hex
 *   ts          = unix seconds, accepted within ±90 s; nonce is single-use for 120 s
 *
 * The gate re-serialises the params it parsed, so `params_json` here must be byte-for-byte
 * what Python produces: keys sorted by code point at every level, no whitespace, and every
 * non-ASCII character written as a lowercase `\uXXXX` escape (surrogate pairs for astral
 * characters). Numbers that are not safe integers are refused: Python and JavaScript print
 * floats differently, and a signature that only sometimes verifies is worse than an error.
 *
 * Nothing here logs. The canonical string contains the API key and the params (which, for
 * a put, contain the secret); it exists only as the HMAC input.
 */
import { createHmac, randomBytes } from "node:crypto";

export const GATE_HMAC_CANONICAL_VERSION = 1;

export class GateSigningError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "GateSigningError";
    this.code = code;
  }
}

/** Code-point order, which is how Python sorts `str` keys (UTF-16 unit order differs for astral characters). */
function byCodePoint(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const d = (x[i] as string).codePointAt(0)! - (y[i] as string).codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

/** A JSON string literal the way Python writes it with ensure_ascii=True. */
function pyString(s: string): string {
  // JSON.stringify already matches Python for quotes, backslashes and control characters
  // (\b \f \n \r \t, the rest as \u00xx). Python additionally escapes everything above ASCII.
  return JSON.stringify(s).replace(/[\u0080-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/** `json.dumps(value, sort_keys=True, separators=(",", ":"))`, for the JSON subset the gate is sent. */
export function pythonCanonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return pyString(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value)) {
        throw new GateSigningError("gate_params_unsignable", "gate params may only contain safe integers as numbers");
      }
      return String(value);
    case "object": {
      if (Array.isArray(value)) {
        // JSON.stringify writes undefined array items as null; keep the signed form equal to the sent form.
        return `[${value.map((v) => pythonCanonicalJson(v === undefined ? null : v)).join(",")}]`;
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined) // JSON.stringify drops these, so they are not sent either
        .sort(byCodePoint);
      return `{${keys.map((k) => `${pyString(k)}:${pythonCanonicalJson(obj[k])}`).join(",")}}`;
    }
    default:
      throw new GateSigningError("gate_params_unsignable", `gate params cannot contain a ${typeof value}`);
  }
}

export interface GateAuth {
  hmac: string;
  nonce: string;
  ts: number;
}

export interface SignOptions {
  /** Unix seconds. Default: now. */
  ts?: number;
  /** Default: 16 random bytes, hex. */
  nonce?: string;
}

/**
 * The `auth` block for one gate call. `secretHex` is the per-key `secret_hmac` the gate
 * holds for `apiKey`; it never leaves this function except as the HMAC key.
 */
export function signGateRequest(
  secretHex: string,
  apiKey: string,
  capability: string,
  params: Record<string, unknown>,
  opts: SignOptions = {},
): GateAuth {
  const hex = secretHex.trim();
  if (!/^(?:[0-9a-fA-F]{2}){16,}$/.test(hex)) {
    // Say nothing about the value itself.
    throw new GateSigningError("gate_hmac_secret_invalid", "ECHO_SDK_HMAC_SECRET must be hex, at least 16 bytes");
  }
  if (!apiKey) throw new GateSigningError("gate_api_key_missing", "cannot sign a gate request without the API key");
  const ts = opts.ts ?? Math.floor(Date.now() / 1000);
  const nonce = opts.nonce ?? randomBytes(16).toString("hex");
  if (!Number.isSafeInteger(ts) || !/^[A-Za-z0-9_-]{8,128}$/.test(nonce)) {
    throw new GateSigningError("gate_auth_fields_invalid", "invalid ts or nonce for a gate signature");
  }
  const canonical = `v${GATE_HMAC_CANONICAL_VERSION}|${apiKey}|${capability}|${pythonCanonicalJson(params)}|${nonce}|${ts}`;
  const hmac = createHmac("sha256", Buffer.from(hex, "hex")).update(canonical, "utf8").digest("hex");
  return { hmac, nonce, ts };
}
