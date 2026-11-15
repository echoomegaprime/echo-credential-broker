#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Fake ECHO SDK gate for the e2e rehearsal.
 *
 * Implements just the part of the gate protocol that src/lib/vault/gate-client.ts
 * speaks: `POST /sdk/invoke` with `{ envelope_version, capability, params }` and
 * the `X-Echo-API-Key` header, answering `{ run_id, status, result: { status_code, body } }`
 * for `echo.vault.put`, `echo.vault.get` and `echo.vault.locate` (which is also
 * what `search` uses). Values live in memory only.
 *
 * It never prints or records a secret value. The traffic it records replaces
 * `secret` with its length and an 8-hex SHA-256 prefix. The stored values can be
 * checked for the presence of a candidate with `holds(value)`; they are never
 * handed out except through `echo.vault.get`, exactly as the real gate does.
 *
 * This is a rehearsal stand-in. It is NOT the canonical vault and proves nothing
 * about it. Never point a production server at it.
 */
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const MAX_BODY_BYTES = 256 * 1024;

function sha8(value) {
  return createHash("sha256").update(String(value), "utf8").digest("hex").slice(0, 8);
}

function sameKey(a, b) {
  const x = Buffer.from(String(a), "utf8");
  const y = Buffer.from(String(b), "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Request params as they may be recorded: the secret is replaced by its shape. */
export function recordableParams(params) {
  if (!params || typeof params !== "object") return {};
  const { secret, ...rest } = params;
  if (secret === undefined) return rest;
  return { ...rest, secret_length: String(secret).length, secret_sha256_8: sha8(secret) };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("body_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => reject(new Error("read_failed")));
  });
}

/**
 * Start the fake gate on 127.0.0.1.
 * @param {{ apiKey: string, port?: number }} opts `apiKey` is the value the server must send in X-Echo-API-Key.
 */
/**
 * The real gate's tier-2 rule (routers/sdk_invoke.py + routers/_auth_p4.py, read 2026-11-15):
 * a capability of danger tier 2+ needs envelope.auth = { hmac, nonce, ts }, where
 * hmac = HMAC-SHA256(bytes.fromhex(secret_hmac), "v1|api_key|capability|params_json|nonce|ts"),
 * params_json is Python's json.dumps(sort_keys=True, separators=(",", ":")), ts is within
 * 90 s and a nonce is single-use. Missing auth is 423, a bad one 401, both as {detail}.
 * This stand-in used to accept unsigned writes; that is how the vault shipped without signing.
 * Written here independently of src/lib/vault/gate-hmac.ts on purpose.
 */
const TIER2_PLUS = new Set(["echo.vault.put"]);
const HMAC_TS_SKEW_S = 90;

function pyJson(v) {
  if (v === null) return "null";
  if (typeof v === "string") {
    return JSON.stringify(v).replace(/[\u0080-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  }
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (Array.isArray(v)) return "[" + v.map(pyJson).join(",") + "]";
  const keys = Object.keys(v).sort((a, b) => {
    const x = [...a];
    const y = [...b];
    for (let i = 0; i < Math.min(x.length, y.length); i++) {
      const d = x[i].codePointAt(0) - y[i].codePointAt(0);
      if (d) return d;
    }
    return x.length - y.length;
  });
  return "{" + keys.map((k) => pyJson(k) + ":" + pyJson(v[k])).join(",") + "}";
}

/** null when the envelope is correctly signed, else { code, detail } as the real gate answers. */
function checkTier2Auth(opts, seenNonces, apiKey, capability, params, auth) {
  if (!auth || typeof auth.hmac !== "string" || !auth.hmac) {
    return { code: 423, detail: { error: "hmac_required_for_tier2_plus", capability } };
  }
  const refuse = (reason) => ({ code: 401, detail: { error: "hmac_verification_failed", reason, capability } });
  if (typeof auth.nonce !== "string" || !auth.nonce || !Number.isInteger(auth.ts)) return refuse("hmac_fields_missing");
  if (Math.abs(Math.floor(Date.now() / 1000) - auth.ts) > HMAC_TS_SKEW_S) return refuse("hmac_ts_out_of_window");
  const msg = `v1|${apiKey}|${capability}|${pyJson(params)}|${auth.nonce}|${auth.ts}`;
  const expected = createHmac("sha256", Buffer.from(opts.hmacSecret, "hex")).update(msg, "utf8").digest("hex");
  if (!sameKey(expected, auth.hmac)) return refuse("hmac_signature_mismatch");
  if (seenNonces.has(auth.nonce)) return refuse("nonce_replay_detected");
  seenNonces.add(auth.nonce);
  return null;
}

export async function startFakeGate(opts) {
  if (!opts || typeof opts.apiKey !== "string" || opts.apiKey.length < 8) throw new Error("fake gate: apiKey is required");
  if (typeof opts.hmacSecret !== "string" || !/^(?:[0-9a-f]{2}){16,}$/i.test(opts.hmacSecret)) {
    throw new Error("fake gate: hmacSecret (hex, 16+ bytes) is required — the real gate refuses unsigned tier-2 calls");
  }
  const seenNonces = new Set();
  /** `${service}\u0000${username}` → { secret, version, updated_at } */
  const store = new Map();
  /** Sanitized traffic: never holds a secret value. */
  const traffic = [];
  let version = 0;

  const envelope = (status, statusCode, body) => ({
    run_id: randomUUID(),
    status,
    result: { status_code: statusCode, body },
  });

  function locate(service) {
    const exact = [...store.keys()].filter((k) => k.split("\u0000")[0] === service);
    const pool = exact.length ? exact : [...store.keys()].filter((k) => k.split("\u0000")[0].toLowerCase().includes(String(service).toLowerCase()));
    const candidates = pool.map((k) => {
      const [actual_service, username] = k.split("\u0000");
      return { actual_service, username, key_shape: "fake" };
    });
    if (candidates.length === 0) return { status: "NOT_FOUND", service, candidates: [], did_you_mean: [] };
    if (candidates.length === 1) {
      return {
        status: "EXACT",
        service,
        candidates,
        get_with: { service: candidates[0].actual_service, username: candidates[0].username },
      };
    }
    return { status: "AMBIGUOUS", service, count: candidates.length, candidates };
  }

  function invoke(capability, params) {
    const service = typeof params.service === "string" ? params.service : "";
    const username = typeof params.username === "string" ? params.username : "";
    switch (capability) {
      case "echo.vault.put": {
        if (!service || !username || typeof params.secret !== "string" || params.secret.length === 0) {
          return envelope("client_error", 400, { error: "invalid_params" });
        }
        version += 1;
        store.set(`${service}\u0000${username}`, { secret: params.secret, version, updated_at: new Date().toISOString() });
        return envelope("ok", 200, { stored: true, service, version, key_fingerprint: `fake-${sha8(params.secret)}` });
      }
      case "echo.vault.get": {
        const found = store.get(`${service}\u0000${username}`);
        if (!found) return envelope("client_error", 404, { error: "not_found" });
        return envelope("ok", 200, {
          service,
          username,
          secret: found.secret,
          key_fingerprint: `fake-${sha8(found.secret)}`,
          version: found.version,
          updated_at: found.updated_at,
        });
      }
      case "echo.vault.locate":
        if (!service) return envelope("client_error", 400, { error: "invalid_params" });
        return envelope("ok", 200, locate(service));
      default:
        return envelope("client_error", 404, { error: "unknown_capability" });
    }
  }

  const server = createServer(async (req, res) => {
    const send = (code, body) => {
      const text = JSON.stringify(body);
      res.writeHead(code, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(text);
    };
    try {
      const path = (req.url ?? "").split("?", 1)[0];
      if (req.method !== "POST" || path !== "/sdk/invoke") {
        traffic.push({ at: new Date().toISOString(), rejected: "not_found", method: req.method, path });
        send(404, envelope("client_error", 404, { error: "not_found" }));
        return;
      }
      const presented = req.headers["x-echo-api-key"];
      if (typeof presented !== "string" || !sameKey(presented, opts.apiKey)) {
        traffic.push({ at: new Date().toISOString(), rejected: "bad_api_key" });
        send(401, envelope("client_error", 401, { error: "unauthorized" }));
        return;
      }
      let parsed;
      try {
        parsed = JSON.parse(await readBody(req));
      } catch {
        traffic.push({ at: new Date().toISOString(), rejected: "invalid_body" });
        send(400, envelope("client_error", 400, { error: "invalid_body" }));
        return;
      }
      const capability = typeof parsed?.capability === "string" ? parsed.capability : "";
      const params = parsed?.params && typeof parsed.params === "object" ? parsed.params : {};
      if (TIER2_PLUS.has(capability)) {
        const refused = checkTier2Auth(opts, seenNonces, presented, capability, params, parsed?.auth);
        if (refused) {
          traffic.push({ at: new Date().toISOString(), capability, rejected: refused.detail.error, reason: refused.detail.reason });
          send(refused.code, { detail: refused.detail });
          return;
        }
      }
      const out = invoke(capability, params);
      traffic.push({
        at: new Date().toISOString(),
        capability,
        params: recordableParams(params),
        status: out.status,
        status_code: out.result.status_code,
      });
      send(out.result.status_code >= 500 ? 500 : 200, out);
    } catch {
      send(500, envelope("server_error", 500, { error: "internal" }));
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, "127.0.0.1", resolve);
  });
  const { port } = server.address();

  return {
    url: `http://127.0.0.1:${port}`,
    port,
    /** Sanitized request log (capability, params without the secret, status). */
    traffic,
    /** Number of stored values. */
    count: () => store.size,
    /** Coordinates only: [{ service, username, secret_length, secret_sha256_8 }]. */
    coordinates: () =>
      [...store.entries()].map(([k, v]) => {
        const [service, username] = k.split("\u0000");
        return { service, username, secret_length: v.secret.length, secret_sha256_8: sha8(v.secret) };
      }),
    /** True when some stored value is exactly `value`. The value itself is never returned. */
    holds: (value) => [...store.values()].some((v) => v.secret === value),
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

function isMain() {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isMain()) {
  const apiKey = process.env.ECHO_SDK_API_KEY;
  if (!apiKey) {
    console.error("fake-gate: set ECHO_SDK_API_KEY to the key the server will present (any 8+ character throwaway value).");
    process.exit(2);
  }
  const hmacSecret = process.env.ECHO_SDK_HMAC_SECRET;
  if (!hmacSecret) {
    console.error("fake-gate: set ECHO_SDK_HMAC_SECRET to the hex secret the server signs with (any 32+ hex characters).");
    process.exit(2);
  }
  const gate = await startFakeGate({ apiKey, hmacSecret, port: Number(process.env.PORT || 0) });
  console.log(`fake gate listening on ${gate.url} (in memory; point ECHO_SDK_GATE_URL at it)`);
  for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => gate.close().then(() => process.exit(0)));
}
