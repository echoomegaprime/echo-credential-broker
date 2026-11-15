// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { createHmac, createHash } from "node:crypto";
import { test } from "node:test";
import {
  Masker,
  bodyShape,
  countFingerprintWindows,
  extractRefreshUrl,
  forbiddenMetadataKeys,
  isSafeEndpoint,
  parseCli,
  parseFingerprint,
  parseResourceMetadata,
  pkceChallenge,
  scanTokenShapes,
  stringLeaves,
} from "./proof-client.mjs";
import { recordableParams, startFakeGate } from "./fake-gate.mjs";
import { approvalButtons, cardLink } from "./fake-telegram.mjs";

// Shaped like vault tokens; generated for this test only.
const ACCESS = `eva_${"A1b2".repeat(11).slice(0, 43)}`;
const REFRESH = `evr_${"C3d4".repeat(11).slice(0, 43)}`;

test("pkceChallenge matches the RFC 7636 appendix B vector", () => {
  assert.equal(pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
});

test("isSafeEndpoint: https anywhere, http only on loopback, never with credentials", () => {
  assert.ok(isSafeEndpoint("https://vault.example/api/mcp"));
  assert.ok(isSafeEndpoint("http://127.0.0.1:8080/api/mcp"));
  assert.ok(isSafeEndpoint("http://localhost:8080/"));
  assert.ok(!isSafeEndpoint("http://vault.example/api/mcp"));
  assert.ok(!isSafeEndpoint("https://user:pw@vault.example/"));
  assert.ok(!isSafeEndpoint("ftp://vault.example/"));
  assert.ok(!isSafeEndpoint("nonsense"));
});

test("discovery parsers read the vault's own challenge and waiting page", () => {
  assert.equal(
    parseResourceMetadata('Bearer resource_metadata="https://v.example/.well-known/oauth-protected-resource"'),
    "https://v.example/.well-known/oauth-protected-resource",
  );
  assert.equal(parseResourceMetadata('Bearer realm="echo-vault"'), null);
  const html = '<meta http-equiv="refresh" content="3;url=https://v.example/api/oauth/authorize?pending=evp_x&amp;a=1"><title>t</title>';
  assert.equal(extractRefreshUrl(html), "https://v.example/api/oauth/authorize?pending=evp_x&a=1");
  assert.equal(extractRefreshUrl("<p>denied</p>"), null);
});

test("Masker hides registered values, their URL-encoded form and any vault token shape", () => {
  const m = new Masker();
  m.register("pkce_verifier", "verifier~value.with-unreserved_chars");
  m.register("state", "a+b/c=d-long-enough");
  const text = `Bearer ${ACCESS} refresh=${REFRESH} v=verifier~value.with-unreserved_chars s=${encodeURIComponent("a+b/c=d-long-enough")}`;
  const masked = m.mask(text);
  assert.ok(!masked.includes(ACCESS) && !masked.includes(REFRESH));
  assert.ok(!masked.includes("verifier~value") && !masked.includes("a%2Bb"));
  assert.match(masked, /\[MASKED:eva_token\].*\[MASKED:evr_token\].*\[MASKED:pkce_verifier\].*\[MASKED:state\]/);
  const tree = m.maskValue({ a: [ACCESS], b: { c: `x ${REFRESH}` }, n: 1, z: null });
  assert.deepEqual(tree, { a: ["[MASKED:eva_token]"], b: { c: "x [MASKED:evr_token]" }, n: 1, z: null });
});

test("bodyShape shows keys, types and lengths, never a value", () => {
  const shape = bodyShape({ authenticated: true, token: "super-secret-value", n: 3, list: [{ id: "abc" }], none: null });
  assert.deepEqual(shape, { authenticated: "boolean", token: "string(18)", n: "number", list: ["array(1) of", { id: "string(3)" }], none: "null" });
  assert.ok(!JSON.stringify(shape).includes("super-secret-value"));
  assert.equal(bodyShape("plain text"), "string(10)");
});

test("scanTokenShapes finds provider token shapes, ignores the client's own tokens, and never returns the match", () => {
  const github = `ghp_${"a".repeat(36)}`;
  const findings = scanTokenShapes(`ok ${ACCESS} and ${github} done`, [ACCESS]);
  assert.deepEqual(findings, [{ detector: "github_token", length: 40 }]);
  assert.ok(!JSON.stringify(findings).includes(github));
  assert.deepEqual(scanTokenShapes(`only my own ${ACCESS}`, [ACCESS]), []);
  assert.equal(scanTokenShapes(`someone else's ${REFRESH}`, [ACCESS]).length, 1);
  assert.deepEqual(scanTokenShapes('{"token":"[REDACTED_SECRET]","authenticated":true}'), []);
});

test("fingerprint scan: finds the secret by its SHA-256 prefix without knowing it", () => {
  const secret = "rh/throwaway+value-0123456789";
  const fp = { prefix: createHash("sha256").update(secret).digest("hex").slice(0, 8), length: secret.length };
  assert.deepEqual(parseFingerprint(`${fp.prefix}:${fp.length}`), fp);
  assert.equal(parseFingerprint("nothex00:12"), null);
  assert.equal(parseFingerprint("abcdef12"), null);
  assert.equal(countFingerprintWindows(`{"token":"${secret}"}`, fp), 1);
  assert.equal(countFingerprintWindows('{"token":"[REDACTED_SECRET]","authenticated":true}'.repeat(50), fp), 0);
  // A JSON-escaped copy is found through the decoded string leaves.
  const nested = JSON.stringify({ content: [{ text: JSON.stringify({ body: { token: secret } }) }] });
  assert.equal(countFingerprintWindows(stringLeaves(JSON.parse(nested)).join("\n"), fp) > 0, true);
});

test("forbiddenMetadataKeys flags fingerprint / length / secret fields in entry metadata", () => {
  assert.deepEqual(forbiddenMetadataKeys({ id: "ve_1", site: "x", status: "active" }), []);
  assert.deepEqual(forbiddenMetadataKeys([{ id: "ve_1", fingerprint: "abcd1234", secret_length: 40 }]), ["$[0].fingerprint", "$[0].secret_length"]);
});

test("parseCli validates before anything is sent", () => {
  assert.deepEqual(parseCli(["--help"]), { help: true });
  const bad = parseCli(["--vault", "http://vault.example", "--kind", "operator_secret", "--path", "bearer", "--fingerprint", "zz"]);
  assert.equal(bad.problems.length, 5);
  const ok = parseCli(["--vault", "https://vault.example/", "--site", "HTTPBIN.org", "--path", "/bearer", "--auto", "--fingerprint", "0a1b2c3d:44"]);
  assert.equal(ok.vault, "https://vault.example");
  assert.equal(ok.site, "httpbin.org");
  assert.equal(ok.account, "proof");
  assert.equal(ok.kind, "api_key");
  assert.equal(ok.scopes, "vault.read vault.write audit.read");
  assert.equal(ok.timeoutMs, 900_000);
  assert.equal(ok.auto, true);
  assert.equal(ok.fingerprintCheck, true);
  assert.deepEqual(ok.fingerprint, { prefix: "0a1b2c3d", length: 44 });
});

test("fake Telegram helpers read the vault's approval keyboard and card link", () => {
  const payload = {
    text: "ECHO Vault approval request",
    reply_markup: { inline_keyboard: [[{ text: "Approve", callback_data: "a:id:mac" }, { text: "Deny", callback_data: "d:id:mac" }]] },
  };
  assert.deepEqual(approvalButtons(payload), { approve: "a:id:mac", deny: "d:id:mac" });
  assert.equal(approvalButtons({ text: "no keyboard" }), null);
  const link = `http://127.0.0.1:8080/card/${"t".repeat(43)}`;
  assert.equal(cardLink({ text: `Open this single-use link to type the secret:\n${link}` }), link);
  assert.equal(cardLink(payload), null);
});

test("fake gate speaks the gate-client envelope, checks the API key and never records a secret", async (t) => {
  const apiKey = "testonly-gate-key";
  const secret = "throwaway-test-value-123";
  const hmacSecret = "ab".repeat(32);
  await assert.rejects(startFakeGate({ apiKey }), /hmacSecret/);
  const gate = await startFakeGate({ apiKey, hmacSecret });
  t.after(() => gate.close());
  let n = 0;
  // The gate's rule for tier 2: HMAC-SHA256 over "v1|key|capability|params|nonce|ts". The params
  // here are ASCII with keys already in sorted order, so JSON.stringify is the canonical form.
  const sign = (capability, params, over = {}) => {
    const ts = over.ts ?? Math.floor(Date.now() / 1000);
    const nonce = over.nonce ?? `nonce-${++n}-${Date.now()}`;
    const msg = `v1|${apiKey}|${capability}|${JSON.stringify(params)}|${nonce}|${ts}`;
    return { hmac: over.hmac ?? createHmac("sha256", Buffer.from(hmacSecret, "hex")).update(msg).digest("hex"), nonce, ts };
  };
  const invoke = async (capability, params, key = apiKey, auth = capability === "echo.vault.put" ? sign(capability, params) : undefined) => {
    const res = await fetch(`${gate.url}/sdk/invoke`, {
      method: "POST",
      headers: { "X-Echo-API-Key": key, "Content-Type": "application/json" },
      body: JSON.stringify({ envelope_version: 1, capability, params, context: { bypass_reason: "test" }, ...(auth ? { auth } : {}) }),
    });
    return { http: res.status, envelope: await res.json() };
  };

  // Tier 2 is refused exactly as the real gate refuses it, before anything is stored.
  const P = { note: "n", secret, service: "locked", username: "entry" };
  const unsigned = await invoke("echo.vault.put", P, apiKey, null);
  assert.equal(unsigned.http, 423);
  assert.equal(unsigned.envelope.detail.error, "hmac_required_for_tier2_plus");
  for (const [auth, reason] of [
    [sign("echo.vault.put", P, { hmac: "0".repeat(64) }), "hmac_signature_mismatch"],
    [sign("echo.vault.put", { ...P, secret: "tampered" }), "hmac_signature_mismatch"],
    [sign("echo.vault.put", P, { ts: Math.floor(Date.now() / 1000) - 600 }), "hmac_ts_out_of_window"],
    [{ hmac: "ab", nonce: "", ts: 1 }, "hmac_fields_missing"],
  ]) {
    const r = await invoke("echo.vault.put", P, apiKey, auth);
    assert.equal(r.http, 401, reason);
    assert.equal(r.envelope.detail.reason, reason);
  }
  const once = sign("echo.vault.put", P);
  assert.equal((await invoke("echo.vault.put", P, apiKey, once)).envelope.status, "ok");
  assert.equal((await invoke("echo.vault.put", P, apiKey, once)).envelope.detail.reason, "nonce_replay_detected");
  assert.ok(!JSON.stringify(gate.traffic).includes(secret));

  assert.equal((await invoke("echo.vault.locate", { service: "svc" }, "wrong-key")).http, 401);
  assert.equal((await invoke("echo.vault.locate", { service: "svc" })).envelope.result.body.status, "NOT_FOUND");
  const put = await invoke("echo.vault.put", { note: "n", secret, service: "svc", username: "entry" });
  assert.equal(put.envelope.status, "ok");
  assert.equal(put.envelope.result.body.stored, true);
  const located = (await invoke("echo.vault.locate", { service: "svc" })).envelope.result.body;
  assert.equal(located.status, "EXACT");
  assert.deepEqual(located.get_with, { service: "svc", username: "entry" });
  assert.equal((await invoke("echo.vault.get", { service: "svc", username: "entry" })).envelope.result.body.secret, secret);
  const missing = await invoke("echo.vault.get", { service: "svc", username: "nobody" });
  assert.equal(missing.envelope.result.status_code, 404);
  assert.notEqual(missing.envelope.status, "ok");

  assert.ok(gate.holds(secret));
  assert.ok(!gate.holds("something else"));
  assert.ok(!JSON.stringify(gate.traffic).includes(secret));
  assert.ok(!JSON.stringify(gate.coordinates()).includes(secret));
  assert.deepEqual(Object.keys(recordableParams({ service: "s", secret })).sort(), ["secret_length", "secret_sha256_8", "service"]);
});
