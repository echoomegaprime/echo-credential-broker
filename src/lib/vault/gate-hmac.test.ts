// library-first: echo.functions.search → no existing impl found (2026-11-15)
/**
 * The expected values in gate-hmac.vectors.json were produced by Python with the gate's
 * own algorithm (routers/_auth_p4.py: json.dumps(sort_keys=True, separators=(",", ":")),
 * then HMAC-SHA256 over "v1|key|capability|params|nonce|ts"). If this file and the gate
 * ever disagree, the gate answers 401 hmac_signature_mismatch on every vault write.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { GateSigningError, pythonCanonicalJson, signGateRequest } from "./gate-hmac.ts";

type FakeGate = { url: string; count(): number; holds(v: string): boolean; close(): Promise<void> };
// Loaded by URL so the type checker does not pull the untyped .mjs stand-in into the program.
const fakeGateUrl = new URL("../../../scripts/e2e/fake-gate.mjs", import.meta.url).href;
const { startFakeGate } = (await import(fakeGateUrl)) as {
  startFakeGate(o: { apiKey: string; hmacSecret: string }): Promise<FakeGate>;
};

type Vectors = {
  secret: string;
  api_key: string;
  capability: string;
  nonce: string;
  ts: number;
  cases: { name: string; params: Record<string, unknown>; json: string; hmac: string }[];
};
const V = JSON.parse(readFileSync(new URL("./gate-hmac.vectors.json", import.meta.url), "utf8")) as Vectors;

describe("gate HMAC signing matches the gate's Python implementation", () => {
  for (const c of V.cases) {
    it(`vector: ${c.name}`, () => {
      assert.equal(pythonCanonicalJson(c.params), c.json);
      const auth = signGateRequest(V.secret, V.api_key, V.capability, c.params, { nonce: V.nonce, ts: V.ts });
      assert.deepEqual(auth, { hmac: c.hmac, nonce: V.nonce, ts: V.ts });
    });
  }

  it("what is signed is what JSON.stringify sends (undefined keys dropped, key order irrelevant)", () => {
    const a = { service: "s", username: undefined, secret: "x", note: "n" } as Record<string, unknown>;
    const b = { note: "n", secret: "x", service: "s" };
    assert.equal(pythonCanonicalJson(a), pythonCanonicalJson(JSON.parse(JSON.stringify(a))));
    assert.equal(pythonCanonicalJson(a), pythonCanonicalJson(b));
  });

  it("defaults: fresh nonce every call, ts is now in unix seconds", () => {
    const p = { service: "s" };
    const one = signGateRequest(V.secret, V.api_key, "echo.vault.put", p);
    const two = signGateRequest(V.secret, V.api_key, "echo.vault.put", p);
    assert.notEqual(one.nonce, two.nonce);
    assert.match(one.nonce, /^[0-9a-f]{32}$/);
    assert.ok(Math.abs(one.ts - Date.now() / 1000) < 5);
    assert.match(one.hmac, /^[0-9a-f]{64}$/);
  });

  it("refuses what it cannot sign identically, and never echoes the secret or the params", () => {
    const SECRET_VALUE = "sk-live-DO-NOT-LEAK-91f3";
    for (const bad of [{ n: 1.5 }, { n: Number.NaN }, { n: 2 ** 60 }, { f: () => 1 }, { b: 10n }] as Record<string, unknown>[]) {
      assert.throws(
        () => signGateRequest(V.secret, V.api_key, "echo.vault.put", { secret: SECRET_VALUE, ...bad }),
        (e: unknown) => e instanceof GateSigningError && e.code === "gate_params_unsignable" && !String(e.message).includes(SECRET_VALUE),
      );
    }
    for (const badSecret of ["", "zz", "abc", "00112233", V.secret + "0"]) {
      assert.throws(
        () => signGateRequest(badSecret, V.api_key, "echo.vault.put", {}),
        (e: unknown) => e instanceof GateSigningError && e.code === "gate_hmac_secret_invalid" && (badSecret.length < 4 || !String(e.message).includes(badSecret)),
      );
    }
    assert.throws(() => signGateRequest(V.secret, "", "echo.vault.put", {}), /API key/);
  });
});

describe("the signer against the stand-in gate's independent verifier", () => {
  it("a signed put is accepted, including non-ASCII params; an unsigned one is 423", async () => {
    const apiKey = "testonly-gate-key";
    const gate = await startFakeGate({ apiKey, hmacSecret: V.secret });
    try {
      const call = async (params: Record<string, unknown>, signed: boolean) => {
        const res = await fetch(`${gate.url}/sdk/invoke`, {
          method: "POST",
          headers: { "X-Echo-API-Key": apiKey, "Content-Type": "application/json" },
          body: JSON.stringify({
            envelope_version: 1,
            capability: "echo.vault.put",
            params,
            context: { bypass_reason: "test" },
            ...(signed ? { auth: signGateRequest(V.secret, apiKey, "echo.vault.put", params) } : {}),
          }),
        });
        return { http: res.status, body: (await res.json()) as { status?: string; detail?: { error?: string } } };
      };
      const params = { service: "svc-ünï", username: "entry", secret: "pä$$\"w\\ord\n😀", note: "httpbin.org — proof" };
      const refused = await call(params, false);
      assert.equal(refused.http, 423);
      assert.equal(refused.body.detail?.error, "hmac_required_for_tier2_plus");
      assert.equal(gate.count(), 0);
      const ok = await call(params, true);
      assert.equal(ok.http, 200);
      assert.equal(ok.body.status, "ok");
      assert.ok(gate.holds(params.secret));
    } finally {
      await gate.close();
    }
  });
});
