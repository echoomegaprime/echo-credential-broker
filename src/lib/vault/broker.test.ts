import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { CredentialStore } from "./store.ts";
import { useCredential } from "./broker.ts";
import { safeJson } from "./redaction.ts";

const FAKE = "github_pat_TESTONLY_BROKER_ABCDEF0123456789XXXX";
const GITHUB_REF = "vault://github/echoomegaprime";

describe("broker useCredential", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("injects Authorization internally and never returns it", async () => {
    const store = new CredentialStore();
    store.put({
      provider: "github",
      account: "echoomegaprime",
      type: "pat",
      secret: FAKE,
      source: "test",
    });
    let sawAuth = false;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      assert.equal(url.startsWith("https://api.github.com/"), true);
      const headers = new Headers(init?.headers);
      const auth = headers.get("Authorization");
      assert.equal(auth, `Bearer ${FAKE}`);
      sawAuth = true;
      return new Response(
        JSON.stringify({ login: "echoomegaprime", id: 314902331 }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    const result = await useCredential(
      { caller: "acceptance-test", store },
      {
        credential_ref: GITHUB_REF,
        provider: "github",
        operation: "GET",
        resource: "/user",
      },
    );
    assert.equal(sawAuth, true);
    assert.equal(result.ok, true);
    const serialized = safeJson(result);
    assert.equal(serialized.includes(FAKE), false);
    assert.equal(serialized.toLowerCase().includes("authorization"), false);
    if (result.ok) {
      const body = (result.data as { body: { login: string } }).body;
      assert.equal(body.login, "echoomegaprime");
    }
  });

  it("does not fall back to anonymous when the ref is missing", async () => {
    const store = new CredentialStore();
    let called = false;
    globalThis.fetch = (async () => {
      called = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    const result = await useCredential(
      { caller: "acceptance-test", store },
      {
        credential_ref: "vault://github/missing",
        provider: "github",
        operation: "GET",
        resource: "/user",
      },
    );
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.error, "credential_unavailable");
    assert.equal(called, false);
  });
});
