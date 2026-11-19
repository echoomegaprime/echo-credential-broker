// library-first: echo.functions.search → no existing impl found (2026-11-19)
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { groupFindings, nodeName, parseArgs } from "./vault-import-push.mjs";

const f = (over) => ({ path: "/a/.env", line: 1, detector: "github_token", provider: "github.com", key_name: null, fingerprint: "a".repeat(16), ...over });

describe("vault-import-push: what gets sent", () => {
  it("one group per distinct secret, keeping where it was found and the first variable name", () => {
    const { groups, skipped } = groupFindings([
      f({}),
      f({ path: "/b/.env", line: 9, key_name: "GITHUB_TOKEN" }),
      f({ fingerprint: "b".repeat(16), provider: "google.com", detector: "google_api_key", key_name: "YOUTUBE_API_KEY" }),
    ]);
    assert.equal(skipped, 0);
    assert.equal(groups.length, 2);
    assert.deepEqual(groups[0].sources, [{ path: "/a/.env", line: 1 }, { path: "/b/.env", line: 9 }]);
    assert.equal(groups[0].key_name, "GITHUB_TOKEN");
  });

  it("never sends what cannot become an entry, and generic guesses only on request", () => {
    const findings = [
      f({ provider: "private-key", detector: "private_key_pem", fingerprint: null }),
      f({ provider: "jwt", detector: "jwt", fingerprint: "c".repeat(16) }),
      f({ provider: "url-credentials", detector: "url_basic_auth", fingerprint: "d".repeat(16) }),
      f({ provider: "echo-vault", detector: "echo_vault_token", fingerprint: "e".repeat(16) }),
      f({ provider: "unknown", detector: "generic_assignment", fingerprint: "f".repeat(16), key_name: "TWILIO_AUTH_TOKEN" }),
    ];
    assert.deepEqual(groupFindings(findings), { groups: [], skipped: 5 });
    const withGeneric = groupFindings(findings, { includeGeneric: true });
    assert.equal(withGeneric.groups.length, 1);
    assert.equal(withGeneric.groups[0].key_name, "TWILIO_AUTH_TOKEN");
  });

  it("caps the sources kept per secret", () => {
    const many = Array.from({ length: 12 }, (_, i) => f({ path: `/x/${i}.env` }));
    assert.equal(groupFindings(many).groups[0].sources.length, 5);
  });
});

describe("vault-import-push: arguments", () => {
  it("normalises a host name to what the vault accepts", () => {
    assert.equal(nodeName("QUENCH.local"), "quench");
    assert.equal(nodeName("My Box_01"), "my-box-01");
    assert.equal(nodeName(""), "node");
  });

  it("defaults to a preview against the production vault and rejects unknown flags", () => {
    const a = parseArgs(["--root", "/home/me"]);
    assert.equal(a.apply, false);
    assert.equal(a.vault, "https://credbroker.echo-op.com");
    assert.deepEqual(a.roots, ["/home/me"]);
    assert.throws(() => parseArgs(["--nope"]), /unknown argument/);
    assert.throws(() => parseArgs(["--root"]), /missing value/);
  });
});
