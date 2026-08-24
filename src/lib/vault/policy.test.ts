import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  assertSafeDestination,
  buildProviderUrl,
  isAllowedHostForProvider,
  isBlockedHost,
  normalizeResourcePath,
} from "./policy.ts";

describe("policy", () => {
  it("allows only the GitHub API host", () => {
    assert.equal(isAllowedHostForProvider("github", "api.github.com"), true);
    assert.equal(isAllowedHostForProvider("github", "github.com"), false);
    assert.equal(isAllowedHostForProvider("github", "evil.example"), false);
  });

  it("blocks metadata services, localhost, and private IPs", () => {
    assert.equal(isBlockedHost("169.254.169.254"), true);
    assert.equal(isBlockedHost("localhost"), true);
    assert.equal(isBlockedHost("127.0.0.1"), true);
    assert.equal(isBlockedHost("metadata.google.internal"), true);
    assert.equal(isBlockedHost("10.0.0.5"), true);
    assert.equal(isBlockedHost("192.168.1.1"), true);
  });

  it("rejects absolute URLs and parent-path tricks as resources", () => {
    assert.throws(() => normalizeResourcePath("https://evil.example/steal"));
    assert.throws(() => normalizeResourcePath("//evil.example/steal"));
    assert.throws(() => normalizeResourcePath("/../../etc/passwd"));
  });

  it("refuses to send a credential to an unapproved hostname", () => {
    assert.throws(() =>
      assertSafeDestination(new URL("https://evil.example/"), "github"),
    );
    assert.throws(() =>
      assertSafeDestination(new URL("https://169.254.169.254/latest"), "github"),
    );
    assert.throws(() =>
      assertSafeDestination(new URL("http://api.github.com/user"), "github"),
    );
  });

  it("builds HTTPS GitHub URLs from paths only", () => {
    const url = buildProviderUrl("github", "/user");
    assert.equal(url.href, "https://api.github.com/user");
  });
});
