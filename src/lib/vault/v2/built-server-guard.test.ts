// library-first: echo.functions.search → no existing impl found (2026-11-15; gate degraded on one query, 0 hits on the other)
/**
 * Guards for a failure only a *built* server shows (found deploying to a Node box):
 * @simplewebauthn/server → @peculiar/x509 → tsyringe throws at module load unless the
 * Reflect polyfill ran first. Unbundled Node (every other test here) hides it; bundled,
 * every /console request answered 500. Two things together keep it fixed, and a full
 * build is too slow for this suite, so both are pinned here.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (p: string): string => readFileSync(new URL(p, import.meta.url), "utf8");

describe("built-server guards", () => {
  it("owner-console loads the Reflect polyfill, then the passkey library, lazily and in that order", () => {
    const src = read("./owner-console.ts");
    assert.doesNotMatch(src, /^import\s+(?!type\b)[^;]*from\s+"@simplewebauthn\/server";/m, "no static import: its chunk would load tsyringe before the polyfill");
    assert.match(src, /import\("reflect-metadata"\)\.then\(\(\) => import\("@simplewebauthn\/server"\)\)/);
  });

  it("the build keeps that chain as real packages and the preset is configurable", () => {
    const cfg = read("../../../../vite.config.ts");
    for (const pkg of ["reflect-metadata*", "@simplewebauthn/server*", "@peculiar/x509*", "tsyringe*"]) {
      assert.ok(cfg.includes(`"${pkg}"`), `traceDeps must include ${pkg}`);
    }
    assert.match(cfg, /preset: process\.env\.NITRO_PRESET\?\.trim\(\) \|\| "vercel"/);
    const pkg = JSON.parse(read("../../../../package.json")) as { dependencies: Record<string, string> };
    assert.ok(pkg.dependencies["reflect-metadata"], "reflect-metadata is a direct dependency");
  });

  it("the polyfill and the library really load in that order", async () => {
    await import("reflect-metadata");
    const m = await import("@simplewebauthn/server");
    const o = await m.generateRegistrationOptions({ rpName: "x", rpID: "vault.test", userName: "owner" });
    assert.equal(typeof o.challenge, "string");
  });
});
