// library-first: echo.functions.search → no existing impl found (2026-11-14)
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { entropy, fingerprint, listDriveRoots, scan, scanText, withTimeout } from "./credential-scan.mjs";

const SCRIPT = fileURLToPath(new URL("./credential-scan.mjs", import.meta.url));
const KEY = Buffer.alloc(32, 7);

// Fake secrets are assembled at runtime so no token-shaped literal sits in the repo.
const rep = (ch, n) => ch.repeat(n);
const SECRETS = {
  github: "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3lM6",
  openai: "sk-proj-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe9Dc8Ba7Zy6Xw5Vu4",
  anthropic: "sk-ant-" + "api03-Qw3Er5Ty7Ui9Op1As2Df4Gh6Jk8Lz0Xc2Vb4Nm6Qa8Ws",
  aws: "AKIA" + "QWERTYUIOPASDFGH",
  stripe: "sk_" + "live_" + "9aB8cD7eF6gH5iJ4kL3mN2oP",
  telegram: "1234567890:AA" + "Hk3Lm9Qw2Er5Ty8Ui1Op4As7Df0Gh3Jk6",
  facebook: "EAA" + rep("Qw3Er5Ty7U", 12),
  generic: "v9Kq2Lx7Rm4Tn8Wz1Yb5Cd3Fg6Hj0",
  urlpass: "S3cr3t-Pa55w0rd!x",
};

describe("credential-scan: detection without disclosure", () => {
  it("finds each provider token and reports length + fingerprint, never the value", () => {
    const text = [
      `GITHUB_TOKEN=${SECRETS.github}`,
      `openai: "${SECRETS.openai}"`,
      `ANTHROPIC_API_KEY='${SECRETS.anthropic}'`,
      `aws_access_key_id = ${SECRETS.aws}`,
      `STRIPE=${SECRETS.stripe}`,
      `bot ${SECRETS.telegram}`,
      `-----BEGIN ${"RSA"} PRIVATE KEY-----`,
      `DATABASE_URL=postgres://admin:${SECRETS.urlpass}@db.internal:5432/app`,
    ].join("\n");
    const findings = scanText(text, KEY);
    const ids = findings.map((f) => f.detector);
    for (const id of ["github_token", "openai_key", "anthropic_key", "aws_access_key_id", "stripe_secret", "telegram_bot_token", "private_key_pem", "url_basic_auth"]) {
      assert.ok(ids.includes(id), `missing detector ${id}`);
    }
    const gh = findings.find((f) => f.detector === "github_token");
    assert.equal(gh.length, SECRETS.github.length);
    assert.equal(gh.fingerprint, fingerprint(SECRETS.github, KEY));
    assert.equal(gh.line, 1);
    const serialized = JSON.stringify(findings);
    for (const s of Object.values(SECRETS)) assert.ok(!serialized.includes(s), "a finding leaked a secret value");
  });

  it("flags a high-entropy value under a secret-named key, with the key name", () => {
    const findings = scanText(`MY_SERVICE_API_KEY="${SECRETS.generic}"`, KEY);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].detector, "generic_assignment");
    assert.equal(findings[0].key_name, "MY_SERVICE_API_KEY");
    assert.equal(findings[0].length, SECRETS.generic.length);
  });

  it("does not double-report a provider token as a generic assignment", () => {
    const findings = scanText(`GITHUB_TOKEN=${SECRETS.github}`, KEY);
    assert.deepEqual(findings.map((f) => f.detector), ["github_token"]);
  });

  it("finds a Facebook page token standing alone (the bare-file shape), by reference only", () => {
    const findings = scanText(SECRETS.facebook, KEY);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].detector, "facebook_page_token");
    assert.equal(findings[0].provider, "facebook.com");
    assert.equal(findings[0].key_name, null);
    assert.equal(findings[0].length, SECRETS.facebook.length);
    assert.equal(findings[0].fingerprint, fingerprint(SECRETS.facebook, KEY));
    assert.ok(!JSON.stringify(findings).includes(SECRETS.facebook), "a finding leaked a secret value");
  });

  it("finds a Facebook page token in an assignment, named by its variable, not double-reported", () => {
    const findings = scanText(`FB_PAGE_TOKEN=${SECRETS.facebook}`, KEY);
    assert.deepEqual(findings.map((f) => f.detector), ["facebook_page_token"]);
    assert.equal(findings[0].key_name, "FB_PAGE_TOKEN");
  });

  it("ignores near-miss EAA strings", () => {
    const misses = [
      "EAA" + rep("Qw3Er5Ty7U", 4), // real prefix, far too short
      "EAA" + rep("a", 99), // one character under the minimum run
      "xEAA" + rep("Qw3Er5Ty7U", 12), // no word boundary before the prefix
      "EAA" + rep("Qw3Er5Ty7U", 6) + "-" + rep("Qw3Er5Ty7U", 6), // run broken by a dash
      "EAACHECKPOINT" + rep("a", 10), // the prefix on an ordinary word
    ];
    for (const m of misses) {
      assert.deepEqual(
        scanText(m, KEY).filter((f) => f.detector === "facebook_page_token"),
        [],
        `near-miss matched: ${m.slice(0, 24)}`,
      );
    }
  });

  it("ignores placeholders, env references and ordinary words", () => {
    const text = [
      "API_KEY=your_api_key_here",
      "PASSWORD=${DB_PASSWORD}",
      "SECRET=<paste-secret-here>",
      "token: process.env.GITHUB_TOKEN",
      "password = changeme",
      `API_KEY=${rep("x", 20)}`,
      "auth_token_header = authorization",
      "name = not-a-secret-at-all",
    ].join("\n");
    assert.deepEqual(scanText(text, KEY), []);
  });

  it("fingerprints are keyed: same value + other key differs; same key is stable", () => {
    const a = fingerprint(SECRETS.github, KEY);
    assert.equal(a, fingerprint(SECRETS.github, KEY));
    assert.notEqual(a, fingerprint(SECRETS.github, Buffer.alloc(32, 9)));
    assert.match(a, /^[0-9a-f]{16}$/);
  });

  it("entropy separates random strings from repeated ones", () => {
    assert.ok(entropy(SECRETS.generic) > 4);
    assert.ok(entropy(rep("a", 30)) < 0.1);
  });
});

describe("credential-scan: walking a tree", () => {
  let dir;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "credscan-"));
    mkdirSync(join(dir, "app", "node_modules", "pkg"), { recursive: true });
    mkdirSync(join(dir, "app", "config"), { recursive: true });
    writeFileSync(join(dir, "app", ".env"), `GITHUB_TOKEN=${SECRETS.github}\nPORT=8080\n`);
    writeFileSync(join(dir, "app", "config", "settings.json"), JSON.stringify({ stripe_secret_key: SECRETS.stripe, name: "demo" }));
    writeFileSync(join(dir, "app", "copy.env.bak"), `GITHUB_TOKEN=${SECRETS.github}\n`); // not a wanted name/ext
    writeFileSync(join(dir, "app", "credentials-backup.bak"), `OPENAI=${SECRETS.openai}\n`); // wanted by NAME
    writeFileSync(join(dir, "app", "node_modules", "pkg", ".env"), `X_TOKEN=${SECRETS.anthropic}\n`); // skipped dir
    writeFileSync(join(dir, "app", "blob.json"), Buffer.concat([Buffer.from(`{"k":"${SECRETS.aws}"}`), Buffer.from([0, 0, 0])])); // binary
    writeFileSync(join(dir, "app", "big.txt"), `T=${SECRETS.telegram}\n` + rep("a", 5000));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("scans wanted files, skips node_modules / binary / oversized, dedupes by fingerprint", async () => {
    const manifest = await scan({ roots: [dir], key: KEY, maxFileBytes: 4096 });
    assert.equal(manifest.contains_secret_values, false);
    const files = manifest.findings.map((f) => f.file).sort();
    assert.deepEqual([...new Set(files)], [".env", "credentials-backup.bak", "settings.json"]);
    assert.equal(manifest.stats.files_skipped_binary, 1);
    assert.equal(manifest.stats.files_skipped_large, 1);
    assert.equal(manifest.summary.by_provider["github.com"], 1);
    assert.equal(manifest.summary.by_provider["stripe.com"], 1);
    assert.equal(manifest.summary.distinct_secrets, 3);
    const serialized = JSON.stringify(manifest);
    for (const s of Object.values(SECRETS)) assert.ok(!serialized.includes(s), "the manifest leaked a secret value");
  });

  it("CLI: manifest on disk and stdout/stderr carry no secret value", () => {
    const out = join(dir, "manifest.json");
    const keyFile = join(dir, "node.key");
    const r = spawnSync(process.execPath, [SCRIPT, "--root", dir, "--out", out, "--hmac-key-file", keyFile], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const summary = JSON.parse(r.stdout);
    assert.equal(summary.ok, true);
    assert.ok(summary.summary.findings >= 3);
    assert.equal(summary.findings, undefined, "stdout must carry counts only");
    const disk = readFileSync(out, "utf8");
    for (const s of Object.values(SECRETS)) {
      assert.ok(!disk.includes(s), "manifest file leaked a secret value");
      assert.ok(!r.stdout.includes(s) && !r.stderr.includes(s), "CLI output leaked a secret value");
    }
    assert.equal(readFileSync(keyFile).length, 32);
  });

  it("withTimeout rejects a hung operation and passes a fast one through", async () => {
    await assert.rejects(withTimeout(new Promise(() => {}), 20, "hung"), /timeout:hung/);
    assert.equal(await withTimeout(Promise.resolve(7), 1000, "fast"), 7);
  });

  it("a root that cannot be read is counted, not fatal, and the heartbeat carries no contents", async () => {
    const beats = [];
    const manifest = await scan({ roots: [join(dir, "does-not-exist"), dir], key: KEY, maxFileBytes: 4096, onProgress: (p) => beats.push(p) });
    assert.equal(manifest.stats.errors, 1);
    assert.equal(manifest.stats.dirs_timed_out, 0);
    assert.ok(manifest.summary.findings >= 3);
    for (const s of Object.values(SECRETS)) assert.ok(!JSON.stringify(beats).includes(s));
  });

  it("listDriveRoots returns at least one root on this platform", async () => {
    const roots = await listDriveRoots();
    assert.ok(roots.length >= 1);
    if (process.platform !== "win32") assert.deepEqual(roots, ["/"]);
    else for (const r of roots) assert.match(r, /^[A-Z]:\\$/);
  });

  it("CLI refuses to run without --out", () => {
    const r = spawnSync(process.execPath, [SCRIPT, "--root", dir], { encoding: "utf8" });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /--out/);
  });
});

describe("credential-scan: a bare token file", () => {
  let dir;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "credscan-fb-"));
    writeFileSync(join(dir, "page_token.txt"), SECRETS.facebook + "\n");
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("reports the page token by reference from a file that holds nothing else", async () => {
    const manifest = await scan({ roots: [dir], key: KEY });
    assert.equal(manifest.contains_secret_values, false);
    assert.equal(manifest.findings.length, 1);
    const f = manifest.findings[0];
    assert.equal(f.file, "page_token.txt");
    assert.equal(f.detector, "facebook_page_token");
    assert.equal(f.provider, "facebook.com");
    assert.equal(f.length, SECRETS.facebook.length);
    assert.ok(!JSON.stringify(manifest).includes(SECRETS.facebook), "the manifest leaked a secret value");
  });
});
