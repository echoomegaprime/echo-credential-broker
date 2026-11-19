// library-first: echo.functions.search → no existing impl found (2026-11-19)
/**
 * The real node script against the real handlers, over a loopback HTTP server.
 * Stores, backend and approvals are in memory; the "owner" approves from the
 * notifier. Proves the two halves agree on the wire format and that no secret
 * appears in anything the script prints or writes.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { FakeVaultBackend } from "../backend.ts";
import { MemoryApprovalStore, type ApprovalNotifier } from "./approvals.ts";
import { MemoryCardStore, MemoryEntryStore, secretFingerprint } from "./cards.ts";
import { handleImportBegin, handleImportFinish, handleImportSubmit, type NodeImportDeps } from "./node-import.ts";
import { MemoryRateLimitStore } from "./rate-limit-store.ts";

const SCRIPT = fileURLToPath(new URL("../../../../scripts/vault-import-push.mjs", import.meta.url));
const SECRETS = {
  google: "AIza" + "Sy" + "B1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R",
  github: "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3lM6",
};
const ENV: NodeJS.ProcessEnv = {
  ECHO_VAULT_APPROVAL_HMAC_KEY: "test-only-approval-hmac-key-0123456789abcdef",
  ECHO_VAULT_APPROVER_TELEGRAM_ID: "424242",
};

const tmp = mkdtempSync(join(tmpdir(), "vault-node-import-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

function startVault() {
  const approvals = new MemoryApprovalStore();
  const prompts: string[] = [];
  // The owner taps Approve as soon as the prompt arrives.
  const notify: ApprovalNotifier = async ({ record }) => {
    prompts.push(record.summary);
    setTimeout(() => void approvals.decide(record.id, "approved", "424242", new Date().toISOString()), 50);
  };
  const entries = new MemoryEntryStore();
  const deps: NodeImportDeps = {
    entries,
    cards: new MemoryCardStore(),
    backend: new FakeVaultBackend(),
    ledger: async () => undefined,
    env: ENV,
    limits: new MemoryRateLimitStore(),
    approvals: { store: approvals, notify, env: ENV, ledger: async () => undefined },
  };
  const routes: Record<string, (r: Request, d: NodeImportDeps) => Promise<Response>> = {
    "/api/import/begin": handleImportBegin,
    "/api/import/submit": handleImportSubmit,
    "/api/import/finish": handleImportFinish,
  };
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const handler = routes[req.url ?? ""];
    if (!handler) {
      res.writeHead(404).end();
      return;
    }
    const out = await handler(
      new Request(`http://127.0.0.1${req.url}`, { method: req.method, headers: req.headers as Record<string, string>, body: Buffer.concat(chunks) }),
      deps,
    );
    res.writeHead(out.status, Object.fromEntries(out.headers)).end(await out.text());
  });
  return new Promise<{ url: string; entries: MemoryEntryStore; prompts: string[]; close: () => void }>((resolveStart) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolveStart({ url: `http://127.0.0.1:${port}`, entries, prompts, close: () => server.close() });
    });
  });
}

function runScript(args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((done) => {
    const child = spawn(process.execPath, [SCRIPT, ...args], { env: { ...process.env, HOME: tmp, USERPROFILE: tmp } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => done({ code, stdout, stderr }));
  });
}

describe("node import: the node script against the vault handlers", () => {
  it("previews, then imports, without a secret in its output or report", async () => {
    const root = join(tmp, "files");
    mkdirSync(join(root, "app"), { recursive: true });
    mkdirSync(join(root, "copy"), { recursive: true });
    writeFileSync(join(root, "app", ".env"), `YOUTUBE_API_KEY=${SECRETS.google}\nGITHUB_TOKEN=${SECRETS.github}\nPORT=1\n`);
    writeFileSync(join(root, "copy", ".env"), `GITHUB_TOKEN=${SECRETS.github}\n`);
    const vault = await startVault();
    try {
      const report = join(tmp, "report.json");
      const base = ["--vault", vault.url, "--node", "TestBox", "--root", root, "--report", report, "--hmac-key-file", join(tmp, "hmac.key")];

      const preview = await runScript(base);
      assert.equal(preview.code, 0, preview.stdout);
      assert.match(preview.stdout, /"mode":"preview"/);
      assert.match(preview.stdout, /"would_import":2/);
      assert.equal((await vault.entries.list({})).length, 0);

      const real = await runScript([...base, "--apply"]);
      assert.equal(real.code, 0, real.stdout);
      assert.match(real.stdout, /"imported":2/);
      assert.match(real.stdout, /"pairing_code":"[0-9A-F]{6}"/);
      const stored = await vault.entries.list({});
      assert.deepEqual(stored.map((e) => `${e.site}/${e.account}`).sort(), ["github.com/github_token", "google.com/youtube_api_key"]);
      assert.equal(stored.find((e) => e.site === "google.com")?.fingerprint, secretFingerprint(SECRETS.google));
      assert.ok(stored.every((e) => e.purpose === "import testbox/.env"));
      assert.equal(vault.prompts.length, 2);
      assert.match(vault.prompts[1], /up to 2 credentials found on node testbox/);

      const again = await runScript([...base, "--apply"]);
      assert.equal(again.code, 0, again.stdout);
      assert.match(again.stdout, /"exists":2/);
      assert.equal((await vault.entries.list({})).length, 2);

      const everything = [preview, real, again].map((r) => r.stdout + r.stderr).join("\n") + readFileSync(report, "utf8");
      for (const s of Object.values(SECRETS)) assert.ok(!everything.includes(s), "the node script leaked a secret value");
    } finally {
      vault.close();
    }
  });

  it("refuses to send secrets to a non-loopback http vault", async () => {
    const res = await runScript(["--vault", "http://vault.example.test", "--root", tmp]);
    assert.equal(res.code, 1);
    assert.match(res.stdout, /vault_must_be_https/);
  });
});
