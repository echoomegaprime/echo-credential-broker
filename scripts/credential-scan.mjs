#!/usr/bin/env node
// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * ECHO Vault credential scanner — runs ON the node that owns the files.
 *
 * It finds where credentials live on disk and writes a manifest of REFERENCES.
 * It never writes, prints, logs or returns a secret value:
 *
 *   - a finding is { path, line, detector, provider, key_name, length, fingerprint }
 *   - `fingerprint` is HMAC-SHA256(value) under a key that stays on this node
 *     (16 hex chars). It lets the same secret be recognised in two files on this
 *     node; without the node key it cannot be reversed or brute-forced offline.
 *   - stdout carries counts only.
 *
 * Zero dependencies; one file; Node >= 18; Windows, Linux and macOS.
 *
 *   node credential-scan.mjs --root C:\Users\me --root D:\ --out scan.json
 *   node credential-scan.mjs --all-drives --out scan.json
 *
 * --all-drives covers LOCAL fixed drives only: a mapped network drive belongs to
 * another node, which scans itself (add --include-network-drives to override).
 * A directory that does not answer within 15s is skipped and counted.
 */
import { execFile } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { open, readdir, stat } from "node:fs/promises";
import { homedir, hostname, platform } from "node:os";
import { basename, dirname, extname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const SCANNER_VERSION = "1.1.0";

const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;

/** Directory names never descended into (case-insensitive). */
const SKIP_DIRS = new Set(
  [
    "node_modules", ".git", ".hg", ".svn", "$recycle.bin", "system volume information", "windows",
    "program files", "program files (x86)", "programdata", "appdata\\local\\temp", "__pycache__",
    ".venv", "venv", "site-packages", "dist", "build", ".next", ".nuxt", ".cache", "cache", "caches",
    "winsxs", "proc", "sys", "dev", "run", "snap", "lost+found", ".npm", ".pnpm-store", ".cargo",
    ".rustup", "target", ".gradle", ".m2", "vendor", "bower_components", ".tox", ".mypy_cache",
    ".pytest_cache", "library", ".trash", ".echo-vault-scan", ".vault-data",
  ].map((s) => s.toLowerCase()),
);

/** File extensions worth opening. Everything else is skipped unless its NAME matches. */
const TEXT_EXTS = new Set([
  "", ".env", ".txt", ".md", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config",
  ".properties", ".xml", ".ps1", ".psm1", ".bat", ".cmd", ".sh", ".bash", ".zsh", ".fish", ".py", ".js",
  ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rb", ".go", ".rs", ".php", ".java", ".cs", ".tf", ".tfvars",
  ".pem", ".key", ".p8", ".ppk", ".crt", ".cer", ".netrc", ".npmrc", ".pypirc", ".sql", ".csv", ".log",
  ".http", ".rest", ".dockerfile", ".service", ".plist", ".reg", ".vars", ".secret", ".secrets", ".creds",
]);

/** File names that are opened whatever their extension. */
const NAME_HINT = /(^\.env(\..+)?$)|credential|secret|token|passw|apikey|api_key|\.netrc$|\.npmrc$|\.pypirc$|\.git-credentials$|^id_(rsa|dsa|ecdsa|ed25519)$|wrangler\.toml$|\.dev\.vars$/i;

/**
 * Provider detectors. `re` must be global; group 1 (or the whole match) is the
 * secret. Kept in step with the token shapes in src/lib/vault/redaction.ts.
 */
export const DETECTORS = [
  { id: "private_key_pem", provider: "private-key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, marker: true },
  { id: "github_pat_fine", provider: "github.com", re: /\b(github_pat_[A-Za-z0-9_]{60,})\b/g },
  { id: "github_token", provider: "github.com", re: /\b(gh[pousr]_[A-Za-z0-9_]{36,})\b/g },
  { id: "anthropic_key", provider: "anthropic.com", re: /\b(sk-ant-[A-Za-z0-9_-]{40,})\b/g },
  { id: "openai_key", provider: "openai.com", re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,})\b/g },
  { id: "xai_key", provider: "x.ai", re: /\b(xai-[A-Za-z0-9]{40,})\b/g },
  { id: "aws_access_key_id", provider: "aws.amazon.com", re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g },
  { id: "stripe_secret", provider: "stripe.com", re: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b/g },
  { id: "stripe_webhook", provider: "stripe.com", re: /\b(whsec_[A-Za-z0-9]{24,})\b/g },
  { id: "slack_token", provider: "slack.com", re: /\b(xox[abposr]-[A-Za-z0-9-]{20,})\b/g },
  { id: "google_api_key", provider: "google.com", re: /\b(AIza[0-9A-Za-z_-]{35})\b/g },
  { id: "google_oauth_secret", provider: "google.com", re: /\b(GOCSPX-[A-Za-z0-9_-]{20,})\b/g },
  { id: "sendgrid_key", provider: "sendgrid.com", re: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})/g },
  { id: "twilio_api_key", provider: "twilio.com", re: /\b(SK[0-9a-f]{32})\b/g },
  { id: "telegram_bot_token", provider: "telegram.org", re: /\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b/g },
  { id: "facebook_page_token", provider: "facebook.com", re: /\b(EAA[A-Za-z0-9]{100,})\b/g },
  { id: "huggingface_token", provider: "huggingface.co", re: /\b(hf_[A-Za-z0-9]{30,})\b/g },
  { id: "npm_token", provider: "npmjs.com", re: /\b(npm_[A-Za-z0-9]{36})\b/g },
  { id: "elevenlabs_key", provider: "elevenlabs.io", re: /\b(sk_[0-9a-f]{48})\b/g },
  { id: "resend_key", provider: "resend.com", re: /\b(re_[A-Za-z0-9_]{24,})\b/g },
  { id: "vercel_token", provider: "vercel.com", re: /\b(vc[a-z]_[A-Za-z0-9]{24,})\b/g },
  { id: "supabase_key", provider: "supabase.com", re: /\b(sb[ps]_[A-Za-z0-9_-]{24,})\b/g },
  { id: "echo_vault_token", provider: "echo-vault", re: /\b(e(?:va|vr|wk)_[A-Za-z0-9_-]{24,})\b/g },
  { id: "jwt", provider: "jwt", re: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g },
  { id: "url_basic_auth", provider: "url-credentials", re: /[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"]{1,64}:([^\s@/'"]{6,})@[^\s/'"]+/gi },
];

/** KEY = value / "key": "value" where the key name says "secret". */
const ASSIGN_RE = /(?:^|[\s,{;(])["']?([A-Za-z][A-Za-z0-9_.-]{1,80})["']?\s*(?::|=|=>)\s*(?:"([^"\r\n]{8,512})"|'([^'\r\n]{8,512})'|([^\s"'`,;#}]{8,512}))/g;
const SECRET_KEY_RE = /(secret|passw(?:or)?d|passwd|pwd|token|api[_-]?key|apikey|auth[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|bearer|signing[_-]?key|encryption[_-]?key|webhook[_-]?secret)/i;
const PLACEHOLDER_RE = /^(?:x{3,}|\*{3,}|\.{3,}|<.*>?|\$\{.*|\{\{.*|%.*%|\$[A-Za-z_][A-Za-z0-9_]*|your[_-].*|changeme|change[_-]me|example.*|placeholder.*|todo|none|null|undefined|true|false|redacted|process\.env.*|os\.environ.*|env\..*|import\.meta.*)$/i;

/** Shannon entropy in bits per character. */
export function entropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** HMAC fingerprint, 16 hex chars. The key never leaves the node. */
export function fingerprint(value, key) {
  return createHmac("sha256", key).update(value, "utf8").digest("hex").slice(0, 16);
}

/**
 * Findings for one file's text. Pure: no I/O, and the returned objects hold no
 * secret value — only its length and keyed fingerprint.
 */
export function scanText(text, key) {
  const findings = [];
  const seen = new Set();
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 20_000) continue; // minified blobs: not a config line
    const covered = [];
    const coveredFindings = [];
    for (const d of DETECTORS) {
      d.re.lastIndex = 0;
      let m;
      while ((m = d.re.exec(line)) !== null) {
        const value = d.marker ? m[0] : (m[1] ?? m[0]);
        const dedupe = `${i}:${d.id}:${m.index}`;
        if (seen.has(dedupe)) continue;
        seen.add(dedupe);
        covered.push(value);
        const finding = {
          line: i + 1,
          detector: d.id,
          provider: d.provider,
          key_name: null,
          length: d.marker ? null : value.length,
          fingerprint: d.marker ? null : fingerprint(value, key),
        };
        coveredFindings.push(finding);
        findings.push(finding);
        if (m[0].length === 0) d.re.lastIndex++;
      }
    }
    ASSIGN_RE.lastIndex = 0;
    let a;
    while ((a = ASSIGN_RE.exec(line)) !== null) {
      const name = a[1];
      const value = a[2] ?? a[3] ?? a[4] ?? "";
      if (!SECRET_KEY_RE.test(name)) continue;
      if (PLACEHOLDER_RE.test(value)) continue;
      const hit = covered.findIndex((c) => value.includes(c) || c.includes(value));
      if (hit >= 0) {
        // Already a provider hit: keep the one finding, and remember which variable held it.
        if (coveredFindings[hit].key_name === null) coveredFindings[hit].key_name = name.slice(0, 80);
        continue;
      }
      if (value.length < 12 || entropy(value) < 3.0) continue;
      if (/^[a-z]+(?:[_-][a-z]+)*$/i.test(value) && value.length < 24) continue; // a word, not a secret
      findings.push({
        line: i + 1,
        detector: "generic_assignment",
        provider: "unknown",
        key_name: name.slice(0, 80),
        length: value.length,
        fingerprint: fingerprint(value, key),
      });
    }
  }
  return findings;
}

/**
 * The secret a finding points at, read back from that line of the file.
 *
 * This is the one function here that returns a secret VALUE. It exists for the
 * on-box importer (scripts/vault-import.ts), which hands the value straight to
 * the vault backend. It must never be wired to stdout, a log or a manifest.
 * Returns null when the line no longer holds the secret the manifest recorded
 * (the file changed since the scan) or the finding has no fingerprint.
 *
 * @param {string} lineText one line of the source file
 * @param {{ detector: string, fingerprint: string | null }} finding
 * @param {Buffer | string} key the node HMAC key the manifest was written with
 * @returns {string | null}
 */
export function locateSecret(lineText, finding, key) {
  if (typeof lineText !== "string" || !finding || typeof finding.fingerprint !== "string") return null;
  if (lineText.length > 20_000) return null;
  const matches = (value) => typeof value === "string" && value.length > 0 && fingerprint(value, key) === finding.fingerprint;
  if (finding.detector === "generic_assignment") {
    ASSIGN_RE.lastIndex = 0;
    let a;
    while ((a = ASSIGN_RE.exec(lineText)) !== null) {
      const value = a[2] ?? a[3] ?? a[4] ?? "";
      if (matches(value)) return value;
    }
    return null;
  }
  const d = DETECTORS.find((x) => x.id === finding.detector);
  if (!d || d.marker) return null;
  d.re.lastIndex = 0;
  let m;
  while ((m = d.re.exec(lineText)) !== null) {
    const value = m[1] ?? m[0];
    if (matches(value)) return value;
    if (m[0].length === 0) d.re.lastIndex++;
  }
  return null;
}

function looksBinary(buf) {
  const n = Math.min(buf.length, 4096);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

function wanted(name) {
  if (NAME_HINT.test(name)) return true;
  return TEXT_EXTS.has(extname(name).toLowerCase());
}

/** Load (or create, owner-only) this node's HMAC key. */
export function loadNodeKey(file) {
  const path = file ?? join(homedir(), ".echo-vault-scan", "hmac.key");
  if (existsSync(path)) return readFileSync(path);
  mkdirSync(dirname(path), { recursive: true });
  const key = randomBytes(32);
  writeFileSync(path, key, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* Windows: ACLs, not modes */
  }
  return key;
}

/** Reject after `ms` so one dead mount cannot hang the whole scan. The I/O itself is abandoned. */
export function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timeout:${label}`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function run(file, args, ms) {
  return new Promise((resolvePromise) => {
    execFile(file, args, { timeout: ms, windowsHide: true }, (err, stdout) => resolvePromise(err ? null : String(stdout)));
  });
}

/**
 * Local fixed drives only. A mapped network drive belongs to another node (which
 * scans itself); removable letters with no media hang. Windows: DriveType 3.
 * Pass includeNetwork to scan mapped drives too.
 */
export async function listDriveRoots(opts = {}) {
  if (platform() !== "win32") return ["/"];
  const types = opts.includeNetwork ? "3,4" : "3";
  const out = await run(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", `(Get-CimInstance Win32_LogicalDisk | Where-Object { @(${types}) -contains $_.DriveType }).DeviceID -join ','`],
    20_000,
  );
  if (out && /[A-Za-z]:/.test(out)) {
    return out.trim().split(",").map((d) => d.trim()).filter((d) => /^[A-Za-z]:$/.test(d)).map((d) => `${d.toUpperCase()}\\`);
  }
  // Fallback when PowerShell/CIM is unavailable: probe letters, each with a short timeout.
  const roots = [];
  for (let c = 67; c <= 90; c++) {
    const root = `${String.fromCharCode(c)}:\\`;
    try {
      await withTimeout(stat(root), 3000, root);
      roots.push(root);
    } catch {
      /* no such drive, no media, or unreachable */
    }
  }
  return roots;
}

/**
 * Walk `roots` and return a manifest of references.
 * @param {{roots:string[], key:Buffer, maxFileBytes?:number, excludes?:string[], maxFiles?:number, dirTimeoutMs?:number, onProgress?:(s:object)=>void}} opts
 */
export async function scan(opts) {
  const maxFileBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const excludes = (opts.excludes ?? []).map((e) => resolve(e).toLowerCase());
  const dirTimeoutMs = opts.dirTimeoutMs ?? 15_000;
  const stats = { dirs: 0, files_seen: 0, files_scanned: 0, files_skipped_large: 0, files_skipped_binary: 0, dirs_timed_out: 0, errors: 0 };
  let lastBeat = Date.now();
  const findings = [];
  const stack = opts.roots.map((r) => resolve(r));
  const started = Date.now();
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try {
      entries = await withTimeout(readdir(dir, { withFileTypes: true }), dirTimeoutMs, "readdir");
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("timeout:")) stats.dirs_timed_out++;
      else stats.errors++;
      continue;
    }
    stats.dirs++;
    if (opts.onProgress && Date.now() - lastBeat >= 15_000) {
      lastBeat = Date.now();
      opts.onProgress({ dirs: stats.dirs, files_scanned: stats.files_scanned, findings: findings.length, at: dir });
    }
    for (const e of entries) {
      const full = join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name.toLowerCase())) continue;
        if (excludes.some((x) => full.toLowerCase().startsWith(x))) continue;
        stack.push(full);
        continue;
      }
      if (!e.isFile()) continue;
      stats.files_seen++;
      if (!wanted(e.name)) continue;
      if (opts.maxFiles && stats.files_scanned >= opts.maxFiles) continue;
      let info;
      try {
        info = await withTimeout(stat(full), dirTimeoutMs, "stat");
      } catch {
        stats.errors++;
        continue;
      }
      if (info.size === 0) continue;
      if (info.size > maxFileBytes) {
        stats.files_skipped_large++;
        continue;
      }
      let buf;
      try {
        const fh = await open(full, "r");
        try {
          buf = await withTimeout(fh.readFile(), dirTimeoutMs * 2, "read");
        } finally {
          await fh.close();
        }
      } catch {
        stats.errors++;
        continue;
      }
      if (looksBinary(buf)) {
        stats.files_skipped_binary++;
        continue;
      }
      stats.files_scanned++;
      for (const f of scanText(buf.toString("utf8"), opts.key)) {
        findings.push({ path: full, file: basename(full), mtime: info.mtime.toISOString(), size: info.size, ...f });
      }
    }
  }
  const byProvider = {};
  const byDetector = {};
  const fingerprints = new Set();
  const files = new Set();
  for (const f of findings) {
    byProvider[f.provider] = (byProvider[f.provider] ?? 0) + 1;
    byDetector[f.detector] = (byDetector[f.detector] ?? 0) + 1;
    if (f.fingerprint) fingerprints.add(f.fingerprint);
    files.add(f.path);
  }
  return {
    scanner: "echo-vault-credential-scan",
    version: SCANNER_VERSION,
    node: hostname(),
    platform: platform(),
    roots: opts.roots,
    started_at: new Date(started).toISOString(),
    finished_at: new Date().toISOString(),
    contains_secret_values: false,
    stats,
    summary: {
      findings: findings.length,
      files_with_findings: files.size,
      distinct_secrets: fingerprints.size,
      by_provider: byProvider,
      by_detector: byDetector,
    },
    findings,
  };
}

function parseArgs(argv) {
  const out = { roots: [], excludes: [], allDrives: false, includeNetwork: false, out: null, keyFile: null, maxFileBytes: undefined, maxFiles: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === "--root") out.roots.push(next());
    else if (a === "--exclude") out.excludes.push(next());
    else if (a === "--all-drives") out.allDrives = true;
    else if (a === "--include-network-drives") out.includeNetwork = true;
    else if (a === "--out") out.out = next();
    else if (a === "--hmac-key-file") out.keyFile = next();
    else if (a === "--max-file-bytes") out.maxFileBytes = Number(next());
    else if (a === "--max-files") out.maxFiles = Number(next());
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.out) throw new Error("--out <manifest.json> is required (the manifest stays on this node)");
  const roots = args.allDrives ? await listDriveRoots({ includeNetwork: args.includeNetwork }) : args.roots;
  if (roots.length === 0) throw new Error("give --root <path> (repeatable) or --all-drives");
  const key = loadNodeKey(args.keyFile);
  const manifest = await scan({
    roots,
    key,
    excludes: args.excludes,
    maxFileBytes: args.maxFileBytes,
    maxFiles: args.maxFiles,
    // Heartbeat: counters and the directory being walked — a path, never contents.
    onProgress: (p) => process.stderr.write(`${new Date().toISOString()} ${JSON.stringify(p)}\n`),
  });
  mkdirSync(dirname(resolve(args.out)), { recursive: true });
  writeFileSync(args.out, JSON.stringify(manifest, null, 2), { mode: 0o600 });
  // stdout: counts only — never a path's contents, never a value.
  process.stdout.write(
    JSON.stringify({ ok: true, node: manifest.node, out: resolve(args.out), stats: manifest.stats, summary: manifest.summary }, null, 2) + "\n",
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`credential-scan failed: ${err instanceof Error ? err.message : "error"}\n`);
    process.exit(1);
  });
}
