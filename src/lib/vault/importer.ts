import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { registerSecretForRedaction, installProcessRedaction } from "./redaction.ts";
import { getStore, type CredentialStore } from "./store.ts";
import type { CredentialType, ProviderId } from "./types.ts";
import { formatVaultRef } from "./refs.ts";

if (!process.env.NODE_TEST_CONTEXT) {
  installProcessRedaction();
}

const CONNECTOR_DIR = "/tmp/grok/connectors";

const ENV_SOURCES: Array<{
  env: string;
  provider: ProviderId;
  account: string;
  type: CredentialType;
}> = [
  { env: "GITHUB_TOKEN", provider: "github", account: "echoomegaprime", type: "pat" },
  { env: "GH_TOKEN", provider: "github", account: "echoomegaprime", type: "pat" },
  { env: "GITHUB_PAT", provider: "github", account: "echoomegaprime", type: "pat" },
  { env: "OPENAI_API_KEY", provider: "openai", account: "primary", type: "api_key" },
  {
    env: "CLOUDFLARE_API_TOKEN",
    provider: "cloudflare",
    account: "echo",
    type: "api_key",
  },
  {
    env: "STRIPE_SECRET_KEY",
    provider: "stripe",
    account: "production",
    type: "api_key",
  },
  { env: "STRIPE_API_KEY", provider: "stripe", account: "production", type: "api_key" },
  { env: "XAI_API_KEY", provider: "xai", account: "primary", type: "api_key" },
];

export interface ImportReport {
  imported: string[];
  skipped: string[];
}

function looksLikeSecret(value: string): boolean {
  const v = value.trim();
  return v.length >= 16 && !v.includes("\n") && !v.startsWith("{");
}

async function readSecretFile(path: string): Promise<string | null> {
  try {
    const raw = await readFile(path, "utf8");
    const trimmed = raw.trim();
    if (!trimmed) return null;
    if (trimmed.startsWith("{")) {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      for (const key of ["token", "password", "secret", "api_key", "pat"]) {
        const val = parsed[key];
        if (typeof val === "string" && looksLikeSecret(val)) {
          registerSecretForRedaction(val);
          return val.trim();
        }
      }
      return null;
    }
    if (trimmed.includes("password=")) {
      const line = trimmed
        .split(/\r?\n/)
        .find((l) => l.startsWith("password="));
      if (line) {
        const secret = line.slice("password=".length).trim();
        registerSecretForRedaction(secret);
        return secret;
      }
    }
    if (looksLikeSecret(trimmed) || /^gh[pousr]_|^github_pat_|^sk-|^xai-/.test(trimmed)) {
      registerSecretForRedaction(trimmed);
      return trimmed;
    }
    return null;
  } catch {
    return null;
  }
}

export async function importSandboxCredentials(
  store: CredentialStore = getStore(),
): Promise<ImportReport> {
  const imported: string[] = [];
  const skipped: string[] = [];

  const githubToken = await readSecretFile(join(CONNECTOR_DIR, "github.token"));
  if (githubToken) {
    const ref = store.put({
      provider: "github",
      account: "echoomegaprime",
      type: "pat",
      secret: githubToken,
      source: "sandbox:connectors/github.token",
    });
    imported.push(ref.ref);
  } else {
    skipped.push("sandbox:connectors/github.token");
  }

  try {
    const files = await readdir(CONNECTOR_DIR);
    for (const name of files) {
      if (name === "github.token" || name === "index.json") continue;
      if (!name.endsWith(".token")) continue;
      const secret = await readSecretFile(join(CONNECTOR_DIR, name));
      if (!secret) {
        skipped.push(`sandbox:connectors/${name}`);
        continue;
      }
      const providerGuess = name.replace(/\.token$/, "");
      if (providerGuess === "github") continue;
      skipped.push(`sandbox:connectors/${name}`);
    }
  } catch {
    /* connector dir absent */
  }

  for (const src of ENV_SOURCES) {
    const value = process.env[src.env];
    if (!value || !looksLikeSecret(value)) {
      skipped.push(`env:${src.env}`);
      continue;
    }
    const ref = formatVaultRef(src.provider, src.account);
    if (store.has(ref) && src.provider === "github") {
      skipped.push(`env:${src.env}`);
      continue;
    }
    registerSecretForRedaction(value);
    const meta = store.put({
      provider: src.provider,
      account: src.account,
      type: src.type,
      secret: value,
      source: `env:${src.env}`,
    });
    imported.push(meta.ref);
  }

  return { imported: unique(imported), skipped: unique(skipped) };
}

function unique(items: string[]): string[] {
  return [...new Set(items)];
}

let importOnce: Promise<ImportReport> | null = null;

export function ensureImported(
  store: CredentialStore = getStore(),
): Promise<ImportReport> {
  if (!importOnce) importOnce = importSandboxCredentials(store);
  return importOnce;
}

export function resetImportForTests(): void {
  importOnce = null;
}
