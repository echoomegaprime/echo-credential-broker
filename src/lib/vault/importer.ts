/**
 * Startup discovery — populates the broker's LOCAL METADATA cache (never
 * secret material) for the default provider/account refs by locating them in
 * the canonical Master Vault.
 *
 * This used to sweep raw secret VALUES out of env vars (`GITHUB_TOKEN`,
 * `OPENAI_API_KEY`, ...) and `/tmp/grok/connectors/*.token` sandbox files
 * into an in-memory store on every boot — a second, ephemeral, disconnected
 * credential store. That store is gone (see store.ts); there is nothing left
 * to import FROM locally. What used to be "import" is now "discover what
 * Vault A already has for the refs this broker exposes" — a metadata-only
 * locate() sweep, so `vault_status` / `vault_list` have something to show
 * immediately at startup without requiring a secret fetch first.
 *
 * Exported names/shapes are UNCHANGED (`ensureImported`, `importSandboxCredentials`,
 * `ImportReport { imported, skipped }`) so broker.ts / tools.ts need no changes.
 */
import { installProcessRedaction } from "./redaction.ts";
import { getStore, type CredentialStore } from "./store.ts";
import type { ProviderId } from "./types.ts";
import { formatVaultRef, parseVaultRef } from "./refs.ts";

if (!process.env.NODE_TEST_CONTEXT) {
  installProcessRedaction();
}

/** The default vault:// refs this broker's built-in provider tools use (see providers.ts). */
const DEFAULT_REFS: Array<{ provider: ProviderId; account: string }> = [
  { provider: "github", account: "echoomegaprime" },
  { provider: "cloudflare", account: "echo" },
  { provider: "openai", account: "primary" },
  { provider: "stripe", account: "production" },
  { provider: "xai", account: "primary" },
];

export interface ImportReport {
  imported: string[];
  skipped: string[];
}

/**
 * Locate metadata (not secrets) for the default refs against the canonical
 * vault, registering whatever is found into the store's local cache.
 */
export async function importSandboxCredentials(
  store: CredentialStore = getStore(),
): Promise<ImportReport> {
  const imported: string[] = [];
  const skipped: string[] = [];

  for (const { provider, account } of DEFAULT_REFS) {
    const ref = formatVaultRef(provider, account);
    const parsed = parseVaultRef(ref);
    if (!parsed) {
      skipped.push(ref);
      continue;
    }
    const found = await store.has(ref); // has() auto-discovers metadata as a side effect
    (found ? imported : skipped).push(ref);
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
