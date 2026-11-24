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
 *
 * Discovery is deliberately NOT memoized for the process lifetime: the exact-
 * coordinate locate() of the five default refs resolves nothing when Vault A
 * holds those credentials under different coordinates, and a memoized empty
 * result used to stick until restart (the 2026-11-24 credential_count=0
 * defect). `ensureImported` now caches only a NON-EMPTY report, and only for
 * IMPORT_CACHE_TTL_MS, and the sweep itself also runs the store's
 * search-backed census — so a cold process converges on what Vault A
 * actually holds, and a transient empty/failed sweep retries on a later call.
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
  { provider: "cloudflare", account: "global_api_key" },
  { provider: "openai", account: "api_key" },
  { provider: "stripe", account: "secret_key" },
  { provider: "xai", account: "api_key" },
];

export interface ImportReport {
  imported: string[];
  skipped: string[];
}

/**
 * Locate metadata (not secrets) for the default refs against the canonical
 * vault, registering whatever is found into the store's local cache — then
 * run the search-backed census, which registers every credential Vault A
 * holds for the broker's providers under its REAL coordinates. The census is
 * what makes discovery robust: the default refs are only the coordinates the
 * built-in provider tools ask for, not an inventory of the vault.
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

  imported.push(...(await store.syncFromVault({ force: true })));

  return { imported: unique(imported), skipped: unique(skipped) };
}

function unique(items: string[]): string[] {
  return [...new Set(items)];
}

/** A successful (non-empty) discovery report is reused only this long. */
const IMPORT_CACHE_TTL_MS = 60_000;

let importOnce: Promise<ImportReport> | null = null;
let importCache: ImportReport | null = null;
let importCachedAt = 0;

/**
 * Run discovery, retryably: concurrent callers share one in-flight sweep,
 * but the result is cached ONLY when it found something, and only for
 * IMPORT_CACHE_TTL_MS. An empty sweep (vault unreachable, or coordinates
 * not yet resolvable) is never latched — the next call retries.
 */
export function ensureImported(
  store: CredentialStore = getStore(),
): Promise<ImportReport> {
  if (importCache && Date.now() - importCachedAt < IMPORT_CACHE_TTL_MS) {
    return Promise.resolve(importCache);
  }
  if (!importOnce) {
    importOnce = importSandboxCredentials(store).then(
      (report) => {
        importOnce = null;
        if (report.imported.length > 0) {
          importCache = report;
          importCachedAt = Date.now();
        }
        return report;
      },
      (err) => {
        importOnce = null;
        throw err;
      },
    );
  }
  return importOnce;
}

export function resetImportForTests(): void {
  importOnce = null;
  importCache = null;
  importCachedAt = 0;
}
