// library-first: echo.functions.search → no existing impl found (2026-11-19)
/**
 * Import source: the OLD Cloudflare vault (worker `echo-vault-api`, D1
 * `echo-master-vault`, one `credentials` table: service, username, password,
 * api_key, category). The worker decrypts on read, so this talks to the
 * worker's own authenticated API (`/list`, then `/get?id=…&reveal=true`) and
 * needs only the worker's API key — never the D1 encryption key.
 *
 *   fetchLegacyVault(deps)   on-box only. Returns the rows AND their secret
 *                            values, for the importer process and nothing else.
 *   planLegacyVault(items)   pure. Rows → the same ImportPlan the scan importer
 *                            produces, so `applyImport` stores, dedups and
 *                            ledgers them identically.
 *
 * Nothing here prints, logs or returns a secret except `fetchLegacyVault`'s
 * `secrets` map, which the script hands straight to `applyImport`'s resolver.
 * Notes and tags of the old rows are never read: free text can hold secrets.
 */
import { containsSecretPrefix, redactString, registerSecretForRedaction } from "../redaction.ts";
import { entryLabel, normalizeAccount, normalizePurpose, normalizeSite, type EntryKind } from "./cards.ts";
import { siteFromName, type ImportPlan, type PlannedEntry, type SkippedFinding } from "./import.ts";

export type LegacyField = "password" | "api_key";

/** One secret-bearing column of one old row. Holds no secret value. */
export interface LegacyItem {
  id: number;
  service: string;
  username: string;
  category: string;
  field: LegacyField;
  /** Keyed fingerprint of the secret (credential-scan `fingerprint`), 16 hex; null when the old vault could not decrypt it. */
  fingerprint: string | null;
}

export interface LegacyPlanOptions {
  /** Also plan rows whose service names no known site, under `<slug>.legacy-vault.invalid`. */
  includeUnmapped?: boolean;
  onlySites?: string[];
}

export const LEGACY_SOURCE = "cloudflare-vault";
/** Reserved TLD: an entry filed here can never match a real host. */
export const UNMAPPED_SUFFIX = "legacy-vault.invalid";
const DECRYPT_ERROR = "[DECRYPT_ERROR]";

export function legacySourcePath(id: number, field: LegacyField): string {
  return `${LEGACY_SOURCE}:credentials/${id}#${field}`;
}

function safeLabel(value: string): string {
  const v = value.replace(/[\r\n\t]+/g, " ").trim().slice(0, 80);
  return containsSecretPrefix(v) || redactString(v) !== v ? "[redacted]" : v;
}

function slug(value: string, max: number): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, max).replace(/-+$/, "");
}

/** "https://dash.cloudflare.com/x" → dash.cloudflare.com; "Twilio (main)" → twilio.com; unknown → null. */
export function siteForService(service: string): string | null {
  const s = service.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || /^[^\s/@]+\.[a-z]{2,}([/:?#]|$)/i.test(s)) {
    try {
      return normalizeSite(s);
    } catch {
      /* fall through to the name hints */
    }
  }
  return siteFromName(s.replace(/[^A-Za-z0-9]+/g, "_"));
}

function accountFor(item: LegacyItem, fallback: string): string {
  for (const candidate of [item.username.trim(), slug(item.service, 64).replace(/-/g, "_")]) {
    if (!candidate) continue;
    try {
      return normalizeAccount(candidate);
    } catch {
      /* spaces, or it looks like a secret: try the next */
    }
  }
  return fallback;
}

function purposeFor(category: string): string {
  const raw = `import ${LEGACY_SOURCE}/${slug(category || "general", 32) || "general"}`;
  try {
    return normalizePurpose(raw);
  } catch {
    return "import";
  }
}

/**
 * Rows → plan. Pure and deterministic. One entry per distinct secret, kind and
 * site: the same key stored under two old rows of one site is one entry listing both. A password
 * column becomes kind `password`, an api_key column kind `api_key`.
 */
export function planLegacyVault(items: LegacyItem[], opts: LegacyPlanOptions = {}): ImportPlan {
  const only = opts.onlySites ? new Set(opts.onlySites.map((s) => normalizeSite(s))) : null;
  const skipped: SkippedFinding[] = [];
  const groups = new Map<string, { site: string; first: LegacyItem; kind: EntryKind; sources: PlannedEntry["sources"] }>();
  const ordered = [...items].sort((a, b) => a.id - b.id || a.field.localeCompare(b.field));
  for (const item of ordered) {
    const detector = `legacy_vault_${item.field}`;
    const source = { path: legacySourcePath(item.id, item.field), line: item.id, detector };
    const skip = (reason: SkippedFinding["reason"]) =>
      skipped.push({ ...source, provider: safeLabel(item.service), key_name: null, reason });
    if (typeof item.fingerprint !== "string" || !/^[0-9a-f]{16}$/.test(item.fingerprint)) {
      skip("legacy_decrypt_failed");
      continue;
    }
    let site = siteForService(item.service);
    if (!site) {
      const label = slug(item.service, 50);
      if (!opts.includeUnmapped || !label) {
        skip("unknown_provider");
        continue;
      }
      try {
        site = normalizeSite(`${label}.${UNMAPPED_SUFFIX}`);
      } catch {
        skip("invalid_site");
        continue;
      }
    }
    if (only && !only.has(site)) {
      skip("provider_not_selected");
      continue;
    }
    const kind: EntryKind = item.field === "password" ? "password" : "api_key";
    // The site is part of the identity: one password reused on two sites is two entries.
    const key = `${item.fingerprint}\n${kind}\n${site}`;
    const known = groups.get(key);
    if (known) known.sources.push(source);
    else groups.set(key, { site, first: item, kind, sources: [source] });
  }

  const taken = new Set<string>();
  const entries: PlannedEntry[] = [];
  for (const [key, group] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const fp = key.slice(0, 16);
    let account = accountFor(group.first, `imported-${fp.slice(0, 8)}`);
    const identity = () => `${group.site}\n${group.kind}\n${account}`;
    if (taken.has(identity())) account = `${account.slice(0, 254 - 9)}-${fp.slice(0, 8)}`;
    taken.add(identity());
    const purpose = purposeFor(group.first.category);
    entries.push({
      scan_fingerprint: fp,
      site: group.site,
      account,
      purpose,
      label: entryLabel(group.site, account, purpose),
      kind: group.kind,
      sources: group.sources,
    });
  }
  entries.sort((a, b) => a.site.localeCompare(b.site) || a.account.localeCompare(b.account) || a.kind.localeCompare(b.kind));
  return { node: LEGACY_SOURCE, entries, skipped };
}

export class LegacyVaultError extends Error {
  code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export interface LegacyFetchDeps {
  /** https origin of the old worker. */
  baseUrl: string;
  /** The worker's API key. A secret: sent in one header, never logged. */
  apiKey: string;
  fingerprint: (secret: string) => string;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  /** Pause between requests; the worker allows 60 a minute per address. */
  delayMs?: number;
  maxRows?: number;
}

export interface LegacyFetchResult {
  rows: number;
  items: LegacyItem[];
  /** legacySourcePath → secret VALUE. For the importer's resolver only. */
  secrets: Map<string, string>;
}

/** Read every row of the old vault through its own API. On-box only: the result holds secret values. */
export async function fetchLegacyVault(deps: LegacyFetchDeps): Promise<LegacyFetchResult> {
  let origin: URL;
  try {
    origin = new URL(deps.baseUrl);
  } catch {
    throw new LegacyVaultError("source_url_invalid");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname);
  if (origin.protocol !== "https:" && !(origin.protocol === "http:" && loopback)) throw new LegacyVaultError("source_url_not_https");
  if (!deps.apiKey) throw new LegacyVaultError("source_key_missing");
  registerSecretForRedaction(deps.apiKey);
  const doFetch = deps.fetch ?? fetch;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const delayMs = deps.delayMs ?? 1100;
  const maxRows = deps.maxRows ?? 20_000;

  const call = async (path: string): Promise<Record<string, unknown> | null> => {
    for (let attempt = 0; ; attempt++) {
      let res: Response;
      try {
        res = await doFetch(new URL(path, origin), { headers: { "X-Echo-API-Key": deps.apiKey }, redirect: "error" });
      } catch {
        throw new LegacyVaultError("source_unreachable");
      }
      if (res.status === 429 && attempt < 3) {
        await sleep(61_000);
        continue;
      }
      if (res.status === 401 || res.status === 403) throw new LegacyVaultError("source_key_rejected");
      if (res.status === 404) return null;
      if (!res.ok) throw new LegacyVaultError(res.status === 429 ? "source_rate_limited" : "source_unavailable");
      try {
        return (await res.json()) as Record<string, unknown>;
      } catch {
        throw new LegacyVaultError("source_unavailable");
      }
    }
  };

  const meta: Array<{ id: number; service: string; username: string; category: string }> = [];
  for (let offset = 0; ; ) {
    const page = await call(`/list?limit=500&offset=${offset}`);
    const list = Array.isArray(page?.credentials) ? (page.credentials as Array<Record<string, unknown>>) : null;
    if (!list) throw new LegacyVaultError("source_unavailable");
    for (const r of list) {
      if (typeof r.id !== "number" || typeof r.service !== "string") continue;
      meta.push({
        id: r.id,
        service: r.service,
        username: typeof r.username === "string" ? r.username : "",
        category: typeof r.category === "string" ? r.category : "general",
      });
    }
    offset += list.length;
    if (page?.has_more !== true || list.length === 0) break;
    if (meta.length > maxRows) throw new LegacyVaultError("source_too_large");
    await sleep(delayMs);
  }

  const items: LegacyItem[] = [];
  const secrets = new Map<string, string>();
  for (const row of meta) {
    await sleep(delayMs);
    const full = await call(`/get?id=${row.id}&reveal=true`);
    if (!full) continue; // deleted between list and get
    for (const field of ["password", "api_key"] as const) {
      const value = full[field];
      if (typeof value !== "string" || value === "") continue;
      if (value === DECRYPT_ERROR) {
        items.push({ ...row, field, fingerprint: null });
        continue;
      }
      registerSecretForRedaction(value);
      secrets.set(legacySourcePath(row.id, field), value);
      items.push({ ...row, field, fingerprint: deps.fingerprint(value) });
    }
  }
  return { rows: meta.length, items, secrets };
}
