// library-first: echo.functions.search → no existing impl found (2026-11-19)
/**
 * Bulk import: turn a credential-scan manifest into vault entries, so the owner
 * does not have to type every existing credential into a card.
 *
 * Two steps, both free of secret values in everything they return:
 *
 *   planImport(manifest)        pure. Manifest findings (references only) →
 *                               one planned entry per distinct secret, plus the
 *                               findings that will not be imported and why.
 *   applyImport(plan, deps)     reads each secret back from its source file
 *                               (through `resolveSecret`, supplied by the
 *                               on-box script), stores it with the same seam
 *                               rotation uses (openEntryVault: backend put →
 *                               entry row → ledger) and reports a status code
 *                               per entry.
 *
 * The secret exists only as a local variable between `resolveSecret` and
 * `writeSecret`; it is registered for redaction first. Nothing here prints, logs
 * or returns it. Source files are never modified.
 *
 * Imported entries are ordinary entries: `entry_use`, `entry_transfer`, re-entry
 * cards, rotation and delete all work on them. Using one still needs the
 * owner's consent exactly as for a card-entered entry.
 */
import { createHash, randomBytes } from "node:crypto";
import { log } from "../log.ts";
import { registerSecretForRedaction } from "../redaction.ts";
import { constantTimeEqual } from "./approvals.ts";
import {
  EntryError,
  entryLabel,
  entryRef,
  MAX_SECRET_LENGTH,
  MIN_SECRET_LENGTH,
  normalizeAccount,
  normalizePurpose,
  normalizeSite,
  openEntryVault,
  secretFingerprint,
  type CardsDeps,
  type EntryKind,
  type EntryMetadata,
} from "./cards.ts";

/** One finding of scripts/credential-scan.mjs. Holds no secret value. */
export interface ScanFinding {
  path: string;
  file?: string;
  line: number;
  detector: string;
  provider: string;
  key_name: string | null;
  length: number | null;
  /** HMAC-SHA256 under the scanning node's key, 16 hex chars. Null for marker findings. */
  fingerprint: string | null;
}

export interface ScanManifest {
  scanner?: string;
  node?: string;
  contains_secret_values?: boolean;
  findings: ScanFinding[];
}

export interface ImportSource {
  path: string;
  line: number;
  detector: string;
}

/** One entry the import will try to create. */
export interface PlannedEntry {
  /** The scan fingerprint that identifies this secret on the scanning node. */
  scan_fingerprint: string;
  site: string;
  account: string;
  purpose: string;
  label: string;
  kind: EntryKind;
  /** Every place the same secret was found; the first readable one is used. */
  sources: ImportSource[];
}

export type SkipReason =
  | "private_key_file"
  | "vault_own_token"
  | "jwt_unattributed"
  | "url_credentials"
  | "unknown_provider"
  | "generic_not_requested"
  | "provider_not_selected"
  | "no_fingerprint"
  | "invalid_site";

export interface SkippedFinding {
  path: string;
  line: number;
  detector: string;
  provider: string;
  key_name: string | null;
  reason: SkipReason;
}

export interface ImportPlan {
  node: string | null;
  entries: PlannedEntry[];
  skipped: SkippedFinding[];
}

export interface PlanOptions {
  /** Also plan `generic_assignment` findings whose variable name identifies a known service. */
  includeGeneric?: boolean;
  /** When set, only these sites are planned (after provider → site mapping). */
  onlySites?: string[];
}

/** Providers the scanner names that are not a service an entry could be used against. */
const UNIMPORTABLE: Record<string, SkipReason> = {
  "private-key": "private_key_file",
  "echo-vault": "vault_own_token",
  jwt: "jwt_unattributed",
  "url-credentials": "url_credentials",
};

/**
 * Variable-name hints for `generic_assignment` findings, first match wins.
 * Only names that identify one service; anything else stays `unknown_provider`.
 */
const NAME_HINTS: ReadonlyArray<readonly [RegExp, string]> = [
  [/cloudflare|(^|_)cf_/i, "cloudflare.com"],
  [/twilio/i, "twilio.com"],
  [/eleven_?labs|(^|_)xi_/i, "elevenlabs.io"],
  [/anthropic|claude/i, "anthropic.com"],
  [/openrouter/i, "openrouter.ai"],
  [/openai/i, "openai.com"],
  [/(^|_)xai(_|$)|grok/i, "x.ai"],
  [/groq/i, "groq.com"],
  [/together/i, "together.ai"],
  [/deepseek/i, "deepseek.com"],
  [/mistral/i, "mistral.ai"],
  [/perplexity|(^|_)pplx/i, "perplexity.ai"],
  [/replicate/i, "replicate.com"],
  [/runpod/i, "runpod.io"],
  [/firecrawl/i, "firecrawl.dev"],
  [/tavily/i, "tavily.com"],
  [/bright_?data/i, "brightdata.com"],
  [/github|(^|_)gh_/i, "github.com"],
  [/stripe/i, "stripe.com"],
  [/sendgrid/i, "sendgrid.com"],
  [/resend/i, "resend.com"],
  [/vercel/i, "vercel.com"],
  [/supabase/i, "supabase.com"],
  [/telegram/i, "telegram.org"],
  [/hugging_?face|(^|_)hf_/i, "huggingface.co"],
  [/notion/i, "notion.so"],
  [/slack/i, "slack.com"],
  [/discord/i, "discord.com"],
  [/pinecone/i, "pinecone.io"],
  [/youtube|gemini|google/i, "google.com"],
  [/(^|_)aws(_|$)/i, "aws.amazon.com"],
];

function siteForFinding(f: ScanFinding, opts: PlanOptions): { site: string } | { reason: SkipReason } {
  const blocked = UNIMPORTABLE[f.provider];
  if (blocked) return { reason: blocked };
  if (f.detector === "generic_assignment" || f.provider === "unknown") {
    if (!opts.includeGeneric) return { reason: "generic_not_requested" };
    const hint = NAME_HINTS.find(([re]) => re.test(f.key_name ?? ""));
    if (!hint) return { reason: "unknown_provider" };
    return { site: hint[1] };
  }
  try {
    return { site: normalizeSite(f.provider) };
  } catch {
    return { reason: "invalid_site" };
  }
}

/** A variable name as an account label ("YOUTUBE_API_KEY" → "youtube_api_key"), or null when it cannot be one. */
function accountFromKeyName(name: string | null): string | null {
  if (!name) return null;
  const cleaned = name.toLowerCase().replace(/[^a-z0-9_.-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 64);
  if (!cleaned) return null;
  try {
    return normalizeAccount(cleaned);
  } catch {
    return null; // e.g. the name itself looks like a secret prefix
  }
}

function purposeFor(node: string | null, file: string): string {
  const tidy = (v: string) => v.replace(/[^A-Za-z0-9._@+-]+/g, "-").replace(/^-+|-+$/g, "");
  const raw = `import ${tidy(node ?? "node") || "node"}/${tidy(file) || "file"}`.slice(0, 64).replace(/[-/ ]+$/, "");
  try {
    return normalizePurpose(raw);
  } catch {
    return "import";
  }
}

function basenameOf(path: string): string {
  return path.split(/[\\/]/).pop() ?? path;
}

/**
 * Manifest → plan. Pure and deterministic: the same manifest always yields the
 * same entries with the same identities, so a second run finds them and skips.
 *
 * One entry per distinct secret (scan fingerprint). The account is the variable
 * the secret was assigned to when the scanner saw one, otherwise
 * `imported-<first 8 of the scan fingerprint>`; a clash inside a site gets the
 * fingerprint suffix so two different keys never collapse into one entry.
 */
export function planImport(manifest: ScanManifest, opts: PlanOptions = {}): ImportPlan {
  if (!manifest || !Array.isArray(manifest.findings)) throw new EntryError("invalid_input", "Not a scan manifest");
  if (manifest.contains_secret_values !== false) {
    throw new EntryError("invalid_input", "The manifest must be a reference-only scan (contains_secret_values: false)");
  }
  const node = typeof manifest.node === "string" && manifest.node ? manifest.node : null;
  const only = opts.onlySites ? new Set(opts.onlySites.map((s) => normalizeSite(s))) : null;
  const skipped: SkippedFinding[] = [];
  const bySecret = new Map<string, { site: string; first: ScanFinding; keyName: string | null; sources: ImportSource[] }>();

  const ordered = [...manifest.findings].sort(
    (a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.detector.localeCompare(b.detector),
  );
  for (const f of ordered) {
    const skip = (reason: SkipReason) =>
      skipped.push({ path: f.path, line: f.line, detector: f.detector, provider: f.provider, key_name: f.key_name, reason });
    if (typeof f.fingerprint !== "string" || !/^[0-9a-f]{16}$/.test(f.fingerprint)) {
      skip(UNIMPORTABLE[f.provider] ?? "no_fingerprint");
      continue;
    }
    const mapped = siteForFinding(f, opts);
    if ("reason" in mapped) {
      skip(mapped.reason);
      continue;
    }
    if (only && !only.has(mapped.site)) {
      skip("provider_not_selected");
      continue;
    }
    const known = bySecret.get(f.fingerprint);
    const source = { path: f.path, line: f.line, detector: f.detector };
    if (known) {
      known.sources.push(source);
      if (!known.keyName && f.key_name) known.keyName = f.key_name;
      continue;
    }
    bySecret.set(f.fingerprint, { site: mapped.site, first: f, keyName: f.key_name, sources: [source] });
  }

  const taken = new Set<string>();
  const entries: PlannedEntry[] = [];
  for (const [fp, group] of [...bySecret.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const kind: EntryKind = "api_key";
    const fallback = `imported-${fp.slice(0, 8)}`;
    let account = accountFromKeyName(group.keyName) ?? fallback;
    if (taken.has(`${group.site}\n${account}`)) account = `${account}-${fp.slice(0, 8)}`.slice(0, 254);
    taken.add(`${group.site}\n${account}`);
    const purpose = purposeFor(node, group.first.file ?? basenameOf(group.first.path));
    entries.push({
      scan_fingerprint: fp,
      site: group.site,
      account,
      purpose,
      label: entryLabel(group.site, account, purpose),
      kind,
      sources: group.sources,
    });
  }
  entries.sort((a, b) => a.site.localeCompare(b.site) || a.account.localeCompare(b.account));
  return { node, entries, skipped };
}

export type ImportStatus =
  | "imported"
  | "would_import"
  | "exists"
  | "already_stored"
  | "source_unreadable"
  | "secret_out_of_range"
  | "secret_in_metadata"
  | "vault_unavailable"
  | "store_unavailable"
  | "store_failed";

export interface ImportOutcome {
  site: string;
  account: string;
  label: string;
  kind: EntryKind;
  status: ImportStatus;
  /** Set once the entry exists (imported, exists, already_stored). */
  entry_id?: string;
  sources: ImportSource[];
}

export interface ImportResult {
  dry_run: boolean;
  planned: number;
  counts: Record<ImportStatus, number>;
  outcomes: ImportOutcome[];
}

export interface ImportDeps extends CardsDeps {
  /**
   * Read the planned entry's secret back from one of its sources. Supplied by
   * the on-box script; returns null when no source still holds that secret.
   * The return value is a secret: it goes to the vault backend and nowhere else.
   */
  resolveSecret: (entry: PlannedEntry) => Promise<string | null>;
  /** Report what would happen without writing anything. Secrets are still read, to check they are present. */
  dryRun?: boolean;
  /** Ledger actor. Default "local:import". */
  actor?: string;
}

const STATUSES: readonly ImportStatus[] = [
  "imported",
  "would_import",
  "exists",
  "already_stored",
  "source_unreadable",
  "secret_out_of_range",
  "secret_in_metadata",
  "vault_unavailable",
  "store_unavailable",
  "store_failed",
];

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Plan → entries. Safe to run twice: an identity that already exists is
 * `exists`, and a secret already held by another entry of the same site and
 * kind is `already_stored`. One failed entry never stops the rest.
 */
export async function applyImport(plan: ImportPlan, deps: ImportDeps): Promise<ImportResult> {
  const dryRun = deps.dryRun === true;
  const actor = deps.actor ?? "local:import";
  const v = openEntryVault(deps);
  const counts = Object.fromEntries(STATUSES.map((s) => [s, 0])) as Record<ImportStatus, number>;
  const outcomes: ImportOutcome[] = [];
  const done = (p: PlannedEntry, status: ImportStatus, entryId?: string) => {
    counts[status]++;
    outcomes.push({
      site: p.site,
      account: p.account,
      label: p.label,
      kind: p.kind,
      status,
      ...(entryId ? { entry_id: entryId } : {}),
      sources: p.sources,
    });
  };

  for (const p of plan.entries) {
    let identity: EntryMetadata | null;
    try {
      identity = await v.entries.findIdentity(p.site, p.account, p.kind);
    } catch {
      // A store outage costs this entry, not the batch.
      done(p, "store_unavailable");
      continue;
    }
    if (identity) {
      done(p, "exists", identity.id);
      continue;
    }
    let secret: string | null = null;
    try {
      secret = await deps.resolveSecret(p);
    } catch {
      secret = null;
    }
    if (typeof secret !== "string" || secret.length === 0) {
      done(p, "source_unreadable");
      continue;
    }
    registerSecretForRedaction(secret);
    if (secret.length < MIN_SECRET_LENGTH || secret.length > MAX_SECRET_LENGTH) {
      done(p, "secret_out_of_range");
      continue;
    }
    if ([p.site, p.account, p.purpose].some((field) => field.includes(secret as string))) {
      done(p, "secret_in_metadata");
      continue;
    }
    const fp = secretFingerprint(secret);
    // The stored fingerprint is 32 bits: it nominates candidates, it does not prove
    // equality. Compare against the stored secret itself before calling it a duplicate.
    let candidates: EntryMetadata[];
    try {
      candidates = (await v.entries.list({ site: p.site })).filter((e) => e.kind === p.kind && e.fingerprint === fp);
    } catch {
      secret = null;
      done(p, "store_unavailable");
      continue;
    }
    let twin: EntryMetadata | null = null;
    for (const candidate of candidates) {
      let held: string;
      try {
        held = await v.readSecret(candidate);
      } catch {
        continue; // cannot prove it is the same secret: import rather than drop a credential
      }
      if (constantTimeEqual(sha256Hex(held), sha256Hex(secret))) {
        twin = candidate;
        break;
      }
    }
    if (twin) {
      secret = null;
      done(p, "already_stored", twin.id);
      continue;
    }
    if (dryRun) {
      done(p, "would_import");
      continue;
    }

    const id = `ve_${randomBytes(16).toString("hex")}`;
    const started = Date.now();
    const ledgerRow = (result: "ok" | "error", error?: string) => ({
      client_id: actor,
      capability: "vault.entry.import",
      resource: `entry:${p.site}/${p.account}`,
      credential_ref: entryRef(id),
      decision: "allow" as const,
      tier: 2 as const,
      result,
      error,
      duration_ms: Date.now() - started,
      task: "bulk import from a credential scan",
    });
    let stored: EntryMetadata | null = null;
    let failure: ImportStatus = "store_failed";
    try {
      await v.writeSecret({ id, site: p.site, account: p.account, purpose: p.purpose, kind: p.kind } as EntryMetadata, secret);
      try {
        stored = await v.entries.insert({
          id,
          site: p.site,
          account: p.account,
          purpose: p.purpose,
          label: p.label,
          kind: p.kind,
          fingerprint: fp,
          secret_length: secret.length,
          nowIso: v.nowIso,
        });
      } catch (err) {
        // The secret is in the backend without a row: take it back out.
        await v.destroySecret({ id } as EntryMetadata).catch(() => undefined);
        throw err;
      }
    } catch (err) {
      const code = err instanceof EntryError ? err.code : "store_failed";
      failure = code === "vault_unavailable" ? "vault_unavailable" : code === "entry_exists" ? "exists" : "store_failed";
      log.warn("vault_entry_import_failed", { site: p.site, error: code });
    }
    secret = null;
    if (!stored) {
      if (failure !== "exists") await v.ledger(ledgerRow("error", failure), false);
      done(p, failure);
      continue;
    }
    await v.ledger(ledgerRow("ok"), false);
    log.info("vault_entry_imported", { entry_id: stored.id, site: stored.site });
    done(p, "imported", stored.id);
  }
  return { dry_run: dryRun, planned: plan.entries.length, counts, outcomes };
}
