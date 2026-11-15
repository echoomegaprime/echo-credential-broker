// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Vault v2 daily audit digest — one Telegram message that tells the owner what
 * the broker did in a window (default: the previous full UTC day).
 *
 * Sources, and nothing else: ledger rows (ledger.ts), entry metadata
 * (cards.ts) and consent grants (entry-grants.ts). The digest never reads a
 * secret, a request body or an approval record.
 *
 * Secrets: ledger rows are already scrubbed on append, but this module does
 * not rely on that. Every string it copies out of a row goes through the
 * ledger's own scrubber (`redactLedgerText`) and `sanitizeDisplayText`
 * (control/bidi characters, length cap); the structured digest then passes
 * through `redactValue` and the formatted text through `redactString` before
 * either leaves this module. `task` free text is only ever shown as a short
 * clipped label on a tier-2 mutation. Credentials appear only as entry labels
 * or as counts — never as a `vault://` ref.
 *
 * Windows are half-open `[from, to)` in UTC. A row belongs to the window when
 * `from <= row.timestamp < to`.
 *
 * Idempotency: `sendDailyDigest` claims the window in a DigestStateStore
 * before it builds anything, marks it sent only after Telegram accepted the
 * message, and releases the claim when the build or the send fails — so a
 * window is never sent twice and a failed send is retried by the next run.
 * A claim left behind by a crashed runner goes stale after 10 minutes.
 *
 * Cost: one full ascending scan of the ledger per digest (needed to know
 * whether a client was ever seen before the window) plus `verifyLedger()`.
 */
import type { Sql } from "../../db.ts";
import { log } from "../log.ts";
import { redactString, redactValue } from "../redaction.ts";
import { approverTelegramId, sanitizeDisplayText } from "./approvals.ts";
import { listEntries, type CardsDeps } from "./cards.ts";
import type { LedgerEntry, LedgerResult } from "./contracts.ts";
import { getDefaultEntryGrantStore, type EntryGrantStore } from "./entry-grants.ts";
import { redactLedgerText, scanLedger, verifyLedger, type LedgerVerifyResult } from "./ledger.ts";
import { callBotApi, TelegramApiError } from "./telegram.ts";

export const DIGEST_DENIAL_BURST_ENV = "ECHO_VAULT_DIGEST_DENIAL_BURST";
export const DEFAULT_DENIAL_BURST = 10;
/** Telegram sendMessage limit (see telegram.ts). */
export const DIGEST_MAX_TEXT = 4096;
export const DIGEST_TRUNCATED_TAIL = "…truncated";

const DAY_MS = 86_400_000;
const MAX_WINDOW_MS = 366 * DAY_MS;
const SCAN_BATCH = 1000;
/** A `committing` row this fresh may simply still be running; it is not reported as orphaned yet. */
const ORPHAN_GRACE_MS = 120_000;
const CLAIM_STALE_MS = 10 * 60_000;
const ENTRY_REF_RE = /^vault:\/\/entry\/ve_[0-9a-f]{32}$/;

const MAX_CLIENTS = 100;
const MAX_ITEMS = 25;
const MAX_REASONS = 5;
const MAX_EXTRA_SECTIONS = 10;
const MAX_EXTRA_LINES = 20;
const TASK_LABEL_MAX = 48;

const RESULTS: readonly LedgerResult[] = ["ok", "error", "denied", "pending_approval", "committing"];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Half-open `[from, to)`, both canonical UTC ISO strings (`YYYY-MM-DDTHH:MM:SS.sssZ`). */
export interface DigestWindow {
  from: string;
  to: string;
}

export interface DigestSection {
  title: string;
  lines: string[];
}

/** Plug-in section (rotation-due, ledger anchor, …), rendered after the built-in sections. */
export type DigestSectionProvider = (window: DigestWindow, deps: DigestDeps) => Promise<DigestSection>;

export interface DigestLedgerSource {
  /** Entries with seq > afterSeq, ascending, at most `limit`. */
  scan(afterSeq: number, limit?: number): Promise<LedgerEntry[]>;
  verify(): Promise<LedgerVerifyResult>;
}

/** Everything is optional: production passes nothing. Tests inject a Memory ledger, stores and a fake fetch. */
export interface DigestDeps {
  /** Default: the process-wide ledger (SQL, hash-chained). A `Ledger` instance fits. */
  ledger?: DigestLedgerSource;
  /** Entry metadata source (listEntries). */
  cards?: CardsDeps;
  grants?: EntryGrantStore;
  /** Which windows were already sent. Default: SqlDigestStateStore. */
  state?: DigestStateStore;
  /** Telegram transport. Default: globalThis.fetch. */
  fetch?: typeof fetch;
  env?: NodeJS.ProcessEnv;
  now?: () => number;
  extraSections?: DigestSectionProvider[];
}

export interface DigestClientStats {
  client_id: string;
  actions: number;
  denied: number;
  errors: number;
  /** Distinct credential entries this client used in the window. */
  entries_used: number;
}

export interface DigestRowRef {
  seq: number;
  timestamp: string;
  client_id: string;
  capability: string;
  resource: string;
}

export type DigestChain = LedgerVerifyResult | { ok: false; reason: "verify_unavailable" };

export interface Digest {
  window: DigestWindow;
  generated_at: string;
  total_actions: number;
  by_result: Record<LedgerResult, number>;
  /** Most active first, at most 100; `clients_omitted` counts the rest. */
  clients: DigestClientStats[];
  clients_omitted: number;
  /** As seen in the ledger: prompts created, approvals a request actually ran under, and refused retries. */
  approvals: { requested: number; granted: number; denied: number; expired: number };
  tier2_mutations: { count: number; items: Array<DigestRowRef & { label?: string }> };
  top_denied_reasons: Array<{ reason: string; count: number }>;
  /** Entries currently `needs_reentry` whose flag landed in the window. Labels only. */
  needs_reentry: Array<{ label: string; flagged_at: string }>;
  /** `created`: granted in the window and still on record. `active`: usable right now. */
  grants: { created: number; active: number };
  anomalies: {
    new_clients: Array<{ client_id: string; first_seen: string }>;
    denial_bursts: Array<{ client_id: string; denied: number; threshold: number }>;
    /** An approved mutation was authorized (`committing`) and no outcome row followed. */
    orphan_committing: Array<DigestRowRef & { approval_ref: string }>;
    ledger_unavailable: { count: number; items: DigestRowRef[] };
  };
  /** Broken chain + every anomaly above. */
  anomaly_count: number;
  chain: DigestChain;
  extra: DigestSection[];
  /** Metadata sources that could not be read ("entries", "grants"); their sections are empty, not zero. */
  unavailable: string[];
}

export class DigestError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "DigestError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------

const DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;
/** A time needs an explicit zone: a bare local time would silently shift the window. */
const DATE_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/;

function parseInstant(value: unknown, field: string): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || !(DATE_ONLY_RE.test(value) || DATE_TIME_RE.test(value))) {
    throw new DigestError("invalid_window", `${field}: use YYYY-MM-DD (UTC) or an ISO time with Z or an offset`);
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new DigestError("invalid_window", `${field}: not a real date`);
  return ms;
}

/**
 * Neither bound → the previous full UTC day. One bound → the 24 h starting at
 * `from` / ending at `to`. Both → exactly that, at most 366 days.
 */
export function resolveDigestWindow(input: { from?: string; to?: string } = {}, nowMs: number = Date.now()): DigestWindow {
  const givenFrom = parseInstant(input.from, "from");
  const givenTo = parseInstant(input.to, "to");
  const previousMidnight = Math.floor(nowMs / DAY_MS) * DAY_MS;
  const to = givenTo ?? (givenFrom !== undefined ? givenFrom + DAY_MS : previousMidnight);
  const from = givenFrom ?? to - DAY_MS;
  if (!(from < to)) throw new DigestError("invalid_window", "from must be before to");
  if (to - from > MAX_WINDOW_MS) throw new DigestError("invalid_window", "window is longer than 366 days");
  return { from: new Date(from).toISOString(), to: new Date(to).toISOString() };
}

function canonicalWindow(window: DigestWindow): DigestWindow {
  return resolveDigestWindow({ from: window?.from, to: window?.to });
}

export function denialBurstThreshold(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env[DIGEST_DENIAL_BURST_ENV]?.trim();
  if (!raw || !/^[0-9]{1,9}$/.test(raw)) return DEFAULT_DENIAL_BURST;
  const n = Number(raw);
  return n >= 1 ? n : DEFAULT_DENIAL_BURST;
}

// ---------------------------------------------------------------------------
// Sanitizing
// ---------------------------------------------------------------------------

/** Scrub like the ledger does, strip control/bidi characters, collapse whitespace, clip. */
function safe(value: unknown, max: number, entropy: boolean): string {
  return sanitizeDisplayText(redactLedgerText(String(value ?? ""), { entropy }), max);
}

function rowRef(row: LedgerEntry): DigestRowRef {
  return {
    seq: row.seq,
    timestamp: safe(row.timestamp, 30, false),
    client_id: safe(row.client_id, 80, false),
    capability: safe(row.capability, 80, false),
    resource: safe(row.resource, 120, true),
  };
}

function inWindow(iso: unknown, fromMs: number, toMs: number): boolean {
  const ms = typeof iso === "string" ? Date.parse(iso) : NaN;
  return Number.isFinite(ms) && ms >= fromMs && ms < toMs;
}

// ---------------------------------------------------------------------------
// buildDigest
// ---------------------------------------------------------------------------

interface ClientAcc {
  actions: number;
  denied: number;
  errors: number;
  entries: Set<string>;
  firstSeen: string;
}

async function runExtraSections(window: DigestWindow, deps: DigestDeps): Promise<DigestSection[]> {
  const out: DigestSection[] = [];
  for (const provider of (deps.extraSections ?? []).slice(0, MAX_EXTRA_SECTIONS)) {
    try {
      const section = await provider({ ...window }, deps);
      const lines = Array.isArray(section?.lines) ? section.lines : [];
      out.push({
        title: safe(section?.title, 60, true) || "Section",
        lines: lines
          .slice(0, MAX_EXTRA_LINES)
          .map((line) => safe(line, 200, true))
          .filter((line) => line.length > 0),
      });
    } catch {
      // A plug-in must never cost the owner the digest; its error text is not trusted either.
      log.warn("vault_digest_section_failed", { index: out.length });
      out.push({ title: "Section unavailable", lines: ["This section could not be built."] });
    }
  }
  return out;
}

/** Build the structured digest for `[from, to)`. Throws only when the ledger cannot be read. */
export async function buildDigest(window: DigestWindow, deps: DigestDeps = {}): Promise<Digest> {
  const win = canonicalWindow(window);
  const fromMs = Date.parse(win.from);
  const toMs = Date.parse(win.to);
  const env = deps.env ?? process.env;
  const nowMs = (deps.now ?? Date.now)();
  const scan = deps.ledger ? (after: number, limit: number) => deps.ledger!.scan(after, limit) : scanLedger;
  const verify = deps.ledger ? () => deps.ledger!.verify() : verifyLedger;

  const seenBefore = new Set<string>();
  const clients = new Map<string, ClientAcc>();
  const byResult = Object.fromEntries(RESULTS.map((r) => [r, 0])) as Record<LedgerResult, number>;
  const requested = new Set<string>();
  const granted = new Set<string>();
  const approvalDenied = new Set<string>();
  const approvalExpired = new Set<string>();
  const tier2: LedgerEntry[] = [];
  const deniedReasons = new Map<string, number>();
  const committing: LedgerEntry[] = [];
  const unavailableRows: LedgerEntry[] = [];
  /** Highest seq of an outcome (ok/error) row, per approval and per (client, capability, resource). */
  const outcomeSeq = new Map<string, number>();
  const outcomeKey = (row: LedgerEntry): string =>
    row.approval_id ? `a:${row.approval_id}` : `r:${row.client_id}\u0000${row.capability}\u0000${row.resource}`;
  let total = 0;

  let after = 0;
  for (;;) {
    const batch = await scan(after, SCAN_BATCH);
    if (batch.length === 0) break;
    for (const row of batch) {
      const ts = Date.parse(row.timestamp);
      if (!Number.isFinite(ts)) continue;
      if (ts < fromMs) {
        seenBefore.add(row.client_id);
        continue;
      }
      if (row.result === "ok" || row.result === "error") {
        const key = outcomeKey(row);
        if ((outcomeSeq.get(key) ?? 0) < row.seq) outcomeSeq.set(key, row.seq);
      }
      if (ts >= toMs) continue;

      total += 1;
      if (row.result in byResult) byResult[row.result] += 1;
      let acc = clients.get(row.client_id);
      if (!acc) {
        acc = { actions: 0, denied: 0, errors: 0, entries: new Set(), firstSeen: row.timestamp };
        clients.set(row.client_id, acc);
      }
      acc.actions += 1;
      if (row.result === "denied") acc.denied += 1;
      if (row.result === "error") acc.errors += 1;
      if (row.credential_ref && ENTRY_REF_RE.test(row.credential_ref)) acc.entries.add(row.credential_ref);

      if (row.approval_id) {
        if (row.result === "pending_approval" && !row.error) requested.add(row.approval_id);
        if (row.decision === "escalate" && row.result !== "pending_approval" && row.result !== "denied") {
          granted.add(row.approval_id);
        }
        if (row.error === "approval_denied") approvalDenied.add(row.approval_id);
        if (row.error === "approval_expired") approvalExpired.add(row.approval_id);
      }
      if (row.tier === 2 && row.result === "ok") tier2.push(row);
      if (row.result === "denied") {
        const reason = safe(row.error || "(no reason recorded)", 80, true) || "(no reason recorded)";
        deniedReasons.set(reason, (deniedReasons.get(reason) ?? 0) + 1);
      }
      if (row.result === "committing") committing.push(row);
      if (typeof row.error === "string" && row.error.includes("ledger_unavailable")) unavailableRows.push(row);
    }
    const last = batch[batch.length - 1].seq;
    if (!(last > after)) break; // a source that does not advance must not loop forever
    after = last;
  }

  const threshold = denialBurstThreshold(env);
  const sortedClients = [...clients.entries()].sort((a, b) => b[1].actions - a[1].actions || (a[0] < b[0] ? -1 : 1));
  const orphans = committing.filter(
    (row) => (outcomeSeq.get(outcomeKey(row)) ?? 0) <= row.seq && Date.parse(row.timestamp) <= nowMs - ORPHAN_GRACE_MS,
  );

  let chain: DigestChain;
  try {
    chain = await verify();
  } catch {
    log.error("vault_digest_verify_failed", {});
    chain = { ok: false, reason: "verify_unavailable" };
  }

  const unavailable: string[] = [];
  let needsReentry: Digest["needs_reentry"] = [];
  try {
    needsReentry = (await listEntries({}, deps.cards))
      .filter((e) => e.status === "needs_reentry" && inWindow(e.updated_at, fromMs, toMs))
      .map((e) => ({ label: safe(e.label, 120, true), flagged_at: safe(e.updated_at, 30, false) }));
  } catch {
    log.warn("vault_digest_source_unavailable", { source: "entries" });
    unavailable.push("entries");
  }
  const grants = { created: 0, active: 0 };
  try {
    for (const g of await (deps.grants ?? getDefaultEntryGrantStore()).list()) {
      if (inWindow(g.granted_at, fromMs, toMs)) grants.created += 1;
      const exp = Date.parse(g.expires_at);
      if (Number.isFinite(exp) && exp > nowMs && (g.uses_remaining === null || g.uses_remaining > 0)) grants.active += 1;
    }
  } catch {
    log.warn("vault_digest_source_unavailable", { source: "grants" });
    unavailable.push("grants");
  }

  const newClients = sortedClients
    .filter(([id]) => !seenBefore.has(id))
    .map(([id, acc]) => ({ client_id: safe(id, 80, false), first_seen: safe(acc.firstSeen, 30, false) }));
  const bursts = sortedClients
    .filter(([, acc]) => acc.denied >= threshold)
    .map(([id, acc]) => ({ client_id: safe(id, 80, false), denied: acc.denied, threshold }));

  const digest: Digest = {
    window: win,
    generated_at: new Date(nowMs).toISOString(),
    total_actions: total,
    by_result: byResult,
    clients: sortedClients.slice(0, MAX_CLIENTS).map(([id, acc]) => ({
      client_id: safe(id, 80, false),
      actions: acc.actions,
      denied: acc.denied,
      errors: acc.errors,
      entries_used: acc.entries.size,
    })),
    clients_omitted: Math.max(0, sortedClients.length - MAX_CLIENTS),
    approvals: {
      requested: requested.size,
      granted: granted.size,
      denied: approvalDenied.size,
      expired: approvalExpired.size,
    },
    tier2_mutations: {
      count: tier2.length,
      items: tier2.slice(0, MAX_ITEMS).map((row) => {
        const label = row.task ? safe(row.task, TASK_LABEL_MAX, true) : "";
        return label ? { ...rowRef(row), label } : rowRef(row);
      }),
    },
    top_denied_reasons: [...deniedReasons.entries()]
      .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
      .slice(0, MAX_REASONS)
      .map(([reason, count]) => ({ reason, count })),
    needs_reentry: needsReentry.slice(0, MAX_ITEMS),
    grants,
    anomalies: {
      new_clients: newClients.slice(0, MAX_ITEMS),
      denial_bursts: bursts.slice(0, MAX_ITEMS),
      orphan_committing: orphans.slice(0, MAX_ITEMS).map((row) => ({
        ...rowRef(row),
        // A short prefix is enough to find the approval; the full id is not repeated here.
        approval_ref: safe((row.approval_id ?? "").slice(0, 8), 8, false) || "none",
      })),
      ledger_unavailable: { count: unavailableRows.length, items: unavailableRows.slice(0, MAX_ITEMS).map(rowRef) },
    },
    anomaly_count: (chain.ok ? 0 : 1) + newClients.length + bursts.length + orphans.length + unavailableRows.length,
    chain,
    extra: await runExtraSections(win, deps),
    unavailable,
  };
  // Last line of defence: nothing secret-shaped leaves this module, whatever a store handed us.
  return redactValue(digest);
}

// ---------------------------------------------------------------------------
// formatDigest
// ---------------------------------------------------------------------------

function windowLabel(window: DigestWindow): string {
  const from = safe(window.from, 30, false);
  const to = safe(window.to, 30, false);
  const fromMs = Date.parse(from);
  if (from.endsWith("T00:00:00.000Z") && Date.parse(to) - fromMs === DAY_MS) return `${from.slice(0, 10)} (UTC day)`;
  return `${from} to ${to} (UTC)`;
}

function when(iso: string): string {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(iso) ? `${iso.slice(5, 10)} ${iso.slice(11, 16)}` : "?";
}

function chainLine(chain: DigestChain): string {
  if (chain.ok) return `Ledger chain: OK (${chain.count} rows verified)`;
  if ("broken_at_seq" in chain) return `Ledger chain: BROKEN at seq ${chain.broken_at_seq} (${safe(chain.reason, 80, true)})`;
  return "Ledger chain: NOT VERIFIED (verification unavailable)";
}

function capList(lines: string[], max: number, noun: string): string[] {
  return lines.length > max ? [...lines.slice(0, max), `… and ${lines.length - max} more ${noun}`] : lines;
}

function plural(n: number, one: string, many: string = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

function capText(text: string): string {
  if (text.length <= DIGEST_MAX_TEXT) return text;
  const tail = `\n${DIGEST_TRUNCATED_TAIL}`;
  const budget = DIGEST_MAX_TEXT - tail.length;
  let kept = "";
  for (const line of text.split("\n")) {
    const next = kept ? `${kept}\n${line}` : line;
    if (next.length > budget) break;
    kept = next;
  }
  return `${(kept || text.slice(0, budget)).trimEnd()}${tail}`;
}

/**
 * Plain text for Telegram (no parse_mode): most important first — chain
 * verdict and anomalies, then totals, clients and the detail sections. Control
 * characters stripped, redacted, hard-capped at 4096 characters.
 */
export function formatDigest(digest: Digest): string {
  const d = digest;
  const a = d.anomalies;
  const blocks: string[][] = [["ECHO Vault daily digest", `Window: ${windowLabel(d.window)}`, chainLine(d.chain)]];

  const anomalies: string[] = [];
  if (!d.chain.ok) {
    anomalies.push(
      "broken_at_seq" in d.chain
        ? `! LEDGER CHAIN BROKEN at seq ${d.chain.broken_at_seq}: the audit trail was altered or damaged`
        : "! Ledger chain could not be verified",
    );
  }
  anomalies.push(
    ...capList(
      a.orphan_committing.map(
        (o) => `! Authorized mutation never reported: ${o.capability} on ${o.resource} by ${o.client_id} (seq ${o.seq}, approval ${o.approval_ref})`,
      ),
      5,
      "unreported mutations",
    ),
  );
  if (a.ledger_unavailable.count > 0) {
    const first = a.ledger_unavailable.items[0];
    anomalies.push(
      `! Ledger unavailable: ${plural(a.ledger_unavailable.count, "event")}${first ? `, first at seq ${first.seq} (${first.client_id}, ${first.capability})` : ""}`,
    );
  }
  anomalies.push(
    ...capList(
      a.denial_bursts.map((b) => `! Denial burst: ${b.client_id}, ${plural(b.denied, "denial")} (threshold ${b.threshold})`),
      5,
      "denial bursts",
    ),
  );
  anomalies.push(
    ...capList(
      a.new_clients.map((c) => `! New client: ${c.client_id} (first seen ${when(c.first_seen)})`),
      5,
      "new clients",
    ),
  );
  if (anomalies.length > 0) blocks.push([`ANOMALIES (${d.anomaly_count})`, ...anomalies]);

  if (d.total_actions === 0) {
    blocks[0].push("No activity in this window.");
  } else {
    const r = d.by_result;
    blocks.push([
      "TOTALS",
      `Actions: ${d.total_actions} (ok ${r.ok}, error ${r.error}, denied ${r.denied}, pending approval ${r.pending_approval}, committing ${r.committing})`,
      `Approvals: requested ${d.approvals.requested}, granted ${d.approvals.granted}, denied ${d.approvals.denied}, expired ${d.approvals.expired}`,
    ]);
    const clientLines = d.clients.map(
      (c) => `${c.client_id}: ${plural(c.actions, "action")}, ${c.denied} denied, ${plural(c.errors, "error")}, ${plural(c.entries_used, "entry", "entries")}`,
    );
    const hidden = Math.max(0, clientLines.length - 12) + d.clients_omitted;
    blocks.push([
      `CLIENTS (${d.clients.length + d.clients_omitted})`,
      ...clientLines.slice(0, 12),
      ...(hidden > 0 ? [`… and ${hidden} more clients`] : []),
    ]);
    if (d.tier2_mutations.count > 0) {
      const lines = d.tier2_mutations.items.map(
        (m) => `${when(m.timestamp)} ${m.client_id}: ${m.capability} on ${m.resource}${m.label ? ` ("${m.label}")` : ""}`,
      );
      const more = d.tier2_mutations.count - Math.min(lines.length, 10);
      blocks.push([`TIER-2 MUTATIONS (${d.tier2_mutations.count})`, ...lines.slice(0, 10), ...(more > 0 ? [`… and ${more} more`] : [])]);
    }
    if (d.top_denied_reasons.length > 0) {
      blocks.push(["TOP DENIED REASONS", ...d.top_denied_reasons.map((x) => `${x.count}x ${x.reason}`)]);
    }
  }

  if (d.needs_reentry.length > 0) {
    blocks.push([`NEEDS RE-ENTRY (${d.needs_reentry.length})`, ...capList(d.needs_reentry.map((e) => e.label), 10, "entries")]);
  }
  if (d.total_actions > 0 || d.grants.created > 0) {
    blocks.push(["CONSENT GRANTS", `Created ${d.grants.created}, active now ${d.grants.active}`]);
  }
  if (d.unavailable.length > 0) {
    blocks.push([`Not included (source unavailable): ${d.unavailable.map((s) => safe(s, 20, false)).join(", ")}`]);
  }
  for (const section of d.extra) {
    blocks.push([safe(section.title, 60, true).toUpperCase(), ...section.lines.map((line) => safe(line, 200, true))]);
  }

  // sanitizeDisplayText already removed control characters from every field; this
  // pass covers the fixed text and anything a caller put in a hand-built digest.
  const text = blocks
    .map((lines) => lines.map((line) => sanitizeDisplayText(line, 400)).join("\n"))
    .join("\n\n");
  return capText(redactString(text));
}

// ---------------------------------------------------------------------------
// Sent-window state
// ---------------------------------------------------------------------------

export type DigestClaim = "claimed" | "already_sent" | "in_progress";

export interface DigestStateRecord extends DigestWindow {
  status: "sending" | "sent";
  claimed_at: string;
  sent_at: string | null;
  message_id: number | null;
}

export interface DigestStateStore {
  /**
   * Atomically claim the window for sending. "claimed" when no row existed or
   * the existing claim is older than `staleBeforeMs` (a crashed runner).
   */
  claim(window: DigestWindow, nowMs: number, staleBeforeMs: number): Promise<DigestClaim>;
  markSent(window: DigestWindow, messageId: number, nowMs: number): Promise<void>;
  /** Drop an unsent claim so the window can be retried. Never removes a sent row. */
  release(window: DigestWindow): Promise<void>;
  /** The most recently sent window, or null. */
  lastSent(): Promise<DigestStateRecord | null>;
}

/** In-memory store (tests / single process). */
export class MemoryDigestStateStore implements DigestStateStore {
  private readonly rows = new Map<string, DigestStateRecord>();

  private key(window: DigestWindow): string {
    return `${window.from}|${window.to}`;
  }

  async claim(window: DigestWindow, nowMs: number, staleBeforeMs: number): Promise<DigestClaim> {
    const existing = this.rows.get(this.key(window));
    if (existing?.status === "sent") return "already_sent";
    if (existing && Date.parse(existing.claimed_at) >= staleBeforeMs) return "in_progress";
    this.rows.set(this.key(window), {
      from: window.from,
      to: window.to,
      status: "sending",
      claimed_at: new Date(nowMs).toISOString(),
      sent_at: null,
      message_id: null,
    });
    return "claimed";
  }

  async markSent(window: DigestWindow, messageId: number, nowMs: number): Promise<void> {
    const row = this.rows.get(this.key(window));
    if (!row) throw new Error("digest_state_missing_claim");
    row.status = "sent";
    row.sent_at = new Date(nowMs).toISOString();
    row.message_id = messageId;
  }

  async release(window: DigestWindow): Promise<void> {
    if (this.rows.get(this.key(window))?.status === "sending") this.rows.delete(this.key(window));
  }

  async lastSent(): Promise<DigestStateRecord | null> {
    const sent = [...this.rows.values()].filter((r) => r.status === "sent").sort((a, b) => (a.to < b.to ? 1 : -1));
    return sent[0] ? { ...sent[0] } : null;
  }
}

type SqlQuery = Pick<Sql, "query">;

function toIsoOrNull(v: unknown): string | null {
  return v == null ? null : v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString();
}

/** Postgres/PGLite store over `vault_digest_state` (migrations/0009_vault_digest_state.sql). */
export class SqlDigestStateStore implements DigestStateStore {
  private readonly getSql: () => Promise<SqlQuery>;

  constructor(getSql?: () => Promise<SqlQuery>) {
    this.getSql =
      getSql ??
      (async () => {
        const db = await import("../../db.ts");
        return db.getSql();
      });
  }

  async claim(window: DigestWindow, nowMs: number, staleBeforeMs: number): Promise<DigestClaim> {
    const sql = await this.getSql();
    // One statement: insert the claim, or take over a stale unsent one. A sent
    // row or a fresh claim matches neither branch and returns nothing.
    const claimed = await sql.query(
      `insert into vault_digest_state (window_from, window_to, status, claimed_at)
       values ($1::text, $2::text, 'sending', $3::timestamptz)
       on conflict (window_from, window_to) do update set claimed_at = excluded.claimed_at
         where vault_digest_state.status = 'sending' and vault_digest_state.claimed_at < $4::timestamptz
       returning window_from`,
      [window.from, window.to, new Date(nowMs).toISOString(), new Date(staleBeforeMs).toISOString()],
    );
    if (claimed.length === 1) return "claimed";
    const rows = await sql.query<{ status: unknown }>(
      "select status from vault_digest_state where window_from = $1::text and window_to = $2::text",
      [window.from, window.to],
    );
    return rows[0]?.status === "sent" ? "already_sent" : "in_progress";
  }

  async markSent(window: DigestWindow, messageId: number, nowMs: number): Promise<void> {
    const sql = await this.getSql();
    const rows = await sql.query(
      `update vault_digest_state set status = 'sent', sent_at = $3::timestamptz, message_id = $4::bigint
        where window_from = $1::text and window_to = $2::text
        returning window_from`,
      [window.from, window.to, new Date(nowMs).toISOString(), messageId],
    );
    if (rows.length !== 1) throw new Error("digest_state_missing_claim");
  }

  async release(window: DigestWindow): Promise<void> {
    const sql = await this.getSql();
    await sql.query(
      "delete from vault_digest_state where window_from = $1::text and window_to = $2::text and status = 'sending'",
      [window.from, window.to],
    );
  }

  async lastSent(): Promise<DigestStateRecord | null> {
    const sql = await this.getSql();
    const rows = await sql.query<Record<string, unknown>>(
      `select window_from, window_to, status, claimed_at, sent_at, message_id from vault_digest_state
        where status = 'sent' order by window_to desc, window_from desc limit 1`,
    );
    const r = rows[0];
    if (!r) return null;
    return {
      from: String(r.window_from),
      to: String(r.window_to),
      status: "sent",
      claimed_at: toIsoOrNull(r.claimed_at) ?? "",
      sent_at: toIsoOrNull(r.sent_at),
      message_id: r.message_id == null ? null : Number(r.message_id),
    };
  }
}

let defaultStateStore: DigestStateStore | null = null;

export function getDefaultDigestStateStore(): DigestStateStore {
  defaultStateStore ??= new SqlDigestStateStore();
  return defaultStateStore;
}

/** Wiring/test hook. Pass null to restore the SQL default. */
export function setDefaultDigestStateStore(store: DigestStateStore | null): void {
  defaultStateStore = store;
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

export type DigestSendFailure =
  | "already_sent"
  | "in_progress"
  | "invalid_window"
  | "state_unavailable"
  | "build_failed"
  | "telegram_failed";

export type DigestSendResult =
  | { sent: true; message_id: number; window: DigestWindow; recorded: boolean }
  | { sent: false; reason: DigestSendFailure; window?: DigestWindow; detail?: string };

async function deliver(window: DigestWindow, deps: DigestDeps, prebuilt?: Digest): Promise<DigestSendResult> {
  const state = deps.state ?? getDefaultDigestStateStore();
  const env = deps.env ?? process.env;
  const now = deps.now ?? Date.now;

  let claim: DigestClaim;
  try {
    claim = await state.claim(window, now(), now() - CLAIM_STALE_MS);
  } catch {
    // Without the state table a retry could not be told from a first send: refuse rather than risk a duplicate.
    log.error("vault_digest_state_unavailable", { from: window.from, to: window.to });
    return { sent: false, reason: "state_unavailable", window };
  }
  if (claim !== "claimed") return { sent: false, reason: claim, window };

  const release = async (): Promise<void> => {
    await state.release(window).catch(() => log.error("vault_digest_release_failed", { from: window.from, to: window.to }));
  };

  let text: string;
  try {
    text = formatDigest(prebuilt ?? (await buildDigest(window, deps)));
  } catch {
    await release();
    log.error("vault_digest_build_failed", { from: window.from, to: window.to });
    return { sent: false, reason: "build_failed", window };
  }

  let messageId: number;
  try {
    const chatId = approverTelegramId(env);
    if (!chatId) throw new TelegramApiError("sendMessage", "telegram_approver_missing");
    const result = await callBotApi<{ message_id?: unknown }>(
      "sendMessage",
      { chat_id: chatId, text, link_preview_options: { is_disabled: true } },
      { fetch: deps.fetch, env },
    );
    messageId = typeof result?.message_id === "number" ? result.message_id : 0;
  } catch (err) {
    // Not sent: drop the claim so the next run retries this window.
    await release();
    const detail = err instanceof TelegramApiError ? err.code : "telegram_error";
    log.warn("vault_digest_send_failed", { from: window.from, to: window.to, code: detail });
    return { sent: false, reason: "telegram_failed", window, detail };
  }

  let recorded = true;
  try {
    await state.markSent(window, messageId, now());
  } catch {
    // The message is out. The claim stays in place (it is never released here), so
    // a rerun within the stale period reports in_progress instead of re-sending.
    recorded = false;
    log.error("vault_digest_mark_sent_failed", { from: window.from, to: window.to });
  }
  log.info("vault_digest_sent", { from: window.from, to: window.to, message_id: messageId, recorded });
  return { sent: true, message_id: messageId, window, recorded };
}

/**
 * Build and send the digest for the previous full UTC day (or the explicit
 * `from`/`to`). Never throws. Sends a window at most once; a Telegram failure
 * leaves the window unsent.
 */
export async function sendDailyDigest(deps: DigestDeps = {}, opts: { from?: string; to?: string } = {}): Promise<DigestSendResult> {
  let window: DigestWindow;
  try {
    window = resolveDigestWindow(opts, (deps.now ?? Date.now)());
  } catch (err) {
    return { sent: false, reason: "invalid_window", detail: err instanceof DigestError ? err.message : undefined };
  }
  return deliver(window, deps);
}

/** Send a digest that was already built (admin_digest_now with send=true). Same once-per-window rule. */
export async function sendDigest(digest: Digest, deps: DigestDeps = {}): Promise<DigestSendResult> {
  let window: DigestWindow;
  try {
    window = canonicalWindow(digest.window);
  } catch {
    return { sent: false, reason: "invalid_window" };
  }
  return deliver(window, deps, digest);
}
