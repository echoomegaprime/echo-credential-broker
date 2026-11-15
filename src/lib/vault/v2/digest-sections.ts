// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Plug-in sections for the daily digest (digest.ts `extraSections`): what is
 * due for rotation, and whether the ledger still matches its newest external
 * anchor. Metadata only — labels, dates, verdicts. Never a secret.
 */
import { listRotationDue, type CardsDeps } from "./cards.ts";
import type { DigestSectionProvider } from "./digest.ts";
import { newestAnchorVerdict, type AnchorDeps } from "./ledger-anchor.ts";

const MAX_LISTED = 15;

/** Entries whose rotate_by has passed. Auto entries are rolled by the rotation runner; manual ones need a card. */
export function rotationDueSection(cards: CardsDeps = {}, now: () => number = Date.now): DigestSectionProvider {
  return async () => {
    const due = await listRotationDue(now(), cards);
    if (due.length === 0) return { title: "ROTATION DUE", lines: ["Nothing due."] };
    const lines = due.slice(0, MAX_LISTED).map((e) => {
      const since = e.rotate_by ? e.rotate_by.slice(0, 10) : "unknown";
      const err = e.last_rotation_error ? `, last error ${e.last_rotation_error}` : "";
      return `${e.label} (${e.rotation_mode}, due ${since}${err})`;
    });
    if (due.length > MAX_LISTED) lines.push(`…and ${due.length - MAX_LISTED} more`);
    return { title: `ROTATION DUE (${due.length})`, lines };
  };
}

/** The newest external anchor and whether the ledger still matches it. */
export function ledgerAnchorSection(anchor: AnchorDeps = {}): DigestSectionProvider {
  return async () => {
    const newest = await newestAnchorVerdict(anchor);
    if (!newest) return { title: "LEDGER ANCHOR", lines: ["! Never anchored: tail truncation would go unnoticed."] };
    const flag = newest.verdict === "ok" ? "" : "! ";
    return {
      title: "LEDGER ANCHOR",
      lines: [`${flag}Newest anchor seq ${newest.seq} at ${newest.anchored_at}: ${newest.verdict}`],
    };
  };
}

/** The sections the scheduled runner adds. */
export function defaultDigestSections(): DigestSectionProvider[] {
  return [rotationDueSection(), ledgerAnchorSection()];
}
