// library-first: echo.functions.search → no existing impl found (2026-11-14)
/**
 * Workload identities for server-side services on the owner's nodes (e.g. the
 * ECHO SDK gate calling /api/rest/tool). These can't do an interactive OAuth
 * flow, so each one gets its own long random token whose SHA-256 is listed in
 * a root-owned file. The raw token lives only in that service's own
 * file-mounted credential; this process stores and compares hashes only.
 *
 * File: path in env ECHO_VAULT_WORKLOAD_TOKENS_FILE, JSON array of
 *   { "sha256": "<64 hex>", "client_id": "workload:<name>", "name": "<display>", "scopes": ["github.read", ...] }
 * Token format presented by the service: `Authorization: Bearer ewk_<43+ url-safe chars>`.
 * Unset env or unreadable/malformed file → no workload is accepted (fail closed).
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import type { ClientIdentity } from "./contracts.ts";
import { SUPPORTED_SCOPES } from "./oauth-server.ts";
import { log } from "../log.ts";

interface WorkloadEntry {
  sha256: Buffer;
  identity: ClientIdentity;
}

const TOKEN_PATTERN = /^ewk_[A-Za-z0-9_-]{43,256}$/;
const CLIENT_ID_PATTERN = /^workload:[a-z0-9][a-z0-9._-]{0,62}$/;

let cache: { path: string; mtimeMs: number; entries: WorkloadEntry[] } | null = null;

function loadEntries(env: NodeJS.ProcessEnv): WorkloadEntry[] {
  const path = env.ECHO_VAULT_WORKLOAD_TOKENS_FILE?.trim();
  if (!path) return [];
  let mtimeMs: number;
  try {
    mtimeMs = statSync(path).mtimeMs;
  } catch {
    log.warn("workload_tokens_unreadable", {});
    return [];
  }
  if (cache && cache.path === path && cache.mtimeMs === mtimeMs) return cache.entries;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    log.warn("workload_tokens_malformed", {});
    cache = { path, mtimeMs, entries: [] };
    return [];
  }
  const supported = new Set<string>(SUPPORTED_SCOPES);
  const entries: WorkloadEntry[] = [];
  if (Array.isArray(parsed)) {
    for (const raw of parsed) {
      const r = raw as Record<string, unknown>;
      if (
        typeof r?.sha256 !== "string" ||
        !/^[0-9a-f]{64}$/.test(r.sha256) ||
        typeof r.client_id !== "string" ||
        !CLIENT_ID_PATTERN.test(r.client_id) ||
        typeof r.name !== "string" ||
        !Array.isArray(r.scopes)
      ) {
        log.warn("workload_tokens_malformed_entry", {});
        cache = { path, mtimeMs, entries: [] };
        return []; // one bad entry poisons the file: fail closed
      }
      entries.push({
        sha256: Buffer.from(r.sha256, "hex"),
        identity: {
          client_id: r.client_id,
          name: r.name.slice(0, 80),
          kind: "workload",
          scopes: (r.scopes as unknown[]).filter((s): s is string => typeof s === "string" && supported.has(s)),
        },
      });
    }
  }
  cache = { path, mtimeMs, entries };
  return entries;
}

/** Resolve `Authorization: Bearer ewk_…` to a workload identity, or null. */
export function authenticateWorkload(headers: Headers, env: NodeJS.ProcessEnv = process.env): ClientIdentity | null {
  const auth = headers.get("authorization") ?? "";
  const match = /^Bearer\s+(\S+)$/i.exec(auth.trim());
  if (!match || !TOKEN_PATTERN.test(match[1])) return null;
  const digest = createHash("sha256").update(match[1], "utf8").digest();
  let found: ClientIdentity | null = null;
  for (const entry of loadEntries(env)) {
    // Compare against every entry so timing does not reveal which one matched.
    if (timingSafeEqual(entry.sha256, digest)) found = entry.identity;
  }
  return found ? { ...found, scopes: [...found.scopes] } : null;
}

export function resetWorkloadCacheForTests(): void {
  cache = null;
}
