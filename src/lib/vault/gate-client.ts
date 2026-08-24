/**
 * Thin client for the ECHO SDK gate's `echo.vault.*` capabilities — the
 * canonical Master Vault ("Vault A"), PyNaCl SecretBox at rest, on FORGE.
 *
 * This is the ONLY place this repo talks to the gate. Shapes below are
 * verified live against the gate (2026-08-24), not guessed:
 *
 *   locate({service}) -> { status: EXACT|AMBIGUOUS|NOT_FOUND, candidates[],
 *                           get_with?: {service, username}, did_you_mean?[] }
 *   get({service, username}) -> { secret, key_fingerprint, updated_at, ... }
 *   put({service, username, secret, note}) -> { stored, version, key_fingerprint }
 *
 * Doctrine: LOCATE, THEN GET — never hand-guess a (service, username) pair.
 * `locate` returns coordinates, never a secret, and never picks for you.
 */

const GATE_URL = (process.env.ECHO_SDK_GATE_URL || "https://forge.echo-op.com").replace(/\/+$/, "");
const API_KEY = process.env.ECHO_SDK_API_KEY || "";
const TIMEOUT_MS = 10_000;

export class GateUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GateUnavailableError";
  }
}

export interface GateEnvelope<T> {
  run_id: string;
  status: "ok" | "client_error" | "server_error" | string;
  result: { status_code: number; body: T };
}

/**
 * Invoke one `echo.vault.*` capability through the gate. Fails CLOSED: any
 * network error, timeout, non-2xx, or malformed envelope throws — callers
 * must never treat a failed gate call as "credential absent" (that would
 * silently make a live outage look like a missing credential).
 */
async function invoke<T>(capability: string, params: Record<string, unknown>, bypassReason: string): Promise<T> {
  if (!API_KEY) {
    throw new GateUnavailableError("ECHO_SDK_API_KEY is not configured — refusing to call the vault gate without auth.");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${GATE_URL}/sdk/invoke`, {
      method: "POST",
      headers: { "X-Echo-API-Key": API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({
        envelope_version: 1,
        capability,
        params,
        context: { bypass_reason: bypassReason },
      }),
      signal: controller.signal,
    });
    const envelope = (await res.json()) as GateEnvelope<T>;
    if (!res.ok || envelope.status !== "ok" || envelope.result?.status_code < 200 || envelope.result?.status_code >= 300) {
      throw new GateUnavailableError(
        `vault gate call failed: ${capability} -> http ${res.status} / envelope ${envelope.status} / body ${envelope.result?.status_code}`,
      );
    }
    return envelope.result.body;
  } catch (error) {
    if (error instanceof GateUnavailableError) throw error;
    throw new GateUnavailableError(`vault gate unreachable calling ${capability}: ${(error as Error).message}`);
  } finally {
    clearTimeout(timer);
  }
}

export interface LocateCandidate {
  actual_service: string;
  username: string;
  key_shape: string;
}

export interface LocateResult {
  status: "EXACT" | "AMBIGUOUS" | "NOT_FOUND";
  service: string;
  count?: number;
  candidates: LocateCandidate[];
  get_with?: { service: string; username: string };
  did_you_mean?: string[];
  hint?: string;
}

export async function vaultLocate(service: string, bypassReason: string): Promise<LocateResult> {
  return invoke<LocateResult>("echo.vault.locate", { service }, bypassReason);
}

export interface GetResult {
  service: string;
  username: string;
  secret: string;
  key_fingerprint: string;
  metadata?: Record<string, unknown>;
  tags?: string[];
  version?: number;
  updated_at?: string;
  created_at?: string;
}

export async function vaultGet(service: string, username: string, bypassReason: string): Promise<GetResult> {
  return invoke<GetResult>("echo.vault.get", { service, username }, bypassReason);
}

export interface PutResult {
  stored: boolean;
  service: string;
  version: number;
  key_fingerprint: string;
}

export async function vaultPut(
  service: string,
  username: string,
  secret: string,
  note: string,
  bypassReason: string,
): Promise<PutResult> {
  return invoke<PutResult>("echo.vault.put", { service, username, secret, note }, bypassReason);
}

/**
 * Doctrine-documented canonical vault names that a bare provider-id locate
 * query does NOT surface (verified live 2026-08-24: `locate("github")`
 * returns 7 legacy-clutter candidates and `GitHub_echoomegaprime_PAT` is not
 * among them — the vault indexes exact historical names, not fuzzy matches).
 * This is NOT a guess: it is the exact name doctrine names as "THE ONLY
 * GITHUB ACCOUNT FOR NEW WORK". Keyed by `${provider}/${account}`.
 */
const CANONICAL_LOCATE_QUERY: Record<string, string> = {
  "github/echoomegaprime": "GitHub_echoomegaprime_PAT",
};

/**
 * Resolve a (locate-query, account-hint) pair to ONE definite (service,
 * username) coordinate against the canonical vault. Never guesses across
 * AMBIGUOUS candidates without a matching hint — that is exactly the bug
 * doctrine already hit once (an un-hinted `get("google")` silently returning
 * one arbitrary credential of 43).
 */
export async function resolveCoordinate(
  locateQuery: string,
  accountHint: string,
  bypassReason: string,
): Promise<{ service: string; username: string } | null> {
  const canonical = CANONICAL_LOCATE_QUERY[`${locateQuery}/${accountHint}`];
  const loc = await vaultLocate(canonical ?? locateQuery, bypassReason);
  if (loc.status === "EXACT" && loc.get_with) return loc.get_with;
  if (loc.status === "AMBIGUOUS") {
    const hint = accountHint.trim().toLowerCase();
    const match = loc.candidates.find(
      (c) => c.username.toLowerCase() === hint || c.actual_service.toLowerCase().includes(hint),
    );
    if (match) return { service: match.actual_service, username: match.username };
    return null; // genuinely ambiguous for this account hint — refuse, do not pick
  }
  return null; // NOT_FOUND
}
