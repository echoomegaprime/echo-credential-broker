// Types for credential-scan.mjs, for the TypeScript that imports it
// (scripts/vault-import.ts and src/lib/vault/v2/import.test.ts).

export const SCANNER_VERSION: string;

export interface TextFinding {
  line: number;
  detector: string;
  provider: string;
  key_name: string | null;
  length: number | null;
  /** HMAC-SHA256 under the node key, 16 hex chars; null for marker findings. */
  fingerprint: string | null;
}

export function entropy(value: string): number;
export function fingerprint(value: string, key: Buffer | string): string;
/** Findings for one file's text. No secret value in the result. */
export function scanText(text: string, key: Buffer | string): TextFinding[];
/** The node's HMAC key; created (mode 0600) on first use. */
export function loadNodeKey(file?: string): Buffer;
/**
 * The secret a finding points at, read back from that line. Returns a secret
 * VALUE: only for the on-box importer, never for stdout, a log or a manifest.
 */
export function locateSecret(
  lineText: string,
  finding: { detector: string; fingerprint: string | null },
  key: Buffer | string,
): string | null;
