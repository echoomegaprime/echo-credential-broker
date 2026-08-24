import type { ProviderId, VaultRef } from "./types.ts";

const PROVIDERS = new Set<ProviderId>([
  "github",
  "cloudflare",
  "openai",
  "stripe",
  "xai",
]);

const REF_RE = /^vault:\/\/([a-z0-9-]+)\/([a-zA-Z0-9._-]+)$/;

export function isProviderId(value: string): value is ProviderId {
  return PROVIDERS.has(value as ProviderId);
}

export function parseVaultRef(input: string): VaultRef | null {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  const match = REF_RE.exec(trimmed);
  if (!match) return null;
  const provider = match[1];
  const account = match[2];
  if (!provider || !account || !isProviderId(provider)) return null;
  return {
    scheme: "vault",
    provider,
    account,
    raw: `vault://${provider}/${account}`,
  };
}

export function formatVaultRef(provider: ProviderId, account: string): string {
  return `vault://${provider}/${account}`;
}

export function assertVaultRef(input: string): VaultRef {
  const parsed = parseVaultRef(input);
  if (!parsed) {
    throw Object.assign(new Error("invalid_credential_ref"), {
      code: "invalid_credential_ref",
    });
  }
  return parsed;
}
