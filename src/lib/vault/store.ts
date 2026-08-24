import { decryptSecret, deriveKey, encryptSecret, fingerprintSecret, randomKey } from "./crypto.ts";
import { registerSecretForRedaction } from "./redaction.ts";
import type {
  CredentialMetadata,
  CredentialType,
  EncryptedBlob,
  ProviderId,
  StoredCredential,
} from "./types.ts";
import { formatVaultRef } from "./refs.ts";

export interface PutCredentialInput {
  provider: ProviderId;
  account: string;
  type: CredentialType;
  secret: string;
  source: string;
}

function wrappingKey(): Buffer {
  const material =
    process.env.ECHO_VAULT_MASTER_KEY ||
    process.env.GROK_SERVER_KEY ||
    process.env.XAI_API_KEY;
  if (material && material.length >= 16) return deriveKey(`echo-vault:${material}`);
  if (!globalVaultKey) globalVaultKey = randomKey();
  return globalVaultKey;
}

let globalVaultKey: Buffer | undefined;

export class CredentialStore {
  private readonly records = new Map<string, StoredCredential>();

  put(input: PutCredentialInput): CredentialMetadata {
    const secret = input.secret.trim();
    if (!secret) {
      throw Object.assign(new Error("empty_secret"), { code: "empty_secret" });
    }
    registerSecretForRedaction(secret);
    const ref = formatVaultRef(input.provider, input.account);
    const meta: CredentialMetadata = {
      ref,
      provider: input.provider,
      account: input.account,
      type: input.type,
      status: "imported",
      last_verified: null,
      fingerprint: fingerprintSecret(secret),
      source: input.source,
    };
    const ciphertext: EncryptedBlob = encryptSecret(secret, wrappingKey());
    this.records.set(ref, { meta, ciphertext });
    return { ...meta };
  }

  getMetadata(ref: string): CredentialMetadata | null {
    const rec = this.records.get(ref);
    return rec ? { ...rec.meta } : null;
  }

  listMetadata(): CredentialMetadata[] {
    return [...this.records.values()].map((r) => ({ ...r.meta }));
  }

  updateMetadata(
    ref: string,
    patch: Partial<Pick<CredentialMetadata, "status" | "last_verified" | "account">>,
  ): CredentialMetadata | null {
    const rec = this.records.get(ref);
    if (!rec) return null;
    rec.meta = { ...rec.meta, ...patch, ref: rec.meta.ref };
    this.records.set(ref, rec);
    return { ...rec.meta };
  }

  /**
   * Resolve the raw secret. NEVER return this across an MCP / HTTP / UI boundary.
   * Callers must keep the value on the stack and let it fall out of scope.
   */
  resolveSecret(ref: string): string | null {
    const rec = this.records.get(ref);
    if (!rec) return null;
    if (rec.meta.status === "revoked") return null;
    try {
      const secret = decryptSecret(rec.ciphertext, wrappingKey());
      registerSecretForRedaction(secret);
      return secret;
    } catch {
      return null;
    }
  }

  revoke(ref: string): boolean {
    const rec = this.records.get(ref);
    if (!rec) return false;
    rec.meta.status = "revoked";
    rec.ciphertext = encryptSecret(randomKey().toString("hex"), wrappingKey());
    this.records.set(ref, rec);
    return true;
  }

  has(ref: string): boolean {
    const rec = this.records.get(ref);
    return Boolean(rec && rec.meta.status !== "revoked");
  }

  count(): number {
    return [...this.records.values()].filter((r) => r.meta.status !== "revoked")
      .length;
  }

  clear(): void {
    this.records.clear();
  }
}

const singleton = new CredentialStore();

export function getStore(): CredentialStore {
  return singleton;
}

export function resetStoreForTests(): CredentialStore {
  singleton.clear();
  return singleton;
}
