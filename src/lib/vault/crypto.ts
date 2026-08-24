import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import type { EncryptedBlob } from "./types.ts";

const ALG = "aes-256-gcm" as const;

export function deriveKey(material: string): Buffer {
  return createHash("sha256").update(material, "utf8").digest();
}

export function fingerprintSecret(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex").slice(0, 8);
}

export function encryptSecret(plain: string, key: Buffer): EncryptedBlob {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALG, key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plain, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    alg: ALG,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ct: ciphertext.toString("base64"),
  };
}

export function decryptSecret(blob: EncryptedBlob, key: Buffer): string {
  if (blob.alg !== ALG) {
    throw new Error("unsupported_cipher");
  }
  const decipher = createDecipheriv(
    ALG,
    key,
    Buffer.from(blob.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(blob.tag, "base64"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(blob.ct, "base64")),
    decipher.final(),
  ]);
  return plain.toString("utf8");
}

export function randomKey(): Buffer {
  return randomBytes(32);
}
