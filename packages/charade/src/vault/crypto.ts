import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";

/**
 * scrypt parameters are a protocol constant, not a local preference.
 * Node 26 rejects N=2^15 at the default memory ceiling, so maxmem is explicit.
 */
export const SCRYPT_PARAMS = {
  N: 2 ** 15,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024,
  keylen: 32,
  saltBytes: 16,
} as const;

export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const MASTER_KEY_BYTES = 32;

export interface SealedBox {
  readonly nonce: Buffer;
  readonly ciphertext: Buffer;
  readonly tag: Buffer;
}

export function deriveKey(input: string, salt: Buffer): Buffer {
  if (salt.length !== SCRYPT_PARAMS.saltBytes) {
    throw new Error(`salt must be ${SCRYPT_PARAMS.saltBytes} bytes`);
  }
  return scryptSync(input.normalize("NFKC"), salt, SCRYPT_PARAMS.keylen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: SCRYPT_PARAMS.maxmem,
  });
}

export function seal(key: Buffer, plaintext: Buffer, aad: Buffer): SealedBox {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce, ciphertext, tag: cipher.getAuthTag() };
}

export function open(key: Buffer, box: SealedBox, aad: Buffer): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, box.nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(box.tag);
  return Buffer.concat([decipher.update(box.ciphertext), decipher.final()]);
}

export function randomKey(): Buffer {
  return randomBytes(MASTER_KEY_BYTES);
}

export function slotAad(slotId: string, type: string): Buffer {
  return Buffer.from(`charade-slot-v1\u0000${slotId}\u0000${type}`, "utf8");
}
