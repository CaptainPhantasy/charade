import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { canonicalJson } from "../core/canonical-json.js";

/** Ed25519 SPKI prefix for a raw 32-byte public key. */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface OwnerKeyPair {
  /** PKCS#8 DER, base64. Stored only inside the encrypted vault payload. */
  readonly privateKey: string;
  /** Raw 32-byte public key, base64url. */
  readonly publicKey: string;
}

export function generateOwnerKeyPair(): OwnerKeyPair {
  const pair = generateKeyPairSync("ed25519");
  const privateDer = pair.privateKey.export({ type: "pkcs8", format: "der" });
  const publicSpki = pair.publicKey.export({ type: "spki", format: "der" });
  const raw = publicSpki.subarray(publicSpki.length - 32);
  return {
    privateKey: Buffer.from(privateDer).toString("base64"),
    publicKey: Buffer.from(raw).toString("base64url"),
  };
}

export function publicKeyObject(publicKey: string): KeyObject {
  const raw = Buffer.from(publicKey, "base64url");
  if (raw.length !== 32) throw new Error("owner public key must be 32 bytes");
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

export function privateKeyObject(privateKey: string): KeyObject {
  return createPrivateKey({
    key: Buffer.from(privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });
}

/**
 * Sign a domain-separated canonical value. The NUL separator prevents a
 * signature for one purpose from being replayed as another.
 */
export function signDomain(privateKey: string, domain: string, value: unknown): string {
  const message = Buffer.from(`${domain}${canonicalJson(value)}`, "utf8");
  return sign(null, message, privateKeyObject(privateKey)).toString("base64url");
}

export function verifyDomain(
  publicKey: string,
  domain: string,
  value: unknown,
  signature: string,
): boolean {
  try {
    const message = Buffer.from(`${domain}${canonicalJson(value)}`, "utf8");
    return verify(
      null,
      message,
      publicKeyObject(publicKey),
      Buffer.from(signature, "base64url"),
    );
  } catch {
    return false;
  }
}

export function publicKeyFingerprint(publicKey: string): string {
  return createHash("sha256")
    .update(Buffer.from(publicKey, "base64url"))
    .digest("hex")
    .slice(0, 16);
}
