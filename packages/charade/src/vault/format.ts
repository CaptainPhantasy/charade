import { canonicalJson } from "../core/canonical-json.js";

export const MAGIC = Buffer.from("CHARADE1", "ascii");
export const FORMAT_VERSION = 1;
export const HEADER_MAX_BYTES = 64 * 1024;

export type SlotType =
  | "passphrase"
  | "recovery"
  | "macos-keychain"
  | "secret-service"
  | "systemd-creds";

export interface ScryptDescriptor {
  readonly name: "scrypt";
  readonly N: number;
  readonly r: number;
  readonly p: number;
  readonly maxmem: number;
  readonly salt: string;
}

export interface SlotWrap {
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}

export interface VaultSlot {
  readonly slotId: string;
  readonly type: SlotType;
  readonly createdAt: string;
  readonly kdf?: ScryptDescriptor;
  readonly wrap: SlotWrap;
  readonly service?: string;
  readonly account?: string;
}

export interface VaultHeader {
  readonly schema: "charade.vault-header/1";
  readonly vaultId: string;
  readonly revision: number;
  readonly createdAt: string;
  readonly cipher: "AES-256-GCM";
  readonly slots: readonly VaultSlot[];
}

export interface OwnerRecord {
  /** PKCS#8 DER, base64. Protected by the encrypted payload. */
  readonly privateKey: string;
  /** Raw 32-byte Ed25519 public key, base64url. */
  readonly publicKey: string;
  readonly createdAt: string;
}

export interface VaultPayload {
  readonly schema: "charade.vault-payload/1";
  readonly vaultId: string;
  readonly revision: number;
  readonly createdAt: string;
  readonly canary: string;
  readonly owner?: OwnerRecord;
  readonly secrets: readonly unknown[];
}

export interface DecodedVault {
  readonly header: VaultHeader;
  readonly headerBytes: Buffer;
  readonly nonce: Buffer;
  readonly ciphertext: Buffer;
  readonly tag: Buffer;
}

export class VaultFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultFormatError";
  }
}

export function headerAad(header: VaultHeader): Buffer {
  return Buffer.from(canonicalJson(header), "utf8");
}

export function encodeVault(
  header: VaultHeader,
  nonce: Buffer,
  ciphertext: Buffer,
  tag: Buffer,
): Buffer {
  const headerBytes = headerAad(header);
  if (headerBytes.length > HEADER_MAX_BYTES) {
    throw new VaultFormatError("vault header is too large");
  }
  const prefix = Buffer.alloc(12);
  MAGIC.copy(prefix, 0);
  prefix.writeUInt16BE(FORMAT_VERSION, 8);
  prefix.writeUInt16BE(headerBytes.length, 10);
  return Buffer.concat([prefix, headerBytes, nonce, ciphertext, tag]);
}

export function decodeVault(bytes: Buffer): DecodedVault {
  if (bytes.length < 12 + 12 + 16) {
    throw new VaultFormatError("vault file is too short");
  }
  if (!bytes.subarray(0, 8).equals(MAGIC)) {
    throw new VaultFormatError("vault magic does not match");
  }
  const version = bytes.readUInt16BE(8);
  if (version !== FORMAT_VERSION) {
    throw new VaultFormatError(`unsupported vault format version ${version}`);
  }
  const headerLength = bytes.readUInt16BE(10);
  if (headerLength === 0 || headerLength > HEADER_MAX_BYTES) {
    throw new VaultFormatError("vault header length is invalid");
  }
  const headerStart = 12;
  const headerEnd = headerStart + headerLength;
  if (bytes.length < headerEnd + 12 + 16) {
    throw new VaultFormatError("vault is truncated");
  }
  const headerBytes = bytes.subarray(headerStart, headerEnd);
  let header: VaultHeader;
  try {
    header = JSON.parse(headerBytes.toString("utf8")) as VaultHeader;
  } catch {
    throw new VaultFormatError("vault header is not valid JSON");
  }
  if (header.schema !== "charade.vault-header/1" || header.cipher !== "AES-256-GCM") {
    throw new VaultFormatError("vault header schema or cipher is unsupported");
  }
  if (canonicalJson(header) !== headerBytes.toString("utf8")) {
    throw new VaultFormatError("vault header is not canonical");
  }
  const nonce = bytes.subarray(headerEnd, headerEnd + 12);
  const tagStart = bytes.length - 16;
  const ciphertext = bytes.subarray(headerEnd + 12, tagStart);
  const tag = bytes.subarray(tagStart);
  return { header, headerBytes, nonce, ciphertext, tag };
}
