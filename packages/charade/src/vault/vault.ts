import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { canonicalJson } from "../core/canonical-json.js";
import {
  MASTER_KEY_BYTES,
  SCRYPT_PARAMS,
  deriveKey,
  open as openSealed,
  randomKey,
  seal,
  slotAad,
} from "./crypto.js";
import {
  decodeVault,
  encodeVault,
  headerAad,
  type VaultHeader,
  type VaultPayload,
  type VaultSlot,
} from "./format.js";
import { acquireLock, writeAtomic } from "./atomic.js";
import type { CustodyAdapter } from "./custody.js";

export interface VaultPaths {
  readonly home: string;
  readonly vault: string;
  readonly backups: string;
}

export function vaultPaths(home: string): VaultPaths {
  return {
    home,
    vault: join(home, "vault.charade"),
    backups: join(home, "backups"),
  };
}

export interface InitOptions {
  readonly home: string;
  readonly passphrase: string;
  readonly now?: Date;
  readonly custodyAdapter?: CustodyAdapter;
}

export interface InitResult {
  readonly vaultPath: string;
  readonly vaultId: string;
  /** Base64url. Shown once; never stored in plaintext. */
  readonly recoveryKey: string;
  readonly header: VaultHeader;
}

export interface OpenVault {
  readonly header: VaultHeader;
  readonly payload: VaultPayload;
  readonly masterKey: Buffer;
  readonly vaultPath: string;
}

export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultError";
  }
}

export function initVault(options: InitOptions): InitResult {
  const paths = vaultPaths(options.home);
  if (existsSync(paths.vault)) {
    throw new VaultError("a vault already exists in this directory");
  }
  mkdirSync(paths.home, { recursive: true, mode: 0o700 });
  chmodSync(paths.home, 0o700);
  const lock = acquireLock(options.home);
  try {
    const createdAt = (options.now ?? new Date()).toISOString();
    const vaultId = `v_${randomBytes(8).toString("hex")}`;
    const masterKey = randomKey();

    const passSalt = randomBytes(SCRYPT_PARAMS.saltBytes);
    const passSlotId = `s_${randomBytes(6).toString("hex")}`;
    const passKek = deriveKey(options.passphrase, passSalt);
    const passBox = seal(passKek, masterKey, slotAad(passSlotId, "passphrase"));
    const passSlot: VaultSlot = {
      slotId: passSlotId,
      type: "passphrase",
      createdAt,
      kdf: {
        name: "scrypt",
        N: SCRYPT_PARAMS.N,
        r: SCRYPT_PARAMS.r,
        p: SCRYPT_PARAMS.p,
        maxmem: SCRYPT_PARAMS.maxmem,
        salt: passSalt.toString("base64url"),
      },
      wrap: {
        nonce: passBox.nonce.toString("base64url"),
        ciphertext: passBox.ciphertext.toString("base64url"),
        tag: passBox.tag.toString("base64url"),
      },
    };

    const recoveryKey = randomKey();
    const recoverySlotId = `s_${randomBytes(6).toString("hex")}`;
    const recoveryBox = seal(recoveryKey, masterKey, slotAad(recoverySlotId, "recovery"));
    const recoverySlot: VaultSlot = {
      slotId: recoverySlotId,
      type: "recovery",
      createdAt,
      wrap: {
        nonce: recoveryBox.nonce.toString("base64url"),
        ciphertext: recoveryBox.ciphertext.toString("base64url"),
        tag: recoveryBox.tag.toString("base64url"),
      },
    };

    const slots: VaultSlot[] = [passSlot, recoverySlot];
    let custodyAccount: string | undefined;
    if (options.custodyAdapter) {
      const availability = options.custodyAdapter.available();
      if (!availability.ok) {
        throw new VaultError(availability.reason ?? "the custody backend is unavailable");
      }
      custodyAccount = `vault:${vaultId}`;
      const custodyKek = randomKey();
      options.custodyAdapter.set(custodyAccount, custodyKek);
      const custodySlotId = `s_${randomBytes(6).toString("hex")}`;
      const custodyBox = seal(
        custodyKek,
        masterKey,
        slotAad(custodySlotId, options.custodyAdapter.id),
      );
      slots.push({
        slotId: custodySlotId,
        type: options.custodyAdapter.id,
        createdAt,
        service: options.custodyAdapter.service,
        account: custodyAccount,
        wrap: {
          nonce: custodyBox.nonce.toString("base64url"),
          ciphertext: custodyBox.ciphertext.toString("base64url"),
          tag: custodyBox.tag.toString("base64url"),
        },
      });
    }

    const header: VaultHeader = {
      schema: "charade.vault-header/1",
      vaultId,
      revision: 1,
      createdAt,
      cipher: "AES-256-GCM",
      slots,
    };
    const payload: VaultPayload = {
      schema: "charade.vault-payload/1",
      vaultId,
      revision: 1,
      createdAt,
      canary: randomBytes(16).toString("base64url"),
      secrets: [],
    };

    try {
      writeSealed(masterKey, paths.vault, header, payload);
    } catch (error) {
      if (options.custodyAdapter && custodyAccount) {
        options.custodyAdapter.delete(custodyAccount);
      }
      throw error;
    }

    return {
      vaultPath: paths.vault,
      vaultId,
      recoveryKey: recoveryKey.toString("base64url"),
      header,
    };
  } finally {
    lock.release();
  }
}

export function openVault(home: string, passphrase: string): OpenVault {
  const paths = vaultPaths(home);
  const decoded = decodeVault(readFileSync(paths.vault));
  const slot = decoded.header.slots.find((item) => item.type === "passphrase");
  if (!slot) throw new VaultError("vault has no passphrase slot");
  const kdf = requireScrypt(slot);
  const kek = deriveKey(passphrase, Buffer.from(kdf.salt, "base64url"));
  return finishOpen(paths.vault, decoded, kek, slot);
}

export function openWithRecovery(home: string, recoveryKeyBase64url: string): OpenVault {
  const paths = vaultPaths(home);
  const decoded = decodeVault(readFileSync(paths.vault));
  const slot = decoded.header.slots.find((item) => item.type === "recovery");
  if (!slot) throw new VaultError("vault has no recovery slot");
  const key = Buffer.from(recoveryKeyBase64url, "base64url");
  if (key.length !== MASTER_KEY_BYTES) {
    throw new VaultError("recovery key is not the expected size");
  }
  return finishOpen(paths.vault, decoded, key, slot);
}

export function openWithCustody(home: string, adapter: CustodyAdapter): OpenVault {
  const paths = vaultPaths(home);
  const decoded = decodeVault(readFileSync(paths.vault));
  const slot = decoded.header.slots.find((item) => item.type === adapter.id);
  if (!slot) throw new VaultError(`vault has no ${adapter.id} slot`);
  if (!slot.account) throw new VaultError("custody slot has no account");
  const key = adapter.get(slot.account);
  if (key.length !== MASTER_KEY_BYTES) {
    throw new VaultError("custody key is not the expected size");
  }
  return finishOpen(paths.vault, decoded, key, slot);
}

function finishOpen(
  vaultPath: string,
  decoded: ReturnType<typeof decodeVault>,
  wrappingKey: Buffer,
  slot: VaultSlot,
): OpenVault {
  const masterKey = openSealed(
    wrappingKey,
    {
      nonce: Buffer.from(slot.wrap.nonce, "base64url"),
      ciphertext: Buffer.from(slot.wrap.ciphertext, "base64url"),
      tag: Buffer.from(slot.wrap.tag, "base64url"),
    },
    slotAad(slot.slotId, slot.type),
  );
  if (masterKey.length !== MASTER_KEY_BYTES) {
    throw new VaultError("unwrapped master key is not the expected size");
  }
  const plaintext = openSealed(
    masterKey,
    {
      nonce: decoded.nonce,
      ciphertext: decoded.ciphertext,
      tag: decoded.tag,
    },
    headerAad(decoded.header),
  );
  const payload = JSON.parse(plaintext.toString("utf8")) as VaultPayload;
  if (payload.schema !== "charade.vault-payload/1" || payload.vaultId !== decoded.header.vaultId) {
    throw new VaultError("vault payload does not match its header");
  }
  if (payload.revision !== decoded.header.revision) {
    throw new VaultError("vault payload revision does not match its header");
  }
  if (!payload.canary) {
    throw new VaultError("vault payload has no canary");
  }
  return { header: decoded.header, payload, masterKey, vaultPath };
}

function requireScrypt(slot: VaultSlot): NonNullable<VaultSlot["kdf"]> {
  const kdf = slot.kdf;
  if (!kdf || kdf.name !== "scrypt") {
    throw new VaultError("passphrase slot has no scrypt descriptor");
  }
  if (
    kdf.N !== SCRYPT_PARAMS.N ||
    kdf.r !== SCRYPT_PARAMS.r ||
    kdf.p !== SCRYPT_PARAMS.p ||
    kdf.maxmem !== SCRYPT_PARAMS.maxmem
  ) {
    throw new VaultError("passphrase slot uses non-protocol scrypt parameters");
  }
  return kdf;
}

export function savePayload(open: OpenVault, payload: VaultPayload): OpenVault {
  const revision = open.header.revision + 1;
  const header: VaultHeader = { ...open.header, revision };
  const nextPayload: VaultPayload = { ...payload, revision };
  writeSealed(open.masterKey, open.vaultPath, header, nextPayload);
  return { ...open, header, payload: nextPayload };
}

function writeSealed(
  masterKey: Buffer,
  vaultPath: string,
  header: VaultHeader,
  payload: VaultPayload,
): void {
  const sealed = seal(
    masterKey,
    Buffer.from(canonicalJson(payload), "utf8"),
    headerAad(header),
  );
  writeAtomic(vaultPath, encodeVault(header, sealed.nonce, sealed.ciphertext, sealed.tag));
}

export function backupVault(home: string, now = new Date()): string {
  const paths = vaultPaths(home);
  const decoded = decodeVault(readFileSync(paths.vault));
  mkdirSync(paths.backups, { recursive: true, mode: 0o700 });
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  const target = join(paths.backups, `vault-r${decoded.header.revision}-${stamp}.charade`);
  writeAtomic(target, readFileSync(paths.vault));
  return target;
}

export interface RecoveryKitResult {
  readonly kitPath: string;
  readonly recoveryKey: string;
  readonly vaultId: string;
  readonly revision: number;
}

/**
 * Replace the recovery slot with a fresh key and write the kit. The kit is
 * written before the vault so a failed vault write never leaves a key that
 * exists only in memory. An existing kit is never overwritten.
 */
export function rekeyRecovery(
  home: string,
  passphrase: string,
  kitPath: string,
  now = new Date(),
): RecoveryKitResult {
  if (existsSync(kitPath)) {
    throw new VaultError("refusing to overwrite an existing recovery kit");
  }
  const open = openVault(home, passphrase);
  const createdAt = now.toISOString();
  const recoveryKey = randomKey();
  const slotId = `s_${randomBytes(6).toString("hex")}`;
  const box = seal(recoveryKey, open.masterKey, slotAad(slotId, "recovery"));
  const revision = open.header.revision + 1;
  const header: VaultHeader = {
    ...open.header,
    revision,
    slots: [
      ...open.header.slots.filter((slot) => slot.type !== "recovery"),
      {
        slotId,
        type: "recovery",
        createdAt,
        wrap: {
          nonce: box.nonce.toString("base64url"),
          ciphertext: box.ciphertext.toString("base64url"),
          tag: box.tag.toString("base64url"),
        },
      },
    ],
  };
  const payload: VaultPayload = { ...open.payload, revision };
  const kit = {
    schema: "charade.recovery-kit/1",
    vaultId: open.header.vaultId,
    revision,
    createdAt,
    recoveryKey: recoveryKey.toString("base64url"),
    note: "This key opens the vault if the passphrase and OS custody are both unavailable. Store it separately.",
  };
  writeAtomic(kitPath, Buffer.from(canonicalJson(kit), "utf8"), 0o600);
  try {
    writeSealed(open.masterKey, open.vaultPath, header, payload);
  } catch (error) {
    try {
      unlinkSync(kitPath);
    } catch {
      // The kit may already be gone.
    }
    throw error;
  }
  return {
    kitPath,
    recoveryKey: recoveryKey.toString("base64url"),
    vaultId: open.header.vaultId,
    revision,
  };
}

export function readRecoveryKit(kitPath: string): string {
  let kit: unknown;
  try {
    kit = JSON.parse(readFileSync(kitPath, "utf8"));
  } catch {
    throw new VaultError("recovery kit is not valid JSON");
  }
  if (
    typeof kit !== "object" ||
    kit === null ||
    (kit as { schema?: unknown }).schema !== "charade.recovery-kit/1" ||
    typeof (kit as { recoveryKey?: unknown }).recoveryKey !== "string"
  ) {
    throw new VaultError("recovery kit does not match the expected schema");
  }
  const key = (kit as { recoveryKey: string }).recoveryKey;
  if (Buffer.from(key, "base64url").length !== MASTER_KEY_BYTES) {
    throw new VaultError("recovery kit key is not the expected size");
  }
  return key;
}

export interface DrillResult {
  readonly vaultId: string;
  readonly revision: number;
  readonly checkedAt: string;
}

/**
 * Prove a backup and the recovery key can open the vault without touching the
 * live file. The drill decrypts in memory only.
 */
export function drillBackup(backupPath: string, recoveryKeyBase64url: string): DrillResult {
  const decoded = decodeVault(readFileSync(backupPath));
  const slot = decoded.header.slots.find((item) => item.type === "recovery");
  if (!slot) throw new VaultError("backup has no recovery slot");
  const key = Buffer.from(recoveryKeyBase64url, "base64url");
  if (key.length !== MASTER_KEY_BYTES) {
    throw new VaultError("recovery key is not the expected size");
  }
  const opened = finishOpen(backupPath, decoded, key, slot);
  return {
    vaultId: opened.header.vaultId,
    revision: opened.header.revision,
    checkedAt: new Date().toISOString(),
  };
}

export function vaultFileMode(home: string): number {
  return statSync(vaultPaths(home).vault).mode & 0o777;
}
