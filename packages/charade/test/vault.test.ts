import assert from "node:assert/strict";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import {
  backupVault,
  drillBackup,
  getOwnerKeyPair,
  initVault,
  openVault,
  openWithCustody,
  openWithRecovery,
  readRecoveryKit,
  rekeyRecovery,
  savePayload,
  vaultFileMode,
  vaultPaths,
  type OpenVault,
} from "../src/vault/vault.js";
import { acquireLock } from "../src/vault/atomic.js";
import type { CustodyAdapter } from "../src/vault/custody.js";
import { signDomain, verifyDomain } from "../src/authority/keys.js";

class MemoryCustody implements CustodyAdapter {
  readonly id = "macos-keychain" as const;
  readonly service = "test.service";
  private readonly values = new Map<string, Buffer>();

  available(): { ok: boolean } {
    return { ok: true };
  }
  set(account: string, secret: Buffer): void {
    this.values.set(account, Buffer.from(secret));
  }
  get(account: string): Buffer {
    const value = this.values.get(account);
    if (!value) throw new Error("missing custody item");
    return Buffer.from(value);
  }
  delete(account: string): void {
    this.values.delete(account);
  }
}

const PASSPHRASE = "correct horse battery staple";

describe("vault", () => {
  let home: string;
  let opened: OpenVault;
  let recoveryKey: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "charade-vault-"));
    const created = initVault({ home, passphrase: PASSPHRASE });
    recoveryKey = created.recoveryKey;
    opened = openVault(home, PASSPHRASE);
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("creates a passphrase and recovery slot with private modes", () => {
    assert.equal(opened.header.slots.length, 2);
    assert.equal(opened.header.slots.some((slot) => slot.type === "passphrase"), true);
    assert.equal(opened.header.slots.some((slot) => slot.type === "recovery"), true);
    assert.equal(vaultFileMode(home), 0o600);
    assert.equal(statSync(home).mode & 0o777, 0o700);
  });

  it("round-trips the payload and canary", () => {
    assert.equal(opened.payload.vaultId, opened.header.vaultId);
    assert.equal(opened.payload.revision, 1);
    assert.ok(opened.payload.canary.length > 0);
  });

  it("creates an owner identity inside the encrypted payload", () => {
    const owner = getOwnerKeyPair(opened);
    assert.equal(Buffer.from(owner.publicKey, "base64url").length, 32);
    const signature = signDomain(owner.privateKey, "charade-test\u0000", { a: 1 });
    assert.equal(verifyDomain(owner.publicKey, "charade-test\u0000", { a: 1 }, signature), true);
  });

  it("does not leave plaintext in the vault file", () => {
    const bytes = readFileSync(vaultPaths(home).vault);
    assert.equal(bytes.includes(Buffer.from(PASSPHRASE)), false);
    assert.equal(bytes.includes(Buffer.from(opened.payload.canary)), false);
  });

  it("rejects the wrong passphrase", () => {
    assert.throws(() => openVault(home, "this is not the passphrase"));
  });

  it("opens with the recovery key and rejects a bad one", () => {
    const recovered = openWithRecovery(home, recoveryKey);
    assert.equal(recovered.header.vaultId, opened.header.vaultId);
    assert.equal(
      Buffer.from(recoveryKey, "base64url").length,
      32,
    );
    assert.throws(() => openWithRecovery(home, "not-a-key"));
  });

  it("rejects ciphertext tampering", () => {
    const path = vaultPaths(home).vault;
    const bytes = Buffer.from(readFileSync(path));
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
    writeFileSync(path, bytes, { mode: 0o600 });
    assert.throws(() => openVault(home, PASSPHRASE));
  });

  it("rejects header tampering", () => {
    const path = vaultPaths(home).vault;
    const bytes = Buffer.from(readFileSync(path));
    bytes[13] = (bytes[13] ?? 0) ^ 1;
    writeFileSync(path, bytes, { mode: 0o600 });
    assert.throws(() => openVault(home, PASSPHRASE));
  });

  it("increments the revision and persists a payload", () => {
    const next = savePayload(opened, {
      ...opened.payload,
      secrets: [{ label: "fixture" }],
    });
    assert.equal(next.header.revision, 2);
    const reopened = openVault(home, PASSPHRASE);
    assert.equal(reopened.header.revision, 2);
    assert.equal(reopened.payload.secrets.length, 1);
  });

  it("backs up and drills a backup without touching the live vault", () => {
    const backup = backupVault(home);
    assert.equal(statSync(backup).mode & 0o777, 0o600);
    const result = drillBackup(backup, recoveryKey);
    assert.equal(result.vaultId, opened.header.vaultId);
    assert.equal(result.revision, 1);
    assert.throws(() => drillBackup(backup, "not-a-key"));
  });

  it("refuses a second writer while the lock is held", () => {
    const lock = acquireLock(home);
    try {
      assert.throws(() => acquireLock(home));
    } finally {
      lock.release();
    }
    const again = acquireLock(home);
    again.release();
  });

  it("adds a custody slot and opens through it", () => {
    const custodyHome = mkdtempSync(join(tmpdir(), "charade-vault-custody-"));
    const adapter = new MemoryCustody();
    try {
      initVault({ home: custodyHome, passphrase: PASSPHRASE, custodyAdapter: adapter });
      const viaCustody = openWithCustody(custodyHome, adapter);
      assert.equal(viaCustody.header.slots.length, 3);
      assert.equal(viaCustody.header.slots.some((slot) => slot.type === "macos-keychain"), true);
      assert.equal(openVault(custodyHome, PASSPHRASE).header.vaultId, viaCustody.header.vaultId);
      const account = viaCustody.header.slots.find((slot) => slot.type === "macos-keychain")?.account;
      assert.ok(account);
      adapter.delete(account);
      assert.throws(() => openWithCustody(custodyHome, adapter));
    } finally {
      rmSync(custodyHome, { recursive: true, force: true });
    }
  });

  it("rekeys recovery, writes a 0600 kit, and drills the right backup", () => {
    const oldKey = recoveryKey;
    const backupBefore = backupVault(home);
    const kit = join(home, "recovery-kit.json");
    const rekeyed = rekeyRecovery(home, PASSPHRASE, kit);
    assert.equal(rekeyed.revision, 2);
    assert.equal(readRecoveryKit(kit), rekeyed.recoveryKey);
    assert.equal(statSync(kit).mode & 0o777, 0o600);
    assert.equal(openWithRecovery(home, rekeyed.recoveryKey).header.vaultId, opened.header.vaultId);
    assert.throws(() => openWithRecovery(home, oldKey));
    assert.equal(drillBackup(backupBefore, oldKey).revision, 1);
    assert.throws(() => drillBackup(backupBefore, rekeyed.recoveryKey));
    const backupAfter = backupVault(home);
    assert.equal(drillBackup(backupAfter, rekeyed.recoveryKey).revision, 2);
    assert.throws(() => rekeyRecovery(home, PASSPHRASE, kit));
  });

  it("recovers a lock whose recorded process is gone", () => {
    const lockPath = join(home, "vault.lock");
    writeFileSync(lockPath, JSON.stringify({ pid: 999999, startedAt: new Date().toISOString() }), {
      mode: 0o600,
    });
    const lock = acquireLock(home);
    lock.release();
  });

  it("leaves no temporary files after a write", () => {
    const names = readdirSync(home);
    assert.equal(names.some((name) => name.includes(".tmp-")), false);
  });
});
