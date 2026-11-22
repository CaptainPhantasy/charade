import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";
import { openVault, readRecoveryKit } from "../src/vault/vault.js";

const CLI = fileURLToPath(new URL("../src/cli/main.js", import.meta.url));
const PASSPHRASE = "correct horse battery staple";
const roots: string[] = [];

function tempHome(): string {
  const home = mkdtempSync(join(tmpdir(), "charade-cli-"));
  roots.push(home);
  return home;
}

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function passFile(home: string, value = PASSPHRASE, mode = 0o600): string {
  const path = join(home, "pass.txt");
  writeFileSync(path, `${value}\n`, { mode });
  return path;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("charade CLI", () => {
  it("dry-runs init without creating a vault", () => {
    const home = tempHome();
    const result = run(["init", "--home", home, "--dry-run"]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /nothing will be written/);
    assert.equal(existsSync(join(home, "vault.charade")), false);
  });

  it("initializes a vault, backs it up, rekeys recovery, and drills the kit", () => {
    const home = tempHome();
    const pass = passFile(home);
    const init = run(["init", "--home", home, "--passphrase-file", pass]);
    assert.equal(init.status, 0);
    assert.match(init.stdout, /vault created/);
    assert.equal(statSync(join(home, "vault.charade")).mode & 0o777, 0o600);
    assert.equal(openVault(home, PASSPHRASE).header.vaultId.startsWith("v_"), true);

    const firstBackup = run(["vault", "backup", "--home", home]);
    assert.equal(firstBackup.status, 0);
    const backupOne = firstBackup.stdout.trim().split(": ").at(-1);
    assert.ok(backupOne && existsSync(backupOne));

    const kit = join(home, "kit.json");
    const rekey = run([
      "vault",
      "recovery-kit",
      "--home",
      home,
      "--out",
      kit,
      "--passphrase-file",
      pass,
    ]);
    assert.equal(rekey.status, 0);
    assert.equal(statSync(kit).mode & 0o777, 0o600);
    assert.equal(readRecoveryKit(kit).length > 20, true);

    const secondBackup = run(["vault", "backup", "--home", home]);
    assert.equal(secondBackup.status, 0);
    const backupTwo = secondBackup.stdout.trim().split(": ").at(-1);
    assert.ok(backupTwo && existsSync(backupTwo));

    const drill = run(["vault", "drill", "--backup", backupTwo, "--kit", kit]);
    assert.equal(drill.status, 0);
    assert.match(drill.stdout, /drill ok/);
    assert.match(readFileSync(kit, "utf8"), /"schema":"charade\.recovery-kit\/1"/);
  });

  it("refuses a group-readable passphrase file", () => {
    const home = tempHome();
    const pass = passFile(home, PASSPHRASE, 0o644);
    const result = run(["init", "--home", home, "--passphrase-file", pass]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /readable by group or others/);
    assert.equal(existsSync(join(home, "vault.charade")), false);
  });

  it("refuses a short passphrase", () => {
    const home = tempHome();
    const pass = passFile(home, "short");
    const result = run(["init", "--home", home, "--passphrase-file", pass]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /at least 12/);
  });

  it("returns a usage error when --home is missing", () => {
    const result = run(["vault", "backup"]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /--home/);
  });
});
