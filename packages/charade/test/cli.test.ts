import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";
import { openVault, readRecoveryKit } from "../src/vault/vault.js";
import { loadGrants, loadPolicy } from "../src/authority/store.js";
import { verifyGrant } from "../src/authority/grants.js";

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

  it("signs owner-changed policy values from a policy file", () => {
    const home = tempHome();
    const pass = passFile(home);
    assert.equal(run(["init", "--home", home, "--passphrase-file", pass]).status, 0);
    const overrides = join(home, "policy-overrides.json");
    writeFileSync(
      overrides,
      JSON.stringify({ limits: { maxLeaseTtlSeconds: 600, defaultLeaseTtlSeconds: 300 } }),
      { mode: 0o600 },
    );
    const result = run([
      "policy",
      "init",
      "--home",
      home,
      "--policy-file",
      overrides,
      "--passphrase-file",
      pass,
    ]);
    assert.equal(result.status, 0);
    const policy = loadPolicy(home);
    assert.equal(policy.limits.maxLeaseTtlSeconds, 600);
    assert.equal(policy.limits.defaultLeaseTtlSeconds, 300);
  });

  it("requires explicit policy and grant acceptance, then signs, verifies, and revokes", () => {
    const home = tempHome();
    const pass = passFile(home);
    assert.equal(run(["init", "--home", home, "--passphrase-file", pass]).status, 0);

    const noPolicy = run(["policy", "init", "--home", home]);
    assert.equal(noPolicy.status, 2);
    assert.equal(existsSync(join(home, "policy.json")), false);

    const signedPolicy = run([
      "policy",
      "init",
      "--home",
      home,
      "--accept-defaults",
      "--passphrase-file",
      pass,
    ]);
    assert.equal(signedPolicy.status, 0);
    assert.equal(existsSync(join(home, "policy.json")), true);

    writeRegistry(home);
    assert.equal(run(["registry", "validate", "--home", home]).status, 0);

    const noGrant = run([
      "grant",
      "create",
      "--home",
      home,
      "--consumer",
      "c1",
      "--services",
      "svc",
      "--duration",
      "24h",
    ]);
    assert.equal(noGrant.status, 2);
    assert.equal(existsSync(join(home, "grants.json")), false);

    const signedGrant = run([
      "grant",
      "create",
      "--home",
      home,
      "--consumer",
      "c1",
      "--services",
      "svc",
      "--duration",
      "24h",
      "--calls",
      "100",
      "--accept",
      "--passphrase-file",
      pass,
    ]);
    assert.equal(signedGrant.status, 0);
    const grants = loadGrants(home);
    assert.equal(grants.length, 1);
    assert.equal(verifyGrant(loadPolicy(home), grants[0]!, new Date()).ok, true);
    assert.equal(run(["receipts", "verify", "--home", home]).status, 0);

    const revoked = run([
      "grant",
      "revoke",
      "--home",
      home,
      "--id",
      grants[0]!.grantId,
      "--accept",
    ]);
    assert.equal(revoked.status, 0);
    assert.equal(loadGrants(home).length, 0);
    assert.equal(run(["receipts", "verify", "--home", home]).status, 0);
  });
});

function writeRegistry(home: string): void {
  const now = new Date().toISOString();
  const registry = {
    schema: "charade.registry/1",
    revision: 1,
    services: [
      {
        id: "svc",
        name: "Example",
        url: "https://example.test",
        transport: "http",
        auth: { type: "header", name: "Authorization", template: "Bearer ${SVC_KEY}" },
        actions: { read: ["GET /v1/*"], write: ["POST /v1/*"], destructive: [] },
      },
    ],
    consumers: [
      { id: "c1", name: "Consumer", services: ["svc"], deviceIds: ["d1"], createdAt: now },
    ],
    devices: [
      {
        id: "d1",
        consumerId: "c1",
        publicKey: Buffer.alloc(32, 3).toString("base64url"),
        createdAt: now,
      },
    ],
  };
  writeFileSync(join(home, "registry.json"), JSON.stringify(registry), { mode: 0o600 });
}
