import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";
import { findActiveSecret, openVault } from "../src/vault/vault.js";

const CLI = fileURLToPath(new URL("../src/cli/main.js", import.meta.url));
const PASSPHRASE = "correct horse battery staple";
const FIXTURE_ONE = "sk-live-fixture-one-9f2c1d";
const FIXTURE_TWO = "sk-live-fixture-two-4a7e3b";
const homes: string[] = [];

afterEach(() => {
  for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true });
});

function tempHome(): string {
  const home = mkdtempSync(join(tmpdir(), "charade-cli-secret-"));
  homes.push(home);
  return home;
}

function run(args: string[], input?: string): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    ...(input === undefined ? {} : { input }),
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

/**
 * Start a command that reads the secret from stdin, confirm the value is not in
 * the process command line while it waits, then deliver the value.
 */
async function runWithStdin(
  args: string[],
  value: string,
): Promise<{ status: number | null; stdout: string; stderr: string; commandLine: string }> {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  await new Promise((resolve) => setTimeout(resolve, 250));
  const ps = spawnSync("ps", ["-o", "command=", "-p", String(child.pid)], { encoding: "utf8" });
  const commandLine = ps.status === 0 ? ps.stdout : "";
  child.stdin.end(`${value}\n`);
  const status = await new Promise<number | null>((resolve) => child.on("exit", resolve));
  return { status, stdout, stderr, commandLine };
}

function seedHome(): { home: string; pass: string } {
  const home = tempHome();
  const pass = join(home, "pass.txt");
  writeFileSync(pass, `${PASSPHRASE}\n`, { mode: 0o600 });
  assert.equal(run(["init", "--home", home, "--passphrase-file", pass]).status, 0);
  assert.equal(
    run(["policy", "init", "--home", home, "--accept-defaults", "--passphrase-file", pass]).status,
    0,
  );
  writeFileSync(join(home, "registry.json"), JSON.stringify(registryFixture()), { mode: 0o600 });
  return { home, pass };
}

function registryFixture(): unknown {
  const now = new Date().toISOString();
  return {
    schema: "charade.registry/1",
    revision: 1,
    services: [
      {
        id: "svc",
        name: "Example",
        url: "https://example.test",
        transport: "http",
        auth: { type: "header", name: "Authorization", template: "Bearer ${SVC_KEY}" },
        actions: { read: ["GET /v1/*"], write: [], destructive: [] },
      },
    ],
    consumers: [{ id: "c1", name: "Consumer", services: ["svc"], deviceIds: [], createdAt: now }],
    devices: [],
  };
}

function scanFor(home: string, needle: string): string[] {
  const hits: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(path);
        continue;
      }
      if (!entry.isFile()) continue;
      if (readFileSync(path).includes(Buffer.from(needle, "utf8"))) hits.push(path);
    }
  };
  walk(home);
  return hits;
}

describe("charade secret", () => {
  it("adds, lists, rotates, and removes a secret without revealing the value", async () => {
    const { home, pass } = seedHome();

    const added = await runWithStdin(["secret", "add", "--home", home, "--service", "svc", "--passphrase-file", pass], FIXTURE_ONE);
    assert.equal(added.status, 0, added.stderr);
    assert.match(added.stdout, /secret added: sec_/);
    assert.match(added.stdout, /service:\s+svc/);
    assert.equal(added.stdout.includes(FIXTURE_ONE), false);
    assert.equal(added.stderr.includes(FIXTURE_ONE), false);
    assert.equal(added.commandLine.includes(FIXTURE_ONE), false, "the value must never be in argv");

    const listed = run(["secret", "list", "--home", home, "--passphrase-file", pass]);
    assert.equal(listed.status, 0, listed.stderr);
    assert.match(listed.stdout, /svc/);
    assert.match(listed.stdout, /active/);
    assert.match(listed.stdout, /ver_/);
    assert.equal(listed.stdout.includes(FIXTURE_ONE), false);

    const open = openVault(home, PASSPHRASE);
    const active = findActiveSecret(open, "svc");
    assert.ok(active);

    const rotated = await runWithStdin(
      ["secret", "rotate", "--home", home, "--id", active.id, "--overlap", "60", "--passphrase-file", pass],
      FIXTURE_TWO,
    );
    assert.equal(rotated.status, 0, rotated.stderr);
    assert.match(rotated.stdout, /secret rotated:/);
    assert.match(rotated.stdout, /previous valid until:/);
    assert.equal(rotated.stdout.includes(FIXTURE_TWO), false);
    assert.equal(rotated.commandLine.includes(FIXTURE_TWO), false, "the value must never be in argv");

    const afterRotate = run(["secret", "list", "--home", home, "--passphrase-file", pass]);
    const rows = afterRotate.stdout.trim().split("\n").filter((line) => line.includes("svc"));
    assert.equal(rows.length, 2, "rotation keeps the previous version during the overlap");
    assert.ok(rows.some((row) => row.includes("active")));
    assert.ok(rows.some((row) => row.includes("previous")));

    const removed = run(["secret", "remove", "--home", home, "--id", active.id, "--passphrase-file", pass]);
    assert.equal(removed.status, 0, removed.stderr);
    assert.match(removed.stdout, /secret removed:/);
    assert.match(run(["secret", "list", "--home", home, "--passphrase-file", pass]).stdout, /no secrets/);

    assert.deepEqual(scanFor(home, FIXTURE_ONE), [], "the value must not appear in any file");
    assert.deepEqual(scanFor(home, FIXTURE_TWO), [], "the value must not appear in any file");
    assert.equal(run(["receipts", "verify", "--home", home]).status, 0);
    const receipts = readFileSync(join(home, "receipts.jsonl"), "utf8");
    assert.match(receipts, /secret\.add|secret\.rotate|secret\.remove/);
  });

  it("refuses an unknown secret id and an unregistered service", () => {
    const { home, pass } = seedHome();
    const unknown = run(["secret", "remove", "--home", home, "--id", "sec_missing", "--passphrase-file", pass]);
    assert.equal(unknown.status, 1);
    assert.match(unknown.stderr, /no secret with id/);

    const badService = run(
      ["secret", "add", "--home", home, "--service", "nope", "--passphrase-file", pass],
      `${FIXTURE_ONE}\n`,
    );
    assert.equal(badService.status, 1);
    assert.match(badService.stderr, /not in the registry/);
    assert.deepEqual(scanFor(home, FIXTURE_ONE), []);
    assert.equal(statSync(join(home, "vault.charade")).mode & 0o777, 0o600);
  });
});
