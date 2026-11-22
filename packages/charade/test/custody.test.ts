import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import {
  commandPath,
  macosKeychain,
  secretService,
  systemdCreds,
  type CommandRunner,
} from "../src/vault/custody.js";

interface Call {
  readonly command: string;
  readonly args: readonly string[];
  readonly input?: Buffer;
}

function runnerWith(handler: (call: Call) => { status: number; stdout?: Buffer }): {
  runner: CommandRunner;
  calls: Call[];
} {
  const calls: Call[] = [];
  return {
    calls,
    runner: {
      run(command, args, input) {
        const call = { command, args, ...(input ? { input } : {}) };
        calls.push(call);
        const result = handler(call);
        return {
          status: result.status,
          stdout: result.stdout ?? Buffer.alloc(0),
          stderr: Buffer.alloc(0),
        };
      },
    },
  };
}

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "charade-custody-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("macOS Keychain adapter", () => {
  it("uses expect with a 0600 secret file, never the secret in argv", () => {
    let capturedSecretFile = "";
    let capturedScript = "";
    const { runner, calls } = runnerWith((call) => {
      capturedSecretFile = readFileSync(call.args[2] ?? "", "utf8");
      capturedScript = readFileSync(call.args[1] ?? "", "utf8");
      return { status: 0 };
    });
    const adapter = macosKeychain(runner, "test.service");
    const key = Buffer.alloc(32, 0x41);
    adapter.set("acct", key);
    assert.equal(calls[0]?.command, "expect");
    assert.equal(calls[0]?.args[3], "acct");
    assert.equal(calls[0]?.args[4], "test.service");
    assert.equal(calls[0]?.args.includes(key.toString("utf8")), false);
    assert.equal(capturedSecretFile, key.toString("base64url"));
    assert.match(capturedScript, /security add-generic-password/);
    assert.equal(capturedScript.includes(key.toString("utf8")), false);
  });

  it("reads and decodes only a Charade wrapping key", () => {
    const key = Buffer.alloc(32, 0x41);
    const encoded = key.toString("base64url");
    const { runner } = runnerWith(() => ({ status: 0, stdout: Buffer.from(`${encoded}\n`) }));
    const adapter = macosKeychain(runner, "test.service");
    assert.deepEqual(adapter.get("acct"), key);
  });

  it("fails without echoing command output", () => {
    const { runner } = runnerWith(() => ({ status: 1, stdout: Buffer.from("top-secret") }));
    const adapter = macosKeychain(runner, "test.service");
    assert.throws(
      () => adapter.set("acct", Buffer.from("top-secret")),
      (error: unknown) => !String(error).includes("top-secret"),
    );
  });
});

describe("Secret Service adapter", () => {
  it("uses secret-tool with stdin, lookup, and clear", () => {
    let stored = "";
    const { runner, calls } = runnerWith((call) => {
      if (call.args[0] === "store") stored = call.input?.toString() ?? "";
      if (call.args[0] === "lookup") return { status: 0, stdout: Buffer.from(stored) };
      return { status: 0 };
    });
    const adapter = secretService(runner, "test.service");
    adapter.set("acct", Buffer.from("value"));
    assert.equal(calls[0]?.command, "secret-tool");
    assert.deepEqual(calls[0]?.args, ["store", "--label=Charade", "service", "test.service", "account", "acct"]);
    assert.equal(adapter.get("acct").toString(), "value");
    adapter.delete("acct");
    assert.deepEqual(calls.at(-1)?.args, ["clear", "service", "test.service", "account", "acct"]);
  });
});

describe("systemd-creds adapter", () => {
  it("encrypts to a 0600 file, decrypts through a temp file, and deletes", () => {
    const store = tempDir();
    const { runner } = runnerWith((call) => {
      if (call.args[0] === "encrypt") {
        const input = call.args[call.args.length - 2];
        const output = call.args[call.args.length - 1];
        if (input && output) writeFileSync(output, readFileSync(input), { mode: 0o600 });
      }
      if (call.args[0] === "decrypt") {
        const output = call.args[call.args.length - 1];
        if (output) writeFileSync(output, Buffer.from("value"), { mode: 0o600 });
      }
      return { status: 0 };
    });
    const adapter = systemdCreds(store, runner, "test.service");
    adapter.set("acct", Buffer.from("value"));
    assert.equal(existsSync(join(store, "acct.cred")), true);
    assert.equal(adapter.get("acct").toString(), "value");
    adapter.delete("acct");
    assert.equal(existsSync(join(store, "acct.cred")), false);
  });
});

describe("command lookup", () => {
  it("finds a real command and reports an absent one", () => {
    assert.equal(typeof commandPath("sh"), "string");
    assert.equal(commandPath("definitely-not-a-charade-command"), undefined);
  });
});
