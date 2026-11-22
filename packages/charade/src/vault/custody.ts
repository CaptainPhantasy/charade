import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const CUSTODY_SERVICE = "dev.floydslabs.charade";

export type CustodyId = "macos-keychain" | "secret-service" | "systemd-creds";

export interface CommandResult {
  readonly status: number | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
}

export interface CommandRunner {
  run(command: string, args: readonly string[], input?: Buffer): CommandResult;
}

export interface CustodyAvailability {
  readonly ok: boolean;
  readonly reason?: string;
}

export interface CustodyAdapter {
  readonly id: CustodyId;
  readonly service: string;
  available(): CustodyAvailability;
  set(account: string, secret: Buffer): void;
  get(account: string): Buffer;
  delete(account: string): void;
}

export class CustodyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CustodyError";
  }
}

export const defaultRunner: CommandRunner = {
  run(command, args, input): CommandResult {
    const result = spawnSync(command, args, {
      input,
      encoding: "buffer",
      maxBuffer: 1024 * 1024,
    });
    return {
      status: result.status,
      stdout: result.stdout ?? Buffer.alloc(0),
      stderr: result.stderr ?? Buffer.alloc(0),
    };
  },
};

export function commandPath(name: string, envPath = process.env.PATH ?? ""): string | undefined {
  for (const directory of envPath.split(":").filter(Boolean)) {
    const candidate = join(directory, name);
    try {
      if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
    } catch {
      // Keep looking.
    }
  }
  return undefined;
}

const KEYCHAIN_EXPECT_SCRIPT = `set timeout 20
set fh [open [lindex $argv 0] r]
set secret [read $fh]
close $fh
spawn security add-generic-password -a [lindex $argv 1] -s [lindex $argv 2] -U -w
expect {
  "password data for new item:" {}
  timeout { exit 2 }
}
send -- "$secret\\r"
expect {
  "retype password for new item:" { send -- "$secret\\r" }
  timeout {}
}
expect eof
set result [wait]
exit [lindex $result 3]
`;

export function macosKeychain(
  runner: CommandRunner = defaultRunner,
  service = CUSTODY_SERVICE,
): CustodyAdapter {
  return {
    id: "macos-keychain",
    service,
    available(): CustodyAvailability {
      if (process.platform !== "darwin") {
        return { ok: false, reason: "macOS Keychain is only available on macOS" };
      }
      if (!commandPath("security")) {
        return { ok: false, reason: "the security command was not found" };
      }
      if (!commandPath("expect")) {
        return {
          ok: false,
          reason: "expect is needed to answer the Keychain prompt without putting the key in argv",
        };
      }
      return { ok: true };
    },
    set(account: string, secret: Buffer): void {
      // The 32-byte KEK is stored as base64url so expect can send it safely.
      // It travels in a 0600 temp file, never in argv. All output is ignored:
      // a failed prompt path must not echo the key into an error.
      const work = mkdtempSync(join(tmpdir(), "charade-keychain-"));
      const secretFile = join(work, "secret");
      const scriptFile = join(work, "add.exp");
      try {
        writeFileSync(secretFile, Buffer.from(secret.toString("base64url"), "utf8"), {
          mode: 0o600,
        });
        writeFileSync(scriptFile, KEYCHAIN_EXPECT_SCRIPT, { mode: 0o600 });
        const result = runner.run("expect", [
          "-f",
          scriptFile,
          secretFile,
          account,
          service,
        ]);
        if (result.status !== 0) {
          throw new CustodyError("macOS Keychain did not store the item");
        }
      } finally {
        rmSync(work, { recursive: true, force: true });
      }
    },
    get(account: string): Buffer {
      const result = runner.run("security", [
        "find-generic-password",
        "-a",
        account,
        "-s",
        service,
        "-w",
      ]);
      if (result.status !== 0) {
        throw new CustodyError("macOS Keychain did not return the item");
      }
      const text = trimTrailingNewline(result.stdout).toString("utf8").trim();
      const decoded = Buffer.from(text, "base64url");
      if (decoded.length !== 32) {
        throw new CustodyError("macOS Keychain item is not a Charade wrapping key");
      }
      return decoded;
    },
    delete(account: string): void {
      runner.run("security", ["delete-generic-password", "-a", account, "-s", service]);
    },
  };
}

export function secretService(
  runner: CommandRunner = defaultRunner,
  service = CUSTODY_SERVICE,
): CustodyAdapter {
  return {
    id: "secret-service",
    service,
    available(): CustodyAvailability {
      if (!commandPath("secret-tool")) {
        return {
          ok: false,
          reason:
            "secret-tool is not installed; install libsecret-tools or use the passphrase fallback",
        };
      }
      return { ok: true };
    },
    set(account: string, secret: Buffer): void {
      const result = runner.run(
        "secret-tool",
        ["store", "--label=Charade", "service", service, "account", account],
        secret,
      );
      if (result.status !== 0) {
        throw new CustodyError("Secret Service did not store the item");
      }
    },
    get(account: string): Buffer {
      const result = runner.run("secret-tool", [
        "lookup",
        "service",
        service,
        "account",
        account,
      ]);
      if (result.status !== 0) {
        throw new CustodyError("Secret Service did not return the item");
      }
      return result.stdout;
    },
    delete(account: string): void {
      runner.run("secret-tool", ["clear", "service", service, "account", account]);
    },
  };
}

export function systemdCreds(
  storeDirectory: string,
  runner: CommandRunner = defaultRunner,
  service = CUSTODY_SERVICE,
): CustodyAdapter {
  const fileFor = (account: string): string =>
    join(storeDirectory, `${account.replace(/[^A-Za-z0-9_.-]/g, "_")}.cred`);

  return {
    id: "systemd-creds",
    service,
    available(): CustodyAvailability {
      if (process.platform !== "linux") {
        return { ok: false, reason: "systemd-creds is only available on Linux" };
      }
      if (!commandPath("systemd-creds")) {
        return { ok: false, reason: "systemd-creds was not found" };
      }
      return { ok: true };
    },
    set(account: string, secret: Buffer): void {
      mkdirSync(storeDirectory, { recursive: true, mode: 0o700 });
      chmodSync(storeDirectory, 0o700);
      const work = mkdtempSync(join(tmpdir(), "charade-cred-"));
      const input = join(work, "plain");
      const output = fileFor(account);
      try {
        writeFileSync(input, secret, { mode: 0o600 });
        const result = runner.run("systemd-creds", [
          "encrypt",
          `--name=charade-${account.replace(/[^A-Za-z0-9_.-]/g, "_")}`,
          input,
          output,
        ]);
        if (result.status !== 0) {
          throw new CustodyError("systemd-creds did not encrypt the item");
        }
        chmodSync(output, 0o600);
      } finally {
        rmSync(work, { recursive: true, force: true });
      }
    },
    get(account: string): Buffer {
      const input = fileFor(account);
      if (!existsSync(input)) throw new CustodyError("systemd-creds item was not found");
      const work = mkdtempSync(join(tmpdir(), "charade-cred-"));
      const output = join(work, "plain");
      try {
        const result = runner.run("systemd-creds", ["decrypt", input, output]);
        if (result.status !== 0) {
          throw new CustodyError("systemd-creds did not decrypt the item");
        }
        return readFileSync(output);
      } finally {
        rmSync(work, { recursive: true, force: true });
      }
    },
    delete(account: string): void {
      try {
        unlinkSync(fileFor(account));
      } catch {
        // Already absent.
      }
    },
  };
}

export function detectCustodyAdapters(
  runner: CommandRunner = defaultRunner,
  systemdStore = join(process.env.HOME ?? ".", ".charade", "custody"),
): readonly CustodyAdapter[] {
  return [
    macosKeychain(runner),
    secretService(runner),
    systemdCreds(systemdStore, runner),
  ];
}

function trimTrailingNewline(value: Buffer): Buffer {
  let end = value.length;
  if (end > 0 && value[end - 1] === 0x0a) end -= 1;
  if (end > 0 && value[end - 1] === 0x0d) end -= 1;
  return value.subarray(0, end);
}
