#!/usr/bin/env node
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import readline from "node:readline";
import { PRODUCT_VERSION, protocolString } from "../core/version.js";
import { initVault, vaultPaths, VaultError } from "../vault/vault.js";

const USAGE = `CHARADE ${PRODUCT_VERSION} (protocol ${protocolString()})

Usage:
  charade init --home <dir> [--passphrase-file <file>] [--dry-run]
  charade --version

The vault is encrypted at rest. The passphrase is never accepted from an
environment variable; use a file with mode 0600 or the interactive prompt.
`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    process.stdout.write(USAGE);
    return;
  }
  if (args.includes("--version") || args.includes("-V")) {
    process.stdout.write(`${PRODUCT_VERSION}\n`);
    return;
  }
  const command = args[0];
  if (command !== "init") {
    process.stderr.write(`unknown command: ${command}\n\n${USAGE}`);
    process.exitCode = 2;
    return;
  }

  const home = takeOption(args, "--home");
  if (!home) {
    process.stderr.write("init: --home <dir> is required\n");
    process.exitCode = 2;
    return;
  }
  const dryRun = args.includes("--dry-run");
  const passphraseFile = takeOption(args, "--passphrase-file");
  const paths = vaultPaths(home);

  if (dryRun) {
    process.stdout.write("CHARADE init — dry run, nothing will be written\n\n");
    process.stdout.write(`  home:        ${paths.home}\n`);
    process.stdout.write(`  vault:       ${paths.vault}\n`);
    process.stdout.write(`  backups:     ${paths.backups}\n`);
    process.stdout.write("  key slots:   passphrase + recovery\n");
    process.stdout.write("  cipher:      AES-256-GCM\n");
    process.stdout.write("  kdf:         scrypt N=2^15 r=8 p=1 maxmem=64MiB\n");
    process.stdout.write("  file modes:  directory 0700, vault 0600\n");
    process.stdout.write("  network:     none\n");
    process.stdout.write("\nNo passphrase was read. No file was created.\n");
    return;
  }

  const passphrase = passphraseFile
    ? readPassphraseFile(passphraseFile)
    : await readPassphrase();
  if (passphrase.length < 12) {
    process.stderr.write("init: passphrase must be at least 12 characters\n");
    process.exitCode = 2;
    return;
  }

  try {
    const result = initVault({ home, passphrase });
    process.stdout.write(`vault created: ${result.vaultPath}\n`);
    process.stdout.write(`vault id:      ${result.vaultId}\n\n`);
    process.stdout.write("RECOVERY KEY — shown once, store it separately from the passphrase:\n\n");
    process.stdout.write(`  ${result.recoveryKey}\n\n`);
    process.stdout.write("If both the passphrase and this key are lost, the vault cannot be opened.\n");
  } catch (error) {
    if (error instanceof VaultError) {
      process.stderr.write(`init: ${error.message}\n`);
      process.exitCode = 1;
      return;
    }
    throw error;
  }
}

function readPassphraseFile(file: string): string {
  const info = statSync(file);
  if ((info.mode & 0o077) !== 0) {
    throw new VaultError("passphrase file must not be readable by group or others");
  }
  if (info.size === 0) {
    throw new VaultError("passphrase file is empty");
  }
  return readFileSync(file, "utf8").replace(/\r?\n$/, "");
}

function takeOption(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) return undefined;
  args.splice(index, 2);
  return value;
}

async function readPassphrase(): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new VaultError(
      "no TTY for the passphrase prompt; use --passphrase-file with mode 0600",
    );
  }
  const first = await hiddenPrompt("Passphrase: ");
  const second = await hiddenPrompt("Passphrase again: ");
  if (first !== second) {
    throw new VaultError("passphrases do not match");
  }
  return first;
}

function hiddenPrompt(label: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });
    const mutable = rl as unknown as { _writeToOutput?: (text: string) => void };
    mutable._writeToOutput = () => undefined;
    process.stdout.write(label);
    rl.question("", (answer) => {
      rl.close();
      process.stdout.write("\n");
      resolve(answer);
    });
  });
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`charade: ${message}\n`);
  process.exitCode = 1;
});
