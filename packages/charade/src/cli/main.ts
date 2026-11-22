#!/usr/bin/env node
import { readFileSync, statSync } from "node:fs";
import readline from "node:readline";
import { PRODUCT_VERSION, protocolString } from "../core/version.js";
import {
  backupVault,
  drillBackup,
  initVault,
  readRecoveryKit,
  rekeyRecovery,
  vaultPaths,
  VaultError,
} from "../vault/vault.js";
import {
  detectCustodyAdapters,
  type CustodyAdapter,
  type CustodyId,
} from "../vault/custody.js";

const USAGE = `CHARADE ${PRODUCT_VERSION} (protocol ${protocolString()})

Usage:
  charade init --home <dir> [--passphrase-file <file>] [--custody <backend>] [--dry-run]
  charade vault backup --home <dir>
  charade vault recovery-kit --home <dir> --out <file> [--passphrase-file <file>]
  charade vault drill --backup <file> --kit <file>
  charade --version

Custody backends: macos-keychain, secret-service, systemd-creds.
The default is the passphrase slot plus a recovery key. The passphrase is never
accepted from an environment variable; use a file with mode 0600 or the prompt.
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
  if (command === "init") {
    await initCommand(args);
    return;
  }
  if (command === "vault") {
    await vaultCommand(args);
    return;
  }
  process.stderr.write(`unknown command: ${command}\n\n${USAGE}`);
  process.exitCode = 2;
}

async function initCommand(args: string[]): Promise<void> {
  const home = takeOption(args, "--home");
  if (!home) {
    process.stderr.write("init: --home <dir> is required\n");
    process.exitCode = 2;
    return;
  }
  const dryRun = args.includes("--dry-run");
  const passphraseFile = takeOption(args, "--passphrase-file");
  const custodyName = takeOption(args, "--custody");
  const paths = vaultPaths(home);
  const adapter = custodyName ? resolveCustody(custodyName, !dryRun) : undefined;

  if (dryRun) {
    process.stdout.write("CHARADE init — dry run, nothing will be written\n\n");
    process.stdout.write(`  home:        ${paths.home}\n`);
    process.stdout.write(`  vault:       ${paths.vault}\n`);
    process.stdout.write(`  backups:     ${paths.backups}\n`);
    process.stdout.write("  key slots:   passphrase + recovery");
    process.stdout.write(adapter ? ` + ${adapter.id}\n` : "\n");
    process.stdout.write("  cipher:      AES-256-GCM\n");
    process.stdout.write("  kdf:         scrypt N=2^15 r=8 p=1 maxmem=64MiB\n");
    process.stdout.write("  file modes:  directory 0700, vault 0600\n");
    process.stdout.write("  network:     none\n");
    if (adapter) {
      const availability = adapter.available();
      process.stdout.write(
        `  custody:     ${adapter.id} — ${availability.ok ? "available" : `unavailable: ${availability.reason}`}\n`,
      );
    }
    process.stdout.write("\nNo passphrase was read. No file was created.\n");
    return;
  }

  const passphrase = await passphraseFrom(args, passphraseFile);
  checkPassphrase(passphrase);
  const result = initVault({ home, passphrase, custodyAdapter: adapter });
  process.stdout.write(`vault created: ${result.vaultPath}\n`);
  process.stdout.write(`vault id:      ${result.vaultId}\n`);
  if (adapter) process.stdout.write(`custody slot:  ${adapter.id}\n`);
  process.stdout.write("\nRECOVERY KEY — shown once, store it separately from the passphrase:\n\n");
  process.stdout.write(`  ${result.recoveryKey}\n\n`);
  process.stdout.write("If both the passphrase and this key are lost, the vault cannot be opened.\n");
}

async function vaultCommand(args: string[]): Promise<void> {
  const sub = args[1];
  if (sub === "backup") {
    const home = takeOption(args, "--home");
    if (!home) usageError("vault backup: --home <dir> is required");
    const path = backupVault(home);
    process.stdout.write(`backup written: ${path}\n`);
    return;
  }
  if (sub === "recovery-kit") {
    const home = takeOption(args, "--home");
    const out = takeOption(args, "--out");
    if (!home || !out) usageError("vault recovery-kit: --home and --out are required");
    const passphrase = await passphraseFrom(args, takeOption(args, "--passphrase-file"));
    checkPassphrase(passphrase);
    const result = rekeyRecovery(home, passphrase, out);
    process.stdout.write(`recovery kit written: ${result.kitPath}\n`);
    process.stdout.write(`vault id:             ${result.vaultId}\n`);
    process.stdout.write(`revision:             ${result.revision}\n`);
    process.stdout.write("The kit contains the new recovery key. It replaces the previous recovery slot.\n");
    return;
  }
  if (sub === "drill") {
    const backup = takeOption(args, "--backup");
    const kit = takeOption(args, "--kit");
    if (!backup || !kit) usageError("vault drill: --backup and --kit are required");
    const recoveryKey = readRecoveryKit(kit);
    const result = drillBackup(backup, recoveryKey);
    process.stdout.write(`drill ok: vault ${result.vaultId}, revision ${result.revision}\n`);
    process.stdout.write(`checked:  ${result.checkedAt}\n`);
    return;
  }
  usageError(`unknown vault command: ${sub ?? "(none)"}`);
}

function resolveCustody(name: string, requireAvailable = true): CustodyAdapter {
  const aliases: Record<string, CustodyId> = {
    keychain: "macos-keychain",
    "macos-keychain": "macos-keychain",
    "secret-service": "secret-service",
    "systemd-creds": "systemd-creds",
  };
  const id = aliases[name];
  const adapter = detectCustodyAdapters().find((item) => item.id === id);
  if (!adapter) {
    throw new VaultError(
      `unknown custody backend "${name}"; use macos-keychain, secret-service, or systemd-creds`,
    );
  }
  const availability = adapter.available();
  if (requireAvailable && !availability.ok) {
    throw new VaultError(
      `custody backend ${adapter.id} is unavailable: ${availability.reason ?? "no reason given"}`,
    );
  }
  return adapter;
}

async function passphraseFrom(args: string[], file: string | undefined): Promise<string> {
  return file ? readPassphraseFile(file) : readPassphrase();
}

function checkPassphrase(passphrase: string): void {
  if (passphrase.length < 12) {
    throw new VaultError("passphrase must be at least 12 characters");
  }
}

class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

function usageError(message: string): never {
  process.stderr.write(`${message}\n\n${USAGE}`);
  throw new UsageError(message);
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
  if (error instanceof UsageError) {
    process.exitCode = 2;
    return;
  }
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`charade: ${message}\n`);
  process.exitCode = 1;
});
