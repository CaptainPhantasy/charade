import { readFileSync, statSync } from "node:fs";
import readline from "node:readline";
import { VaultError } from "../vault/vault.js";
import { USAGE } from "./usage.js";

/** A command-shape problem: exit code 2, usage on stderr, no state change. */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export function usageError(message: string, usage: string = USAGE): never {
  process.stderr.write(`${message}\n\n${usage}`);
  throw new UsageError(message);
}

/** Remove one `--name value` pair from args and return the value. */
export function takeOption(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) return undefined;
  args.splice(index, 2);
  return value;
}

/** Remove one flag from args and report whether it was present. */
export function takeFlag(args: string[], name: string): boolean {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

/** Remove every `--name value` pair, flattening comma-separated values. */
export function takeOptionList(args: string[], name: string): string[] {
  const values: string[] = [];
  for (;;) {
    const value = takeOption(args, name);
    if (value === undefined) break;
    values.push(...value.split(",").map((item) => item.trim()).filter(Boolean));
  }
  return values;
}

export function requireOption(args: string[], name: string, usage: string, context: string): string {
  const value = takeOption(args, name);
  if (!value) usageError(`${context}: ${name} is required`, usage);
  return value;
}

export function readPassphraseFile(file: string): string {
  const info = statSync(file);
  if ((info.mode & 0o077) !== 0) {
    throw new VaultError("passphrase file must not be readable by group or others");
  }
  if (info.size === 0) {
    throw new VaultError("passphrase file is empty");
  }
  return readFileSync(file, "utf8").replace(/\r?\n$/, "");
}

export function checkPassphrase(passphrase: string): void {
  if (passphrase.length < 12) {
    throw new VaultError("passphrase must be at least 12 characters");
  }
}

export async function passphraseFrom(args: string[], file: string | undefined): Promise<string> {
  return file ? readPassphraseFile(file) : readPassphrase();
}

export async function readPassphrase(): Promise<string> {
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

/**
 * Read a secret value without ever putting it in argv. A terminal gets a masked
 * prompt; a pipe gets one line from stdin (the trailing newline is removed).
 */
export async function readSecretValue(): Promise<string> {
  if (process.stdin.isTTY) {
    const value = await hiddenPrompt("Secret value: ");
    if (!value) throw new VaultError("secret value is empty");
    return value;
  }
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk as Buffer));
  const value = Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
  if (!value) throw new VaultError("no secret value was provided on stdin");
  return value;
}

export function hiddenPrompt(label: string): Promise<string> {
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
