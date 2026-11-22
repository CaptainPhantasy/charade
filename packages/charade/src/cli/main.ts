#!/usr/bin/env node
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import readline from "node:readline";
import { PRODUCT_VERSION, protocolString } from "../core/version.js";
import {
  backupVault,
  drillBackup,
  getOwnerKeyPair,
  initVault,
  openVault,
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
import {
  addGrant,
  createPolicy,
  loadGrants,
  loadPolicy,
  policyPath,
  revokeGrant,
  type PolicyOverrides,
} from "../authority/store.js";
import {
  DEFAULT_GATES,
  DEFAULT_LIMITS,
  policyHash,
} from "../authority/policy.js";
import { parseDuration, signGrant } from "../authority/grants.js";
import { publicKeyFingerprint } from "../authority/keys.js";
import { loadRegistry } from "../registry/registry.js";
import { ReceiptLog, verifyReceipts } from "../audit/receipts.js";

const USAGE = `CHARADE ${PRODUCT_VERSION} (protocol ${protocolString()})

Usage:
  charade init --home <dir> [--passphrase-file <file>] [--custody <backend>] [--dry-run]
  charade vault backup --home <dir>
  charade vault recovery-kit --home <dir> --out <file> [--passphrase-file <file>]
  charade vault drill --backup <file> --kit <file>
  charade policy init --home <dir> [--accept-defaults] [--dry-run] [--passphrase-file <file>]
  charade policy show --home <dir>
  charade grant create --home <dir> --consumer <id> --services <ids> --duration <preset> [--accept]
  charade grant list --home <dir>
  charade grant revoke --home <dir> --id <grant> [--accept]
  charade registry validate --home <dir>
  charade receipts verify --home <dir>
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
  if (command === "policy") {
    await policyCommand(args);
    return;
  }
  if (command === "grant") {
    await grantCommand(args);
    return;
  }
  if (command === "registry") {
    await registryCommand(args);
    return;
  }
  if (command === "receipts") {
    await receiptsCommand(args);
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

async function policyCommand(args: string[]): Promise<void> {
  const sub = args[1];
  const home = takeOption(args, "--home");
  if (!home) usageError("policy: --home <dir> is required");
  if (sub === "init") {
    const policyFile = takeOption(args, "--policy-file");
    const accept = args.includes("--accept-defaults") || Boolean(policyFile);
    const dryRun = args.includes("--dry-run");
    if (!accept) {
      process.stdout.write("Proposed owner policy — nothing is signed until you accept:\n\n");
      process.stdout.write(`${JSON.stringify({ limits: DEFAULT_LIMITS, gates: DEFAULT_GATES }, null, 2)}\n\n`);
      process.stdout.write("Review every limit and gate. Rerun with --accept-defaults to sign them,\n");
      process.stdout.write("or supply --policy-file with only the limits/gates you changed. No policy was written.\n");
      process.exitCode = 2;
      return;
    }
    const overrides = policyFile ? readPolicyOverrides(policyFile) : {};
    if (existsSync(policyPath(home))) {
      throw new VaultError("an owner policy already exists; refusing to overwrite it");
    }
    if (dryRun) {
      process.stdout.write("CHARADE policy init — dry run, nothing will be signed\n\n");
      process.stdout.write(`  policy:  ${policyPath(home)}\n`);
      process.stdout.write(`  limits:  ${JSON.stringify({ ...DEFAULT_LIMITS, ...(overrides.limits ?? {}) })}\n`);
      process.stdout.write(`  gates:   ${JSON.stringify({ ...DEFAULT_GATES, ...(overrides.gates ?? {}) })}\n`);
      process.stdout.write("\nNo passphrase was read. No policy was written.\n");
      return;
    }
    const passphrase = await passphraseFrom(args, takeOption(args, "--passphrase-file"));
    checkPassphrase(passphrase);
    const open = openVault(home, passphrase);
    const policy = createPolicy(open, overrides);
    const owner = getOwnerKeyPair(open);
    const log = new ReceiptLog(join(dirname(open.vaultPath), "receipts.jsonl"));
    const receipt = log.append({
      actor: { type: "owner", id: "owner" },
      action: "policy.accept",
      subject: policyHash(policy),
      outcome: "ok",
      requestId: `rq_${randomBytes(6).toString("hex")}`,
    });
    process.stdout.write(`policy signed:   ${policyPath(home)}\n`);
    process.stdout.write(`policy hash:     ${policyHash(policy)}\n`);
    process.stdout.write(`owner:           ${publicKeyFingerprint(owner.publicKey)}\n`);
    process.stdout.write(`receipt:         ${receipt.receiptId}\n`);
    return;
  }
  if (sub === "show") {
    const policy = loadPolicy(home);
    process.stdout.write(`policy: ${policyPath(home)}\n`);
    process.stdout.write(`hash:   ${policyHash(policy)}\n`);
    process.stdout.write(`owner:  ${publicKeyFingerprint(policy.ownerPublicKey)}\n\n`);
    process.stdout.write(`${JSON.stringify({ limits: policy.limits, gates: policy.gates, custody: policy.custody }, null, 2)}\n`);
    return;
  }
  usageError(`unknown policy command: ${sub ?? "(none)"}`);
}

function readPolicyOverrides(file: string): PolicyOverrides {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    throw new VaultError("policy file is not valid JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new VaultError("policy file must be a JSON object");
  }
  const record = value as Record<string, unknown>;
  for (const forbidden of ["ownerPublicKey", "signature", "schema", "policyVersion"]) {
    if (forbidden in record) {
      throw new VaultError(`policy file may not set ${forbidden}; the vault owns it`);
    }
  }
  const overrides: PolicyOverrides = {
    ...(isRecord(record.limits) ? { limits: record.limits as PolicyOverrides["limits"] } : {}),
    ...(isRecord(record.gates) ? { gates: record.gates as PolicyOverrides["gates"] } : {}),
    ...(isRecord(record.custody) ? { custody: record.custody as PolicyOverrides["custody"] } : {}),
  };
  return overrides;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function grantCommand(args: string[]): Promise<void> {
  const sub = args[1];
  const home = takeOption(args, "--home");
  if (!home) usageError("grant: --home <dir> is required");
  if (sub === "create") {
    const consumerId = takeOption(args, "--consumer");
    const services = (takeOption(args, "--services") ?? "").split(",").filter(Boolean);
    const duration = takeOption(args, "--duration");
    const deviceId = takeOption(args, "--device");
    const methods = (takeOption(args, "--methods") ?? "GET").split(",").filter(Boolean);
    const paths = (takeOption(args, "--paths") ?? "/*").split(",").filter(Boolean);
    const calls = Number(takeOption(args, "--calls") ?? "1000");
    const accept = args.includes("--accept");
    if (!consumerId || !duration || services.length === 0) {
      usageError("grant create: --consumer, --services, and --duration are required");
    }
    if (!Number.isInteger(calls) || calls <= 0) usageError("grant create: --calls must be a positive integer");
    const durationSeconds = parseDuration(duration);
    if (!accept) {
      process.stdout.write("Proposed grant — nothing is signed until you accept:\n\n");
      process.stdout.write(`  consumer: ${consumerId}\n`);
      process.stdout.write(`  services: ${services.join(", ")}\n`);
      process.stdout.write(`  methods:  ${methods.join(", ")}\n`);
      process.stdout.write(`  paths:    ${paths.join(", ")}\n`);
      process.stdout.write(`  duration: ${durationSeconds}s\n`);
      process.stdout.write(`  calls:    ${calls}/day\n`);
      process.stdout.write("  env:      not allowed\n");
      process.stdout.write("  hard stops: money, publish, send, delete, permission change\n\n");
      process.stdout.write("Rerun with --accept to sign this grant. No grant was written.\n");
      process.exitCode = 2;
      return;
    }
    const passphrase = await passphraseFrom(args, takeOption(args, "--passphrase-file"));
    checkPassphrase(passphrase);
    const open = openVault(home, passphrase);
    const policy = loadPolicy(home);
    const registry = loadRegistry(join(home, "registry.json"));
    const consumer = registry.consumers.find((item) => item.id === consumerId);
    if (!consumer) throw new VaultError(`consumer ${consumerId} is not in the registry`);
    const missing = services.filter((service) => !consumer.services.includes(service));
    if (missing.length > 0) {
      throw new VaultError(`consumer ${consumerId} is not registered for: ${missing.join(", ")}`);
    }
    const grant = signGrant(getOwnerKeyPair(open).privateKey, policy, {
      consumerId,
      ...(deviceId ? { deviceId } : {}),
      services,
      methods,
      paths,
      durationSeconds,
      ceilings: { callsPerDay: calls },
      hardStops: policy.gates.hardStops,
      envAllowed: false,
    });
    addGrant(home, grant);
    const log = new ReceiptLog(join(dirname(open.vaultPath), "receipts.jsonl"));
    const receipt = log.append({
      actor: { type: "owner", id: "owner" },
      action: "grant.create",
      subject: grant.grantId,
      outcome: "ok",
      requestId: `rq_${randomBytes(6).toString("hex")}`,
    });
    process.stdout.write(`grant signed: ${grant.grantId}\n`);
    process.stdout.write(`expires:      ${grant.expiresAt}\n`);
    process.stdout.write(`receipt:      ${receipt.receiptId}\n`);
    return;
  }
  if (sub === "list") {
    const grants = loadGrants(home);
    if (grants.length === 0) {
      process.stdout.write("no grants\n");
      return;
    }
    for (const grant of grants) {
      process.stdout.write(`${grant.grantId}  ${grant.consumerId}  ${grant.services.join(",")}  expires ${grant.expiresAt}\n`);
    }
    return;
  }
  if (sub === "revoke") {
    const grantId = takeOption(args, "--id");
    if (!grantId) usageError("grant revoke: --id is required");
    if (!args.includes("--accept")) {
      process.stdout.write(`About to revoke ${grantId}. Rerun with --accept; nothing was changed.\n`);
      process.exitCode = 2;
      return;
    }
    if (!revokeGrant(home, grantId)) throw new VaultError(`grant ${grantId} was not found`);
    const log = new ReceiptLog(join(home, "receipts.jsonl"));
    log.append({
      actor: { type: "owner", id: "owner" },
      action: "grant.revoke",
      subject: grantId,
      outcome: "ok",
      requestId: `rq_${randomBytes(6).toString("hex")}`,
    });
    process.stdout.write(`revoked: ${grantId}\n`);
    return;
  }
  usageError(`unknown grant command: ${sub ?? "(none)"}`);
}

async function registryCommand(args: string[]): Promise<void> {
  const sub = args[1];
  const home = takeOption(args, "--home");
  if (!home) usageError("registry: --home <dir> is required");
  if (sub === "validate") {
    const registry = loadRegistry(join(home, "registry.json"));
    process.stdout.write(
      `registry ok: ${registry.services.length} services, ${registry.consumers.length} consumers, ${registry.devices.length} devices\n`,
    );
    return;
  }
  usageError(`unknown registry command: ${sub ?? "(none)"}`);
}

async function receiptsCommand(args: string[]): Promise<void> {
  const sub = args[1];
  const home = takeOption(args, "--home");
  if (!home) usageError("receipts: --home <dir> is required");
  if (sub === "verify") {
    const result = verifyReceipts(join(home, "receipts.jsonl"));
    if (!result.ok) {
      process.stderr.write(`receipt chain broken at record ${result.brokenAt ?? "unknown"}\n`);
      process.exitCode = 1;
      return;
    }
    process.stdout.write(`receipt chain ok: ${result.count} records\n`);
    process.stdout.write(`head: ${result.headHash || "(empty)"}\n`);
    return;
  }
  usageError(`unknown receipts command: ${sub ?? "(none)"}`);
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
