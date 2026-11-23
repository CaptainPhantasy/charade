import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { ReceiptLog } from "../audit/receipts.js";
import { loadPolicy } from "../authority/store.js";
import { loadRegistry } from "../registry/registry.js";
import {
  findActiveSecret,
  openVault,
  putSecret,
  removeSecret,
  rotateSecret,
  VaultError,
  type OpenVault,
} from "../vault/vault.js";
import { USAGE } from "./usage.js";
import {
  checkPassphrase,
  passphraseFrom,
  readSecretValue,
  requireOption,
  takeOption,
  usageError,
} from "./util.js";

const SECRET_ACTIONS = new Set(["add", "list", "rotate", "remove"]);

export async function secretCommand(args: string[]): Promise<void> {
  const sub = args[1];
  if (!sub || !SECRET_ACTIONS.has(sub)) {
    usageError(`unknown secret command: ${sub ?? "(none)"}`, USAGE);
  }
  const home = requireOption(args, "--home", USAGE, `secret ${sub}`);
  if (sub === "list") {
    await listSecrets(home, args);
    return;
  }
  if (sub === "add") {
    await addSecret(home, args);
    return;
  }
  if (sub === "rotate") {
    await rotateSecretCommand(home, args);
    return;
  }
  await removeSecretCommand(home, args);
}

async function openFor(home: string, args: string[]): Promise<OpenVault> {
  const passphrase = await passphraseFrom(args, takeOption(args, "--passphrase-file"));
  checkPassphrase(passphrase);
  return openVault(home, passphrase);
}

function receiptLog(open: OpenVault): ReceiptLog {
  return new ReceiptLog(join(dirname(open.vaultPath), "receipts.jsonl"));
}

function requestId(): string {
  return `rq_${randomBytes(6).toString("hex")}`;
}

async function addSecret(home: string, args: string[]): Promise<void> {
  const serviceId = requireOption(args, "--service", USAGE, "secret add");
  const label = takeOption(args, "--label");
  const open = await openFor(home, args);
  assertServiceKnown(home, serviceId);
  if (findActiveSecret(open, serviceId)) {
    process.stderr.write(
      `service ${serviceId} already has an active secret; use \`charade secret rotate --id <id>\`\n`,
    );
    process.exitCode = 1;
    return;
  }
  const value = await readSecretValue();
  const next = putSecret(open, { serviceId, ...(label ? { label } : {}), value });
  const created = findActiveSecret(next, serviceId);
  receiptLog(next).append({
    actor: { type: "owner", id: "owner" },
    action: "secret.add",
    subject: serviceId,
    outcome: "ok",
    requestId: requestId(),
  });
  process.stdout.write(`secret added: ${created?.id ?? "unknown"}\n`);
  process.stdout.write(`service:      ${serviceId}\n`);
  process.stdout.write(`version:      ${created?.versionId ?? "unknown"}\n`);
  process.stdout.write(`status:       ${created?.status ?? "unknown"}\n`);
}

async function listSecrets(home: string, args: string[]): Promise<void> {
  const open = await openFor(home, args);
  const secrets = open.payload.secrets;
  if (secrets.length === 0) {
    process.stdout.write("no secrets\n");
    return;
  }
  process.stdout.write("id                     service          version                status    created\n");
  for (const secret of secrets) {
    process.stdout.write(
      `${secret.id.padEnd(22)} ${secret.serviceId.padEnd(16)} ${secret.versionId.padEnd(22)} ${secret.status.padEnd(9)} ${secret.createdAt}\n`,
    );
  }
}

async function rotateSecretCommand(home: string, args: string[]): Promise<void> {
  const secretId = requireOption(args, "--id", USAGE, "secret rotate");
  const overlapOption = takeOption(args, "--overlap");
  const open = await openFor(home, args);
  const target = open.payload.secrets.find(
    (secret) => secret.id === secretId && secret.status === "active",
  );
  if (!target) {
    process.stderr.write(`no active secret with id ${secretId}; run \`charade secret list\`\n`);
    process.exitCode = 1;
    return;
  }
  let overlap: number;
  if (overlapOption) {
    overlap = Number(overlapOption);
    if (!Number.isInteger(overlap) || overlap <= 0) {
      usageError("secret rotate: --overlap must be a positive integer", USAGE);
    }
  } else {
    overlap = loadPolicy(home).limits.rotationOverlapSeconds;
  }
  const value = await readSecretValue();
  const next = rotateSecret(open, secretId, value, overlap);
  const active = findActiveSecret(next, target.serviceId);
  const previous = next.payload.secrets.find(
    (secret) =>
      secret.id === secretId &&
      secret.versionId === target.versionId &&
      secret.status === "previous",
  );
  receiptLog(next).append({
    actor: { type: "owner", id: "owner" },
    action: "secret.rotate",
    subject: target.serviceId,
    outcome: "ok",
    requestId: requestId(),
  });
  process.stdout.write(`secret rotated:        ${secretId}\n`);
  process.stdout.write(`service:               ${target.serviceId}\n`);
  process.stdout.write(`active version:        ${active?.versionId ?? "unknown"}\n`);
  process.stdout.write(`previous version:      ${target.versionId}\n`);
  process.stdout.write(`previous valid until:  ${target.previousValidUntil ?? "unknown"}\n`);
}

async function removeSecretCommand(home: string, args: string[]): Promise<void> {
  const secretId = requireOption(args, "--id", USAGE, "secret remove");
  const open = await openFor(home, args);
  const target = open.payload.secrets.find((secret) => secret.id === secretId);
  if (!target) {
    process.stderr.write(`no secret with id ${secretId}; run \`charade secret list\`\n`);
    process.exitCode = 1;
    return;
  }
  const next = removeSecret(open, secretId);
  receiptLog(next).append({
    actor: { type: "owner", id: "owner" },
    action: "secret.remove",
    subject: target.serviceId,
    outcome: "ok",
    requestId: requestId(),
  });
  process.stdout.write(`secret removed: ${secretId}\n`);
  process.stdout.write(`service:        ${target.serviceId}\n`);
  process.stdout.write("Existing leases that pinned a version of this secret will be refused.\n");
}

/**
 * A secret for an unregistered service cannot be injected, so it is a
 * mistake worth naming now rather than at the first proxy call.
 */
function assertServiceKnown(home: string, serviceId: string): void {
  let services: readonly { id: string }[];
  try {
    services = loadRegistry(join(home, "registry.json"), { allowEmpty: true }).services;
  } catch {
    return;
  }
  if (services.length === 0) return;
  if (!services.some((service) => service.id === serviceId)) {
    throw new VaultError(
      `service ${serviceId} is not in the registry; run \`charade registry add-service\` first`,
    );
  }
}
