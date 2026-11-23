import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateOwnerKeyPair } from "../authority/keys.js";
import {
  addConsumer,
  addDevice,
  addService,
  loadRegistry,
  registryPath,
  type AuthType,
  type DeviceRecord,
  type ServiceRecord,
} from "../registry/registry.js";
import { VaultError } from "../vault/vault.js";
import { USAGE } from "./usage.js";
import {
  requireOption,
  takeOption,
  takeOptionList,
  usageError,
} from "./util.js";

const AUTH_TYPES: ReadonlySet<string> = new Set(["header", "basic", "query", "oauth2"]);

export async function registryCommand(args: string[]): Promise<void> {
  const sub = args[1];
  const home = requireOption(args, "--home", USAGE, `registry ${sub ?? ""}`.trim());
  const path = registryPath(home);
  if (sub === "validate") {
    const registry = loadRegistry(path);
    process.stdout.write(
      `registry ok: ${registry.services.length} services, ${registry.consumers.length} consumers, ${registry.devices.length} devices\n`,
    );
    return;
  }
  if (sub === "add-service") {
    addServiceCommand(path, args);
    return;
  }
  if (sub === "add-consumer") {
    addConsumerCommand(path, args);
    return;
  }
  if (sub === "add-device") {
    addDeviceCommand(path, args);
    return;
  }
  usageError(`unknown registry command: ${sub ?? "(none)"}`, USAGE);
}

export async function deviceCommand(args: string[]): Promise<void> {
  const sub = args[1];
  if (sub !== "enroll") usageError(`unknown device command: ${sub ?? "(none)"}`, USAGE);
  const home = requireOption(args, "--home", USAGE, "device enroll");
  const consumerId = requireOption(args, "--consumer", USAGE, "device enroll");
  const deviceId = requireOption(args, "--id", USAGE, "device enroll");
  const out = requireOption(args, "--out", USAGE, "device enroll");

  if (existsSync(out)) {
    throw new VaultError(`refusing to overwrite the existing device file ${out}`);
  }
  const registry = loadRegistry(registryPath(home));
  const consumer = registry.consumers.find((item) => item.id === consumerId);
  if (!consumer) {
    throw new VaultError(
      `consumer ${consumerId} is not in the registry; run \`charade registry add-consumer\` first`,
    );
  }

  const keys = generateOwnerKeyPair();
  const device: DeviceRecord = {
    id: deviceId,
    consumerId,
    publicKey: keys.publicKey,
    createdAt: new Date().toISOString(),
  };
  addDevice(registryPath(home), device);
  writeFileSync(
    out,
    `${JSON.stringify(
      {
        schema: "charade.device/1",
        deviceId,
        consumerId,
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
      },
      null,
      2,
    )}\n`,
    { mode: 0o600, flag: "wx" },
  );

  process.stdout.write(`device enrolled: ${deviceId}\n`);
  process.stdout.write(`consumer:        ${consumerId}\n`);
  process.stdout.write(`public key:      ${keys.publicKey}\n`);
  process.stdout.write(`private key:     ${out} (mode 0600; the only copy)\n`);
  process.stdout.write("Keep this file off shared storage; it is the device identity.\n");
}

function addServiceCommand(path: string, args: string[]): void {
  const id = requireOption(args, "--id", USAGE, "registry add-service");
  const name = requireOption(args, "--name", USAGE, "registry add-service");
  const url = requireOption(args, "--url", USAGE, "registry add-service");
  const authType = requireOption(args, "--auth", USAGE, "registry add-service");
  if (!AUTH_TYPES.has(authType)) {
    usageError(`registry add-service: --auth must be header, basic, query, or oauth2`, USAGE);
  }
  if (authType === "oauth2") {
    throw new VaultError(
      "oauth2 connectors are not implemented in this build; register the service with " +
        "header, basic, or query auth, or wait for oauth2 support",
    );
  }
  const authName = takeOption(args, "--auth-name");
  const authTemplate = takeOption(args, "--auth-template");
  const read = takeOptionList(args, "--read");
  const write = takeOptionList(args, "--write");
  const destructive = takeOptionList(args, "--destructive");
  if (read.length + write.length + destructive.length === 0) {
    throw new VaultError(
      "registry add-service: declare at least one action pattern with --read, --write, " +
        "or --destructive; a service with no actions can never be called",
    );
  }

  const service: ServiceRecord = {
    id,
    name,
    url,
    transport: "http",
    auth: {
      type: authType as AuthType,
      ...(authName ? { name: authName } : {}),
      ...(authTemplate ? { template: authTemplate } : {}),
    },
    actions: { read, write, destructive },
  };
  const registry = addService(path, service);
  process.stdout.write(`service added: ${id}\n`);
  process.stdout.write(`actions:       ${read.length} read, ${write.length} write, ${destructive.length} destructive\n`);
  process.stdout.write(`revision:      ${registry.revision}\n`);
}

function addConsumerCommand(path: string, args: string[]): void {
  const id = requireOption(args, "--id", USAGE, "registry add-consumer");
  const name = requireOption(args, "--name", USAGE, "registry add-consumer");
  const services = takeOptionList(args, "--services");
  if (services.length === 0) {
    throw new VaultError(
      "registry add-consumer: --services is required; name the services this consumer may use",
    );
  }
  const registry = addConsumer(path, {
    id,
    name,
    services,
    deviceIds: [],
    createdAt: new Date().toISOString(),
  });
  process.stdout.write(`consumer added: ${id}\n`);
  process.stdout.write(`services:       ${services.join(", ")}\n`);
  process.stdout.write(`revision:       ${registry.revision}\n`);
  process.stdout.write(`next:           charade device enroll --home <dir> --consumer ${id} --id <device-id> --out <file>\n`);
}

function addDeviceCommand(path: string, args: string[]): void {
  const id = requireOption(args, "--id", USAGE, "registry add-device");
  const consumerId = requireOption(args, "--consumer", USAGE, "registry add-device");
  const publicKey = requireOption(args, "--public-key", USAGE, "registry add-device");
  if (Buffer.from(publicKey, "base64url").length !== 32) {
    throw new VaultError("registry add-device: --public-key must be a base64url Ed25519 key (32 bytes)");
  }
  const device: DeviceRecord = {
    id,
    consumerId,
    publicKey,
    createdAt: new Date().toISOString(),
  };
  const registry = addDevice(path, device);
  process.stdout.write(`device added: ${id}\n`);
  process.stdout.write(`consumer:     ${consumerId}\n`);
  process.stdout.write(`revision:     ${registry.revision}\n`);
}

export function deviceFilePath(home: string, id: string): string {
  return join(home, `${id}.device.json`);
}
