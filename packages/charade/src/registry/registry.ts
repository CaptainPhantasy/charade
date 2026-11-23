import { existsSync, readFileSync } from "node:fs";
import { canonicalJson } from "../core/canonical-json.js";
import { writeAtomic } from "../vault/atomic.js";

export type AuthType = "header" | "basic" | "query" | "oauth2";

export interface ServiceAuth {
  readonly type: AuthType;
  readonly name?: string;
  readonly template?: string;
}

export interface ServiceActions {
  readonly read: readonly string[];
  readonly write: readonly string[];
  readonly destructive: readonly string[];
}

export interface ServiceRecord {
  readonly id: string;
  readonly name: string;
  readonly url: string;
  readonly transport: "http";
  readonly auth: ServiceAuth;
  readonly actions: ServiceActions;
  readonly fallbacks?: readonly string[];
  readonly notes?: string;
}

export interface ConsumerRecord {
  readonly id: string;
  readonly name: string;
  readonly role?: string;
  readonly services: readonly string[];
  readonly deviceIds: readonly string[];
  readonly maxTtlSeconds?: number;
  readonly callsPerDay?: number;
  readonly createdAt: string;
}

export interface DeviceRecord {
  readonly id: string;
  readonly consumerId: string;
  readonly publicKey: string;
  readonly createdAt: string;
  readonly revokedAt?: string;
}

export interface Registry {
  readonly schema: "charade.registry/1";
  readonly revision: number;
  readonly services: readonly ServiceRecord[];
  readonly consumers: readonly ConsumerRecord[];
  readonly devices: readonly DeviceRecord[];
}

export class RegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryError";
  }
}

export interface LoadRegistryOptions {
  /** An empty registry is refused unless the owner policy explicitly allows it. */
  readonly allowEmpty?: boolean;
}

export function registryPath(home: string): string {
  return `${home}/registry.json`;
}

export function loadRegistry(path: string, options: LoadRegistryOptions = {}): Registry {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new RegistryError(
      code === "ENOENT" ? "registry file is missing" : "registry file is unreadable",
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new RegistryError("registry file is not valid JSON");
  }
  return validateRegistry(value, options);
}

export function saveRegistry(path: string, registry: Registry): Registry {
  const next: Registry = { ...registry, revision: registry.revision + 1 };
  validateRegistry(next, { allowEmpty: true });
  writeAtomic(path, Buffer.from(canonicalJson(next), "utf8"), 0o600);
  return next;
}

/**
 * A registry is created on first use. An empty file still has to be readable,
 * so a malformed registry is never silently replaced by a fresh one.
 */
export function loadRegistryForEdit(path: string): Registry {
  if (!existsSync(path)) return emptyRegistry();
  return loadRegistry(path, { allowEmpty: true });
}

export function addService(path: string, service: ServiceRecord): Registry {
  const registry = loadRegistryForEdit(path);
  return saveRegistry(path, { ...registry, services: [...registry.services, service] });
}

export function addConsumer(path: string, consumer: ConsumerRecord): Registry {
  const registry = loadRegistryForEdit(path);
  return saveRegistry(path, { ...registry, consumers: [...registry.consumers, consumer] });
}

/** Adding a device also records it on its consumer, in both directions. */
export function addDevice(path: string, device: DeviceRecord): Registry {
  const registry = loadRegistryForEdit(path);
  const consumers = registry.consumers.map((consumer) =>
    consumer.id === device.consumerId
      ? { ...consumer, deviceIds: [...consumer.deviceIds, device.id] }
      : consumer,
  );
  return saveRegistry(path, {
    ...registry,
    consumers,
    devices: [...registry.devices, device],
  });
}

export function emptyRegistry(): Registry {
  return { schema: "charade.registry/1", revision: 0, services: [], consumers: [], devices: [] };
}

export function validateRegistry(
  value: unknown,
  options: LoadRegistryOptions = {},
): Registry {
  const root = asObject(value, "registry");
  if (root.schema !== "charade.registry/1") {
    throw new RegistryError("registry schema is unsupported");
  }
  const revision = root.revision;
  if (!Number.isInteger(revision) || (revision as number) < 0) {
    throw new RegistryError("registry revision must be a non-negative integer");
  }
  const services = asArray(root.services, "registry.services").map(validateService);
  const consumers = asArray(root.consumers, "registry.consumers").map(validateConsumer);
  const devices = asArray(root.devices, "registry.devices").map(validateDevice);
  if (services.length === 0 && !options.allowEmpty) {
    throw new RegistryError("registry has no services");
  }
  unique(services.map((item) => item.id), "service");
  unique(consumers.map((item) => item.id), "consumer");
  unique(devices.map((item) => item.id), "device");

  const serviceIds = new Set(services.map((item) => item.id));
  const consumerIds = new Set(consumers.map((item) => item.id));
  const deviceById = new Map(devices.map((item) => [item.id, item]));
  for (const consumer of consumers) {
    for (const serviceId of consumer.services) {
      if (!serviceIds.has(serviceId)) {
        throw new RegistryError(`consumer ${consumer.id} references unknown service ${serviceId}`);
      }
    }
    for (const deviceId of consumer.deviceIds) {
      const device = deviceById.get(deviceId);
      if (!device) {
        throw new RegistryError(`consumer ${consumer.id} references unknown device ${deviceId}`);
      }
      if (device.consumerId !== consumer.id) {
        throw new RegistryError(`device ${deviceId} belongs to ${device.consumerId}, not ${consumer.id}`);
      }
    }
  }
  for (const device of devices) {
    if (!consumerIds.has(device.consumerId)) {
      throw new RegistryError(`device ${device.id} references unknown consumer ${device.consumerId}`);
    }
  }
  for (const service of services) {
    for (const fallback of service.fallbacks ?? []) {
      if (!serviceIds.has(fallback)) {
        throw new RegistryError(`service ${service.id} references unknown fallback ${fallback}`);
      }
    }
  }

  return {
    schema: "charade.registry/1",
    revision: revision as number,
    services,
    consumers,
    devices,
  };
}

function validateService(value: unknown): ServiceRecord {
  const item = asObject(value, "service");
  const id = asString(item.id, "service.id");
  const name = asString(item.name, "service.name");
  const url = asString(item.url, "service.url");
  if (!/^https?:\/\//.test(url)) throw new RegistryError(`service ${id} url must be http(s)`);
  if (item.transport !== "http") throw new RegistryError(`service ${id} transport must be http`);
  const auth = asObject(item.auth, `service ${id} auth`);
  const type = auth.type;
  if (type !== "header" && type !== "basic" && type !== "query" && type !== "oauth2") {
    throw new RegistryError(`service ${id} auth type is unsupported`);
  }
  const authType = type as AuthType;
  const actions = asObject(item.actions, `service ${id} actions`);
  const read = stringArray(actions.read, `service ${id} actions.read`);
  const write = stringArray(actions.write, `service ${id} actions.write`);
  const destructive = stringArray(actions.destructive, `service ${id} actions.destructive`);
  const fallbacks = item.fallbacks === undefined
    ? undefined
    : stringArray(item.fallbacks, `service ${id} fallbacks`);
  return {
    id,
    name,
    url,
    transport: "http",
    auth: {
      type: authType,
      ...(typeof auth.name === "string" ? { name: auth.name } : {}),
      ...(typeof auth.template === "string" ? { template: auth.template } : {}),
    },
    actions: { read, write, destructive },
    ...(fallbacks ? { fallbacks } : {}),
    ...(typeof item.notes === "string" ? { notes: item.notes } : {}),
  };
}

function validateConsumer(value: unknown): ConsumerRecord {
  const item = asObject(value, "consumer");
  const id = asString(item.id, "consumer.id");
  const name = asString(item.name, "consumer.name");
  const services = stringArray(item.services, `consumer ${id} services`);
  const deviceIds = stringArray(item.deviceIds, `consumer ${id} deviceIds`);
  const createdAt = asString(item.createdAt, `consumer ${id} createdAt`);
  const maxTtlSeconds = optionalPositiveInteger(item.maxTtlSeconds, `consumer ${id} maxTtlSeconds`);
  const callsPerDay = optionalPositiveInteger(item.callsPerDay, `consumer ${id} callsPerDay`);
  return {
    id,
    name,
    ...(typeof item.role === "string" ? { role: item.role } : {}),
    services,
    deviceIds,
    ...(maxTtlSeconds !== undefined ? { maxTtlSeconds } : {}),
    ...(callsPerDay !== undefined ? { callsPerDay } : {}),
    createdAt,
  };
}

function validateDevice(value: unknown): DeviceRecord {
  const item = asObject(value, "device");
  const id = asString(item.id, "device.id");
  const consumerId = asString(item.consumerId, `device ${id} consumerId`);
  const publicKey = asString(item.publicKey, `device ${id} publicKey`);
  if (Buffer.from(publicKey, "base64url").length !== 32) {
    throw new RegistryError(`device ${id} publicKey must be 32 bytes`);
  }
  return {
    id,
    consumerId,
    publicKey,
    createdAt: asString(item.createdAt, `device ${id} createdAt`),
    ...(typeof item.revokedAt === "string" ? { revokedAt: item.revokedAt } : {}),
  };
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new RegistryError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function asArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new RegistryError(`${label} must be an array`);
  return value;
}

function asString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new RegistryError(`${label} must be a non-empty string`);
  }
  return value;
}

function stringArray(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value)) throw new RegistryError(`${label} must be an array`);
  return value.map((item, index) => asString(item, `${label}[${index}]`));
}

function optionalPositiveInteger(value: unknown, label: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || (value as number) <= 0) {
    throw new RegistryError(`${label} must be a positive integer`);
  }
  return value as number;
}

function unique(values: readonly string[], label: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) throw new RegistryError(`duplicate ${label} id ${value}`);
    seen.add(value);
  }
}
