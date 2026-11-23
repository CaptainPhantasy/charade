import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CharadeClient, CharadeClientError } from "../client/index.js";
import { VaultError } from "../vault/vault.js";
import { USAGE } from "./usage.js";
import { requireOption, takeOption } from "./util.js";

interface DeviceFile {
  readonly schema: string;
  readonly deviceId: string;
  readonly consumerId: string;
  readonly privateKey: string;
}

export async function callCommand(args: string[]): Promise<void> {
  const home = requireOption(args, "--home", USAGE, "call");
  const service = requireOption(args, "--service", USAGE, "call");
  const path = requireOption(args, "--path", USAGE, "call");
  const method = (takeOption(args, "--method") ?? "GET").toUpperCase();
  const devicePath = requireOption(args, "--device", USAGE, "call");
  const socketPath = takeOption(args, "--socket") ?? join(home, "broker.sock");
  const dataPath = takeOption(args, "--data");

  const device = readDeviceFile(devicePath);
  const body = dataPath === undefined ? undefined : await readData(dataPath);

  const client = new CharadeClient({
    socketPath,
    consumerId: device.consumerId,
    deviceId: device.deviceId,
    devicePrivateKey: device.privateKey,
  });

  await client.openSession();
  try {
    const response = await client.withLease(service, method, (lease) =>
      client.call({
        leaseToken: lease.token,
        service,
        path,
        method,
        ...(body ? { body } : {}),
      }),
    );
    process.stderr.write(`charade: ${method} ${path} -> ${response.status}\n`);
    process.stdout.write(response.body);
    if (response.status >= 400) process.exitCode = 1;
  } catch (error) {
    if (error instanceof CharadeClientError) {
      process.stderr.write(`charade: ${error.code ?? "request failed"}\n`);
      if (error.body) {
        process.stderr.write(`  what happened: ${error.body.whatHappened}\n`);
        process.stderr.write(`  what next:     ${error.body.whatNext}\n`);
      }
      process.exitCode = 1;
      return;
    }
    throw error;
  } finally {
    await client.closeSession().catch(() => undefined);
  }
}

function readDeviceFile(path: string): DeviceFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new VaultError(`device file ${path} is unreadable or not JSON`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new VaultError(`device file ${path} is not a device record`);
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.deviceId !== "string" || typeof record.consumerId !== "string") {
    throw new VaultError(`device file ${path} is missing deviceId or consumerId`);
  }
  if (typeof record.privateKey !== "string" || record.privateKey.length === 0) {
    throw new VaultError(`device file ${path} is missing the private key`);
  }
  return {
    schema: typeof record.schema === "string" ? record.schema : "charade.device/1",
    deviceId: record.deviceId,
    consumerId: record.consumerId,
    privateKey: record.privateKey,
  };
}

async function readData(path: string): Promise<Buffer> {
  if (path !== "-") return readFileSync(path);
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk as Buffer));
  return Buffer.concat(chunks);
}
