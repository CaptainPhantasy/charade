import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateOwnerKeyPair } from "../../src/authority/keys.js";
import { DEFAULT_GATES } from "../../src/authority/policy.js";
import { addGrant, createPolicy, loadPolicy } from "../../src/authority/store.js";
import { signGrant } from "../../src/authority/grants.js";
import { initVault, openVault, putSecret } from "../../src/vault/vault.js";
import { saveRegistry, type Registry } from "../../src/registry/registry.js";

export const CLI = fileURLToPath(new URL("../../src/cli/main.js", import.meta.url));
export const PASSPHRASE = "correct horse battery staple";
export const SECRET_VALUE = "sk-live-harness-fixture-3c9a";
export const SERVICE_ID = "svc";
export const CONSUMER_ID = "c1";
export const DEVICE_ID = "d1";

export interface Capture {
  readonly url?: string;
  readonly method?: string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: string;
}

export interface HarnessOptions {
  /** Pre-sign a grant (default true). Set false when the test creates it through the CLI. */
  readonly withGrant?: boolean;
  readonly grantMethods?: readonly string[];
  readonly grantPaths?: readonly string[];
}

export interface Harness {
  readonly home: string;
  readonly pass: string;
  readonly socket: string;
  readonly deviceFile: string;
  readonly deviceId: string;
  readonly consumerId: string;
  readonly secretValue: string;
  readonly upstreamPort: number;
  readonly captures: Capture[];
  close(): Promise<void>;
}

/**
 * A complete, honest fixture: real vault, signed policy and grant, registry,
 * enrolled device, and a local upstream that records what it received.
 */
export async function createHarness(options: HarnessOptions = {}): Promise<Harness> {
  const now = new Date();
  const home = mkdtempSync(join(tmpdir(), "charade-harness-"));
  const captures: Capture[] = [];

  const upstream = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      captures.push({ url: request.url, method: request.method, headers: request.headers, body });
      // Deliberately does not echo auth headers back to the consumer.
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ url: request.url, method: request.method, body }));
    });
  });
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const upstreamPort = (upstream.address() as AddressInfo).port;

  const pass = join(home, "pass.txt");
  writeFileSync(pass, `${PASSPHRASE}\n`, { mode: 0o600 });
  initVault({ home, passphrase: PASSPHRASE });
  const open = openVault(home, PASSPHRASE);
  createPolicy(open);
  putSecret(openVault(home, PASSPHRASE), { serviceId: SERVICE_ID, value: SECRET_VALUE });

  const device = generateOwnerKeyPair();
  const registry: Registry = {
    schema: "charade.registry/1",
    revision: 1,
    services: [
      {
        id: SERVICE_ID,
        name: "Mock",
        url: `http://127.0.0.1:${upstreamPort}`,
        transport: "http",
        auth: { type: "header", name: "Authorization", template: "Bearer ${SVC_KEY}" },
        actions: { read: ["GET /v1/*"], write: ["POST /v1/*"], destructive: [] },
      },
    ],
    consumers: [
      {
        id: CONSUMER_ID,
        name: "Consumer",
        services: [SERVICE_ID],
        deviceIds: [DEVICE_ID],
        createdAt: now.toISOString(),
      },
    ],
    devices: [
      {
        id: DEVICE_ID,
        consumerId: CONSUMER_ID,
        publicKey: device.publicKey,
        createdAt: now.toISOString(),
      },
    ],
  };
  saveRegistry(join(home, "registry.json"), registry);

  const ownerPrivate = open.payload.owner?.privateKey ?? "";
  if (!ownerPrivate) throw new Error("fixture vault has no owner key");
  if (options.withGrant !== false) {
    addGrant(
      home,
      signGrant(ownerPrivate, loadPolicy(home), {
        consumerId: CONSUMER_ID,
        deviceId: DEVICE_ID,
        services: [SERVICE_ID],
        methods: options.grantMethods ?? ["GET", "POST"],
        paths: options.grantPaths ?? ["/v1/*"],
        durationSeconds: 86_400,
        ceilings: { callsPerDay: 1_000 },
        hardStops: { ...DEFAULT_GATES.hardStops },
        envAllowed: false,
      }),
    );
  }

  const deviceFile = join(home, "device.json");
  writeFileSync(
    deviceFile,
    JSON.stringify({
      schema: "charade.device/1",
      deviceId: DEVICE_ID,
      consumerId: CONSUMER_ID,
      privateKey: device.privateKey,
      publicKey: device.publicKey,
    }),
    { mode: 0o600 },
  );

  return {
    home,
    pass,
    socket: join(home, "broker.sock"),
    deviceFile,
    deviceId: DEVICE_ID,
    consumerId: CONSUMER_ID,
    secretValue: SECRET_VALUE,
    upstreamPort,
    captures,
    close: async () => {
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
      rmSync(home, { recursive: true, force: true });
    },
  };
}

export interface BrokerProcess {
  readonly child: ChildProcessWithoutNullStreams;
  readonly stdout: () => string;
  readonly stderr: () => string;
}

export function startBroker(home: string, socket: string, pass: string): BrokerProcess {
  const child = spawn(
    process.execPath,
    [CLI, "broker", "serve", "--home", home, "--passphrase-file", pass, "--socket", socket],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  let out = "";
  let err = "";
  child.stdout.on("data", (chunk: Buffer) => {
    out += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    err += chunk.toString("utf8");
  });
  return { child, stdout: () => out, stderr: () => err };
}

export function runCli(
  args: string[],
  input?: string,
): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    ...(input === undefined ? {} : { input }),
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

/**
 * Run the CLI without blocking this process: a mock upstream in the test also
 * needs the event loop while the child works.
 */
export function runCliAsync(
  args: string[],
  input?: string,
): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk: Buffer) => {
      out += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      err += chunk.toString("utf8");
    });
    child.on("exit", (status) => resolve({ status, stdout: out, stderr: err }));
    child.stdin.end(input ?? "");
  });
}

export function health(socketPath: string): Promise<{ status: number; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      { socketPath, method: "GET", path: "/health", timeout: 2000 },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            status: response.statusCode ?? 0,
            json: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<string, unknown>,
          });
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("health probe timed out")));
    request.on("error", reject);
    request.end();
  });
}

export async function waitFor<T>(label: string, fn: () => Promise<T>, timeoutMs = 10_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
  throw new Error(`${label} was not ready in ${timeoutMs} ms: ${String(lastError)}`);
}

export async function waitForReady(harness: Harness): Promise<BrokerProcess> {
  const broker = startBroker(harness.home, harness.socket, harness.pass);
  await waitFor("broker health", async () => {
    const result = await health(harness.socket);
    if (result.status !== 200) throw new Error(`status ${result.status}`);
    return result;
  });
  return broker;
}

export async function stopBroker(broker: BrokerProcess): Promise<void> {
  if (broker.child.exitCode !== null || broker.child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => broker.child.on("exit", () => resolve()));
  broker.child.kill("SIGTERM");
  await exited;
}
