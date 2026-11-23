import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";
import { generateOwnerKeyPair } from "../src/authority/keys.js";
import { addGrant, createPolicy, loadPolicy } from "../src/authority/store.js";
import { DEFAULT_GATES } from "../src/authority/policy.js";
import { signGrant } from "../src/authority/grants.js";
import { initVault, openVault, putSecret } from "../src/vault/vault.js";
import { saveRegistry, type Registry } from "../src/registry/registry.js";

const CLI = fileURLToPath(new URL("../src/cli/main.js", import.meta.url));
const PASSPHRASE = "correct horse battery staple";
const NOW = new Date("2026-01-01T00:00:00Z");
const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function tempHome(): string {
  const home = mkdtempSync(join(tmpdir(), "charade-cli-broker-"));
  cleanups.push(() => rmSync(home, { recursive: true, force: true }));
  return home;
}

function passFile(home: string): string {
  const path = join(home, "pass.txt");
  writeFileSync(path, `${PASSPHRASE}\n`, { mode: 0o600 });
  return path;
}

function fixtureHome(options: { policy?: boolean } = {}): string {
  const home = tempHome();
  initVault({ home, passphrase: PASSPHRASE, now: NOW });
  if (options.policy === false) return home;
  const open = openVault(home, PASSPHRASE);
  createPolicy(open);
  const seeded = putSecret(openVault(home, PASSPHRASE), {
    serviceId: "svc",
    value: "fixture-injected-value",
    now: NOW,
  });
  void seeded;
  const device = generateOwnerKeyPair();
  const registry: Registry = {
    schema: "charade.registry/1",
    revision: 1,
    services: [
      {
        id: "svc",
        name: "Mock",
        url: "http://127.0.0.1:9",
        transport: "http",
        auth: { type: "header", name: "Authorization", template: "Bearer ${SVC_KEY}" },
        actions: { read: ["GET /v1/*"], write: [], destructive: [] },
      },
    ],
    consumers: [
      { id: "c1", name: "Consumer", services: ["svc"], deviceIds: ["d1"], createdAt: NOW.toISOString() },
    ],
    devices: [
      { id: "d1", consumerId: "c1", publicKey: device.publicKey, createdAt: NOW.toISOString() },
    ],
  };
  saveRegistry(join(home, "registry.json"), registry);
  const ownerPrivate = open.payload.owner?.privateKey ?? "";
  assert.ok(ownerPrivate);
  addGrant(
    home,
    signGrant(
      ownerPrivate,
      loadPolicy(home),
      {
        consumerId: "c1",
        deviceId: "d1",
        services: ["svc"],
        methods: ["GET"],
        paths: ["/v1/*"],
        durationSeconds: 86_400,
        ceilings: { callsPerDay: 10 },
        hardStops: { ...DEFAULT_GATES.hardStops },
        envAllowed: false,
      },
      NOW,
    ),
  );
  return home;
}

interface BrokerProcess {
  readonly child: ChildProcessWithoutNullStreams;
  readonly stdout: () => string;
  readonly stderr: () => string;
  readonly socket: string;
}

async function startBroker(home: string, socket: string): Promise<BrokerProcess> {
  const child = spawn(
    process.execPath,
    [CLI, "broker", "serve", "--home", home, "--passphrase-file", passFile(home), "--socket", socket],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  cleanups.push(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  let out = "";
  let err = "";
  child.stdout.on("data", (chunk: Buffer) => {
    out += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    err += chunk.toString("utf8");
  });
  return { child, stdout: () => out, stderr: () => err, socket };
}

function health(socketPath: string): Promise<{ status: number; json: Record<string, unknown> }> {
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

async function waitFor<T>(label: string, fn: () => Promise<T>, timeoutMs = 10_000): Promise<T> {
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

function exitOf(child: ChildProcessWithoutNullStreams): Promise<number | null> {
  return new Promise((resolve) => {
    if (child.exitCode !== null) {
      resolve(child.exitCode);
      return;
    }
    child.on("exit", (code) => resolve(code));
  });
}

/** TCP listeners held by this pid, or null when no inspection tool exists. */
function tcpListeners(pid: number): string[] | null {
  const lsof = spawnSync("lsof", ["-nP", "-a", "-p", String(pid), "-iTCP", "-sTCP:LISTEN"], {
    encoding: "utf8",
  });
  if (!lsof.error && lsof.status === 0) {
    return lsof.stdout.split("\n").filter((line) => line.trim().length > 0);
  }
  const ss = spawnSync("ss", ["-ltnp"], { encoding: "utf8" });
  if (!ss.error && typeof ss.stdout === "string") {
    return ss.stdout.split("\n").filter((line) => line.includes(`pid=${pid},`));
  }
  return null;
}

describe("charade broker serve (CLI child process)", () => {
  it("serves health over a Unix socket, binds no TCP listener, and removes the socket on exit", async () => {
    const home = fixtureHome();
    const socket = join(home, "broker.sock");
    const broker = await startBroker(home, socket);

    const report = await waitFor("broker health", async () => {
      const result = await health(socket);
      if (result.status !== 200) throw new Error(`status ${result.status}`);
      return result;
    });
    assert.equal(report.json.ready, true);
    assert.equal(report.json.alive, true);
    assert.equal(report.json.overall, "ok");
    assert.equal(JSON.stringify(report.json).includes(home), false);

    const out = broker.stdout();
    assert.match(out, new RegExp(`socket:\\s+${socket.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.match(out, /protocol:\s+1\.0/);
    assert.match(out, /ready:\s+yes/);
    assert.equal(out.includes(PASSPHRASE), false);

    assert.equal(statSync(socket).mode & 0o777, 0o600);
    assert.equal(statSync(home).mode & 0o777, 0o700);

    const listeners = tcpListeners(broker.child.pid as number);
    if (listeners !== null) {
      assert.deepEqual(listeners, [], "the broker must not bind a TCP listener");
    }

    broker.child.kill("SIGTERM");
    const code = await exitOf(broker.child);
    assert.equal(code, 0);
    assert.equal(existsSync(socket), false, "the socket is removed on exit");
    assert.match(broker.stdout(), /stopping \(SIGTERM\)/);
  });

  it("serves 503 with a named failing check when the owner policy is missing", async () => {
    const home = fixtureHome({ policy: false });
    const socket = join(home, "broker.sock");
    const broker = await startBroker(home, socket);

    const report = await waitFor("degraded health", () => health(socket));
    assert.equal(report.status, 503);
    assert.equal(report.json.ready, false);
    assert.equal(report.json.alive, true);

    await waitFor("startup diagnostics", async () => {
      const err = broker.stderr();
      if (!/policy/.test(err)) throw new Error("no policy diagnostic yet");
      return err;
    });
    assert.match(broker.stdout(), /ready:\s+no/);
    assert.match(broker.stderr(), /policy: owner policy is missing or invalid/);
    assert.match(broker.stderr(), /next: run `charade policy init`/);

    broker.child.kill("SIGTERM");
    assert.equal(await exitOf(broker.child), 0);
  });

  it("reports status for a running and a stopped broker", async () => {
    const home = fixtureHome();
    const socket = join(home, "broker.sock");
    assert.equal(runCli(["broker", "status", "--home", home]).status, 1);

    const broker = await startBroker(home, socket);
    await waitFor("broker health", async () => {
      const result = await health(socket);
      if (result.status !== 200) throw new Error(`status ${result.status}`);
      return result;
    });

    const status = runCli(["broker", "status", "--home", home, "--json"]);
    assert.equal(status.status, 0);
    const parsed = JSON.parse(status.stdout) as Record<string, unknown>;
    assert.equal(parsed.listening, true);
    assert.equal(parsed.ready, true);

    broker.child.kill("SIGTERM");
    await exitOf(broker.child);
  });
});

function runCli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
