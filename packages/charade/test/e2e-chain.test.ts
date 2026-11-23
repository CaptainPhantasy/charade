import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import {
  health,
  runCli,
  runCliAsync,
  startBroker,
  stopBroker,
  waitFor,
  type BrokerProcess,
} from "./support/harness.js";

const PASSPHRASE = "correct horse battery staple";
const SECRET = "sk-e2e-chain-fixture-8b1f4c";
const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

describe("full chain through the CLI", () => {
  it("initializes, registers, enrolls, grants, stores a secret, serves, proxies, survives a restart, and verifies receipts", async () => {
    const captures: Array<Record<string, string | undefined>> = [];
    const upstream = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        captures.push({
          url: request.url,
          authorization: String(request.headers.authorization ?? ""),
          body: Buffer.concat(chunks).toString("utf8"),
        });
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ url: request.url, ok: true }));
      });
    });
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
    cleanups.push(() => new Promise<void>((resolve) => upstream.close(() => resolve())));
    const port = (upstream.address() as AddressInfo).port;

    const home = mkdtempSync(join(tmpdir(), "charade-e2e-"));
    cleanups.push(() => rmSync(home, { recursive: true, force: true }));
    const pass = join(home, "pass.txt");
    writeFileSync(pass, `${PASSPHRASE}\n`, { mode: 0o600 });
    const socket = join(home, "broker.sock");
    const deviceFile = join(home, "device.json");

    const step = (args: string[], input?: string): void => {
      const result = runCli(args, input);
      assert.equal(result.status, 0, `${args.join(" ")}\n${result.stderr}`);
    };

    step(["init", "--home", home, "--passphrase-file", pass]);
    step(["policy", "init", "--home", home, "--accept-defaults", "--passphrase-file", pass]);
    step([
      "registry", "add-service", "--home", home,
      "--id", "svc", "--name", "E2E", "--url", `http://127.0.0.1:${port}`,
      "--auth", "header", "--auth-template", "Bearer ${SVC_KEY}",
      "--read", "GET /v1/*",
    ]);
    step(["registry", "add-consumer", "--home", home, "--id", "c1", "--name", "Agent", "--services", "svc"]);
    step(["device", "enroll", "--home", home, "--consumer", "c1", "--id", "d1", "--out", deviceFile]);
    step([
      "grant", "create", "--home", home, "--consumer", "c1", "--services", "svc",
      "--device", "d1", "--methods", "GET", "--paths", "/v1/*", "--duration", "24h",
      "--calls", "10", "--accept", "--passphrase-file", pass,
    ]);
    step(["secret", "add", "--home", home, "--service", "svc", "--passphrase-file", pass], `${SECRET}\n`);
    step(["registry", "validate", "--home", home]);

    const callOnce = async (label: string): Promise<void> => {
      const called = await runCliAsync([
        "call", "--home", home, "--service", "svc", "--path", "/v1/echo",
        "--device", deviceFile, "--socket", socket,
      ]);
      assert.equal(called.status, 0, `${label}: ${called.stderr}`);
      const body = JSON.parse(called.stdout) as { url: string };
      assert.equal(body.url, "/v1/echo");
      assert.equal(called.stdout.includes(SECRET), false);
    };

    let broker: BrokerProcess = startBroker(home, socket, pass);
    await waitFor("first broker", async () => {
      const report = await health(socket);
      if (report.status !== 200) throw new Error(`status ${report.status}`);
      return report;
    });
    await callOnce("first run");

    const receiptsAfterFirst = runCli(["receipts", "verify", "--home", home]);
    assert.equal(receiptsAfterFirst.status, 0, receiptsAfterFirst.stderr);
    assert.match(receiptsAfterFirst.stdout, /receipt chain ok: \d+ records/);

    await stopBroker(broker);
    broker = startBroker(home, socket, pass);
    await waitFor("second broker", async () => {
      const report = await health(socket);
      if (report.status !== 200) throw new Error(`status ${report.status}`);
      return report;
    });
    await callOnce("after restart");

    const receiptsAfterRestart = runCli(["receipts", "verify", "--home", home]);
    assert.equal(receiptsAfterRestart.status, 0, receiptsAfterRestart.stderr);
    const count = (output: string): number => Number(/receipt chain ok: (\d+) records/.exec(output)?.[1] ?? -1);
    assert.ok(
      count(receiptsAfterRestart.stdout) > count(receiptsAfterFirst.stdout),
      "the restart continues the same receipt chain",
    );

    assert.equal(captures.length, 2);
    for (const captured of captures) {
      assert.equal(captured.authorization, `Bearer ${SECRET}`, "the broker injected the value upstream");
      assert.equal(JSON.stringify(captured).includes("charade"), false);
    }

    // The fixture value must not be readable anywhere in the home directory.
    const leaks: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) walk(path);
        else if (entry.isFile() && readFileSync(path).includes(Buffer.from(SECRET, "utf8"))) leaks.push(path);
      }
    };
    walk(home);
    assert.deepEqual(leaks, []);

    await stopBroker(broker);
  });
});
