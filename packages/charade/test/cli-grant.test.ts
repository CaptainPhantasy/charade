import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { afterEach, describe, it } from "node:test";
import { CharadeClient, CharadeClientError } from "../src/client/index.js";
import { generateOwnerKeyPair } from "../src/authority/keys.js";
import { loadGrants } from "../src/authority/store.js";
import {
  CLI,
  createHarness,
  runCli,
  runCliAsync,
  SERVICE_ID,
  stopBroker,
  waitForReady,
  type BrokerProcess,
  type Harness,
} from "./support/harness.js";

const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function deviceRecord(harness: Harness): { deviceId: string; consumerId: string; privateKey: string } {
  return JSON.parse(readFileSync(harness.deviceFile, "utf8")) as {
    deviceId: string;
    consumerId: string;
    privateKey: string;
  };
}

function clientFor(harness: Harness): CharadeClient {
  const device = deviceRecord(harness);
  return new CharadeClient({
    socketPath: harness.socket,
    consumerId: device.consumerId,
    deviceId: device.deviceId,
    devicePrivateKey: device.privateKey,
  });
}

async function expectRefusal(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof CharadeClientError, `expected a client error, got ${String(error)}`);
    assert.equal(error.code, code);
    return true;
  });
}

describe("grant administration and lease scope", () => {
  it("refuses an out-of-scope method or path and allows the granted one", async () => {
    const harness = await createHarness({ grantMethods: ["GET"], grantPaths: ["/v1/allowed"] });
    cleanups.push(harness.close);
    const broker: BrokerProcess = await waitForReady(harness);
    cleanups.push(() => stopBroker(broker));

    const client = clientFor(harness);
    await client.openSession();
    const issued = await client.issueLease([SERVICE_ID]);
    const call = (path: string, method = "GET"): Promise<{ status: number }> =>
      client.call({ leaseToken: issued.token, service: SERVICE_ID, path, method }).then((r) => ({ status: r.status }));

    assert.equal((await call("/v1/allowed")).status, 200);
    assert.equal((await call("/v1/allowed?query=1")).status, 200, "a query is not part of the grant path");
    await expectRefusal(call("/v1/other"), "charade.scope_denied");
    await expectRefusal(call("/v1/allowed", "POST"), "charade.scope_denied");
  });

  it("creates a grant through the CLI, leases it, then refuses the next lease after revocation", async () => {
    const harness = await createHarness({ withGrant: false });
    cleanups.push(harness.close);

    const created = runCli([
      "grant", "create",
      "--home", harness.home,
      "--consumer", "c1",
      "--services", "svc",
      "--device", "d1",
      "--methods", "GET",
      "--paths", "/v1/*",
      "--duration", "24h",
      "--calls", "5",
      "--accept",
      "--passphrase-file", harness.pass,
    ]);
    assert.equal(created.status, 0, created.stderr);
    assert.match(created.stdout, /grant signed: gr_/);
    const grants = loadGrants(harness.home);
    assert.equal(grants.length, 1);
    assert.deepEqual(grants[0]?.methods, ["GET"]);
    assert.deepEqual(grants[0]?.paths, ["/v1/*"]);

    const listed = runCli(["grant", "list", "--home", harness.home]);
    assert.match(listed.stdout, /methods GET/);
    assert.match(listed.stdout, /paths \/v1\/\*/);

    const broker = await waitForReady(harness);
    cleanups.push(() => stopBroker(broker));

    const client = clientFor(harness);
    await client.openSession();
    const issued = await client.issueLease([SERVICE_ID]);
    const response = await client.call({ leaseToken: issued.token, service: SERVICE_ID, path: "/v1/echo" });
    assert.equal(response.status, 200);

    const grantId = grants[0]?.grantId ?? "";
    const revoked = runCli(["grant", "revoke", "--home", harness.home, "--id", grantId, "--accept"]);
    assert.equal(revoked.status, 0, revoked.stderr);

    await expectRefusal(client.issueLease([SERVICE_ID]), "charade.grant_missing");
  });

  it("refuses a grant naming an unknown device or another consumer's device", async () => {
    const harness = await createHarness({ withGrant: false });
    cleanups.push(harness.close);

    const unknown = runCli([
      "grant", "create", "--home", harness.home, "--consumer", "c1", "--services", "svc",
      "--device", "d-missing", "--duration", "24h", "--accept", "--passphrase-file", harness.pass,
    ]);
    assert.equal(unknown.status, 1);
    assert.match(unknown.stderr, /device d-missing is not enrolled/);

    const otherKeys = generateOwnerKeyPair();
    assert.equal(
      runCli(["registry", "add-consumer", "--home", harness.home, "--id", "c2", "--name", "Other", "--services", "svc"]).status,
      0,
    );
    assert.equal(
      runCli([
        "registry", "add-device", "--home", harness.home, "--id", "d2", "--consumer", "c2",
        "--public-key", otherKeys.publicKey,
      ]).status,
      0,
    );

    const foreign = runCli([
      "grant", "create", "--home", harness.home, "--consumer", "c1", "--services", "svc",
      "--device", "d2", "--duration", "24h", "--accept", "--passphrase-file", harness.pass,
    ]);
    assert.equal(foreign.status, 1);
    assert.match(foreign.stderr, /belongs to consumer c2, not c1/);
    assert.equal(loadGrants(harness.home).length, 0, "no grant is signed on a validation failure");
  });

  it("keeps the CLI surface documented in --help", () => {
    const child = spawn(process.execPath, [CLI, "--help"]);
    let help = "";
    child.stdout.on("data", (chunk: Buffer) => {
      help += chunk.toString("utf8");
    });
    return new Promise<void>((resolve, reject) => {
      child.on("exit", () => {
        for (const flag of ["--device", "--methods", "--paths", "--calls", "--duration"]) {
          try {
            assert.match(help, new RegExp(flag.replace(/[-]/g, "\\-")));
          } catch (error) {
            reject(error);
            return;
          }
        }
        resolve();
      });
    });
  });
});
