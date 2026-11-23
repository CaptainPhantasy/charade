import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { afterEach, describe, it } from "node:test";
import { CharadeClient, shouldRenew, type IssuedLease } from "../src/client/index.js";
import {
  createHarness,
  runCliAsync,
  runCli,
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

async function setup(): Promise<{ harness: Harness; broker: BrokerProcess }> {
  const harness = await createHarness();
  cleanups.push(harness.close);
  const broker = await waitForReady(harness);
  cleanups.push(() => stopBroker(broker));
  return { harness, broker };
}

function deviceRecord(harness: Harness): {
  deviceId: string;
  consumerId: string;
  privateKey: string;
} {
  return JSON.parse(readFileSync(harness.deviceFile, "utf8")) as {
    deviceId: string;
    consumerId: string;
    privateKey: string;
  };
}

function clientFor(harness: Harness, options: { now?: () => Date } = {}): CharadeClient {
  const device = deviceRecord(harness);
  return new CharadeClient({
    socketPath: harness.socket,
    consumerId: device.consumerId,
    deviceId: device.deviceId,
    devicePrivateKey: device.privateKey,
    ...(options.now ? { now: options.now } : {}),
  });
}

describe("consumer client", () => {
  it("opens a session, leases, proxies without leaking the value, and renews", async () => {
    const { harness } = await setup();
    const client = clientFor(harness);
    await client.openSession();
    assert.ok(client.sessionToken);

    const issued = await client.issueLease([SERVICE_ID]);
    assert.equal(issued.lease.services.includes(SERVICE_ID), true);
    assert.equal(JSON.stringify(issued).includes(harness.secretValue), false);

    const first = await client.call({
      leaseToken: issued.token,
      service: SERVICE_ID,
      path: "/v1/echo?q=1",
    });
    assert.equal(first.status, 200);
    assert.equal(harness.captures.length, 1);
    assert.equal(harness.captures[0]?.url, "/v1/echo?q=1");
    assert.equal(
      harness.captures[0]?.headers.authorization,
      `Bearer ${harness.secretValue}`,
      "the broker injects the stored value upstream",
    );
    assert.equal(first.body.toString("utf8").includes(harness.secretValue), false);

    const renewed = await client.renew(SERVICE_ID);
    assert.notEqual(renewed.token, issued.token);
    const second = await client.call({
      leaseToken: renewed.token,
      service: SERVICE_ID,
      path: "/v1/echo",
    });
    assert.equal(second.status, 200);
    assert.equal(harness.captures.length, 2);

    await client.closeSession();
    assert.equal(client.sessionToken, undefined);
  });

  it("renews at two thirds of the lease window", async () => {
    const { harness } = await setup();
    let clock = new Date();
    const client = clientFor(harness, { now: () => clock });
    await client.openSession();
    const issued = await client.issueLease([SERVICE_ID]);
    assert.equal(shouldRenew(issued.lease, clock), false);

    clock = new Date(clock.getTime() + 90_000);
    assert.equal(shouldRenew(issued.lease, clock), true);

    const calls: IssuedLease[] = [];
    const response = await client.withLease(SERVICE_ID, "GET", async (lease) => {
      calls.push(lease);
      return client.call({ leaseToken: lease.token, service: SERVICE_ID, path: "/v1/echo" });
    });
    assert.equal(response.status, 200);
    assert.notEqual(calls[0]?.token, issued.token, "the lease was renewed before the call");
  });

  it("reports a broker refusal with its code and next step", async () => {
    const { harness } = await setup();
    const client = clientFor(harness);
    await client.openSession();
    const issued = await client.issueLease([SERVICE_ID]);
    await assert.rejects(
      client.call({ leaseToken: issued.token, service: SERVICE_ID, path: "/admin/secret" }),
      (error: unknown) => {
        const typed = error as { code?: string; body?: { whatNext?: string } };
        assert.equal(typed.code, "charade.action_unknown");
        assert.ok(typed.body?.whatNext);
        return true;
      },
    );
  });
});

describe("charade call (CLI)", () => {
  it("proxies through the CLI and prints the upstream body", async () => {
    const { harness } = await setup();
    const result = await runCliAsync([
      "call",
      "--home",
      harness.home,
      "--service",
      SERVICE_ID,
      "--path",
      "/v1/echo",
      "--method",
      "POST",
      "--device",
      harness.deviceFile,
      "--data",
      "-",
    ], "payload-body");
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stderr, /POST \/v1\/echo -> 200/);
    const body = JSON.parse(result.stdout) as Record<string, string>;
    assert.equal(body.url, "/v1/echo");
    assert.equal(body.method, "POST");
    assert.equal(body.body, "payload-body");
    assert.equal(result.stdout.includes(harness.secretValue), false);
    assert.equal(harness.captures[0]?.headers.authorization, `Bearer ${harness.secretValue}`);

    const denied = await runCliAsync([
      "call",
      "--home",
      harness.home,
      "--service",
      SERVICE_ID,
      "--path",
      "/v2/not-declared",
      "--device",
      harness.deviceFile,
    ]);
    assert.equal(denied.status, 1);
    assert.match(denied.stderr, /charade\.action_unknown/);
    assert.match(denied.stderr, /what next:/);
  });

  it("refuses to run without an enrolled device file", () => {
    const result = runCli(["call", "--home", "/tmp/nowhere", "--service", "svc", "--path", "/v1/x"]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /--device/);
  });
});
