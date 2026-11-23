import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { CharadeClient } from "../src/client/index.js";
import { CallCounters } from "../src/broker/counters.js";
import {
  createHarness,
  SERVICE_ID,
  startInProcessBroker,
  type Harness,
} from "./support/harness.js";

const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function clientFor(harness: Harness): CharadeClient {
  const device = JSON.parse(readFileSync(harness.deviceFile, "utf8")) as {
    deviceId: string;
    consumerId: string;
    privateKey: string;
  };
  return new CharadeClient({
    socketPath: harness.socket,
    consumerId: device.consumerId,
    deviceId: device.deviceId,
    devicePrivateKey: device.privateKey,
  });
}

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "charade-counters-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

describe("durable call counters", () => {
  it("persists the count, refuses past the ceiling, and rolls over on a new day", () => {
    let clock = new Date("2026-03-01T10:00:00Z");
    const counters = new CallCounters(join(tempDir(), "counters.json"), () => clock);

    assert.equal(counters.admit("gr_1", 2), true);
    assert.equal(counters.admit("gr_1", 2), true);
    assert.equal(counters.admit("gr_1", 2), false, "the ceiling is spent");
    assert.equal(counters.load().counts.gr_1, 2);

    // A restarted process reads the same file; the ceiling stays spent.
    const reloaded = new CallCounters(counters.path, () => clock);
    assert.equal(reloaded.admit("gr_1", 2), false);

    // Another grant has its own counter.
    assert.equal(reloaded.admit("gr_2", 1), true);

    clock = new Date("2026-03-02T00:00:01Z");
    assert.equal(reloaded.admit("gr_1", 2), true, "a new day resets the count");
    assert.equal(reloaded.load().counts.gr_1, 1);
  });

  it("treats a corrupt counter file as a refusal, not a fresh day", () => {
    const path = join(tempDir(), "counters.json");
    const counters = new CallCounters(path);
    counters.admit("gr_1", 5);
    writeFileSync(path, "{not json");
    assert.throws(() => counters.admit("gr_1", 5), /not valid JSON/);
  });

  it("refuses the third call at the broker and still refuses after a restart", async () => {
    const harness = await createHarness({ callsPerDay: 2 });
    cleanups.push(harness.close);
    let broker = await startInProcessBroker(harness);
    cleanups.push(() => broker.stop());

    const client = clientFor(harness);
    await client.openSession();
    const issued = await client.issueLease([SERVICE_ID]);
    const call = (): Promise<{ status: number }> =>
      client
        .call({ leaseToken: issued.token, service: SERVICE_ID, path: "/v1/echo" })
        .then((response) => ({ status: response.status }));

    assert.equal((await call()).status, 200);
    assert.equal((await call()).status, 200);
    await assert.rejects(call(), (error: unknown) => {
      assert.equal((error as { code?: string }).code, "charade.ceiling_reached");
      return true;
    });

    await broker.stop();
    broker = await startInProcessBroker(harness);

    const second = clientFor(harness);
    await second.openSession();
    const reissued = await second.issueLease([SERVICE_ID]);
    await assert.rejects(
      second.call({ leaseToken: reissued.token, service: SERVICE_ID, path: "/v1/echo" }),
      (error: unknown) => {
        assert.equal((error as { code?: string }).code, "charade.ceiling_reached");
        return true;
      },
    );
  });
});
