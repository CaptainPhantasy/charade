import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import {
  createHarness,
  runCli,
  stopBroker,
  waitForReady,
  type BrokerProcess,
  type Harness,
} from "./support/harness.js";

const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

interface DoctorReport {
  readonly schema: string;
  readonly version: string;
  readonly protocol: string;
  readonly home: string;
  readonly socket: string;
  readonly telemetry: boolean;
  readonly overall: string;
  readonly exit: number;
  readonly checks: Array<{ id: string; status: string; summary: string; remedy?: string }>;
}

function doctor(home: string, extra: string[] = []): { status: number | null; report?: DoctorReport; stdout: string; stderr: string } {
  const result = runCli(["doctor", "--home", home, "--json", ...extra]);
  let report: DoctorReport | undefined;
  try {
    report = JSON.parse(result.stdout) as DoctorReport;
  } catch {
    report = undefined;
  }
  return { status: result.status, ...(report ? { report } : {}), stdout: result.stdout, stderr: result.stderr };
}

describe("charade doctor", () => {
  it("reports a healthy install with a running broker", async () => {
    const harness: Harness = await createHarness();
    cleanups.push(harness.close);
    const broker: BrokerProcess = await waitForReady(harness);
    cleanups.push(() => stopBroker(broker));

    const result = doctor(harness.home, ["--passphrase-file", harness.pass]);
    assert.equal(result.status, 0, result.stdout);
    assert.ok(result.report);
    assert.equal(result.report.schema, "charade.doctor/1");
    assert.equal(result.report.telemetry, false);
    assert.equal(result.report.overall, "ok");
    assert.equal(result.report.exit, 0);
    const byId = new Map(result.report.checks.map((check) => [check.id, check]));
    assert.equal(byId.get("runtime")?.status, "pass");
    assert.equal(byId.get("vault-file")?.status, "pass");
    assert.equal(byId.get("vault-unlock")?.status, "pass");
    assert.equal(byId.get("policy")?.status, "pass");
    assert.equal(byId.get("registry")?.status, "pass");
    assert.equal(byId.get("grants")?.status, "pass");
    assert.equal(byId.get("receipts")?.status, "pass");
    assert.equal(byId.get("broker")?.status, "pass");
    assert.equal(byId.get("listeners")?.status, "pass");
  });

  it("reports a broken empty home with remedies and exit 1", () => {
    const home = mkdtempSync(join(tmpdir(), "charade-doctor-empty-"));
    cleanups.push(() => rmSync(home, { recursive: true, force: true }));

    const result = doctor(home);
    assert.equal(result.status, 1);
    assert.ok(result.report);
    assert.equal(result.report.overall, "broken");
    const byId = new Map(result.report.checks.map((check) => [check.id, check]));
    assert.equal(byId.get("policy")?.status, "fail");
    assert.match(String(byId.get("policy")?.remedy), /policy init/);
    assert.equal(byId.get("registry")?.status, "fail");
    assert.equal(byId.get("vault")?.status, "fail");
    assert.match(result.stdout, /"exit": 1/);
  });

  it("returns exit 3 when a required check could not run", async () => {
    const harness = await createHarness();
    cleanups.push(harness.close);

    // No broker and no passphrase: the vault unlock check is skipped, not passed.
    const result = doctor(harness.home);
    assert.equal(result.status, 3, result.stdout);
    assert.ok(result.report);
    assert.equal(result.report.overall, "unknown");
    const byId = new Map(result.report.checks.map((check) => [check.id, check]));
    assert.equal(byId.get("vault-unlock")?.status, "skipped");
    assert.equal(byId.get("broker")?.status, "skipped");
  });

  it("prints a human report and marks an invalid policy", async () => {
    const harness = await createHarness();
    cleanups.push(harness.close);
    const human = runCli(["doctor", "--home", harness.home, "--passphrase-file", harness.pass]);
    assert.match(human.stdout, /state:\s+degraded/);
    assert.match(human.stdout, /pass\s+policy:/);

    const policyFile = join(harness.home, "policy.json");
    assert.equal(statSync(policyFile).mode & 0o777, 0o600);
  });
});
