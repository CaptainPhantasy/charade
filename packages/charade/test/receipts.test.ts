import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import {
  ReceiptIntegrityError,
  ReceiptLog,
  verifyReceipts,
} from "../src/audit/receipts.js";

const ACTOR = { type: "consumer" as const, id: "c1", deviceId: "d1" };
const dirs: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "charade-receipts-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("receipts", () => {
  it("appends a verifiable hash chain and resumes it after reload", () => {
    const path = join(tempDir(), "receipts.jsonl");
    const log = new ReceiptLog(path);
    log.append({ actor: ACTOR, action: "lease.issue", outcome: "ok", requestId: "rq1" });
    log.append({ actor: ACTOR, action: "proxy.use", subject: "svc", outcome: "ok", requestId: "rq2" });
    const verified = log.verify();
    assert.equal(verified.ok, true);
    assert.equal(verified.count, 2);
    const resumed = new ReceiptLog(path);
    const third = resumed.append({
      actor: { type: "owner", id: "owner" },
      action: "policy.accept",
      outcome: "ok",
      requestId: "rq3",
    });
    assert.equal(third.sequence, 3);
    assert.equal(verifyReceipts(path).count, 3);
  });

  it("detects a tampered record and refuses to append to it", () => {
    const path = join(tempDir(), "receipts.jsonl");
    const log = new ReceiptLog(path);
    log.append({ actor: ACTOR, action: "lease.issue", outcome: "ok", requestId: "rq1" });
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const record = JSON.parse(lines[0] ?? "{}");
    record.outcome = "failed";
    writeFileSync(path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    assert.equal(verifyReceipts(path).ok, false);
    assert.throws(() => new ReceiptLog(path), ReceiptIntegrityError);
  });

  it("writes a 0600 anchor at the chain head", () => {
    const dir = tempDir();
    const log = new ReceiptLog(join(dir, "receipts.jsonl"));
    log.append({ actor: ACTOR, action: "lease.issue", outcome: "ok", requestId: "rq1" });
    const anchor = log.anchor(join(dir, "anchors"));
    assert.equal(statSync(anchor).mode & 0o777, 0o600);
    assert.match(readFileSync(anchor, "utf8"), /"schema":"charade\.receipt-anchor\/1"/);
  });
});
