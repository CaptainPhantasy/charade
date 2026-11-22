import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
} from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { canonicalJson } from "../core/canonical-json.js";
import type { Receipt, ReceiptActor } from "../core/protocol.js";
import { writeAtomic } from "../vault/atomic.js";

export interface ReceiptInput {
  readonly actor: ReceiptActor;
  readonly action: string;
  readonly subject?: string;
  readonly outcome: Receipt["outcome"];
  readonly requestId: string;
  readonly ts?: string;
}

export interface ReceiptVerification {
  readonly ok: boolean;
  readonly count: number;
  readonly headHash: string;
  readonly brokenAt?: number;
}

export class ReceiptIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReceiptIntegrityError";
  }
}

export class ReceiptLog {
  private head = "";
  private sequence = 0;

  constructor(readonly path: string) {
    if (existsSync(path)) {
      const verification = verifyReceipts(path);
      if (!verification.ok) {
        throw new ReceiptIntegrityError(
          `receipt chain is broken at record ${verification.brokenAt ?? "unknown"}`,
        );
      }
      this.head = verification.headHash;
      this.sequence = verification.count;
    }
  }

  append(input: ReceiptInput): Receipt {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const sequence = this.sequence + 1;
    const body = {
      schema: "charade.receipt/1" as const,
      receiptId: `r_${randomBytes(8).toString("hex")}`,
      sequence,
      ts: input.ts ?? new Date().toISOString(),
      actor: input.actor,
      action: input.action,
      ...(input.subject ? { subject: input.subject } : {}),
      outcome: input.outcome,
      requestId: input.requestId,
      prevHash: this.head,
    };
    const hash = hashReceipt(body);
    const record: Receipt = { ...body, hash };
    appendFileSync(this.path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    chmodSync(this.path, 0o600);
    this.head = hash;
    this.sequence = sequence;
    return record;
  }

  verify(): ReceiptVerification {
    return verifyReceipts(this.path);
  }

  anchor(anchorDirectory: string, now = new Date()): string {
    mkdirSync(anchorDirectory, { recursive: true, mode: 0o700 });
    const anchor = {
      schema: "charade.receipt-anchor/1",
      sequence: this.sequence,
      headHash: this.head,
      ts: now.toISOString(),
    };
    const path = join(anchorDirectory, `receipt-${this.sequence}.json`);
    writeAtomic(path, Buffer.from(canonicalJson(anchor), "utf8"), 0o600);
    return path;
  }
}

export function verifyReceipts(path: string): ReceiptVerification {
  if (!existsSync(path)) return { ok: true, count: 0, headHash: "" };
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return { ok: false, count: 0, headHash: "", brokenAt: 1 };
  }
  const lines = text.split("\n").filter((line) => line.length > 0);
  let prev = "";
  let head = "";
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    let record: Receipt;
    try {
      record = JSON.parse(line) as Receipt;
    } catch {
      return { ok: false, count: index, headHash: prev, brokenAt: index + 1 };
    }
    if (
      record.schema !== "charade.receipt/1" ||
      record.sequence !== index + 1 ||
      record.prevHash !== prev
    ) {
      return { ok: false, count: index, headHash: prev, brokenAt: index + 1 };
    }
    const { hash: claimed, ...body } = record;
    if (hashReceipt(body) !== claimed) {
      return { ok: false, count: index, headHash: prev, brokenAt: index + 1 };
    }
    prev = claimed;
    head = claimed;
  }
  return { ok: true, count: lines.length, headHash: head };
}

function hashReceipt(body: Omit<Receipt, "hash">): string {
  return createHash("sha256").update(canonicalJson(body)).digest("hex");
}
