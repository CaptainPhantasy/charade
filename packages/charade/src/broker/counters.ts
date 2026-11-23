import { readFileSync } from "node:fs";
import { canonicalJson } from "../core/canonical-json.js";
import { writeAtomic } from "../vault/atomic.js";

export interface CounterState {
  readonly schema: "charade.counters/1";
  readonly day: string;
  readonly counts: Readonly<Record<string, number>>;
}

export class CounterError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CounterError";
  }
}

/**
 * Durable per-grant daily call counters. A restart must not restore an
 * exhausted ceiling, and a corrupt file must not silently reset it either:
 * an unreadable counter file is a refusal, not a fresh day.
 */
export class CallCounters {
  constructor(
    readonly path: string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  private today(): string {
    return this.now().toISOString().slice(0, 10);
  }

  load(): CounterState {
    let text: string;
    try {
      text = readFileSync(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return { schema: "charade.counters/1", day: this.today(), counts: {} };
      }
      throw new CounterError("counter file is unreadable");
    }
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      throw new CounterError("counter file is not valid JSON");
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new CounterError("counter file is not an object");
    }
    const record = value as Record<string, unknown>;
    if (record.schema !== "charade.counters/1") {
      throw new CounterError("counter file schema is unsupported");
    }
    if (typeof record.day !== "string") throw new CounterError("counter file has no day");
    const counts = record.counts;
    if (typeof counts !== "object" || counts === null || Array.isArray(counts)) {
      throw new CounterError("counter file has no counts");
    }
    const parsed: Record<string, number> = {};
    for (const [key, value] of Object.entries(counts as Record<string, unknown>)) {
      if (!Number.isInteger(value) || (value as number) < 0) {
        throw new CounterError(`counter for ${key} is not a non-negative integer`);
      }
      parsed[key] = value as number;
    }
    return { schema: "charade.counters/1", day: record.day, counts: parsed };
  }

  /** Count one call for this grant, or refuse when the day's ceiling is spent. */
  admit(grantId: string, ceiling: number): boolean {
    if (!Number.isInteger(ceiling) || ceiling <= 0) return false;
    const state = this.load();
    const day = this.today();
    const used = state.day === day ? (state.counts[grantId] ?? 0) : 0;
    if (used >= ceiling) return false;
    const counts: Record<string, number> = state.day === day ? { ...state.counts } : {};
    counts[grantId] = used + 1;
    const next: CounterState = { schema: "charade.counters/1", day, counts };
    writeAtomic(this.path, Buffer.from(canonicalJson(next), "utf8"), 0o600);
    return true;
  }
}
