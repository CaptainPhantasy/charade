/**
 * Canonical JSON for signatures and hashes.
 *
 * Rules:
 * - object keys sorted lexicographically (UTF-16 code units);
 * - only null, booleans, strings, integers, arrays, and plain objects;
 * - numbers must be finite integers (no floats, NaN, or Infinity);
 * - undefined object properties are omitted; undefined array entries are rejected;
 * - cycles are rejected.
 *
 * This is deliberately stricter than JSON.stringify. A number that cannot be
 * represented exactly is refused rather than silently rounded into a signature.
 */
export class CanonicalJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalJsonError";
  }
}

export function canonicalJson(value: unknown): string {
  return serialize(value, new Set<object>());
}

function serialize(value: unknown, seen: Set<object>): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new CanonicalJsonError("non-finite number");
      }
      if (!Number.isInteger(value)) {
        throw new CanonicalJsonError("non-integer number");
      }
      return Object.is(value, -0) ? "0" : String(value);
    case "object": {
      if (seen.has(value as object)) {
        throw new CanonicalJsonError("cyclic value");
      }
      if (Array.isArray(value)) {
        seen.add(value);
        const parts: string[] = [];
        for (const item of value) {
          if (item === undefined) {
            throw new CanonicalJsonError("undefined array entry");
          }
          parts.push(serialize(item, seen));
        }
        seen.delete(value);
        return `[${parts.join(",")}]`;
      }
      seen.add(value as object);
      const record = value as Record<string, unknown>;
      const parts: string[] = [];
      for (const key of Object.keys(record).sort()) {
        const item = record[key];
        if (item === undefined) continue;
        parts.push(`${JSON.stringify(key)}:${serialize(item, seen)}`);
      }
      seen.delete(value as object);
      return `{${parts.join(",")}}`;
    }
    default:
      throw new CanonicalJsonError(`unsupported type: ${typeof value}`);
  }
}
