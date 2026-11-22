import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CanonicalJsonError,
  ERROR_CATALOG,
  aggregateHealth,
  canonicalJson,
  protocolCompatible,
  protocolString,
  type HealthCheck,
} from "../src/core/index.js";

describe("canonicalJson", () => {
  it("sorts object keys and preserves array order", () => {
    assert.equal(
      canonicalJson({ b: 1, a: [3, 2, 1], c: { z: true, y: null } }),
      '{"a":[3,2,1],"b":1,"c":{"y":null,"z":true}}',
    );
  });

  it("omits undefined object properties and rejects undefined array entries", () => {
    assert.equal(canonicalJson({ a: 1, b: undefined }), '{"a":1}');
    assert.throws(() => canonicalJson([1, undefined]), CanonicalJsonError);
  });

  it("accepts integers only and normalizes negative zero", () => {
    assert.equal(canonicalJson(-0), "0");
    assert.throws(() => canonicalJson(1.5), CanonicalJsonError);
    assert.throws(() => canonicalJson(Number.NaN), CanonicalJsonError);
    assert.throws(() => canonicalJson(Number.POSITIVE_INFINITY), CanonicalJsonError);
  });

  it("rejects cycles and unsupported values", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    assert.throws(() => canonicalJson(cyclic), CanonicalJsonError);
    assert.throws(() => canonicalJson(() => 1), CanonicalJsonError);
    assert.throws(() => canonicalJson(1n), CanonicalJsonError);
  });
});

describe("protocol", () => {
  it("reports a stable protocol string", () => {
    assert.equal(protocolString(), "1.0");
  });

  it("requires a matching major version", () => {
    assert.equal(protocolCompatible({ major: 1, minor: 0 }), true);
    assert.equal(protocolCompatible({ major: 1, minor: 7 }), true);
    assert.equal(protocolCompatible({ major: 2, minor: 0 }), false);
  });
});

describe("health", () => {
  const check = (
    id: string,
    required: boolean,
    status: HealthCheck["status"],
  ): HealthCheck => ({ id, required, status, summary: id });

  it("is unknown when there are no checks", () => {
    assert.equal(aggregateHealth([]).overall, "unknown");
  });

  it("is ok only when every check passes", () => {
    assert.equal(
      aggregateHealth([check("a", true, "pass"), check("b", false, "pass")]).overall,
      "ok",
    );
  });

  it("is broken when a required check fails", () => {
    assert.equal(
      aggregateHealth([check("a", true, "fail"), check("b", false, "warn")]).overall,
      "broken",
    );
  });

  it("is unknown when a required check was skipped, not applicable, or unknown", () => {
    for (const status of ["skipped", "not_applicable", "unknown"] as const) {
      const report = aggregateHealth([check("a", true, status)]);
      assert.equal(report.overall, "unknown");
      assert.deepEqual(report.unknowns, ["a"]);
    }
  });

  it("is degraded when only optional checks have problems", () => {
    assert.equal(aggregateHealth([check("a", true, "pass"), check("b", false, "fail")]).overall, "degraded");
    assert.equal(aggregateHealth([check("a", true, "pass"), check("b", false, "unknown")]).overall, "degraded");
  });
});

describe("error catalog", () => {
  it("gives every code a plain-language explanation and a next step", () => {
    for (const [code, definition] of Object.entries(ERROR_CATALOG)) {
      assert.ok(definition.whatHappened.length > 0, code);
      assert.ok(definition.whatNext.length > 0, code);
      assert.equal(typeof definition.ownerOnly, "boolean", code);
      assert.equal(typeof definition.retriable, "boolean", code);
    }
  });
});
