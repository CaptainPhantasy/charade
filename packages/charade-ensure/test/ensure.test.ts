import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { detectCharade, EXIT_ABSENT, EXIT_AMBIGUOUS, EXIT_BROKEN, EXIT_COMPATIBLE } from "../src/detect.js";

const join = (...parts: string[]): string => parts.join("/");

describe("charade ensure", () => {
  it("reports absent without installing anything", () => {
    const result = detectCharade({ env: {}, pathEntries: [], isFile: () => false, join });
    assert.equal(result.exitCode, EXIT_ABSENT);
    assert.equal(result.binary.state, "absent");
    assert.equal(result.doors.length, 3);
    assert.equal(result.doors.some((door) => door.commands.some((command) => command.includes("install -g"))), true);
  });

  it("reports a broken explicit path rather than falling through to PATH", () => {
    const result = detectCharade({
      env: { CHARADE_BIN: "/missing/charade" },
      pathEntries: ["/bin"],
      isFile: (path) => path === "/bin/charade",
      join,
    });
    assert.equal(result.exitCode, EXIT_BROKEN);
    assert.equal(result.binary.state, "configured_broken");
    assert.equal(result.binary.installations.length, 0);
  });

  it("finds a compatible binary on PATH", () => {
    const result = detectCharade({
      env: { PATH: "/opt/bin:/usr/bin" },
      isFile: (path) => path === "/opt/bin/charade",
      join,
    });
    assert.equal(result.exitCode, EXIT_COMPATIBLE);
    assert.equal(result.binary.state, "found");
    assert.equal(result.binary.path, "/opt/bin/charade");
  });

  it("reports multiple installations instead of choosing silently", () => {
    const result = detectCharade({
      env: { PATH: "/one:/two" },
      isFile: () => true,
      join,
    });
    assert.equal(result.exitCode, EXIT_AMBIGUOUS);
    assert.equal(result.binary.installations.length, 2);
    assert.equal(result.warnings.length, 1);
  });

  it("never reports a configured broker as reachable without a probe", () => {
    const result = detectCharade({
      env: { CHARADE_SOCKET: "/tmp/charade.sock" },
      pathEntries: [],
      isFile: () => false,
      join,
    });
    assert.equal(result.broker.state, "configured");
    assert.equal(result.broker.socket, "/tmp/charade.sock");
  });
});
