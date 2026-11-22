import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import {
  emptyRegistry,
  loadRegistry,
  RegistryError,
  saveRegistry,
  validateRegistry,
  type Registry,
} from "../src/registry/registry.js";

const NOW = "2026-01-01T00:00:00Z";
const dirs: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "charade-registry-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(): Registry {
  return {
    schema: "charade.registry/1",
    revision: 1,
    services: [
      {
        id: "svc",
        name: "Example",
        url: "https://example.test",
        transport: "http",
        auth: { type: "header", name: "Authorization", template: "Bearer ${SVC_KEY}" },
        actions: { read: ["GET /v1/*"], write: ["POST /v1/*"], destructive: [] },
      },
    ],
    consumers: [
      {
        id: "c1",
        name: "Consumer",
        services: ["svc"],
        deviceIds: ["d1"],
        createdAt: NOW,
      },
    ],
    devices: [
      {
        id: "d1",
        consumerId: "c1",
        publicKey: Buffer.alloc(32, 1).toString("base64url"),
        createdAt: NOW,
      },
    ],
  };
}

describe("registry", () => {
  it("validates, saves, and reloads a registry with an incremented revision", () => {
    const dir = tempDir();
    const path = join(dir, "registry.json");
    const saved = saveRegistry(path, fixture());
    assert.equal(saved.revision, 2);
    const loaded = loadRegistry(path);
    assert.equal(loaded.revision, 2);
    assert.equal(loaded.services[0]?.id, "svc");
    assert.equal(loaded.consumers[0]?.deviceIds[0], "d1");
  });

  it("refuses a missing or malformed registry instead of using an empty one", () => {
    const dir = tempDir();
    assert.throws(() => loadRegistry(join(dir, "missing.json")), RegistryError);
    const path = join(dir, "bad.json");
    writeFileSync(path, "{", { mode: 0o600 });
    assert.throws(() => loadRegistry(path), RegistryError);
  });

  it("refuses an empty service registry unless explicitly allowed", () => {
    const empty = emptyRegistry();
    assert.throws(() => validateRegistry(empty), RegistryError);
    assert.equal(validateRegistry(empty, { allowEmpty: true }).services.length, 0);
  });

  it("refuses unknown service references, bad devices, and duplicates", () => {
    const registry = fixture();
    assert.throws(
      () =>
        validateRegistry({
          ...registry,
          consumers: [{ ...registry.consumers[0]!, services: ["missing"] }],
        }),
      RegistryError,
    );
    assert.throws(
      () =>
        validateRegistry({
          ...registry,
          devices: [{ ...registry.devices[0]!, publicKey: "short" }],
        }),
      RegistryError,
    );
    assert.throws(
      () => validateRegistry({ ...registry, services: [registry.services[0]!, registry.services[0]!] }),
      RegistryError,
    );
    assert.throws(
      () => validateRegistry({ ...registry, services: [{ ...registry.services[0]!, url: "ftp://x" }] }),
      RegistryError,
    );
  });
});
