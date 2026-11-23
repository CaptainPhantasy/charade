import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";
import { generateOwnerKeyPair, privateKeyObject } from "../src/authority/keys.js";
import { loadRegistry } from "../src/registry/registry.js";

const CLI = fileURLToPath(new URL("../src/cli/main.js", import.meta.url));
const homes: string[] = [];

afterEach(() => {
  for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true });
});

function tempHome(): string {
  const home = mkdtempSync(join(tmpdir(), "charade-cli-registry-"));
  homes.push(home);
  return home;
}

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function addService(home: string, extra: string[] = []): ReturnType<typeof run> {
  return run([
    "registry",
    "add-service",
    "--home",
    home,
    "--id",
    "svc",
    "--name",
    "Example",
    "--url",
    "https://api.example.test",
    "--auth",
    "header",
    "--auth-name",
    "Authorization",
    "--auth-template",
    "Bearer ${SVC_KEY}",
    "--read",
    "GET /v1/*",
    "--write",
    "POST /v1/*",
    ...extra,
  ]);
}

describe("charade registry and device administration", () => {
  it("adds a service, consumer, and enrolled device, and validates the result", () => {
    const home = tempHome();

    const service = addService(home);
    assert.equal(service.status, 0, service.stderr);
    assert.match(service.stdout, /service added: svc/);
    assert.match(service.stdout, /revision:\s+1/);

    const consumer = run([
      "registry",
      "add-consumer",
      "--home",
      home,
      "--id",
      "c1",
      "--name",
      "Agent",
      "--services",
      "svc",
    ]);
    assert.equal(consumer.status, 0, consumer.stderr);
    assert.match(consumer.stdout, /consumer added: c1/);
    assert.match(consumer.stdout, /device enroll/);

    const out = join(home, "c1.device.json");
    const enrolled = run(["device", "enroll", "--home", home, "--consumer", "c1", "--id", "d1", "--out", out]);
    assert.equal(enrolled.status, 0, enrolled.stderr);
    assert.match(enrolled.stdout, /device enrolled: d1/);
    assert.equal(enrolled.stdout.includes('"privateKey"'), false, "the private key is never printed");

    const deviceFile = JSON.parse(readFileSync(out, "utf8")) as Record<string, string>;
    assert.equal(deviceFile.schema, "charade.device/1");
    assert.equal(deviceFile.deviceId, "d1");
    assert.equal(statSync(out).mode & 0o777, 0o600);
    // The private key must be a usable PKCS#8 Ed25519 key.
    assert.equal(privateKeyObject(deviceFile.privateKey as string).asymmetricKeyType, "ed25519");

    const registry = loadRegistry(join(home, "registry.json"));
    assert.equal(registry.services.length, 1);
    assert.equal(registry.consumers[0]?.deviceIds.includes("d1"), true);
    const device = registry.devices.find((item) => item.id === "d1");
    assert.ok(device);
    assert.equal(device.consumerId, "c1");
    assert.equal(device.publicKey, deviceFile.publicKey);

    const validated = run(["registry", "validate", "--home", home]);
    assert.equal(validated.status, 0, validated.stderr);
    assert.match(validated.stdout, /1 services, 1 consumers, 1 devices/);
  });

  it("accepts an externally generated device key with add-device", () => {
    const home = tempHome();
    assert.equal(addService(home).status, 0);
    assert.equal(
      run(["registry", "add-consumer", "--home", home, "--id", "c1", "--name", "Agent", "--services", "svc"]).status,
      0,
    );
    const keys = generateOwnerKeyPair();
    const added = run([
      "registry",
      "add-device",
      "--home",
      home,
      "--id",
      "d2",
      "--consumer",
      "c1",
      "--public-key",
      keys.publicKey,
    ]);
    assert.equal(added.status, 0, added.stderr);
    const registry = loadRegistry(join(home, "registry.json"));
    assert.equal(registry.devices[0]?.publicKey, keys.publicKey);
  });

  it("refuses oauth2, unknown services, duplicate ids, short keys, and overwriting a device file", () => {
    const home = tempHome();

    const oauth = run([
      "registry", "add-service", "--home", home,
      "--id", "oauth-svc", "--name", "OAuth", "--url", "https://oauth.test",
      "--auth", "oauth2", "--read", "GET /v1/*",
    ]);
    assert.equal(oauth.status, 1);
    assert.match(oauth.stderr, /oauth2 connectors are not implemented/);
    assert.match(oauth.stderr, /header, basic, or query/);

    const noActions = run([
      "registry", "add-service", "--home", home,
      "--id", "bare", "--name", "Bare", "--url", "https://bare.test", "--auth", "header",
    ]);
    assert.equal(noActions.status, 1);
    assert.match(noActions.stderr, /declare at least one action pattern/);

    assert.equal(addService(home).status, 0);
    const duplicate = addService(home);
    assert.equal(duplicate.status, 1);
    assert.match(duplicate.stderr, /duplicate service id svc/);

    const unknownService = run([
      "registry", "add-consumer", "--home", home,
      "--id", "c9", "--name", "Ghost", "--services", "missing",
    ]);
    assert.equal(unknownService.status, 1);
    assert.match(unknownService.stderr, /unknown service missing/);

    assert.equal(
      run(["registry", "add-consumer", "--home", home, "--id", "c1", "--name", "Agent", "--services", "svc"]).status,
      0,
    );

    const shortKey = run([
      "registry", "add-device", "--home", home,
      "--id", "d9", "--consumer", "c1", "--public-key", Buffer.alloc(16, 1).toString("base64url"),
    ]);
    assert.equal(shortKey.status, 1);
    assert.match(shortKey.stderr, /32 bytes/);

    const unknownConsumer = run(["device", "enroll", "--home", home, "--consumer", "ghost", "--id", "d1", "--out", join(home, "d1.json")]);
    assert.equal(unknownConsumer.status, 1);
    assert.match(unknownConsumer.stderr, /not in the registry/);
    assert.equal(existsSync(join(home, "d1.json")), false);

    const out = join(home, "d1.device.json");
    assert.equal(run(["device", "enroll", "--home", home, "--consumer", "c1", "--id", "d1", "--out", out]).status, 0);
    const overwrite = run(["device", "enroll", "--home", home, "--consumer", "c1", "--id", "d3", "--out", out]);
    assert.equal(overwrite.status, 1);
    assert.match(overwrite.stderr, /refusing to overwrite/);
  });

  it("keeps the registry file at mode 0600", () => {
    const home = tempHome();
    assert.equal(addService(home).status, 0);
    assert.equal(statSync(join(home, "registry.json")).mode & 0o777, 0o600);
  });
});
