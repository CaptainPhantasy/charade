import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import {
  LeaseError,
  LeaseStore,
  isIdempotentMethod,
  shouldRenew,
  type IssueLeaseOptions,
} from "../src/registry/leases.js";
import type { ConsumerRecord, DeviceRecord } from "../src/registry/registry.js";
import { generateOwnerKeyPair } from "../src/authority/keys.js";
import { DEFAULT_GATES, defaultPolicyDraft, signPolicy } from "../src/authority/policy.js";
import { signGrant } from "../src/authority/grants.js";

const NOW = new Date("2026-01-01T00:00:00Z");
const dirs: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "charade-lease-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function setup(): {
  store: LeaseStore;
  options: IssueLeaseOptions;
  path: string;
  consumer: ConsumerRecord;
  device: DeviceRecord;
} {
  const owner = generateOwnerKeyPair();
  const policy = signPolicy(owner.privateKey, defaultPolicyDraft(owner.publicKey));
  const consumer: ConsumerRecord = {
    id: "c1",
    name: "Consumer",
    services: ["svc"],
    deviceIds: ["d1"],
    createdAt: NOW.toISOString(),
  };
  const device: DeviceRecord = {
    id: "d1",
    consumerId: "c1",
    publicKey: Buffer.alloc(32, 2).toString("base64url"),
    createdAt: NOW.toISOString(),
  };
  const grant = signGrant(
    owner.privateKey,
    policy,
    {
      consumerId: "c1",
      deviceId: "d1",
      services: ["svc"],
      methods: ["GET"],
      paths: ["/v1/*"],
      durationSeconds: 86_400,
      ceilings: { callsPerDay: 100 },
      hardStops: DEFAULT_GATES.hardStops,
      envAllowed: false,
    },
    NOW,
  );
  const path = join(tempDir(), "leases.json");
  return {
    store: new LeaseStore(path),
    path,
    consumer,
    device,
    options: {
      grant,
      policy,
      consumer,
      device,
      secretVersionIds: { svc: "v1" },
      now: NOW,
    },
  };
}

describe("leases", () => {
  it("issues a lease without storing the token", () => {
    const { store, options, path } = setup();
    const issued = store.issue(options);
    assert.equal(issued.token.length > 20, true);
    assert.equal(issued.lease.services[0], "svc");
    assert.equal(issued.lease.secretVersionIds.svc, "v1");
    const file = readFileSync(path, "utf8");
    assert.equal(file.includes(issued.token), false);
    assert.equal(file.includes("tokenHash"), true);
    const found = store.findByToken(issued.token, NOW);
    assert.equal(found.tokenKind, "current");
    assert.equal(found.lease.leaseId, issued.lease.leaseId);
  });

  it("caps the TTL at the policy maximum and grants a short remaining lifetime", () => {
    const { store, options } = setup();
    const issued = store.issue({ ...options, ttlSeconds: 1000 });
    const seconds =
      (new Date(issued.lease.expiresAt).getTime() - new Date(issued.lease.createdAt).getTime()) / 1000;
    assert.equal(seconds, 300);
  });

  it("renews at two-thirds of the lease and retries only idempotent methods", () => {
    const { store, options } = setup();
    const issued = store.issue(options);
    assert.equal(shouldRenew(issued.lease, new Date(NOW.getTime() + 79_000)), false);
    assert.equal(shouldRenew(issued.lease, new Date(NOW.getTime() + 81_000)), true);
    assert.equal(isIdempotentMethod("GET"), true);
    assert.equal(isIdempotentMethod("put"), true);
    assert.equal(isIdempotentMethod("POST"), false);
    assert.equal(isIdempotentMethod("PATCH"), false);
  });

  it("renews before expiry and keeps the previous token for its original lifetime", () => {
    const { store, options } = setup();
    const issued = store.issue(options);
    const renewAt = new Date(NOW.getTime() + 90_000);
    const renewed = store.renew(
      issued.lease.leaseId,
      issued.token,
      options.grant,
      options.policy,
      renewAt,
    );
    assert.notEqual(renewed.token, issued.token);
    assert.equal(store.findByToken(issued.token, renewAt).tokenKind, "previous");
    assert.equal(store.findByToken(renewed.token, renewAt).tokenKind, "current");
    assert.equal(
      store.findByToken(issued.token, new Date(NOW.getTime() + 119_000)).tokenKind,
      "previous",
    );
    assert.throws(
      () => store.findByToken(issued.token, new Date(NOW.getTime() + 121_000)),
      (error: unknown) => error instanceof LeaseError && error.code === "lease_expired",
    );
    assert.equal(
      store.findByToken(renewed.token, new Date(NOW.getTime() + 200_000)).tokenKind,
      "current",
    );
  });

  it("revokes immediately for new requests", () => {
    const { store, options } = setup();
    const issued = store.issue(options);
    store.revoke(issued.lease.leaseId, new Date(NOW.getTime() + 1000));
    assert.throws(
      () => store.findByToken(issued.token, new Date(NOW.getTime() + 2000)),
      (error: unknown) => error instanceof LeaseError && error.code === "lease_revoked",
    );
  });

  it("refuses device mismatches, expired grants, and unregistered consumers", () => {
    const { store, options, consumer, device } = setup();
    assert.throws(
      () => store.issue({ ...options, device: { ...device, id: "d2" } }),
      (error: unknown) => error instanceof LeaseError && error.code === "device_mismatch",
    );
    assert.throws(
      () => store.issue({ ...options, now: new Date(NOW.getTime() + 90_000_000) }),
      (error: unknown) => error instanceof LeaseError && error.code === "grant_invalid",
    );
    assert.throws(
      () => store.issue({ ...options, consumer: { ...consumer, services: [] } }),
      (error: unknown) => error instanceof LeaseError && error.code === "consumer_invalid",
    );
  });

  it("refuses to load a malformed lease store", () => {
    const dir = tempDir();
    const path = join(dir, "leases.json");
    writeFileSync(path, "{\"schema\":\"charade.leases/1\",\"revision\":0,\"leases\":[{}]}", {
      mode: 0o600,
    });
    const store = new LeaseStore(path);
    assert.throws(() => store.load(), LeaseError);
  });
});
