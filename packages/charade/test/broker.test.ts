import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sign } from "node:crypto";
import { afterEach, describe, it } from "node:test";
import {
  generateOwnerKeyPair,
  privateKeyObject,
} from "../src/authority/keys.js";
import { createPolicy, addGrant } from "../src/authority/store.js";
import { DEFAULT_GATES } from "../src/authority/policy.js";
import { signGrant } from "../src/authority/grants.js";
import { initVault, openVault, putSecret } from "../src/vault/vault.js";
import { saveRegistry, type Registry } from "../src/registry/registry.js";
import { verifyReceipts } from "../src/audit/receipts.js";
import { Broker } from "../src/broker/server.js";
import { SESSION_DOMAIN } from "../src/broker/session.js";

const PASSPHRASE = "correct horse battery staple";
const NOW = new Date("2026-01-01T00:00:00Z");
const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

interface Fixture {
  readonly home: string;
  readonly broker: Broker;
  readonly upstream: Server;
  readonly ownerPrivate: string;
  readonly devicePrivate: string;
  readonly captured: Array<{ url?: string; headers: Record<string, string | string[] | undefined>; body: string }>;
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

async function fixture(options: { hardStopSend?: boolean; omitRegistry?: boolean } = {}): Promise<Fixture> {
  const home = mkdtempSync(join(tmpdir(), "charade-broker-"));
  const captured: Fixture["captured"] = [];
  const upstream = createServer((request, response) => {
    if (request.url === "/v1/redirect") {
      response.writeHead(302, { location: "http://127.0.0.1:1/not-allowed" });
      response.end();
      return;
    }
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      captured.push({
        url: request.url,
        headers: request.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      });
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("upstream-ok");
    });
  });
  const port = await listen(upstream);
  cleanups.push(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

  initVault({ home, passphrase: PASSPHRASE, now: NOW });
  let open = openVault(home, PASSPHRASE);
  // The vault owner is the authority; sign with the key inside the payload.
  const policy = createPolicy(open);
  const ownerKeys = {
    privateKey: open.payload.owner?.privateKey ?? "",
    publicKey: policy.ownerPublicKey,
  };
  assert.ok(ownerKeys.privateKey);
  open = putSecret(open, { serviceId: "svc", value: "fixture-injected", now: NOW });

  const device = generateOwnerKeyPair();
  const registry: Registry = {
    schema: "charade.registry/1",
    revision: 1,
    services: [
      {
        id: "svc",
        name: "Mock",
        url: `http://127.0.0.1:${port}`,
        transport: "http",
        auth: { type: "header", name: "Authorization", template: "Bearer ${SVC_KEY}" },
        actions: {
          read: ["GET /v1/*"],
          write: ["POST /v1/*"],
          destructive: options.hardStopSend ? ["send POST /send"] : [],
        },
      },
    ],
    consumers: [
      { id: "c1", name: "Consumer", services: ["svc"], deviceIds: ["d1"], createdAt: NOW.toISOString() },
    ],
    devices: [
      {
        id: "d1",
        consumerId: "c1",
        publicKey: device.publicKey,
        createdAt: NOW.toISOString(),
      },
    ],
  };
  if (!options.omitRegistry) saveRegistry(join(home, "registry.json"), registry);

  const policyForGrant = policy;
  const grant = signGrant(
    ownerKeys.privateKey,
    policyForGrant,
    {
      consumerId: "c1",
      deviceId: "d1",
      services: ["svc"],
      methods: ["GET", "POST"],
      paths: ["/v1/*", "/send"],
      durationSeconds: 86_400,
      ceilings: { callsPerDay: 100 },
      hardStops: { ...DEFAULT_GATES.hardStops, send: options.hardStopSend ?? true },
      envAllowed: false,
    },
    NOW,
  );
  addGrant(home, grant);

  const broker = new Broker({ home, passphrase: PASSPHRASE, now: () => NOW });
  await broker.start();
  cleanups.push(() => broker.stop());
  return {
    home,
    broker,
    upstream,
    ownerPrivate: ownerKeys.privateKey,
    devicePrivate: device.privateKey,
    captured,
  };
}

function call(
  socketPath: string,
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body?: Buffer | string,
): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      { socketPath, method, path, headers },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks),
          }),
        );
      },
    );
    request.on("error", reject);
    if (body !== undefined) request.write(body);
    request.end();
  });
}

async function jsonCall(
  socketPath: string,
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body?: unknown,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const response = await call(
    socketPath,
    method,
    path,
    {
      ...headers,
      ...(payload ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(payload)) } : {}),
    },
    payload,
  );
  return {
    status: response.status,
    json: JSON.parse(response.body.toString("utf8") || "{}") as Record<string, unknown>,
  };
}

async function openSession(
  socketPath: string,
  role: "owner" | "consumer",
  privateKey: string,
  consumerId?: string,
  deviceId = role === "owner" ? "owner" : "d1",
): Promise<Record<string, unknown>> {
  const challenge = await jsonCall(socketPath, "POST", "/v1/session/challenge", {}, {
    role,
    ...(consumerId ? { consumerId } : {}),
    deviceId,
  });
  assert.equal(challenge.status, 200);
  const nonce = challenge.json.nonce as string;
  const message = Buffer.from(`${SESSION_DOMAIN}${nonce}\u0000${deviceId}`, "utf8");
  const signature = sign(null, message, privateKeyObject(privateKey)).toString("base64url");
  const session = await jsonCall(socketPath, "POST", "/v1/session", {}, {
    challengeId: challenge.json.challengeId,
    signature,
    deviceId,
  });
  assert.equal(session.status, 200);
  return session.json;
}

describe("broker", () => {
  it("serves honest health, issues leases, proxies without leaking the secret, and revokes", async () => {
    const f = await fixture();
    assert.equal(statSync(f.broker.socketPath).mode & 0o777, 0o600);

    const health = await jsonCall(f.broker.socketPath, "GET", "/health");
    assert.equal(health.status, 200);
    assert.equal(health.json.ready, true);
    assert.equal(health.json.overall, "ok");
    assert.equal(JSON.stringify(health.json).includes(f.home), false);

    const session = await openSession(f.broker.socketPath, "consumer", f.devicePrivate, "c1");
    const auth = { authorization: `Bearer ${session.sessionToken as string}` };

    const lease = await jsonCall(f.broker.socketPath, "POST", "/v1/leases", auth, { service: "svc" });
    assert.equal(lease.status, 201);
    const leaseToken = lease.json.token as string;
    const leaseRecord = lease.json.lease as { leaseId: string; secretVersionIds: Record<string, string> };
    assert.ok(leaseToken);
    assert.equal(JSON.stringify(lease.json).includes("fixture-injected"), false);

    const proxied = await call(
      f.broker.socketPath,
      "POST",
      "/v1/proxy/svc/v1/echo?x=1",
      {
        ...auth,
        "x-charade-lease": leaseToken,
        "x-charade-session": auth.authorization,
        "content-type": "text/plain",
        "content-length": "5",
      },
      "hello",
    );
    assert.equal(proxied.status, 200);
    assert.equal(proxied.body.toString(), "upstream-ok");
    assert.equal(f.captured.length, 1);
    assert.equal(f.captured[0]?.url, "/v1/echo?x=1");
    assert.equal(f.captured[0]?.headers.authorization, "Bearer fixture-injected");
    assert.equal(f.captured[0]?.headers["x-charade-lease"], undefined);
    assert.equal(f.captured[0]?.headers["x-charade-session"], undefined);
    assert.equal(f.captured[0]?.body, "hello");

    const redirected = await call(
      f.broker.socketPath,
      "GET",
      "/v1/proxy/svc/v1/redirect",
      { ...auth, "x-charade-lease": leaseToken },
    );
    assert.equal(redirected.status, 502);
    assert.equal(f.captured.length, 1);

    const receipts = readFileSync(join(f.home, "receipts.jsonl"), "utf8");
    assert.equal(receipts.includes("fixture-injected"), false);
    assert.equal(verifyReceipts(join(f.home, "receipts.jsonl")).ok, true);
    assert.match(receipts, /proxy\.attempt/);
    assert.match(receipts, /proxy\.complete/);

    const renewed = await jsonCall(
      f.broker.socketPath,
      "POST",
      `/v1/leases/${leaseRecord.leaseId}/renew`,
      auth,
      { token: leaseToken },
    );
    assert.equal(renewed.status, 200);
    const newToken = renewed.json.token as string;
    const proxiedAgain = await call(
      f.broker.socketPath,
      "POST",
      "/v1/proxy/svc/v1/echo",
      { ...auth, "x-charade-lease": newToken, "content-length": "0" },
      "",
    );
    assert.equal(proxiedAgain.status, 200);

    const revoked = await jsonCall(
      f.broker.socketPath,
      "POST",
      `/v1/leases/${leaseRecord.leaseId}/revoke`,
      auth,
      {},
    );
    assert.equal(revoked.status, 200);
    const afterRevoke = await call(
      f.broker.socketPath,
      "POST",
      "/v1/proxy/svc/v1/echo",
      { ...auth, "x-charade-lease": newToken, "content-length": "0" },
      "",
    );
    assert.equal(afterRevoke.status, 401);
  });

  it("denies unknown actions and hard-stopped destructive actions", async () => {
    const f = await fixture({ hardStopSend: true });
    const session = await openSession(f.broker.socketPath, "consumer", f.devicePrivate, "c1");
    const auth = { authorization: `Bearer ${session.sessionToken as string}` };
    const lease = await jsonCall(f.broker.socketPath, "POST", "/v1/leases", auth, { service: "svc" });
    const leaseToken = lease.json.token as string;
    const headers = { ...auth, "x-charade-lease": leaseToken, "content-length": "0" };

    const unknown = await call(f.broker.socketPath, "GET", "/v1/proxy/svc/unknown", headers);
    assert.equal(unknown.status, 403);
    assert.match(unknown.body.toString(), /action_unknown/);

    const hardStop = await call(f.broker.socketPath, "POST", "/v1/proxy/svc/send", headers, "");
    assert.equal(hardStop.status, 403);
    assert.match(hardStop.body.toString(), /action_denied/);
  });

  it("fails loud when the registry disappears, and refuses leases", async () => {
    const f = await fixture();
    const session = await openSession(f.broker.socketPath, "consumer", f.devicePrivate, "c1");
    const auth = { authorization: `Bearer ${session.sessionToken as string}` };
    rmSync(join(f.home, "registry.json"));
    const health = await jsonCall(f.broker.socketPath, "GET", "/health");
    assert.equal(health.status, 503);
    assert.equal(health.json.ready, false);
    assert.equal(health.json.overall, "broken");
    assert.equal(JSON.stringify(health.json).includes(f.home), false);
    const lease = await jsonCall(f.broker.socketPath, "POST", "/v1/leases", auth, { service: "svc" });
    assert.equal(lease.status, 503);
    assert.match(JSON.stringify(lease.json), /registry_unreadable/);
  });

  it("gives the owner full health and denies a consumer the admin surface", async () => {
    const f = await fixture();
    const owner = await openSession(f.broker.socketPath, "owner", f.ownerPrivate);
    const ownerHealth = await jsonCall(f.broker.socketPath, "GET", "/v1/admin/health", {
      authorization: `Bearer ${owner.sessionToken as string}`,
    });
    assert.equal(ownerHealth.status, 200);
    const consumer = await openSession(f.broker.socketPath, "consumer", f.devicePrivate, "c1");
    const denied = await jsonCall(f.broker.socketPath, "GET", "/v1/admin/health", {
      authorization: `Bearer ${consumer.sessionToken as string}`,
    });
    assert.equal(denied.status, 403);
    assert.match(JSON.stringify(denied.json), /owner_required/);
  });

  it("rotates without stopping an existing lease and pins new leases to the new version", async () => {
    const f = await fixture();
    const consumer = await openSession(f.broker.socketPath, "consumer", f.devicePrivate, "c1");
    const auth = { authorization: `Bearer ${consumer.sessionToken as string}` };
    const firstLease = await jsonCall(f.broker.socketPath, "POST", "/v1/leases", auth, { service: "svc" });
    const firstToken = firstLease.json.token as string;
    const firstProxy = await call(
      f.broker.socketPath,
      "GET",
      "/v1/proxy/svc/v1/echo",
      { ...auth, "x-charade-lease": firstToken },
    );
    assert.equal(firstProxy.status, 200);
    assert.equal(f.captured[0]?.headers.authorization, "Bearer fixture-injected");

    const owner = await openSession(f.broker.socketPath, "owner", f.ownerPrivate);
    const rotated = await jsonCall(
      f.broker.socketPath,
      "POST",
      "/v1/admin/credentials/rotate",
      { authorization: `Bearer ${owner.sessionToken as string}` },
      { serviceId: "svc", value: "fixture-rotated" },
    );
    assert.equal(rotated.status, 200);
    assert.equal(JSON.stringify(rotated.json).includes("fixture-rotated"), false);

    const oldLeaseStillWorks = await call(
      f.broker.socketPath,
      "GET",
      "/v1/proxy/svc/v1/echo",
      { ...auth, "x-charade-lease": firstToken },
    );
    assert.equal(oldLeaseStillWorks.status, 200);
    assert.equal(f.captured[1]?.headers.authorization, "Bearer fixture-injected");

    const secondLease = await jsonCall(f.broker.socketPath, "POST", "/v1/leases", auth, { service: "svc" });
    const secondToken = secondLease.json.token as string;
    const newLeaseProxy = await call(
      f.broker.socketPath,
      "GET",
      "/v1/proxy/svc/v1/echo",
      { ...auth, "x-charade-lease": secondToken },
    );
    assert.equal(newLeaseProxy.status, 200);
    assert.equal(f.captured[2]?.headers.authorization, "Bearer fixture-rotated");
    assert.equal(readFileSync(join(f.home, "receipts.jsonl"), "utf8").includes("fixture-rotated"), false);
  });

  it("has no default environment-value endpoint", async () => {
    const f = await fixture();
    const session = await openSession(f.broker.socketPath, "consumer", f.devicePrivate, "c1");
    const response = await jsonCall(f.broker.socketPath, "POST", "/v1/env", {
      authorization: `Bearer ${session.sessionToken as string}`,
    }, {});
    assert.equal(response.status, 403);
    assert.match(JSON.stringify(response.json), /env_not_granted/);
  });

  it("refuses to reuse a session challenge", async () => {
    const f = await fixture();
    const challenge = await jsonCall(f.broker.socketPath, "POST", "/v1/session/challenge", {}, {
      role: "consumer",
      consumerId: "c1",
      deviceId: "d1",
    });
    const nonce = challenge.json.nonce as string;
    const signature = sign(
      null,
      Buffer.from(`${SESSION_DOMAIN}${nonce}\u0000d1`, "utf8"),
      privateKeyObject(f.devicePrivate),
    ).toString("base64url");
    const first = await jsonCall(f.broker.socketPath, "POST", "/v1/session", {}, {
      challengeId: challenge.json.challengeId,
      signature,
      deviceId: "d1",
    });
    assert.equal(first.status, 200);
    const replay = await jsonCall(f.broker.socketPath, "POST", "/v1/session", {}, {
      challengeId: challenge.json.challengeId,
      signature,
      deviceId: "d1",
    });
    assert.equal(replay.status, 401);
  });
});
