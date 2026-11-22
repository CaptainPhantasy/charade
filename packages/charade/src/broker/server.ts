import { chmodSync, existsSync, mkdirSync, unlinkSync } from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { CharadeError, type ErrorCode } from "../core/errors.js";
import { protocolString } from "../core/version.js";
import type { Grant } from "../core/protocol.js";
import { loadGrants, loadPolicy } from "../authority/store.js";
import { verifyGrant } from "../authority/grants.js";
import {
  loadRegistry,
  RegistryError,
  type ConsumerRecord,
  type DeviceRecord,
  type Registry,
  type ServiceRecord,
} from "../registry/registry.js";
import { LeaseError, LeaseStore, type LeaseRecord } from "../registry/leases.js";
import { ReceiptLog } from "../audit/receipts.js";
import {
  findActiveSecret,
  findSecretVersion,
  openVault,
  rotateSecret,
  type OpenVault,
} from "../vault/vault.js";
import { SessionError, SessionStore, type Session } from "./session.js";
import { brokerHealth, brokerReady } from "./health.js";
import { classifyAction } from "./connectors.js";
import { forwardProxy, ProxyError } from "./proxy/forward.js";

const MAX_BODY = 1024 * 1024;

export interface BrokerOptions {
  readonly home: string;
  readonly passphrase: string;
  readonly socketPath?: string;
  readonly now?: () => Date;
}

export class Broker {
  readonly home: string;
  readonly socketPath: string;
  private readonly passphrase: string;
  private readonly now: () => Date;
  private readonly sessions = new SessionStore();
  private readonly counters = new Map<string, { day: string; count: number }>();
  private open?: OpenVault;
  private policy?: ReturnType<typeof loadPolicy>;
  private policyError?: string;
  private registry?: Registry;
  private registryError?: string;
  private grants: readonly Grant[] = [];
  private grantsError?: string;
  private receipts?: ReceiptLog;
  private receiptsError?: string;
  private leases?: LeaseStore;
  private server?: Server;

  constructor(options: BrokerOptions) {
    this.home = options.home;
    this.socketPath = options.socketPath ?? join(options.home, "broker.sock");
    this.passphrase = options.passphrase;
    this.now = options.now ?? (() => new Date());
  }

  async start(): Promise<this> {
    this.open = openVault(this.home, this.passphrase);
    this.leases = new LeaseStore(join(this.home, "leases.json"));
    try {
      this.receipts = new ReceiptLog(join(this.home, "receipts.jsonl"));
    } catch {
      this.receiptsError = "receipt chain is broken";
    }
    this.refresh();

    const directory = dirname(this.socketPath);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    chmodSync(directory, 0o700);
    if (existsSync(this.socketPath)) unlinkSync(this.socketPath);

    this.server = createServer((request, response) => {
      void this.handle(request, response);
    });
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => {
        this.server?.off("listening", onListening);
        reject(error);
      };
      const onListening = (): void => {
        this.server?.off("error", onError);
        resolve();
      };
      this.server?.once("error", onError);
      this.server?.once("listening", onListening);
      this.server?.listen(this.socketPath);
    });
    chmodSync(this.socketPath, 0o600);
    return this;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    const server = this.server;
    this.server = undefined;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try {
      unlinkSync(this.socketPath);
    } catch {
      // Already gone.
    }
  }

  health() {
    this.refresh();
    return brokerHealth({
      vaultOk: Boolean(this.open),
      ...(this.policy ? { policy: this.policy } : {}),
      ...(this.policyError ? { policyError: this.policyError } : {}),
      ...(this.registry ? { registry: this.registry } : {}),
      ...(this.registryError ? { registryError: this.registryError } : {}),
      grantsOk: !this.grantsError,
      ...(this.grantsError ? { grantsError: this.grantsError } : {}),
      receiptsOk: !this.receiptsError,
      ...(this.receiptsError ? { receiptsError: this.receiptsError } : {}),
    });
  }

  private refresh(): void {
    try {
      this.policy = loadPolicy(this.home);
      this.policyError = undefined;
    } catch {
      this.policy = undefined;
      this.policyError = "owner policy is missing or invalid";
    }
    try {
      this.registry = loadRegistry(join(this.home, "registry.json"));
      this.registryError = undefined;
    } catch {
      this.registry = undefined;
      this.registryError = "registry is missing, empty, or invalid";
    }
    try {
      this.grants = loadGrants(this.home);
      this.grantsError = undefined;
    } catch {
      this.grants = [];
      this.grantsError = "grant store is unreadable or invalid";
    }
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const requestId = `rq_${randomBytes(6).toString("hex")}`;
    try {
      await this.route(request, response, requestId);
    } catch (error) {
      this.sendError(response, error, requestId);
    }
  }

  private async route(
    request: IncomingMessage,
    response: ServerResponse,
    requestId: string,
  ): Promise<void> {
    const url = new URL(request.url ?? "/", "http://charade.local");
    const method = (request.method ?? "GET").toUpperCase();
    const path = url.pathname;

    if (method === "GET" && path === "/health") {
      const report = this.health();
      return sendJson(
        response,
        brokerReady(report) ? 200 : 503,
        {
          alive: true,
          ready: brokerReady(report),
          protocol: protocolString(),
          overall: report.overall,
        },
        requestId,
      );
    }

    if (method === "POST" && path === "/v1/session/challenge") {
      const body = await readJson(request);
      this.refresh();
      const role = body.role === "owner" ? "owner" : body.role === "consumer" ? "consumer" : undefined;
      if (!role) throw new CharadeError("charade.session_invalid", requestId);
      if (role === "owner" && !this.policy) throw new CharadeError("charade.owner_policy_missing", requestId);
      if (role === "consumer" && !this.registry) throw new CharadeError("charade.registry_unreadable", requestId);
      const challenge = this.sessions.createChallenge(
        {
          role,
          ...(typeof body.consumerId === "string" ? { consumerId: body.consumerId } : {}),
          ...(typeof body.deviceId === "string" ? { deviceId: body.deviceId } : {}),
        },
        this.registry,
        this.policy,
        this.now(),
      );
      return sendJson(response, 200, challenge, requestId);
    }

    if (method === "POST" && path === "/v1/session") {
      const body = await readJson(request);
      this.refresh();
      if (!this.policy) throw new CharadeError("charade.owner_policy_missing", requestId);
      if (typeof body.challengeId !== "string" || typeof body.signature !== "string" || typeof body.deviceId !== "string") {
        throw new CharadeError("charade.session_invalid", requestId);
      }
      const grant = this.sessions.complete(
        body.challengeId,
        body.signature,
        body.deviceId,
        this.registry,
        this.policy,
        this.now(),
      );
      return sendJson(response, 200, grant, requestId);
    }

    if (method === "DELETE" && path === "/v1/session") {
      const token = bearer(request);
      if (!token) throw new CharadeError("charade.session_invalid", requestId);
      this.sessions.revoke(token);
      return sendJson(response, 200, { revoked: true }, requestId);
    }

    if (method === "GET" && (path === "/v1/health" || path === "/v1/admin/health")) {
      const session = this.requireSession(request, requestId);
      if (path === "/v1/admin/health" && session.role !== "owner") {
        throw new CharadeError("charade.owner_required", requestId);
      }
      const report = this.health();
      return sendJson(response, 200, { protocol: protocolString(), report }, requestId);
    }

    if (method === "GET" && path === "/v1/catalog") {
      const session = this.requireConsumer(request, requestId);
      this.refresh();
      if (!this.registry) throw new CharadeError("charade.registry_unreadable", requestId);
      const consumer = this.registry.consumers.find((item) => item.id === session.consumerId);
      if (!consumer) throw new CharadeError("charade.device_mismatch", requestId);
      const services = this.registry.services
        .filter((service) => consumer.services.includes(service.id))
        .map((service) => ({
          id: service.id,
          name: service.name,
          url: service.url,
          auth: { type: service.auth.type, ...(service.auth.name ? { name: service.auth.name } : {}) },
          actions: service.actions,
        }));
      return sendJson(response, 200, { services }, requestId);
    }

    if (method === "POST" && path === "/v1/admin/credentials/rotate") {
      return this.rotateCredential(request, response, requestId);
    }

    if (method === "POST" && path === "/v1/leases") {
      return this.createLease(request, response, requestId);
    }

    const renewMatch = /^\/v1\/leases\/([^/]+)\/renew$/.exec(path);
    if (method === "POST" && renewMatch) {
      return this.renewLease(request, response, requestId, decodeURIComponent(renewMatch[1] ?? ""));
    }

    const revokeMatch = /^\/v1\/leases\/([^/]+)\/revoke$/.exec(path);
    if (method === "POST" && revokeMatch) {
      return this.revokeLease(request, response, requestId, decodeURIComponent(revokeMatch[1] ?? ""));
    }

    if (path.startsWith("/v1/proxy/")) {
      return this.proxy(request, response, requestId, url);
    }

    if (method === "POST" && path === "/v1/env") {
      this.requireConsumer(request, requestId);
      throw new CharadeError("charade.env_not_granted", requestId);
    }

    throw new CharadeError("charade.unknown", requestId);
  }

  private async rotateCredential(
    request: IncomingMessage,
    response: ServerResponse,
    requestId: string,
  ): Promise<void> {
    const session = this.requireSession(request, requestId);
    if (session.role !== "owner") throw new CharadeError("charade.owner_required", requestId);
    this.requireOperational(requestId);
    const body = await readJson(request);
    if (typeof body.serviceId !== "string" || typeof body.value !== "string" || body.value.length === 0) {
      throw new CharadeError("charade.unknown", requestId);
    }
    const open = this.open as OpenVault;
    const active = findActiveSecret(open, body.serviceId);
    if (!active) throw new CharadeError("charade.secret_missing", requestId);
    const previousVersionId = active.versionId;
    const overlap = typeof body.overlapSeconds === "number" ? body.overlapSeconds : 900;
    const next = rotateSecret(open, active.id, body.value, overlap, this.now());
    this.open = next;
    const fresh = findActiveSecret(next, body.serviceId);
    const previous = findSecretVersion(next, previousVersionId);
    this.receipt(
      { type: "owner", id: "owner" },
      "credential.rotate",
      body.serviceId,
      "ok",
      requestId,
    );
    return sendJson(
      response,
      200,
      {
        serviceId: body.serviceId,
        previousVersionId,
        activeVersionId: fresh?.versionId,
        previousValidUntil: previous?.previousValidUntil,
      },
      requestId,
    );
  }

  private async createLease(
    request: IncomingMessage,
    response: ServerResponse,
    requestId: string,
  ): Promise<void> {
    const session = this.requireConsumer(request, requestId);
    this.requireOperational(requestId);
    const body = await readJson(request);
    const requested = typeof body.service === "string"
      ? [body.service]
      : Array.isArray(body.services) && body.services.every((item) => typeof item === "string")
        ? (body.services as string[])
        : [];
    if (requested.length === 0) throw new CharadeError("charade.scope_denied", requestId);
    const now = this.now();
    const policy = this.policy as NonNullable<typeof this.policy>;
    const registry = this.registry as Registry;
    const grant = this.grants.find(
      (item) =>
        item.consumerId === session.consumerId &&
        requested.every((service) => item.services.includes(service)) &&
        verifyGrant(policy, item, now).ok,
    );
    if (!grant) throw new CharadeError("charade.grant_missing", requestId);
    const consumer = registry.consumers.find((item) => item.id === session.consumerId);
    if (!consumer) throw new CharadeError("charade.device_mismatch", requestId);
    const device = registry.devices.find((item) => item.id === session.deviceId);
    if (!device || device.consumerId !== consumer.id) {
      throw new CharadeError("charade.device_mismatch", requestId);
    }
    if (device.revokedAt) throw new CharadeError("charade.device_revoked", requestId);
    const secretVersionIds: Record<string, string> = {};
    for (const service of requested) {
      const secret = findActiveSecret(this.open as OpenVault, service);
      if (!secret) throw new CharadeError("charade.secret_missing", requestId);
      secretVersionIds[service] = secret.versionId;
    }
    const ttlSeconds = typeof body.ttlSeconds === "number" ? body.ttlSeconds : undefined;
    const issued = (this.leases as LeaseStore).issue({
      grant,
      policy,
      consumer,
      device,
      secretVersionIds,
      ...(ttlSeconds !== undefined ? { ttlSeconds } : {}),
      now,
    });
    this.receipt(
      consumerActor(session),
      "lease.issue",
      issued.lease.leaseId,
      "ok",
      requestId,
    );
    return sendJson(response, 201, issued, requestId);
  }

  private async renewLease(
    request: IncomingMessage,
    response: ServerResponse,
    requestId: string,
    leaseId: string,
  ): Promise<void> {
    const session = this.requireConsumer(request, requestId);
    this.requireOperational(requestId);
    const body = await readJson(request);
    if (typeof body.token !== "string") throw new CharadeError("charade.session_invalid", requestId);
    const found = (this.leases as LeaseStore).findByToken(body.token, this.now());
    ensureLeaseBelongsToSession(found.lease, session, requestId);
    const grant = this.grants.find((item) => item.grantId === found.lease.grantId);
    if (!grant) throw new CharadeError("charade.grant_revoked", requestId);
    const ttlSeconds = typeof body.ttlSeconds === "number" ? body.ttlSeconds : undefined;
    const renewed = (this.leases as LeaseStore).renew(
      leaseId,
      body.token,
      grant,
      this.policy as NonNullable<typeof this.policy>,
      this.now(),
      ttlSeconds,
    );
    this.receipt(consumerActor(session), "lease.renew", leaseId, "ok", requestId);
    return sendJson(response, 200, renewed, requestId);
  }

  private async revokeLease(
    request: IncomingMessage,
    response: ServerResponse,
    requestId: string,
    leaseId: string,
  ): Promise<void> {
    const session = this.requireSession(request, requestId);
    this.requireOperational(requestId);
    const lease = (this.leases as LeaseStore).load().leases.find((item) => item.leaseId === leaseId);
    if (!lease) throw new CharadeError("charade.lease_expired", requestId);
    if (session.role !== "owner" && lease.consumerId !== session.consumerId) {
      throw new CharadeError("charade.scope_denied", requestId);
    }
    (this.leases as LeaseStore).revoke(leaseId, this.now());
    this.receipt(
      session.role === "owner" ? { type: "owner", id: "owner" } : consumerActor(session),
      "lease.revoke",
      leaseId,
      "ok",
      requestId,
    );
    return sendJson(response, 200, { revoked: true }, requestId);
  }

  private async proxy(
    request: IncomingMessage,
    response: ServerResponse,
    requestId: string,
    url: URL,
  ): Promise<void> {
    const session = this.requireConsumer(request, requestId);
    this.requireOperational(requestId);
    const leaseToken = headerValue(request, "x-charade-lease");
    if (!leaseToken) throw new CharadeError("charade.lease_expired", requestId);
    const found = (this.leases as LeaseStore).findByToken(leaseToken, this.now());
    ensureLeaseBelongsToSession(found.lease, session, requestId);
    const grant = this.grants.find((item) => item.grantId === found.lease.grantId);
    if (!grant) throw new CharadeError("charade.grant_revoked", requestId);
    const verification = verifyGrant(this.policy as NonNullable<typeof this.policy>, grant, this.now());
    if (!verification.ok) throw new CharadeError("charade.grant_expired", requestId);

    const rest = url.pathname.slice("/v1/proxy/".length);
    const slash = rest.indexOf("/");
    const serviceId = decodeURIComponent(slash === -1 ? rest : rest.slice(0, slash));
    const remainingPath = slash === -1 ? "/" : rest.slice(slash);
    const service = this.registry?.services.find((item) => item.id === serviceId);
    if (!service) throw new CharadeError("charade.scope_denied", requestId);
    if (!found.lease.services.includes(service.id)) {
      throw new CharadeError("charade.scope_denied", requestId);
    }

    const decision = classifyAction(service, request.method ?? "GET", remainingPath);
    const actor = consumerActor(session);
    if (decision.class === "unknown") {
      this.receipt(actor, "proxy.denied", service.id, "denied", requestId);
      throw new CharadeError("charade.action_unknown", requestId);
    }
    if (decision.class === "destructive" && decision.stop && grant.hardStops[decision.stop]) {
      this.receipt(actor, "proxy.denied", service.id, "denied", requestId);
      throw new CharadeError("charade.action_denied", requestId);
    }
    if (!this.admitCall(grant)) {
      this.receipt(actor, "proxy.denied", service.id, "denied", requestId);
      throw new CharadeError("charade.ceiling_reached", requestId);
    }

    const versionId = found.lease.secretVersionIds[service.id];
    const secret = versionId ? findSecretVersion(this.open as OpenVault, versionId) : undefined;
    if (!secret) throw new CharadeError("charade.secret_missing", requestId);
    if (
      secret.status === "previous" &&
      secret.previousValidUntil &&
      new Date(secret.previousValidUntil).getTime() <= this.now().getTime()
    ) {
      throw new CharadeError("charade.secret_missing", requestId);
    }

    const body = request.method === "GET" || request.method === "HEAD"
      ? Buffer.alloc(0)
      : await readBody(request);
    this.receipt(actor, "proxy.attempt", service.id, "ok", requestId);
    response.setHeader("x-charade-protocol", protocolString());
    response.setHeader("x-charade-request-id", requestId);
    response.setHeader("cache-control", "no-store");
    try {
      const result = await forwardProxy(response, {
        service,
        secretValue: secret.value,
        method: request.method ?? "GET",
        remainingPath,
        search: url.search,
        headers: request.headers,
        body,
      });
      this.receipt(actor, "proxy.complete", service.id, "ok", requestId);
      void result;
    } catch (error) {
      this.receipt(actor, "proxy.failed", service.id, "failed", requestId);
      throw error;
    }
  }

  private admitCall(grant: Grant): boolean {
    const day = this.now().toISOString().slice(0, 10);
    const key = grant.grantId;
    const current = this.counters.get(key);
    if (!current || current.day !== day) {
      this.counters.set(key, { day, count: 1 });
      return true;
    }
    if (current.count >= grant.ceilings.callsPerDay) return false;
    current.count += 1;
    return true;
  }

  private requireOperational(requestId: string): void {
    this.refresh();
    if (this.policyError) throw new CharadeError("charade.owner_policy_missing", requestId);
    if (this.registryError) throw new CharadeError("charade.registry_unreadable", requestId);
    if (this.grantsError) throw new CharadeError("charade.grant_missing", requestId);
    if (this.receiptsError) throw new CharadeError("charade.integrity_broken", requestId);
  }

  private requireSession(request: IncomingMessage, requestId: string): Session {
    const token = bearer(request);
    if (!token) throw new CharadeError("charade.session_invalid", requestId);
    try {
      return this.sessions.touch(token, this.now());
    } catch {
      throw new CharadeError("charade.session_invalid", requestId);
    }
  }

  private requireConsumer(request: IncomingMessage, requestId: string): Session & { consumerId: string } {
    const session = this.requireSession(request, requestId);
    if (session.role !== "consumer" || !session.consumerId) {
      throw new CharadeError("charade.owner_required", requestId);
    }
    return session as Session & { consumerId: string };
  }

  private receipt(
    actor: { type: "owner" | "consumer" | "device" | "broker"; id: string; deviceId?: string },
    action: string,
    subject: string,
    outcome: "ok" | "denied" | "failed" | "unknown",
    requestId: string,
  ): void {
    if (!this.receipts) throw new CharadeError("charade.integrity_broken", requestId);
    this.receipts.append({ actor, action, subject, outcome, requestId, ts: this.now().toISOString() });
  }

  private sendError(response: ServerResponse, error: unknown, requestId: string): void {
    if (response.headersSent) {
      response.destroy();
      return;
    }
    if (error instanceof CharadeError) {
      return sendJson(response, statusFor(error.code), { ...error.toBody(), requestId }, requestId);
    }
    if (error instanceof SessionError) {
      return sendJson(response, 401, {
        ...new CharadeError("charade.session_invalid", requestId).toBody(),
        requestId,
      }, requestId);
    }
    if (error instanceof LeaseError) {
      const code = leaseErrorCode(error.code);
      return sendJson(response, statusFor(code), {
        ...new CharadeError(code, requestId).toBody(),
        requestId,
      }, requestId);
    }
    if (error instanceof RegistryError) {
      return sendJson(response, 503, {
        ...new CharadeError("charade.registry_unreadable", requestId).toBody(),
        requestId,
      }, requestId);
    }
    if (error instanceof ProxyError) {
      return sendJson(response, 502, {
        ...new CharadeError("charade.unknown", requestId).toBody(),
        requestId,
      }, requestId);
    }
    return sendJson(response, 500, {
      ...new CharadeError("charade.unknown", requestId).toBody(),
      requestId,
    }, requestId);
  }
}

function bearer(request: IncomingMessage): string | undefined {
  const value = headerValue(request, "authorization");
  if (!value || !value.startsWith("Bearer ")) return undefined;
  return value.slice("Bearer ".length);
}

function headerValue(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

function consumerActor(session: Session): {
  type: "consumer";
  id: string;
  deviceId: string;
} {
  if (!session.consumerId) throw new Error("consumer session has no consumer");
  return { type: "consumer", id: session.consumerId, deviceId: session.deviceId };
}

function ensureLeaseBelongsToSession(
  lease: LeaseRecord,
  session: Session & { consumerId: string },
  requestId: string,
): void {
  if (lease.consumerId !== session.consumerId || lease.deviceId !== session.deviceId) {
    throw new CharadeError("charade.device_mismatch", requestId);
  }
}

function leaseErrorCode(code: LeaseError["code"]): ErrorCode {
  switch (code) {
    case "device_mismatch":
      return "charade.device_mismatch";
    case "device_revoked":
      return "charade.device_revoked";
    case "lease_revoked":
      return "charade.lease_revoked";
    case "lease_expired":
    case "lease_not_found":
      return "charade.lease_expired";
    case "consumer_invalid":
    case "ttl_invalid":
      return "charade.scope_denied";
    case "grant_invalid":
      return "charade.grant_missing";
  }
}

function statusFor(code: ErrorCode): number {
  switch (code) {
    case "charade.owner_required":
    case "charade.grant_missing":
    case "charade.grant_expired":
    case "charade.grant_revoked":
    case "charade.scope_denied":
    case "charade.action_denied":
    case "charade.action_unknown":
    case "charade.env_not_granted":
      return 403;
    case "charade.lease_expired":
    case "charade.lease_revoked":
    case "charade.device_mismatch":
    case "charade.device_revoked":
    case "charade.session_invalid":
      return 401;
    case "charade.ceiling_reached":
      return 429;
    case "charade.owner_policy_missing":
    case "charade.registry_unreadable":
    case "charade.registry_invalid":
    case "charade.vault_locked":
      return 503;
    case "charade.protocol_mismatch":
      return 426;
    case "charade.secret_missing":
      return 502;
    case "charade.integrity_broken":
      return 500;
    case "charade.unknown":
      return 500;
  }
}

async function readBody(request: IncomingMessage, limit = MAX_BODY): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > limit) throw new CharadeError("charade.unknown");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const body = await readBody(request);
  if (body.length === 0) return {};
  try {
    const value = JSON.parse(body.toString("utf8")) as unknown;
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error("not an object");
    }
    return value as Record<string, unknown>;
  } catch {
    throw new CharadeError("charade.unknown");
  }
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
  requestId: string,
): void {
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("cache-control", "no-store");
  response.setHeader("x-charade-protocol", protocolString());
  response.setHeader("x-charade-request-id", requestId);
  response.writeHead(status);
  response.end(JSON.stringify(body));
}
