import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { canonicalJson } from "../core/canonical-json.js";
import type { Grant, OwnerPolicy } from "../core/protocol.js";
import { verifyGrant } from "../authority/grants.js";
import { writeAtomic } from "../vault/atomic.js";
import type { ConsumerRecord, DeviceRecord } from "./registry.js";

export interface LeaseRecord {
  readonly schema: "charade.lease/1";
  readonly leaseId: string;
  readonly tokenHash: string;
  readonly previousTokenHash?: string;
  readonly previousValidUntil?: string;
  readonly consumerId: string;
  readonly deviceId: string;
  readonly grantId: string;
  readonly services: readonly string[];
  readonly methods: readonly string[];
  readonly paths: readonly string[];
  readonly secretVersionIds: Readonly<Record<string, string>>;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly renewableUntil: string;
  readonly revokedAt?: string;
}

export interface LeaseFile {
  readonly schema: "charade.leases/1";
  readonly revision: number;
  readonly leases: readonly LeaseRecord[];
}

export type LeaseErrorCode =
  | "grant_invalid"
  | "consumer_invalid"
  | "device_mismatch"
  | "device_revoked"
  | "ttl_invalid"
  | "lease_not_found"
  | "lease_expired"
  | "lease_revoked";

export class LeaseError extends Error {
  readonly code: LeaseErrorCode;
  constructor(code: LeaseErrorCode, message: string) {
    super(message);
    this.name = "LeaseError";
    this.code = code;
  }
}

export interface IssueLeaseOptions {
  readonly grant: Grant;
  readonly policy: OwnerPolicy;
  readonly consumer: ConsumerRecord;
  readonly device: DeviceRecord;
  readonly secretVersionIds: Readonly<Record<string, string>>;
  readonly ttlSeconds?: number;
  readonly now?: Date;
}

export interface IssuedLease {
  readonly lease: LeaseRecord;
  /** Returned once; only the hash is stored. */
  readonly token: string;
}

export interface RenewedLease extends IssuedLease {
  readonly previousTokenValidUntil: string;
}

export class LeaseStore {
  constructor(readonly path: string) {}

  load(): LeaseFile {
    let text: string;
    try {
      text = readFileSync(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return { schema: "charade.leases/1", revision: 0, leases: [] };
      }
      throw new LeaseError("lease_not_found", "lease store is unreadable");
    }
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      throw new LeaseError("lease_not_found", "lease store is not valid JSON");
    }
    if (
      typeof value !== "object" ||
      value === null ||
      (value as { schema?: unknown }).schema !== "charade.leases/1" ||
      !Array.isArray((value as { leases?: unknown }).leases)
    ) {
      throw new LeaseError("lease_not_found", "lease store schema is invalid");
    }
    const file = value as LeaseFile;
    for (const lease of file.leases) assertLease(lease);
    return file;
  }

  private save(file: LeaseFile): void {
    const next: LeaseFile = { ...file, revision: file.revision + 1 };
    writeAtomic(this.path, Buffer.from(canonicalJson(next), "utf8"), 0o600);
  }

  list(now = new Date()): readonly LeaseRecord[] {
    return this.load().leases.filter(
      (lease) => !lease.revokedAt && new Date(lease.expiresAt).getTime() > now.getTime(),
    );
  }

  issue(options: IssueLeaseOptions): IssuedLease {
    const now = options.now ?? new Date();
    const verification = verifyGrant(options.policy, options.grant, now);
    if (!verification.ok) {
      throw new LeaseError("grant_invalid", verification.reason ?? "grant is invalid");
    }
    if (options.grant.consumerId !== options.consumer.id) {
      throw new LeaseError("consumer_invalid", "grant belongs to a different consumer");
    }
    if (options.device.consumerId !== options.consumer.id) {
      throw new LeaseError("device_mismatch", "device belongs to a different consumer");
    }
    if (options.device.revokedAt) {
      throw new LeaseError("device_revoked", "device is revoked");
    }
    if (options.grant.deviceId && options.grant.deviceId !== options.device.id) {
      throw new LeaseError("device_mismatch", "grant is bound to a different device");
    }
    for (const service of options.grant.services) {
      if (!options.consumer.services.includes(service)) {
        throw new LeaseError("consumer_invalid", `consumer is not registered for ${service}`);
      }
    }
    const ttl = clampTtl(
      options.grant,
      options.policy,
      options.consumer.maxTtlSeconds,
      options.ttlSeconds,
      now,
    );
    const token = newToken();
    const leaseId = `l_${randomBytes(8).toString("hex")}`;
    const record: LeaseRecord = {
      schema: "charade.lease/1",
      leaseId,
      tokenHash: hashToken(token),
      consumerId: options.consumer.id,
      deviceId: options.device.id,
      grantId: options.grant.grantId,
      services: options.grant.services,
      methods: options.grant.methods,
      paths: options.grant.paths,
      secretVersionIds: options.secretVersionIds,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
      renewableUntil: options.grant.expiresAt,
    };
    const file = this.load();
    this.save({ ...file, leases: [...file.leases, record] });
    return { lease: record, token };
  }

  renew(
    leaseId: string,
    token: string,
    grant: Grant,
    policy: OwnerPolicy,
    now = new Date(),
    ttlSeconds?: number,
  ): RenewedLease {
    const file = this.load();
    const index = file.leases.findIndex((lease) => lease.leaseId === leaseId);
    const current = file.leases[index];
    if (!current) throw new LeaseError("lease_not_found", "lease was not found");
    if (current.revokedAt) throw new LeaseError("lease_revoked", "lease was revoked");
    if (current.tokenHash !== hashToken(token)) {
      throw new LeaseError("lease_not_found", "lease token does not match");
    }
    if (new Date(current.expiresAt).getTime() <= now.getTime()) {
      throw new LeaseError("lease_expired", "lease expired; issue a new lease under the grant");
    }
    const verification = verifyGrant(policy, grant, now);
    if (!verification.ok) {
      throw new LeaseError("grant_invalid", verification.reason ?? "grant is invalid");
    }
    if (grant.grantId !== current.grantId) {
      throw new LeaseError("grant_invalid", "grant does not match the lease");
    }
    const ttl = clampTtl(grant, policy, undefined, ttlSeconds, now);
    const nextToken = newToken();
    const updated: LeaseRecord = {
      ...current,
      tokenHash: hashToken(nextToken),
      previousTokenHash: current.tokenHash,
      previousValidUntil: current.expiresAt,
      expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
      renewableUntil: grant.expiresAt,
    };
    const leases = [...file.leases];
    leases[index] = updated;
    this.save({ ...file, leases });
    return {
      lease: updated,
      token: nextToken,
      previousTokenValidUntil: current.expiresAt,
    };
  }

  revoke(leaseId: string, now = new Date()): LeaseRecord {
    const file = this.load();
    const index = file.leases.findIndex((lease) => lease.leaseId === leaseId);
    const current = file.leases[index];
    if (!current) throw new LeaseError("lease_not_found", "lease was not found");
    const updated: LeaseRecord = { ...current, revokedAt: now.toISOString() };
    const leases = [...file.leases];
    leases[index] = updated;
    this.save({ ...file, leases });
    return updated;
  }

  findByToken(
    token: string,
    now = new Date(),
  ): { readonly lease: LeaseRecord; readonly tokenKind: "current" | "previous" } {
    const hash = hashToken(token);
    const leases = this.load().leases;
    const current = leases.find((lease) => lease.tokenHash === hash);
    if (current) {
      if (current.revokedAt) throw new LeaseError("lease_revoked", "lease was revoked");
      if (new Date(current.expiresAt).getTime() <= now.getTime()) {
        throw new LeaseError("lease_expired", "lease expired");
      }
      return { lease: current, tokenKind: "current" };
    }
    const previous = leases.find((lease) => lease.previousTokenHash === hash);
    if (previous) {
      if (previous.revokedAt) throw new LeaseError("lease_revoked", "lease was revoked");
      if (
        previous.previousValidUntil &&
        new Date(previous.previousValidUntil).getTime() > now.getTime()
      ) {
        return { lease: previous, tokenKind: "previous" };
      }
      throw new LeaseError("lease_expired", "previous lease token expired");
    }
    throw new LeaseError("lease_not_found", "lease token was not found");
  }
}

function clampTtl(
  grant: Grant,
  policy: OwnerPolicy,
  consumerMaxTtl: number | undefined,
  ttlSeconds: number | undefined,
  now: Date,
): number {
  const requested = ttlSeconds ?? policy.limits.defaultLeaseTtlSeconds;
  if (!Number.isInteger(requested) || requested <= 0) {
    throw new LeaseError("ttl_invalid", "lease TTL must be a positive integer");
  }
  const grantRemaining = Math.floor(
    (new Date(grant.expiresAt).getTime() - now.getTime()) / 1000,
  );
  const consumerMax = consumerMaxTtl ?? policy.limits.maxLeaseTtlSeconds;
  const ttl = Math.min(requested, policy.limits.maxLeaseTtlSeconds, consumerMax, grantRemaining);
  if (ttl <= 0) throw new LeaseError("grant_invalid", "grant has no remaining lifetime");
  return ttl;
}

/** Clients renew at two-thirds of the lease lifetime. */
export function shouldRenew(lease: LeaseRecord, now = new Date()): boolean {
  const created = new Date(lease.createdAt).getTime();
  const expires = new Date(lease.expiresAt).getTime();
  return now.getTime() >= created + ((expires - created) * 2) / 3;
}

/** Only idempotent requests may be retried after a lease is reissued. */
export function isIdempotentMethod(method: string): boolean {
  return ["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"].includes(method.toUpperCase());
}

function newToken(): string {
  return randomBytes(32).toString("base64url");
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function assertLease(lease: unknown): asserts lease is LeaseRecord {
  if (
    typeof lease !== "object" ||
    lease === null ||
    (lease as { schema?: unknown }).schema !== "charade.lease/1" ||
    typeof (lease as { leaseId?: unknown }).leaseId !== "string" ||
    typeof (lease as { tokenHash?: unknown }).tokenHash !== "string"
  ) {
    throw new LeaseError("lease_not_found", "lease record is invalid");
  }
}
