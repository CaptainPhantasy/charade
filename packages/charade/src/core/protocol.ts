import type { HealthReport } from "./health.js";

export type HardStop =
  | "money"
  | "publish"
  | "send"
  | "delete"
  | "permissionChange";

export type ActionClass = "read" | "write" | "destructive";

export type CustodyBackend =
  | "passphrase"
  | "macos-keychain"
  | "secret-service"
  | "systemd-creds";

export interface OwnerPolicyLimits {
  readonly defaultGrantDurationSeconds: number;
  readonly maxGrantDurationSeconds: number;
  readonly defaultLeaseTtlSeconds: number;
  readonly maxLeaseTtlSeconds: number;
  readonly rotationOverlapSeconds: number;
  readonly envExceptionMaxTtlSeconds: number;
  readonly receiptRetentionDays: number;
  readonly sessionIdleSeconds: number;
  readonly sessionAbsoluteSeconds: number;
}

export interface OwnerPolicyGates {
  readonly hardStops: Readonly<Record<HardStop, boolean>>;
  readonly newConsumers: "owner-approval";
  readonly memberEnrollment: "owner-approval";
  readonly rotation: "owner-approval" | "owner-or-agent-request";
  readonly envExceptions: "owner-per-use";
  readonly updateCheck: "never-without-consent";
  readonly telemetry: "forbidden";
}

export interface OwnerPolicy {
  readonly schema: "charade.owner-policy/1";
  readonly policyVersion: number;
  readonly ownerPublicKey: string;
  readonly limits: OwnerPolicyLimits;
  readonly gates: OwnerPolicyGates;
  readonly custody: { readonly autoUnlock: CustodyBackend | "none" };
  /** base64url Ed25519 signature over canonical JSON without this field. */
  readonly signature: string;
}

export interface GrantCeilings {
  readonly callsPerDay: number;
}

export interface Grant {
  readonly schema: "charade.grant/1";
  readonly grantId: string;
  readonly consumerId: string;
  readonly deviceId?: string;
  readonly services: readonly string[];
  readonly methods: readonly string[];
  readonly paths: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly ceilings: GrantCeilings;
  readonly hardStops: Readonly<Record<HardStop, boolean>>;
  readonly envAllowed: boolean;
  readonly policyHash: string;
  /** base64url Ed25519 signature over canonical JSON without this field. */
  readonly signature: string;
}

export interface Lease {
  readonly schema: "charade.lease/1";
  readonly leaseId: string;
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
}

export interface LeaseIssueResponse {
  readonly lease: Lease;
  /** Returned once; only its hash is stored. */
  readonly token: string;
}

export type ActorType = "owner" | "consumer" | "device" | "broker";

export interface ReceiptActor {
  readonly type: ActorType;
  readonly id: string;
  readonly deviceId?: string;
}

export interface Receipt {
  readonly schema: "charade.receipt/1";
  readonly receiptId: string;
  readonly sequence: number;
  readonly ts: string;
  readonly actor: ReceiptActor;
  readonly action: string;
  readonly subject?: string;
  readonly outcome: "ok" | "denied" | "failed" | "unknown";
  readonly requestId: string;
  readonly prevHash: string;
  readonly hash: string;
}

/** Unauthenticated liveness only. No paths, counts, or dependency names. */
export interface LivenessResponse {
  readonly alive: true;
  readonly ready: boolean;
  readonly protocol: string;
  readonly overall: "ok" | "degraded" | "broken" | "unknown";
}

export interface ConsumerHealthResponse {
  readonly protocol: string;
  readonly report: HealthReport;
}

export interface SessionChallenge {
  readonly challengeId: string;
  readonly nonce: string;
  readonly expiresAt: string;
}

export interface SessionRequest {
  readonly challengeId: string;
  /** base64url Ed25519 signature over the domain-separated challenge. */
  readonly signature: string;
  readonly deviceId: string;
}

export interface SessionGrant {
  readonly sessionToken: string;
  readonly expiresAt: string;
  readonly idleExpiresAt: string;
}
