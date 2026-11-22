import { createHash } from "node:crypto";
import { canonicalJson } from "../core/canonical-json.js";
import type {
  OwnerPolicy,
  OwnerPolicyGates,
  OwnerPolicyLimits,
} from "../core/protocol.js";
import { signDomain, verifyDomain } from "./keys.js";

export const POLICY_DOMAIN = "charade-owner-policy-v1\u0000";

/**
 * Proposed defaults. Nothing here is active until the owner accepts it and the
 * policy is signed; see `docs/defaults.md`.
 */
export const DEFAULT_LIMITS: OwnerPolicyLimits = {
  defaultGrantDurationSeconds: 86_400,
  maxGrantDurationSeconds: 604_800,
  defaultLeaseTtlSeconds: 120,
  maxLeaseTtlSeconds: 300,
  rotationOverlapSeconds: 900,
  envExceptionMaxTtlSeconds: 300,
  receiptRetentionDays: 365,
  sessionIdleSeconds: 900,
  sessionAbsoluteSeconds: 28_800,
};

export const DEFAULT_GATES: OwnerPolicyGates = {
  hardStops: {
    money: true,
    publish: true,
    send: true,
    delete: true,
    permissionChange: true,
  },
  newConsumers: "owner-approval",
  memberEnrollment: "owner-approval",
  rotation: "owner-or-agent-request",
  envExceptions: "owner-per-use",
  updateCheck: "never-without-consent",
  telemetry: "forbidden",
};

export type PolicyDraft = Omit<OwnerPolicy, "signature">;

export function defaultPolicyDraft(ownerPublicKey: string): PolicyDraft {
  return {
    schema: "charade.owner-policy/1",
    policyVersion: 1,
    ownerPublicKey,
    limits: DEFAULT_LIMITS,
    gates: DEFAULT_GATES,
    custody: { autoUnlock: "passphrase" },
  };
}

export function policyPayload(policy: OwnerPolicy): PolicyDraft {
  const { signature: _signature, ...payload } = policy;
  return payload;
}

export function signPolicy(privateKey: string, draft: PolicyDraft): OwnerPolicy {
  assertPolicyDraft(draft);
  const signature = signDomain(privateKey, POLICY_DOMAIN, draft);
  return { ...draft, signature };
}

export function verifyPolicy(policy: OwnerPolicy): boolean {
  try {
    assertPolicyDraft(policyPayload(policy));
  } catch {
    return false;
  }
  return verifyDomain(
    policy.ownerPublicKey,
    POLICY_DOMAIN,
    policyPayload(policy),
    policy.signature,
  );
}

export function assertPolicy(policy: OwnerPolicy): void {
  assertPolicyDraft(policyPayload(policy));
  if (!verifyPolicy(policy)) throw new Error("owner policy signature is invalid");
}

export function policyHash(policy: OwnerPolicy): string {
  return `sha256:${createHash("sha256")
    .update(canonicalJson(policyPayload(policy)))
    .digest("hex")}`;
}

function assertPolicyDraft(draft: PolicyDraft): void {
  if (draft.schema !== "charade.owner-policy/1") {
    throw new Error("owner policy schema is unsupported");
  }
  if (!Number.isInteger(draft.policyVersion) || draft.policyVersion < 1) {
    throw new Error("owner policy version must be a positive integer");
  }
  if (Buffer.from(draft.ownerPublicKey, "base64url").length !== 32) {
    throw new Error("owner public key must be 32 bytes");
  }
  assertLimits(draft.limits);
  assertGates(draft.gates);
  if (draft.custody.autoUnlock === undefined) {
    throw new Error("custody auto-unlock policy is required");
  }
}

function assertLimits(limits: OwnerPolicyLimits): void {
  const positive = [
    "defaultGrantDurationSeconds",
    "maxGrantDurationSeconds",
    "defaultLeaseTtlSeconds",
    "maxLeaseTtlSeconds",
    "rotationOverlapSeconds",
    "envExceptionMaxTtlSeconds",
    "receiptRetentionDays",
    "sessionIdleSeconds",
    "sessionAbsoluteSeconds",
  ] as const;
  for (const key of positive) {
    const value = limits[key];
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error(`policy limit ${key} must be a positive integer`);
    }
  }
  if (limits.defaultGrantDurationSeconds > limits.maxGrantDurationSeconds) {
    throw new Error("default grant duration exceeds the maximum");
  }
  if (limits.defaultLeaseTtlSeconds > limits.maxLeaseTtlSeconds) {
    throw new Error("default lease TTL exceeds the maximum");
  }
  if (limits.sessionIdleSeconds > limits.sessionAbsoluteSeconds) {
    throw new Error("session idle timeout exceeds the absolute maximum");
  }
}

function assertGates(gates: OwnerPolicyGates): void {
  for (const key of ["money", "publish", "send", "delete", "permissionChange"] as const) {
    if (typeof gates.hardStops[key] !== "boolean") {
      throw new Error(`hard stop ${key} must be boolean`);
    }
  }
  if (gates.telemetry !== "forbidden") {
    throw new Error("telemetry must remain forbidden");
  }
  if (gates.updateCheck !== "never-without-consent") {
    throw new Error("update checks must require consent");
  }
}
