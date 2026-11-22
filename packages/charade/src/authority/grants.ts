import { randomBytes } from "node:crypto";
import type { Grant, HardStop, OwnerPolicy } from "../core/protocol.js";
import { signDomain, verifyDomain } from "./keys.js";
import { policyHash, verifyPolicy } from "./policy.js";

export const GRANT_DOMAIN = "charade-grant-v1\u0000";

export const GRANT_PRESETS = {
  "1h": 3_600,
  "8h": 28_800,
  "24h": 86_400,
  "7d": 604_800,
} as const;

export interface GrantDraft {
  readonly consumerId: string;
  readonly deviceId?: string;
  readonly services: readonly string[];
  readonly methods: readonly string[];
  readonly paths: readonly string[];
  readonly durationSeconds: number;
  readonly ceilings: { readonly callsPerDay: number };
  readonly hardStops: Readonly<Record<HardStop, boolean>>;
  readonly envAllowed: boolean;
}

export interface GrantVerification {
  readonly ok: boolean;
  readonly reason?: string;
}

export function signGrant(
  privateKey: string,
  policy: OwnerPolicy,
  draft: GrantDraft,
  now = new Date(),
): Grant {
  if (!verifyPolicy(policy)) throw new Error("cannot sign a grant under an invalid policy");
  assertGrantDraft(draft, policy);
  const body = {
    schema: "charade.grant/1" as const,
    grantId: `gr_${randomBytes(8).toString("hex")}`,
    consumerId: draft.consumerId,
    ...(draft.deviceId ? { deviceId: draft.deviceId } : {}),
    services: draft.services,
    methods: draft.methods,
    paths: draft.paths,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + draft.durationSeconds * 1000).toISOString(),
    ceilings: draft.ceilings,
    hardStops: draft.hardStops,
    envAllowed: draft.envAllowed,
    policyHash: policyHash(policy),
  };
  const signature = signDomain(privateKey, GRANT_DOMAIN, body);
  return { ...body, signature };
}

export function verifyGrant(
  policy: OwnerPolicy,
  grant: Grant,
  now = new Date(),
): GrantVerification {
  if (!verifyPolicy(policy)) return { ok: false, reason: "owner policy is invalid" };
  if (grant.schema !== "charade.grant/1") return { ok: false, reason: "grant schema is unsupported" };
  if (grant.policyHash !== policyHash(policy)) {
    return { ok: false, reason: "grant was issued under a different policy" };
  }
  if (!Array.isArray(grant.services) || grant.services.length === 0) {
    return { ok: false, reason: "grant has no services" };
  }
  if (!Array.isArray(grant.methods) || grant.methods.length === 0) {
    return { ok: false, reason: "grant has no methods" };
  }
  if (!Array.isArray(grant.paths) || grant.paths.length === 0) {
    return { ok: false, reason: "grant has no paths" };
  }
  if (new Date(grant.expiresAt).getTime() <= now.getTime()) {
    return { ok: false, reason: "grant has expired" };
  }
  if (new Date(grant.issuedAt).getTime() > now.getTime() + 60_000) {
    return { ok: false, reason: "grant is issued in the future" };
  }
  const { signature, ...body } = grant;
  if (!verifyDomain(policy.ownerPublicKey, GRANT_DOMAIN, body, signature)) {
    return { ok: false, reason: "grant signature is invalid" };
  }
  return { ok: true };
}

export function grantActive(grant: Grant, now = new Date()): boolean {
  return new Date(grant.expiresAt).getTime() > now.getTime();
}

export function parseDuration(value: string): number {
  const preset = GRANT_PRESETS[value as keyof typeof GRANT_PRESETS];
  if (preset) return preset;
  if (/^\d+$/.test(value)) {
    const seconds = Number(value);
    if (seconds > 0) return seconds;
  }
  throw new Error(`duration must be one of ${Object.keys(GRANT_PRESETS).join(", ")} or positive seconds`);
}

function assertGrantDraft(draft: GrantDraft, policy: OwnerPolicy): void {
  if (!draft.consumerId) throw new Error("grant needs a consumer");
  for (const field of ["services", "methods", "paths"] as const) {
    const values = draft[field];
    if (!Array.isArray(values) || values.length === 0) {
      throw new Error(`grant ${field} must not be empty`);
    }
    for (const value of values) {
      if (typeof value !== "string" || value.length === 0) {
        throw new Error(`grant ${field} entries must be non-empty strings`);
      }
    }
  }
  if (!Number.isInteger(draft.durationSeconds) || draft.durationSeconds <= 0) {
    throw new Error("grant duration must be a positive integer");
  }
  if (draft.durationSeconds > policy.limits.maxGrantDurationSeconds) {
    throw new Error("grant duration exceeds the owner policy maximum");
  }
  if (!Number.isInteger(draft.ceilings.callsPerDay) || draft.ceilings.callsPerDay <= 0) {
    throw new Error("grant call ceiling must be a positive integer");
  }
  for (const key of ["money", "publish", "send", "delete", "permissionChange"] as const) {
    if (typeof draft.hardStops[key] !== "boolean") {
      throw new Error(`grant hard stop ${key} must be boolean`);
    }
  }
  if (typeof draft.envAllowed !== "boolean") {
    throw new Error("grant envAllowed must be boolean");
  }
}
