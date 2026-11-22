import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { canonicalJson } from "../core/canonical-json.js";
import type {
  Grant,
  OwnerPolicy,
  OwnerPolicyGates,
  OwnerPolicyLimits,
} from "../core/protocol.js";
import type { PolicyDraft } from "./policy.js";
import { writeAtomic } from "../vault/atomic.js";
import { getOwnerKeyPair, type OpenVault } from "../vault/vault.js";
import {
  assertPolicy,
  defaultPolicyDraft,
  signPolicy,
  verifyPolicy,
} from "./policy.js";

export function policyPath(home: string): string {
  return join(home, "policy.json");
}

export function savePolicy(home: string, policy: OwnerPolicy): void {
  assertPolicy(policy);
  writeAtomic(policyPath(home), Buffer.from(canonicalJson(policy), "utf8"), 0o600);
}

export function loadPolicy(home: string): OwnerPolicy {
  const path = policyPath(home);
  if (!existsSync(path)) throw new Error("owner policy is missing");
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("owner policy is not valid JSON");
  }
  const policy = value as OwnerPolicy;
  assertPolicy(policy);
  return policy;
}

export interface PolicyOverrides {
  readonly limits?: Partial<OwnerPolicyLimits>;
  readonly gates?: Partial<Omit<OwnerPolicyGates, "hardStops">> & {
    readonly hardStops?: Partial<OwnerPolicyGates["hardStops"]>;
  };
  readonly custody?: { readonly autoUnlock: OwnerPolicy["custody"]["autoUnlock"] };
}

/**
 * Sign the policy the owner chose. Overrides are a plain JSON object the owner
 * can review; an unsigned default is never active. The owner public key always
 * comes from the vault, never from the override file.
 */
export function createPolicy(open: OpenVault, overrides: PolicyOverrides = {}): OwnerPolicy {
  const owner = getOwnerKeyPair(open);
  const base = defaultPolicyDraft(owner.publicKey);
  const draft: PolicyDraft = {
    ...base,
    limits: { ...base.limits, ...(overrides.limits ?? {}) },
    gates: {
      ...base.gates,
      ...(overrides.gates ?? {}),
      hardStops: { ...base.gates.hardStops, ...(overrides.gates?.hardStops ?? {}) },
    },
    custody: overrides.custody ?? base.custody,
  };
  const policy = signPolicy(owner.privateKey, draft);
  savePolicy(dirname(open.vaultPath), policy);
  return policy;
}

/** Sign the proposed defaults. The owner must choose this explicitly. */
export function createDefaultPolicy(open: OpenVault): OwnerPolicy {
  return createPolicy(open);
}

export function verifyStoredPolicy(home: string): boolean {
  try {
    const policy = loadPolicy(home);
    return verifyPolicy(policy);
  } catch {
    return false;
  }
}

export function grantsPath(home: string): string {
  return join(home, "grants.json");
}

interface GrantFile {
  readonly schema: "charade.grants/1";
  readonly revision: number;
  readonly grants: readonly Grant[];
}

export function loadGrants(home: string): readonly Grant[] {
  const path = grantsPath(home);
  if (!existsSync(path)) return [];
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("grant store is not valid JSON");
  }
  if (
    typeof value !== "object" ||
    value === null ||
    (value as { schema?: unknown }).schema !== "charade.grants/1" ||
    !Array.isArray((value as { grants?: unknown }).grants)
  ) {
    throw new Error("grant store schema is invalid");
  }
  const file = value as GrantFile;
  for (const grant of file.grants) {
    if (
      typeof grant !== "object" ||
      grant === null ||
      grant.schema !== "charade.grant/1" ||
      typeof grant.grantId !== "string"
    ) {
      throw new Error("grant store contains an invalid grant");
    }
  }
  return file.grants;
}

export function saveGrants(home: string, grants: readonly Grant[]): void {
  const file: GrantFile = { schema: "charade.grants/1", revision: grants.length, grants };
  writeAtomic(grantsPath(home), Buffer.from(canonicalJson(file), "utf8"), 0o600);
}

export function addGrant(home: string, grant: Grant): readonly Grant[] {
  const grants = [...loadGrants(home), grant];
  saveGrants(home, grants);
  return grants;
}

export function revokeGrant(home: string, grantId: string): boolean {
  const grants = loadGrants(home);
  const next = grants.filter((grant) => grant.grantId !== grantId);
  if (next.length === grants.length) return false;
  saveGrants(home, next);
  return true;
}

export function findGrant(home: string, grantId: string): Grant | undefined {
  return loadGrants(home).find((grant) => grant.grantId === grantId);
}
