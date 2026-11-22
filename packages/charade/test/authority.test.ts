import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  generateOwnerKeyPair,
  publicKeyFingerprint,
  signDomain,
  verifyDomain,
} from "../src/authority/keys.js";
import {
  DEFAULT_GATES,
  DEFAULT_LIMITS,
  defaultPolicyDraft,
  policyHash,
  signPolicy,
  verifyPolicy,
} from "../src/authority/policy.js";
import {
  GRANT_DOMAIN,
  parseDuration,
  signGrant,
  verifyGrant,
} from "../src/authority/grants.js";

const NOW = new Date("2026-01-01T00:00:00Z");

function fixture() {
  const owner = generateOwnerKeyPair();
  const policy = signPolicy(owner.privateKey, defaultPolicyDraft(owner.publicKey));
  const grant = signGrant(
    owner.privateKey,
    policy,
    {
      consumerId: "c1",
      deviceId: "d1",
      services: ["svc"],
      methods: ["GET"],
      paths: ["/v1/*"],
      durationSeconds: GRANT_PRESETS_24H,
      ceilings: { callsPerDay: 1000 },
      hardStops: DEFAULT_GATES.hardStops,
      envAllowed: false,
    },
    NOW,
  );
  return { owner, policy, grant };
}

const GRANT_PRESETS_24H = 86_400;

describe("owner keys", () => {
  it("generates a 32-byte public key and signs domain-separated values", () => {
    const owner = generateOwnerKeyPair();
    assert.equal(Buffer.from(owner.publicKey, "base64url").length, 32);
    assert.equal(publicKeyFingerprint(owner.publicKey).length, 16);
    const value = { b: 2, a: 1 };
    const signature = signDomain(owner.privateKey, "domain\u0000", value);
    assert.equal(verifyDomain(owner.publicKey, "domain\u0000", value, signature), true);
    assert.equal(verifyDomain(owner.publicKey, "other\u0000", value, signature), false);
    assert.equal(verifyDomain(owner.publicKey, "domain\u0000", { ...value, a: 9 }, signature), false);
  });
});

describe("owner policy", () => {
  it("signs and verifies the proposed defaults", () => {
    const owner = generateOwnerKeyPair();
    const policy = signPolicy(owner.privateKey, defaultPolicyDraft(owner.publicKey));
    assert.equal(policy.limits.defaultGrantDurationSeconds, DEFAULT_LIMITS.defaultGrantDurationSeconds);
    assert.equal(policy.gates.hardStops.money, true);
    assert.equal(policy.gates.telemetry, "forbidden");
    assert.equal(verifyPolicy(policy), true);
    assert.match(policyHash(policy), /^sha256:[0-9a-f]{64}$/);
  });

  it("rejects a tampered policy", () => {
    const owner = generateOwnerKeyPair();
    const policy = signPolicy(owner.privateKey, defaultPolicyDraft(owner.publicKey));
    const tampered = {
      ...policy,
      limits: { ...policy.limits, maxLeaseTtlSeconds: 999_999 },
    };
    assert.equal(verifyPolicy(tampered), false);
  });
});

describe("owner grants", () => {
  it("signs and verifies a scoped grant", () => {
    const { policy, grant } = fixture();
    assert.equal(grant.ceilings.callsPerDay, 1000);
    assert.equal(grant.envAllowed, false);
    assert.equal(verifyGrant(policy, grant, new Date(NOW.getTime() + 3_600_000)).ok, true);
  });

  it("rejects expired, tampered, and wrong-policy grants", () => {
    const { policy, grant } = fixture();
    assert.equal(verifyGrant(policy, grant, new Date(NOW.getTime() + 90_000_000)).ok, false);
    assert.equal(
      verifyGrant(policy, { ...grant, services: ["other"] }, new Date(NOW.getTime() + 1000)).ok,
      false,
    );
    const otherOwner = generateOwnerKeyPair();
    const otherPolicy = signPolicy(otherOwner.privateKey, defaultPolicyDraft(otherOwner.publicKey));
    assert.equal(verifyGrant(otherPolicy, grant, new Date(NOW.getTime() + 1000)).ok, false);
    assert.equal(verifyGrant(policy, { ...grant, signature: "bad" }, new Date()).ok, false);
  });

  it("refuses a grant longer than the policy maximum", () => {
    const owner = generateOwnerKeyPair();
    const policy = signPolicy(owner.privateKey, defaultPolicyDraft(owner.publicKey));
    assert.throws(() =>
      signGrant(owner.privateKey, policy, {
        consumerId: "c1",
        services: ["svc"],
        methods: ["GET"],
        paths: ["/v1/*"],
        durationSeconds: policy.limits.maxGrantDurationSeconds + 1,
        ceilings: { callsPerDay: 10 },
        hardStops: DEFAULT_GATES.hardStops,
        envAllowed: false,
      }),
    );
  });

  it("parses the documented duration presets", () => {
    assert.equal(parseDuration("1h"), 3600);
    assert.equal(parseDuration("24h"), 86_400);
    assert.equal(parseDuration("7d"), 604_800);
    assert.equal(parseDuration("90"), 90);
    assert.throws(() => parseDuration("forever"));
  });

  it("uses a distinct domain for grants", () => {
    const { owner, grant } = fixture();
    assert.equal(
      verifyDomain(owner.publicKey, GRANT_DOMAIN, grant, grant.signature),
      false,
    );
  });
});
