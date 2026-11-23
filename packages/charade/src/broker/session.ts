import { createHash, randomBytes, verify } from "node:crypto";
import { SESSION_DOMAIN, type OwnerPolicy } from "../core/protocol.js";
import type { Registry } from "../registry/registry.js";
import { publicKeyObject } from "../authority/keys.js";

export { SESSION_DOMAIN };

const CHALLENGE_TTL_MS = 60_000;

export type SessionRole = "owner" | "consumer";

export interface Challenge {
  readonly challengeId: string;
  readonly nonce: string;
  readonly role: SessionRole;
  readonly consumerId?: string;
  readonly deviceId: string;
  readonly expiresAt: string;
}

export interface Session {
  readonly role: SessionRole;
  readonly consumerId?: string;
  readonly deviceId: string;
  readonly idleSeconds: number;
  readonly idleExpiresAt: string;
  readonly absoluteExpiresAt: string;
}

export interface SessionGrant extends Session {
  readonly sessionToken: string;
}

export type SessionErrorCode =
  | "challenge_not_found"
  | "challenge_expired"
  | "device_mismatch"
  | "device_revoked"
  | "signature_invalid"
  | "session_invalid"
  | "session_expired";

export class SessionError extends Error {
  readonly code: SessionErrorCode;
  constructor(code: SessionErrorCode, message: string) {
    super(message);
    this.name = "SessionError";
    this.code = code;
  }
}

export class SessionStore {
  private readonly challenges = new Map<string, Challenge>();
  private readonly sessions = new Map<string, Session>();

  createChallenge(
    input: { role: SessionRole; consumerId?: string; deviceId?: string },
    registry: Registry | undefined,
    policy: OwnerPolicy | undefined,
    now = new Date(),
  ): Challenge {
    const deviceId = input.deviceId ?? (input.role === "owner" ? "owner" : undefined);
    if (!deviceId) throw new SessionError("device_mismatch", "consumer challenge needs a device");
    if (input.role === "owner") {
      if (!policy) throw new SessionError("signature_invalid", "owner policy is missing");
    } else {
      if (!registry) throw new SessionError("signature_invalid", "registry is missing");
      if (!input.consumerId) throw new SessionError("device_mismatch", "consumer challenge needs a consumer");
      const device = registry.devices.find((item) => item.id === deviceId);
      if (!device || device.consumerId !== input.consumerId) {
        throw new SessionError("device_mismatch", "device is not enrolled for this consumer");
      }
      if (device.revokedAt) throw new SessionError("device_revoked", "device is revoked");
    }
    const challenge: Challenge = {
      challengeId: `ch_${randomBytes(12).toString("hex")}`,
      nonce: randomBytes(24).toString("base64url"),
      role: input.role,
      ...(input.consumerId ? { consumerId: input.consumerId } : {}),
      deviceId,
      expiresAt: new Date(now.getTime() + CHALLENGE_TTL_MS).toISOString(),
    };
    this.challenges.set(challenge.challengeId, challenge);
    return challenge;
  }

  complete(
    challengeId: string,
    signature: string,
    deviceId: string,
    registry: Registry | undefined,
    policy: OwnerPolicy | undefined,
    now = new Date(),
  ): SessionGrant {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) throw new SessionError("challenge_not_found", "challenge was not found");
    this.challenges.delete(challengeId);
    if (new Date(challenge.expiresAt).getTime() <= now.getTime()) {
      throw new SessionError("challenge_expired", "challenge expired");
    }
    if (challenge.deviceId !== deviceId) {
      throw new SessionError("device_mismatch", "challenge belongs to a different device");
    }
    let publicKey: string;
    if (challenge.role === "owner") {
      if (!policy) throw new SessionError("signature_invalid", "owner policy is missing");
      publicKey = policy.ownerPublicKey;
    } else {
      if (!registry) throw new SessionError("signature_invalid", "registry is missing");
      const device = registry.devices.find((item) => item.id === deviceId);
      if (!device) throw new SessionError("device_mismatch", "device is not enrolled");
      if (device.revokedAt) throw new SessionError("device_revoked", "device is revoked");
      if (device.consumerId !== challenge.consumerId) {
        throw new SessionError("device_mismatch", "device changed consumers");
      }
      publicKey = device.publicKey;
    }
    const message = Buffer.from(
      `${SESSION_DOMAIN}${challenge.nonce}\u0000${challenge.deviceId}`,
      "utf8",
    );
    let valid = false;
    try {
      valid = verify(
        null,
        message,
        publicKeyObject(publicKey),
        Buffer.from(signature, "base64url"),
      );
    } catch {
      valid = false;
    }
    if (!valid) throw new SessionError("signature_invalid", "challenge signature is invalid");
    if (!policy) throw new SessionError("signature_invalid", "owner policy is missing");
    const sessionToken = randomBytes(32).toString("base64url");
    const session: Session = {
      role: challenge.role,
      ...(challenge.consumerId ? { consumerId: challenge.consumerId } : {}),
      deviceId,
      idleSeconds: policy.limits.sessionIdleSeconds,
      idleExpiresAt: new Date(now.getTime() + policy.limits.sessionIdleSeconds * 1000).toISOString(),
      absoluteExpiresAt: new Date(
        now.getTime() + policy.limits.sessionAbsoluteSeconds * 1000,
      ).toISOString(),
    };
    this.sessions.set(hashToken(sessionToken), session);
    return { ...session, sessionToken };
  }

  require(token: string, now = new Date()): Session {
    const hash = hashToken(token);
    const session = this.sessions.get(hash);
    if (!session) throw new SessionError("session_invalid", "session is not valid");
    if (
      new Date(session.absoluteExpiresAt).getTime() <= now.getTime() ||
      new Date(session.idleExpiresAt).getTime() <= now.getTime()
    ) {
      this.sessions.delete(hash);
      throw new SessionError("session_expired", "session expired");
    }
    return session;
  }

  touch(token: string, now = new Date()): Session {
    const session = this.require(token, now);
    const updated: Session = {
      ...session,
      idleExpiresAt: new Date(
        Math.min(
          new Date(session.absoluteExpiresAt).getTime(),
          now.getTime() + session.idleSeconds * 1000,
        ),
      ).toISOString(),
    };
    this.sessions.set(hashToken(token), updated);
    return updated;
  }

  revoke(token: string): void {
    this.sessions.delete(hashToken(token));
  }
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}
