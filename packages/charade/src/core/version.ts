/** Product and protocol identity. Keep this file dependency-free. */
export const PRODUCT_NAME = "CHARADE" as const;
export const PRODUCT_VERSION = "0.1.0" as const;
export const PROTOCOL_MAJOR = 1 as const;
export const PROTOCOL_MINOR = 0 as const;

export interface ProtocolVersion {
  readonly major: number;
  readonly minor: number;
}

export function protocolVersion(): ProtocolVersion {
  return { major: PROTOCOL_MAJOR, minor: PROTOCOL_MINOR };
}

export function protocolString(): string {
  return `${PROTOCOL_MAJOR}.${PROTOCOL_MINOR}`;
}

/**
 * Major versions must match. A newer minor is forward-compatible; an older
 * minor is accepted because the peer only omits capabilities we may not need.
 * Patch differences are not part of the protocol identity.
 */
export function protocolCompatible(peer: ProtocolVersion): boolean {
  return peer.major === PROTOCOL_MAJOR && peer.minor >= 0;
}
