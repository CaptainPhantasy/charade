/**
 * Stable error codes. Every code carries plain-language fields so the CLI,
 * TUI, and API cannot disagree about what happened or what to do next.
 */
export type ErrorCode =
  | "charade.owner_policy_missing"
  | "charade.owner_required"
  | "charade.vault_locked"
  | "charade.registry_unreadable"
  | "charade.registry_invalid"
  | "charade.grant_missing"
  | "charade.grant_expired"
  | "charade.grant_revoked"
  | "charade.scope_denied"
  | "charade.lease_expired"
  | "charade.lease_revoked"
  | "charade.device_mismatch"
  | "charade.device_revoked"
  | "charade.session_invalid"
  | "charade.action_denied"
  | "charade.action_unknown"
  | "charade.ceiling_reached"
  | "charade.secret_missing"
  | "charade.env_not_granted"
  | "charade.protocol_mismatch"
  | "charade.integrity_broken"
  | "charade.unknown";

export interface ErrorDefinition {
  /** What happened, in one sentence a person can repeat. */
  readonly whatHappened: string;
  /** The next concrete step. Never empty. */
  readonly whatNext: string;
  /** True only when a decision belongs to the owner. */
  readonly ownerOnly: boolean;
  /** True when retrying the same request may succeed without a state change. */
  readonly retriable: boolean;
}

export const ERROR_CATALOG: Readonly<Record<ErrorCode, ErrorDefinition>> = {
  "charade.owner_policy_missing": {
    whatHappened: "The owner policy is missing, unsigned, or unreadable.",
    whatNext: "Run `charade init` or sign the policy in the Admin TUI; the broker will not issue grants until then.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.owner_required": {
    whatHappened: "This action needs the owner's explicit approval.",
    whatNext: "Open the Admin TUI or ask the owner to approve this action; nothing was changed.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.vault_locked": {
    whatHappened: "The vault is locked, so no credential can be used.",
    whatNext: "Unlock the vault in the Admin TUI or with `charade unlock`; existing work pauses until it is unlocked.",
    ownerOnly: true,
    retriable: true,
  },
  "charade.registry_unreadable": {
    whatHappened: "The service registry could not be read.",
    whatNext: "Check the registry path and permissions, then run `charade doctor`. No leases are issued while it is unreadable.",
    ownerOnly: false,
    retriable: true,
  },
  "charade.registry_invalid": {
    whatHappened: "The service registry is readable but does not match the expected schema.",
    whatNext: "Run `charade doctor --json` and fix the reported field; no leases are issued until it validates.",
    ownerOnly: false,
    retriable: false,
  },
  "charade.grant_missing": {
    whatHappened: "No owner-signed grant authorizes this consumer and service.",
    whatNext: "Ask the owner to create a grant; the request was denied.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.grant_expired": {
    whatHappened: "The grant has expired.",
    whatNext: "Ask the owner for a new grant; the work can resume when one is accepted.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.grant_revoked": {
    whatHappened: "The grant was revoked.",
    whatNext: "Stop using this consumer and ask the owner whether a new grant is intended.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.scope_denied": {
    whatHappened: "The request is outside the grant's scoped services, methods, or paths.",
    whatNext: "Use a permitted resource or ask the owner to widen the scope; nothing was forwarded.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.lease_expired": {
    whatHappened: "The short lease expired.",
    whatNext: "Renew the lease under the still-valid grant; retry only if the request is idempotent.",
    ownerOnly: false,
    retriable: true,
  },
  "charade.lease_revoked": {
    whatHappened: "The lease was revoked.",
    whatNext: "Request a new lease under a valid grant, or ask the owner why it was revoked.",
    ownerOnly: false,
    retriable: true,
  },
  "charade.device_mismatch": {
    whatHappened: "The lease or session belongs to a different device.",
    whatNext: "Use the enrolled device or ask the owner to enroll this one; the request was refused.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.device_revoked": {
    whatHappened: "This device has been revoked.",
    whatNext: "Ask the owner to enroll it again if access is still intended.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.session_invalid": {
    whatHappened: "The session is missing, expired, or invalid.",
    whatNext: "Open a new session with the enrolled device key; nothing was changed.",
    ownerOnly: false,
    retriable: true,
  },
  "charade.ceiling_reached": {
    whatHappened: "The grant's call ceiling was reached.",
    whatNext: "Ask the owner to raise the ceiling or wait for the next window; the request was not forwarded.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.secret_missing": {
    whatHappened: "No active secret version is available for this service.",
    whatNext: "Ask the owner to add or rotate the service credential; the request was not forwarded.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.action_denied": {
    whatHappened: "The action class is blocked by the owner's hard-stop policy.",
    whatNext: "Ask the owner to approve this one action; the request was not forwarded.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.action_unknown": {
    whatHappened: "The request could not be classified into a declared action class.",
    whatNext: "Use a declared method and path, or ask the owner to classify it; unknown actions are denied by default.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.env_not_granted": {
    whatHappened: "Environment-value access is not granted.",
    whatNext: "Use the proxy path, or ask the owner for a single-use, short-lived env exception.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.protocol_mismatch": {
    whatHappened: "The client and broker do not speak the same protocol major version.",
    whatNext: "Upgrade the older side; no request was processed.",
    ownerOnly: false,
    retriable: false,
  },
  "charade.integrity_broken": {
    whatHappened: "The receipt chain, vault, or backup failed its integrity check.",
    whatNext: "Stop using the broker and restore from a verified backup; run `charade doctor --json` for details.",
    ownerOnly: true,
    retriable: false,
  },
  "charade.unknown": {
    whatHappened: "An unexpected error occurred.",
    whatNext: "Run `charade doctor --json` and report the request ID; no success is being claimed.",
    ownerOnly: false,
    retriable: false,
  },
};

export interface ErrorBody {
  readonly code: ErrorCode;
  readonly whatHappened: string;
  readonly whatNext: string;
  readonly ownerOnly: boolean;
  readonly retriable: boolean;
  readonly requestId?: string;
  readonly receiptId?: string;
}

export class CharadeError extends Error {
  readonly code: ErrorCode;
  readonly requestId?: string;
  readonly receiptId?: string;

  constructor(code: ErrorCode, requestId?: string, receiptId?: string) {
    const definition = ERROR_CATALOG[code];
    super(definition.whatHappened);
    this.name = "CharadeError";
    this.code = code;
    this.requestId = requestId;
    this.receiptId = receiptId;
  }

  toBody(): ErrorBody {
    const definition = ERROR_CATALOG[this.code];
    const body: ErrorBody = {
      code: this.code,
      whatHappened: definition.whatHappened,
      whatNext: definition.whatNext,
      ownerOnly: definition.ownerOnly,
      retriable: definition.retriable,
      ...(this.requestId ? { requestId: this.requestId } : {}),
      ...(this.receiptId ? { receiptId: this.receiptId } : {}),
    };
    return body;
  }
}
