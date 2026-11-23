import { sign } from "node:crypto";
import { privateKeyObject } from "../authority/keys.js";
import type { ErrorBody } from "../core/errors.js";
import { SESSION_DOMAIN, type Lease } from "../core/protocol.js";
import { send, type TransportResponse } from "./transport.js";

const IDEMPOTENT_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD", "OPTIONS"]);

export interface CharadeClientOptions {
  /** The broker's Unix socket path. */
  readonly socketPath: string;
  /** The consumer this device belongs to, as enrolled in the registry. */
  readonly consumerId: string;
  /** The enrolled device id. */
  readonly deviceId: string;
  /** PKCS#8 DER, base64, from the device file. */
  readonly devicePrivateKey: string;
  readonly now?: () => Date;
  readonly requestTimeoutMs?: number;
}

export interface IssuedLease {
  readonly lease: Lease;
  readonly token: string;
}

export interface ProxyCall {
  readonly leaseToken: string;
  readonly service: string;
  readonly path: string;
  readonly method?: string;
  readonly headers?: Record<string, string>;
  readonly body?: Buffer;
}

/** Anything the broker refused, with its stable code and plain-language fields. */
export class CharadeClientError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly body?: ErrorBody,
  ) {
    super(message);
    this.name = "CharadeClientError";
  }
}

interface CachedLease {
  readonly lease: Lease;
  readonly token: string;
}

export class CharadeClient {
  private readonly options: CharadeClientOptions;
  private readonly now: () => Date;
  private token?: string;
  private readonly leases = new Map<string, CachedLease>();

  constructor(options: CharadeClientOptions) {
    this.options = options;
    this.now = options.now ?? (() => new Date());
  }

  get sessionToken(): string | undefined {
    return this.token;
  }

  /** Sign the broker's challenge with the device key and keep the session token. */
  async openSession(): Promise<void> {
    const challenge = await this.request<{ challengeId: string; nonce: string }>(
      "POST",
      "/v1/session/challenge",
      {
        role: "consumer",
        consumerId: this.options.consumerId,
        deviceId: this.options.deviceId,
      },
    );
    const message = Buffer.from(
      `${SESSION_DOMAIN}${challenge.nonce}\u0000${this.options.deviceId}`,
      "utf8",
    );
    const signature = sign(null, message, privateKeyObject(this.options.devicePrivateKey)).toString(
      "base64url",
    );
    const session = await this.request<{ sessionToken: string }>("POST", "/v1/session", {
      challengeId: challenge.challengeId,
      signature,
      deviceId: this.options.deviceId,
    });
    this.token = session.sessionToken;
  }

  async closeSession(): Promise<void> {
    if (!this.token) return;
    await this.request("DELETE", "/v1/session", undefined, { authorization: `Bearer ${this.token}` });
    this.token = undefined;
    this.leases.clear();
  }

  async issueLease(services: readonly string[], ttlSeconds?: number): Promise<IssuedLease> {
    const issued = await this.request<IssuedLease>(
      "POST",
      "/v1/leases",
      { services: [...services], ...(ttlSeconds !== undefined ? { ttlSeconds } : {}) },
      this.auth(),
    );
    this.leases.set(services.join(","), { lease: issued.lease, token: issued.token });
    return issued;
  }

  /** Renew the cached lease for this service (or the given one) and replace it. */
  async renew(service: string, ttlSeconds?: number): Promise<IssuedLease> {
    const cached = this.leases.get(service);
    if (!cached) throw new CharadeClientError(`no lease for ${service}`, 0);
    const renewed = await this.request<IssuedLease>(
      "POST",
      `/v1/leases/${encodeURIComponent(cached.lease.leaseId)}/renew`,
      { token: cached.token, ...(ttlSeconds !== undefined ? { ttlSeconds } : {}) },
      this.auth(),
    );
    this.leases.set(service, { lease: renewed.lease, token: renewed.token });
    return renewed;
  }

  /** One proxied request. The value is injected by the broker, never here. */
  async call(input: ProxyCall): Promise<TransportResponse> {
    if (!this.token) throw new CharadeClientError("no session; call openSession() first", 0);
    const method = (input.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.token}`,
      "x-charade-lease": input.leaseToken,
      ...(input.headers ?? {}),
    };
    const suffix = input.path.startsWith("/") ? input.path : `/${input.path}`;
    const response = await send({
      socketPath: this.options.socketPath,
      method,
      path: `/v1/proxy/${encodeURIComponent(input.service)}${suffix}`,
      headers,
      ...(input.body ? { body: input.body } : {}),
      ...(this.options.requestTimeoutMs ? { timeoutMs: this.options.requestTimeoutMs } : {}),
    });
    // A charade-coded body is the broker refusing; an upstream status is data.
    if (response.status >= 400) {
      const parsed = parseErrorBody(response.body);
      if (parsed?.code?.startsWith("charade.")) {
        throw new CharadeClientError(
          `${parsed.code}: ${parsed.whatHappened} Next: ${parsed.whatNext}`,
          response.status,
          parsed.code,
          parsed,
        );
      }
    }
    return response;
  }

  /**
   * Lease a service, renew it once two thirds of its TTL have passed, and retry
   * once when a refused call is safe to repeat.
   */
  async withLease<T>(
    service: string,
    method: string,
    fn: (lease: IssuedLease) => Promise<T>,
  ): Promise<T> {
    try {
      return await fn(await this.ensureLease(service));
    } catch (error) {
      const retriable =
        error instanceof CharadeClientError &&
        (error.code === "charade.lease_expired" || error.code === "charade.lease_revoked");
      if (!retriable || !IDEMPOTENT_METHODS.has(method.toUpperCase())) throw error;
      return fn(await this.ensureLease(service, true));
    }
  }

  private async ensureLease(service: string, force = false): Promise<IssuedLease> {
    const cached = this.leases.get(service);
    if (!cached) return this.issueLease([service]);
    if (force || shouldRenew(cached.lease, this.now())) return this.renew(service);
    return { lease: cached.lease, token: cached.token };
  }

  private auth(): Record<string, string> {
    if (!this.token) throw new CharadeClientError("no session; call openSession() first", 0);
    return { authorization: `Bearer ${this.token}` };
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<T> {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const response = await send({
      socketPath: this.options.socketPath,
      method,
      path,
      headers: {
        ...headers,
        ...(payload ? { "content-type": "application/json" } : {}),
      },
      ...(payload ? { body: payload } : {}),
      ...(this.options.requestTimeoutMs ? { timeoutMs: this.options.requestTimeoutMs } : {}),
    });
    if (response.status >= 400) {
      const parsed = parseErrorBody(response.body);
      const message = parsed
        ? `${parsed.code}: ${parsed.whatHappened} Next: ${parsed.whatNext}`
        : `request failed with status ${response.status}`;
      throw new CharadeClientError(message, response.status, parsed?.code, parsed);
    }
    if (response.body.length === 0) return undefined as T;
    return JSON.parse(response.body.toString("utf8")) as T;
  }
}

/** Renew once two thirds of the lease window has elapsed. */
export function shouldRenew(
  lease: { createdAt: string; expiresAt: string },
  now = new Date(),
): boolean {
  const created = new Date(lease.createdAt).getTime();
  const expires = new Date(lease.expiresAt).getTime();
  if (!Number.isFinite(created) || !Number.isFinite(expires)) return true;
  const window = expires - created;
  if (window <= 0) return true;
  return now.getTime() >= created + (window * 2) / 3;
}

function parseErrorBody(body: Buffer): ErrorBody | undefined {
  try {
    const value = JSON.parse(body.toString("utf8")) as unknown;
    if (typeof value === "object" && value !== null && typeof (value as ErrorBody).code === "string") {
      return value as ErrorBody;
    }
    return undefined;
  } catch {
    return undefined;
  }
}
