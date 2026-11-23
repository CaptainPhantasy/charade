import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { IncomingHttpHeaders, ServerResponse } from "node:http";
import type { ServiceRecord } from "../../registry/registry.js";
import { injectAuth } from "../connectors.js";
import { netFetch } from "./net.js";

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export class ProxyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProxyError";
  }
}

/** The upstream response contained the injected credential. */
export class LeakDetectedError extends Error {
  constructor() {
    super("upstream response contained the injected credential");
    this.name = "LeakDetectedError";
  }
}

export interface ForwardInput {
  readonly service: ServiceRecord;
  readonly secretValue: string;
  readonly method: string;
  readonly remainingPath: string;
  readonly search: string;
  readonly headers: IncomingHttpHeaders;
  readonly body: Buffer;
  /** Aborted when the consumer disconnects, so the upstream call stops too. */
  readonly signal?: AbortSignal;
}

export interface ForwardResult {
  readonly status: number;
}

export async function forwardProxy(
  response: ServerResponse,
  input: ForwardInput,
): Promise<ForwardResult> {
  const target = buildTarget(input.service, input.remainingPath, input.search);
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(input.headers)) {
    if (value === undefined) continue;
    headers[key] = Array.isArray(value) ? value.join(", ") : value;
  }
  // A Connection header can name extra hop-by-hop fields to drop (RFC 9110).
  const connection = headers.connection;
  if (connection) {
    for (const token of connection.split(",")) {
      const name = token.trim().toLowerCase();
      if (name.length > 0) delete headers[name];
    }
  }
  for (const key of HOP_BY_HOP) delete headers[key];
  delete headers.authorization;
  delete headers["x-charade-session"];
  delete headers["x-charade-lease"];
  delete headers.host;
  delete headers["content-length"];

  const injected = injectAuth(input.service, input.secretValue, headers, target);
  if (input.body.length > 0) injected.headers["content-length"] = String(input.body.length);

  const init: RequestInit = {
    method: input.method,
    headers: injected.headers,
    redirect: "manual",
    signal: input.signal
      ? AbortSignal.any([AbortSignal.timeout(30_000), input.signal])
      : AbortSignal.timeout(30_000),
  };
  if (input.method !== "GET" && input.method !== "HEAD") init.body = input.body;

  const upstream = await netFetch(injected.url, init);
  if (upstream.status >= 300 && upstream.status < 400) {
    throw new ProxyError("upstream redirect refused");
  }

  const responseHeaders: Record<string, string | string[]> = {};
  for (const [key, value] of upstream.headers.entries()) {
    if (HOP_BY_HOP.has(key.toLowerCase())) continue;
    if (key.toLowerCase() === "content-encoding") continue;
    if (key.toLowerCase() === "content-length") continue;
    responseHeaders[key] = value;
  }
  response.writeHead(upstream.status, responseHeaders);
  if (upstream.body) {
    const source = Readable.fromWeb(
      upstream.body as import("node:stream/web").ReadableStream<Uint8Array>,
    );
    await pipeline(source, leakGuard(input.secretValue), response);
  } else {
    response.end();
  }
  return { status: upstream.status };
}

/**
 * The value must never reach the consumer, even if an upstream echoes it back
 * (a misconfigured service, a debug endpoint, a proxy in the middle). The guard
 * keeps only a rolling tail, so streaming behaviour and memory use are intact.
 */
function leakGuard(secret: string): Transform {
  const needle = Buffer.from(secret, "utf8");
  const keep = Math.max(0, needle.length - 1);
  let tail = Buffer.alloc(0);
  if (needle.length === 0) return new Transform({ transform: (chunk, _encoding, callback) => callback(null, chunk) });
  return new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      const window = Buffer.concat([tail, chunk]);
      if (window.includes(needle)) {
        callback(new LeakDetectedError());
        return;
      }
      tail = window.subarray(Math.max(0, window.length - keep));
      callback(null, chunk);
    },
  });
}

function buildTarget(service: ServiceRecord, remainingPath: string, search: string): URL {
  const base = new URL(service.url);
  const suffix = remainingPath.startsWith("/") ? remainingPath : `/${remainingPath}`;
  let decoded: string;
  try {
    decoded = decodeURIComponent(suffix);
  } catch {
    throw new ProxyError("upstream path is not valid encoding");
  }
  if (decoded.split("/").includes("..")) {
    throw new ProxyError("upstream path traversal refused");
  }
  const target = new URL(base.toString());
  target.pathname = `${base.pathname.replace(/\/$/, "")}${suffix}`;
  target.search = search;
  if (target.origin !== base.origin) {
    throw new ProxyError("upstream target changed origin");
  }
  return target;
}
