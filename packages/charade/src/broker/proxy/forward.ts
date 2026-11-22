import { Readable } from "node:stream";
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

export interface ForwardInput {
  readonly service: ServiceRecord;
  readonly secretValue: string;
  readonly method: string;
  readonly remainingPath: string;
  readonly search: string;
  readonly headers: IncomingHttpHeaders;
  readonly body: Buffer;
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
    signal: AbortSignal.timeout(30_000),
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
    await pipeline(
      Readable.fromWeb(upstream.body as import("node:stream/web").ReadableStream<Uint8Array>),
      response,
    );
  } else {
    response.end();
  }
  return { status: upstream.status };
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
