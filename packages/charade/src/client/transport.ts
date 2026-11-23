import { request as httpRequest, type IncomingHttpHeaders } from "node:http";

export interface TransportRequest {
  readonly socketPath: string;
  readonly method: string;
  readonly path: string;
  readonly headers?: Record<string, string>;
  readonly body?: Buffer;
  readonly timeoutMs?: number;
}

export interface TransportResponse {
  readonly status: number;
  readonly headers: IncomingHttpHeaders;
  readonly body: Buffer;
}

/**
 * The client's only transport: HTTP/1.1 over the broker's Unix socket. There is
 * no TCP path to fall back to, by design.
 */
export function send(input: TransportRequest): Promise<TransportResponse> {
  const timeoutMs = input.timeoutMs ?? 30_000;
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { ...(input.headers ?? {}) };
    if (input.body && input.body.length > 0) {
      headers["content-length"] = String(input.body.length);
    }
    const request = httpRequest(
      {
        socketPath: input.socketPath,
        method: input.method,
        path: input.path,
        headers,
        timeout: timeoutMs,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks),
          }),
        );
      },
    );
    request.on("timeout", () => request.destroy(new Error(`no response within ${timeoutMs} ms`)));
    request.on("error", reject);
    if (input.body && input.body.length > 0) request.write(input.body);
    request.end();
  });
}
