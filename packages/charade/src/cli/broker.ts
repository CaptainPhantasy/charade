import { request as httpRequest } from "node:http";
import { join } from "node:path";
import { Broker } from "../broker/server.js";
import { protocolString } from "../core/version.js";
import { USAGE } from "./usage.js";
import {
  checkPassphrase,
  passphraseFrom,
  requireOption,
  takeFlag,
  takeOption,
  usageError,
} from "./util.js";

export interface ProbeResult {
  readonly status: number;
  readonly body: Record<string, unknown>;
}

/** Ask a running broker for its unauthenticated liveness document. */
export function probeHealth(socketPath: string, timeoutMs = 1500): Promise<ProbeResult> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      { socketPath, method: "GET", path: "/health", timeout: timeoutMs },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let body: Record<string, unknown> = {};
          try {
            body = JSON.parse(text) as Record<string, unknown>;
          } catch {
            body = { raw: text };
          }
          resolve({ status: response.statusCode ?? 0, body });
        });
      },
    );
    request.on("timeout", () => {
      request.destroy(new Error(`no response within ${timeoutMs} ms`));
    });
    request.on("error", reject);
    request.end();
  });
}

export async function brokerCommand(args: string[]): Promise<void> {
  const sub = args[1];
  if (sub === "serve") {
    await serveCommand(args);
    return;
  }
  if (sub === "status") {
    await statusCommand(args);
    return;
  }
  usageError(`unknown broker command: ${sub ?? "(none)"}`, USAGE);
}

async function serveCommand(args: string[]): Promise<void> {
  const home = requireOption(args, "--home", USAGE, "broker serve");
  const socket = takeOption(args, "--socket");
  const passphrase = await passphraseFrom(args, takeOption(args, "--passphrase-file"));
  checkPassphrase(passphrase);

  const broker = new Broker({
    home,
    passphrase,
    ...(socket ? { socketPath: socket } : {}),
  });
  await broker.start();

  const report = broker.health();
  const ready = report.overall === "ok" || report.overall === "degraded";
  process.stdout.write(`socket:   ${broker.socketPath}\n`);
  process.stdout.write(`protocol: ${protocolString()}\n`);
  process.stdout.write(`state:    ${report.overall}\n`);
  process.stdout.write(`ready:    ${ready ? "yes" : "no"}\n`);
  if (!ready) {
    process.stderr.write(
      "\nThe broker is serving liveness with HTTP 503 and will not issue leases:\n",
    );
    for (const check of report.checks) {
      if (check.status === "pass") continue;
      const remedy = check.remedy ? `; next: ${check.remedy}` : "";
      process.stderr.write(`  - ${check.id}: ${check.summary}${remedy}\n`);
    }
    process.stderr.write("\n");
  }
  process.stdout.write("Press Ctrl-C to stop. The socket is removed on exit.\n");

  let stopping = false;
  const shutdown = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    process.stdout.write(`\nstopping (${signal})\n`);
    void broker.stop().then(
      () => process.exit(0),
      () => process.exit(1),
    );
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  // The listening socket keeps the process alive; this promise never settles.
  await new Promise<void>(() => undefined);
}

async function statusCommand(args: string[]): Promise<void> {
  const home = takeOption(args, "--home");
  const socket = takeOption(args, "--socket") ?? (home ? join(home, "broker.sock") : undefined);
  const json = takeFlag(args, "--json");
  if (!socket) usageError("broker status: --home <dir> or --socket <path> is required", USAGE);

  let probe: ProbeResult;
  try {
    probe = await probeHealth(socket);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (json) {
      process.stdout.write(
        `${JSON.stringify({ socket, listening: false, error: message }, null, 2)}\n`,
      );
    } else {
      process.stderr.write(`no broker is listening at ${socket}: ${message}\n`);
    }
    process.exitCode = 1;
    return;
  }

  const payload = {
    socket,
    listening: true,
    status: probe.status,
    alive: probe.body.alive === true,
    ready: probe.body.ready === true,
    overall: typeof probe.body.overall === "string" ? probe.body.overall : "unknown",
    protocol: typeof probe.body.protocol === "string" ? probe.body.protocol : protocolString(),
  };
  if (json) {
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  } else {
    process.stdout.write(`socket:   ${payload.socket}\n`);
    process.stdout.write(`alive:    ${payload.alive ? "yes" : "no"}\n`);
    process.stdout.write(`ready:    ${payload.ready ? "yes" : "no"}\n`);
    process.stdout.write(`state:    ${payload.overall}\n`);
    process.stdout.write(`protocol: ${payload.protocol}\n`);
    if (!payload.ready) {
      process.stdout.write(
        "Not ready: leases are refused. Run `charade doctor --home <dir>` for the failing check.\n",
      );
    }
  }
  process.exitCode = payload.ready ? 0 : 1;
}
