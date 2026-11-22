import fs from "node:fs";
import path from "node:path";

/**
 * Detection is read-only, network-free, and never installs anything.
 * The consuming release owns the UI; this module owns the contract.
 */
export const EXIT_COMPATIBLE = 0;
export const EXIT_ABSENT = 10;
export const EXIT_INCOMPATIBLE = 11;
export const EXIT_BROKEN = 12;
export const EXIT_AMBIGUOUS = 13;

export type BinaryState = "found" | "absent" | "configured_broken";
export type BrokerState = "unknown" | "absent" | "configured";

export interface Installation {
  readonly path: string;
  readonly source: "env" | "path";
}

export interface EnsureDoor {
  readonly id: "install" | "point" | "skip";
  readonly title: string;
  readonly why: string;
  readonly commands: readonly string[];
  readonly risks: readonly string[];
}

export interface EnsureResult {
  readonly schema: "charade.ensure/1";
  readonly exitCode: number;
  readonly binary: {
    readonly state: BinaryState;
    readonly path?: string;
    readonly installations: readonly Installation[];
  };
  readonly broker: {
    readonly state: BrokerState;
    readonly socket?: string;
  };
  readonly doors: readonly EnsureDoor[];
  readonly warnings: readonly string[];
}

export interface DetectOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly pathEntries?: readonly string[];
  readonly isFile?: (path: string) => boolean;
  readonly join?: (...parts: string[]) => string;
}

const DOORS: readonly EnsureDoor[] = [
  {
    id: "install",
    title: "Install Charade",
    why: "No compatible Charade was found.",
    commands: ["npm install -g @floydslabs/charade@0.1.0"],
    risks: [
      "Ask the owner before installing; never install silently.",
      "Verify the published checksum, provenance, and license before enabling the broker.",
    ],
  },
  {
    id: "point",
    title: "Use an existing Charade",
    why: "Point this tool at an installation that is already running.",
    commands: ["charade config point --socket <path>"],
    risks: ["The owner must approve which instance and which grants are used."],
  },
  {
    id: "skip",
    title: "Skip Charade",
    why: "The host tool can operate without a broker.",
    commands: [],
    risks: [],
  },
];

function defaultIsFile(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

function defaultJoin(...parts: string[]): string {
  return path.join(...parts);
}

export function detectCharade(options: DetectOptions = {}): EnsureResult {
  const env = options.env ?? process.env;
  const pathEntries = options.pathEntries ?? (env.PATH ?? "").split(":").filter(Boolean);
  const isFile = options.isFile ?? defaultIsFile;
  const join = options.join ?? defaultJoin;
  const warnings: string[] = [];
  const installations: Installation[] = [];

  const configured = env.CHARADE_BIN?.trim();
  if (configured) {
    if (!isFile(configured)) {
      return result({
        exitCode: EXIT_BROKEN,
        binary: { state: "configured_broken", path: configured, installations: [] },
        broker: brokerState(env),
        warnings: ["CHARADE_BIN is set but does not point to an executable file."],
      });
    }
    installations.push({ path: configured, source: "env" });
  }

  for (const entry of pathEntries) {
    const candidate = join(entry, "charade");
    if (isFile(candidate) && !installations.some((item) => item.path === candidate)) {
      installations.push({ path: candidate, source: "path" });
    }
  }

  if (installations.length === 0) {
    return result({
      exitCode: EXIT_ABSENT,
      binary: { state: "absent", installations: [] },
      broker: brokerState(env),
      warnings,
    });
  }

  if (installations.length > 1) {
    warnings.push("More than one Charade installation was found; the first PATH match wins.");
    return result({
      exitCode: EXIT_AMBIGUOUS,
      binary: {
        state: "found",
        path: installations[0]?.path,
        installations,
      },
      broker: brokerState(env),
      warnings,
    });
  }

  return result({
    exitCode: EXIT_COMPATIBLE,
    binary: {
      state: "found",
      path: installations[0]?.path,
      installations,
    },
    broker: brokerState(env),
    warnings,
  });
}

function brokerState(env: Readonly<Record<string, string | undefined>>): EnsureResult["broker"] {
  const socket = env.CHARADE_SOCKET?.trim();
  if (!socket) return { state: "absent" };
  // Probing is added with the broker. Until then, a configured socket is
  // reported as configured, never as reachable.
  return { state: "configured", socket };
}

function result(input: {
  exitCode: number;
  binary: EnsureResult["binary"];
  broker: EnsureResult["broker"];
  warnings: readonly string[];
}): EnsureResult {
  return {
    schema: "charade.ensure/1",
    exitCode: input.exitCode,
    binary: input.binary,
    broker: input.broker,
    doors: DOORS,
    warnings: input.warnings,
  };
}
