import { existsSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { aggregateHealth, type CheckStatus, type HealthCheck } from "../core/health.js";
import { PRODUCT_VERSION, protocolString } from "../core/version.js";
import { verifyGrant } from "../authority/grants.js";
import { loadGrants, loadPolicy, verifyStoredPolicy, policyPath } from "../authority/store.js";
import { loadRegistry, registryPath } from "../registry/registry.js";
import { verifyReceipts } from "../audit/receipts.js";
import { openVault, vaultPaths, VaultError } from "../vault/vault.js";
import { probeHealth } from "./broker.js";
import { USAGE } from "./usage.js";
import { passphraseFrom, takeFlag, takeOption, usageError } from "./util.js";

interface DoctorCheck extends HealthCheck {
  readonly detail?: string;
}

export async function doctorCommand(args: string[]): Promise<void> {
  const home = takeOption(args, "--home");
  const json = takeFlag(args, "--json");
  const socketArg = takeOption(args, "--socket");
  const passphraseFile = takeOption(args, "--passphrase-file");
  if (!home) usageError("doctor: --home <dir> is required", USAGE);
  const socket = socketArg ?? join(home, "broker.sock");

  const checks: DoctorCheck[] = [];

  // Runtime floor: the package declares node >= 22.
  const major = Number(process.versions.node.split(".")[0]);
  checks.push({
    id: "runtime",
    required: true,
    status: Number.isInteger(major) && major >= 22 ? "pass" : "fail",
    summary:
      Number.isInteger(major) && major >= 22
        ? `node ${process.versions.node} meets the floor of 22`
        : `node ${process.versions.node} is below the required 22`,
    ...(Number.isInteger(major) && major >= 22
      ? {}
      : { remedy: "install Node.js 22 or newer" }),
  });

  // Vault file and permissions, plus an unlock attempt when a passphrase exists.
  const paths = vaultPaths(home);
  if (!existsSync(paths.vault)) {
    checks.push({
      id: "vault",
      required: true,
      status: "fail",
      summary: "vault file is missing",
      remedy: "run `charade init --home <dir>`",
    });
  } else {
    const mode = statSync(paths.vault).mode & 0o777;
    checks.push({
      id: "vault-file",
      required: true,
      status: mode === 0o600 ? "pass" : "fail",
      summary: mode === 0o600 ? "vault file is 0600" : `vault file mode is ${mode.toString(8)}`,
      ...(mode === 0o600 ? {} : { remedy: "chmod 600 the vault file" }),
    });
    const passphrase = await optionalPassphrase(args, passphraseFile);
    if (passphrase === undefined) {
      checks.push({
        id: "vault-unlock",
        required: true,
        status: "skipped",
        summary: "vault unlock was not attempted (no passphrase supplied)",
        remedy: "pass --passphrase-file with mode 0600 to check the vault",
      });
    } else {
      try {
        openVault(home, passphrase);
        checks.push({ id: "vault-unlock", required: true, status: "pass", summary: "vault unlocks" });
      } catch (error) {
        checks.push({
          id: "vault-unlock",
          required: true,
          status: "fail",
          summary: `vault did not unlock: ${error instanceof VaultError ? error.message : "unknown error"}`,
          remedy: "retype the passphrase; use the recovery kit if it is lost",
        });
      }
    }
  }

  // Owner policy signature.
  checks.push(
    verifyStoredPolicy(home)
      ? { id: "policy", required: true, status: "pass", summary: "owner policy signature verifies" }
      : {
          id: "policy",
          required: true,
          status: "fail",
          summary: existsSync(policyPath(home))
            ? "owner policy is present but its signature does not verify"
            : "owner policy is missing",
          remedy: "run `charade policy init --home <dir>` and accept the policy",
        },
  );

  // Registry.
  let registryOk = false;
  let registrySummary = "registry is missing, empty, or invalid";
  try {
    const registry = loadRegistry(registryPath(home));
    registryOk = true;
    registrySummary = `registry is valid: ${registry.services.length} services, ${registry.consumers.length} consumers, ${registry.devices.length} devices`;
  } catch (error) {
    registrySummary = error instanceof Error ? error.message : registrySummary;
  }
  checks.push({
    id: "registry",
    required: true,
    status: registryOk ? "pass" : "fail",
    summary: registrySummary,
    ...(registryOk ? {} : { remedy: "run `charade registry add-service` and `charade registry validate`" }),
  });

  // Grants: signatures are checked against the stored policy.
  try {
    const grants = loadGrants(home);
    if (grants.length === 0) {
      checks.push({
        id: "grants",
        required: false,
        status: "warn",
        summary: "no grants are signed; no lease can be issued",
        remedy: "run `charade grant create` for each consumer",
      });
    } else {
      const policy = loadPolicy(home);
      const now = new Date();
      const invalid = grants.filter((grant) => !verifyGrant(policy, grant, now).ok);
      const expired = grants.filter((grant) => verifyGrant(policy, grant, now).ok && new Date(grant.expiresAt) <= now);
      checks.push({
        id: "grants",
        required: true,
        status: invalid.length === 0 ? "pass" : "fail",
        summary:
          invalid.length === 0
            ? `${grants.length} grants verify (${expired.length} expired)`
            : `${invalid.length} of ${grants.length} grants do not verify`,
        ...(invalid.length === 0 ? {} : { remedy: "re-sign the affected grants or revoke them" }),
      });
    }
  } catch {
    checks.push({
      id: "grants",
      required: true,
      status: "fail",
      summary: "grant store is unreadable",
      remedy: "inspect grants.json; no lease is issued until it is valid",
    });
  }

  // Receipt chain.
  const receiptsPath = join(home, "receipts.jsonl");
  if (!existsSync(receiptsPath)) {
    checks.push({
      id: "receipts",
      required: true,
      status: "pass",
      summary: "no receipts recorded yet; there is nothing to verify",
    });
  } else {
    const verification = verifyReceipts(receiptsPath);
    checks.push({
      id: "receipts",
      required: true,
      status: verification.ok ? "pass" : "fail",
      summary: verification.ok
        ? `receipt chain is intact: ${verification.count} records`
        : `receipt chain is broken at record ${verification.brokenAt ?? "unknown"}`,
      ...(verification.ok ? {} : { remedy: "restore the receipt log from a verified backup" }),
    });
  }

  // Live broker: liveness only, never dependency detail, because /health is unauthenticated.
  try {
    const probe = await probeHealth(socket);
    checks.push({
      id: "broker",
      required: false,
      status: probe.status === 200 ? "pass" : "warn",
      summary: `broker answered /health with ${probe.status} (ready=${String(probe.body.ready)})`,
      ...(probe.status === 200
        ? {}
        : { remedy: "run `charade doctor` after the reported dependency is fixed, or start the broker" }),
    });
    checks.push(tcpCheck(socket));
  } catch {
    checks.push({
      id: "broker",
      required: false,
      status: "skipped",
      summary: `no broker is listening at ${socket}`,
      remedy: "start it with `charade broker serve --home <dir>`",
    });
    checks.push({ id: "listeners", required: false, status: "skipped", summary: "no broker to inspect" });
  }

  // Telemetry is a build-time property and is reported as the `telemetry` field.

  const report = aggregateHealth(checks);
  const failed = checks.some((check) => check.status === "fail");
  // 3 means "a required check could not run", never "assume it passed".
  const unknown = report.overall === "unknown" || report.unknowns.length > 0;
  const exitCode = failed ? 1 : unknown ? 3 : 0;

  if (json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          schema: "charade.doctor/1",
          version: PRODUCT_VERSION,
          protocol: protocolString(),
          node: process.versions.node,
          platform: `${process.platform} ${process.arch}`,
          home,
          socket,
          telemetry: false,
          overall: report.overall,
          checks,
          exit: exitCode,
        },
        null,
        2,
      )}\n`,
    );
  } else {
    process.stdout.write(`CHARADE doctor — ${PRODUCT_VERSION} (protocol ${protocolString()})\n`);
    process.stdout.write(`home:   ${home}\n`);
    process.stdout.write(`socket: ${socket}\n`);
    process.stdout.write(`state:  ${report.overall}\n\n`);
    for (const check of checks) {
      process.stdout.write(`  ${symbol(check.status)} ${check.id}: ${check.summary}\n`);
      if (check.remedy && check.status !== "pass") {
        process.stdout.write(`      next: ${check.remedy}\n`);
      }
    }
    process.stdout.write("\n");
  }

  process.exitCode = exitCode;
}

function symbol(status: CheckStatus): string {
  switch (status) {
    case "pass":
      return "pass   ";
    case "fail":
      return "FAIL   ";
    case "warn":
      return "warn   ";
    case "skipped":
      return "skipped";
    case "unknown":
      return "unknown";
    case "not_applicable":
      return "n/a    ";
  }
}

/** Best-effort check that the broker holds no TCP listener. */
function tcpCheck(socket: string): DoctorCheck {
  let listing: string;
  try {
    listing = execFileSync("lsof", ["-nP", "-U"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return {
      id: "listeners",
      required: false,
      status: "skipped",
      summary: "lsof is unavailable, so TCP listeners were not inspected",
    };
  }

  const pids = new Set<string>();
  for (const line of listing.split("\n")) {
    if (!line.includes(socket)) continue;
    const pid = line.trim().split(/\s+/)[1];
    if (pid && /^\d+$/.test(pid)) pids.add(pid);
  }
  if (pids.size === 0) {
    return {
      id: "listeners",
      required: false,
      status: "skipped",
      summary: "could not identify the broker process holding the socket",
    };
  }

  const offending: string[] = [];
  for (const pid of pids) {
    let tcp: string;
    try {
      tcp = execFileSync("lsof", ["-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
    } catch {
      continue; // lsof exits 1 when nothing matches: no TCP listener.
    }
    if (tcp.split("\n").some((line) => line.trim().length > 0)) offending.push(pid);
  }

  return offending.length === 0
    ? {
        id: "listeners",
        required: false,
        status: "pass",
        summary: "broker holds a Unix socket and no TCP listener",
      }
    : {
        id: "listeners",
        required: false,
        status: "fail",
        summary: `broker process ${offending.join(", ")} holds a TCP listener`,
        remedy: "stop the broker; standalone mode must not listen on TCP",
      };
}

async function optionalPassphrase(args: string[], file: string | undefined): Promise<string | undefined> {
  if (file) return passphraseFrom(args, file);
  if (!process.stdin.isTTY) return undefined;
  return passphraseFrom(args, undefined);
}
