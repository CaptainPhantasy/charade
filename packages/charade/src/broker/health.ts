import { aggregateHealth, type HealthCheck, type HealthReport } from "../core/health.js";
import type { OwnerPolicy } from "../core/protocol.js";
import type { Registry } from "../registry/registry.js";
import { authSupported } from "./connectors.js";

export interface BrokerHealthInput {
  readonly vaultOk: boolean;
  readonly policy?: OwnerPolicy;
  readonly policyError?: string;
  readonly registry?: Registry;
  readonly registryError?: string;
  readonly grantsOk: boolean;
  readonly grantsError?: string;
  readonly receiptsOk: boolean;
  readonly receiptsError?: string;
}

export function brokerHealth(input: BrokerHealthInput): HealthReport {
  const checks: HealthCheck[] = [
    {
      id: "vault",
      required: true,
      status: input.vaultOk ? ("pass" as const) : ("fail" as const),
      summary: input.vaultOk ? "vault is unlocked" : "vault is locked",
      ...(input.vaultOk ? {} : { remedy: "unlock the vault in the Admin TUI or with `charade unlock`" }),
    },
    {
      id: "policy",
      required: true,
      status: input.policy ? ("pass" as const) : ("fail" as const),
      summary: input.policy ? "owner policy is signed" : "owner policy is missing or invalid",
      ...(input.policy && !input.policyError ? {} : { remedy: "run `charade policy init` and accept the policy" }),
    },
    {
      id: "registry",
      required: true,
      status: input.registry ? ("pass" as const) : ("fail" as const),
      summary: input.registry ? "registry is readable" : "registry is missing, empty, or invalid",
      ...(input.registry ? {} : { remedy: "run `charade registry validate` and fix the reported field" }),
    },
    {
      id: "grants",
      required: true,
      status: input.grantsOk ? ("pass" as const) : ("fail" as const),
      summary: input.grantsOk ? "grant store is readable" : "grant store is unreadable or invalid",
      ...(input.grantsOk ? {} : { remedy: "inspect the grant store; no leases are issued" }),
    },
    {
      id: "receipts",
      required: true,
      status: input.receiptsOk ? ("pass" as const) : ("fail" as const),
      summary: input.receiptsOk ? "receipt chain is intact" : "receipt chain is broken",
      ...(input.receiptsOk ? {} : { remedy: "restore the receipt log from a verified backup" }),
    },
  ];

  if (input.registry) {
    for (const service of input.registry.services) {
      checks.push({
        id: `connector:${service.id}`,
        required: false,
        status: authSupported(service) ? ("pass" as const) : ("warn" as const),
        summary: authSupported(service)
          ? `connector ${service.id} is supported`
          : `connector ${service.id} uses an unsupported auth type`,
        ...(authSupported(service)
          ? {}
          : { remedy: "change the service auth type or wait for oauth2 support" }),
      });
    }
  }

  return aggregateHealth(checks);
}

export function brokerReady(report: HealthReport): boolean {
  return report.overall === "ok" || report.overall === "degraded";
}
