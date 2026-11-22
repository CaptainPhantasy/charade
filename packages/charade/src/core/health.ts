/**
 * Health is liveness plus honest readiness. A required check that did not run
 * is never reported as healthy.
 */
export type CheckStatus =
  | "pass"
  | "fail"
  | "warn"
  | "skipped"
  | "not_applicable"
  | "unknown";

export type HealthOverall = "ok" | "degraded" | "broken" | "unknown";

export interface HealthCheck {
  readonly id: string;
  readonly required: boolean;
  readonly status: CheckStatus;
  readonly summary: string;
  readonly remedy?: string;
}

export interface HealthReport {
  readonly overall: HealthOverall;
  readonly checks: readonly HealthCheck[];
  /** Required checks that did not produce a pass or fail. */
  readonly unknowns: readonly string[];
}

const NON_DECISIVE: ReadonlySet<CheckStatus> = new Set([
  "skipped",
  "not_applicable",
  "unknown",
]);

export function aggregateHealth(checks: readonly HealthCheck[]): HealthReport {
  if (checks.length === 0) {
    return { overall: "unknown", checks, unknowns: [] };
  }

  let requiredFailure = false;
  let requiredUnknown = false;
  let optionalProblem = false;

  for (const check of checks) {
    if (check.required && check.status === "fail") {
      requiredFailure = true;
      continue;
    }
    if (check.required && NON_DECISIVE.has(check.status)) {
      requiredUnknown = true;
      continue;
    }
    if (!check.required && (check.status === "fail" || check.status === "warn" || NON_DECISIVE.has(check.status))) {
      optionalProblem = true;
    }
  }

  const unknowns = checks
    .filter((check) => check.required && NON_DECISIVE.has(check.status))
    .map((check) => check.id);

  if (requiredFailure) {
    return { overall: "broken", checks, unknowns };
  }
  if (requiredUnknown) {
    return { overall: "unknown", checks, unknowns };
  }
  if (optionalProblem) {
    return { overall: "degraded", checks, unknowns };
  }
  return { overall: "ok", checks, unknowns };
}
