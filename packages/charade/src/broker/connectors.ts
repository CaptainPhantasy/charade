import type { HardStop } from "../core/protocol.js";
import type { ServiceRecord } from "../registry/registry.js";

export type ActionClass = "read" | "write" | "destructive";

export interface ActionDecision {
  readonly class: ActionClass | "unknown";
  readonly stop?: HardStop;
}

const HARD_STOPS: ReadonlySet<string> = new Set([
  "money",
  "publish",
  "send",
  "delete",
  "permissionChange",
]);

/**
 * Patterns are owner-accepted at service registration:
 *   read/write:   "GET /v1/*"
 *   destructive:  "send POST /messages/*"
 * Unknown methods or paths are denied; nothing is read-classified by default.
 */
export function classifyAction(
  service: ServiceRecord,
  method: string,
  path: string,
): ActionDecision {
  const upper = method.toUpperCase();
  for (const pattern of service.actions.destructive) {
    const parsed = parsePattern(pattern, true);
    if (parsed && parsed.method === upper && glob(parsed.path, path)) {
      return { class: "destructive", stop: parsed.stop as HardStop };
    }
  }
  for (const pattern of service.actions.write) {
    const parsed = parsePattern(pattern, false);
    if (parsed && parsed.method === upper && glob(parsed.path, path)) {
      return { class: "write" };
    }
  }
  for (const pattern of service.actions.read) {
    const parsed = parsePattern(pattern, false);
    if (parsed && parsed.method === upper && glob(parsed.path, path)) {
      return { class: "read" };
    }
  }
  return { class: "unknown" };
}

export interface AuthInjection {
  readonly headers: Record<string, string>;
  readonly url: URL;
}

export function injectAuth(
  service: ServiceRecord,
  secretValue: string,
  headers: Record<string, string>,
  url: URL,
): AuthInjection {
  const auth = service.auth;
  if (auth.type === "header") {
    const name = auth.name ?? "Authorization";
    headers[name] = auth.template
      ? auth.template.replace(/\$\{[^}]+\}/g, secretValue)
      : secretValue;
    return { headers, url };
  }
  if (auth.type === "basic") {
    const name = auth.name ?? "Authorization";
    headers[name] = auth.template
      ? auth.template.replace(/\$\{[^}]+\}/g, secretValue)
      : `Basic ${Buffer.from(secretValue, "utf8").toString("base64")}`;
    return { headers, url };
  }
  if (auth.type === "query") {
    url.searchParams.set(auth.name ?? "api_key", secretValue);
    return { headers, url };
  }
  throw new Error("oauth2 connectors are not implemented in this build");
}

export function authSupported(service: ServiceRecord): boolean {
  return service.auth.type !== "oauth2";
}

function parsePattern(
  pattern: string,
  destructive: boolean,
): { readonly stop?: string; readonly method: string; readonly path: string } | undefined {
  const parts = pattern.trim().split(/\s+/);
  if (destructive) {
    if (parts.length !== 3) return undefined;
    const [stop, method, path] = parts;
    if (!stop || !HARD_STOPS.has(stop) || !method || !path) return undefined;
    return { stop, method: method.toUpperCase(), path };
  }
  if (parts.length !== 2) return undefined;
  const [method, path] = parts;
  if (!method || !path) return undefined;
  return { method: method.toUpperCase(), path };
}

function glob(pattern: string, value: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`).test(value);
}
