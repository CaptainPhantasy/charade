#!/usr/bin/env node
/**
 * Import boundaries. The security core stays small and cannot reach I/O.
 * Run from the repo root as `npm run check:imports`.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));
const failures = [];

const CORE = new Set(["node:crypto", "node:buffer"]);
const VAULT = new Set([
  "node:fs",
  "node:path",
  "node:crypto",
  "node:child_process",
  "node:os",
  "node:buffer",
]);
const KEYRING = new Set(["node:fs", "node:path", "node:crypto", "node:os", "node:buffer"]);
const AUTHORITY = new Set(["node:crypto", "node:buffer", "node:fs", "node:path"]);
const REGISTRY = new Set(["node:fs", "node:path", "node:crypto", "node:buffer"]);
const AUDIT = new Set(["node:fs", "node:path", "node:crypto", "node:buffer"]);
const ENSURE = new Set(["node:fs", "node:path", "node:http", "node:net"]);
const BROKER = new Set([
  "node:http",
  "node:net",
  "node:tls",
  "node:fs",
  "node:path",
  "node:crypto",
  "node:stream",
  "node:events",
  "node:url",
  "node:buffer",
  "node:zlib",
  "node:string_decoder",
]);

function walk(dir) {
  const out = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (full.endsWith(".ts")) out.push(full);
  }
  return out;
}

function specifiers(source) {
  const found = [];
  const patterns = [
    /(?:import|export)\s[^'"]*?from\s*["']([^"']+)["']/g,
    /import\s*\(\s*["']([^"']+)["']\s*\)/g,
    /require\(\s*["']([^"']+)["']\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) found.push(match[1]);
  }
  return found;
}

function allowedFor(rel) {
  if (rel.includes("packages/charade/src/core/")) return { set: CORE, allowRelative: "core" };
  if (rel.includes("packages/charade/src/vault/")) return { set: VAULT, allowRelative: "vault" };
  if (rel.includes("packages/charade/src/keyring/")) return { set: KEYRING, allowRelative: "keyring" };
  if (rel.includes("packages/charade/src/authority/")) return { set: AUTHORITY, allowRelative: "authority" };
  if (rel.includes("packages/charade/src/registry/")) return { set: REGISTRY, allowRelative: "registry" };
  if (rel.includes("packages/charade/src/audit/")) return { set: AUDIT, allowRelative: "audit" };
  if (rel.includes("packages/charade/src/broker/")) return { set: BROKER, allowRelative: "broker" };
  if (rel.includes("packages/charade/src/cli/")) return { set: null, allowRelative: "cli" };
  if (rel.includes("packages/charade-ensure/src/")) return { set: ENSURE, allowRelative: "ensure" };
  if (rel.includes("packages/charade-tui/src/")) return { set: null, allowRelative: "tui" };
  return { set: null, allowRelative: "unknown" };
}

for (const file of walk(join(root, "packages"))) {
  const rel = relative(root, file);
  const { set, allowRelative } = allowedFor(rel);
  const source = readFileSync(file, "utf8");
  for (const specifier of specifiers(source)) {
    if (specifier.startsWith(".")) {
      if ((allowRelative === "core" || allowRelative === "ensure") && specifier.includes("../")) {
        failures.push(`${rel}: ${specifier} leaves the ${allowRelative} boundary`);
      }
      continue;
    }
    if (specifier.startsWith("node:")) {
      if (set && !set.has(specifier)) {
        failures.push(`${rel}: ${specifier} is outside the ${allowRelative} import boundary`);
      }
      continue;
    }
    if (allowRelative === "tui") {
      if (specifier === "react" || specifier === "ink" || specifier.startsWith("ink-")) continue;
      failures.push(`${rel}: unexpected TUI dependency "${specifier}"`);
      continue;
    }
    failures.push(`${rel}: external dependency "${specifier}" is not allowed here`);
  }
}

if (failures.length) {
  console.error("imports: FAIL");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log("imports: PASS — security core has no I/O or external dependencies");
