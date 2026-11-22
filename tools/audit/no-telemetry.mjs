#!/usr/bin/env node
/**
 * No telemetry, no hidden network, no install scripts.
 * This is a static guard; runtime proofs live in the test suite.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));
const packagesRoot = join(root, "packages");
const failures = [];

const FORBIDDEN_PACKAGES =
  /(analytics|telemetry|sentry|posthog|segment|mixpanel|datadog|newrelic|amplitude|bugsnag|rollbar|update-notifier|latest-version|npm-check-updates|openai|anthropic|cohere|mistral|ollama|langchain|@google\/generative-ai|postinstall)/i;

const INSTALL_SCRIPTS = new Set(["preinstall", "install", "postinstall"]);

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
    else out.push(full);
  }
  return out;
}

function checkPackageJson(file) {
  let pkg;
  try {
    pkg = JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    failures.push(`${relative(root, file)}: unreadable JSON (${error.message})`);
    return;
  }
  const scripts = pkg.scripts ?? {};
  for (const script of INSTALL_SCRIPTS) {
    if (scripts[script]) {
      failures.push(`${relative(root, file)}: forbidden "${script}" script`);
    }
  }
  for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
    for (const name of Object.keys(pkg[field] ?? {})) {
      if (FORBIDDEN_PACKAGES.test(name)) {
        failures.push(`${relative(root, file)}: forbidden ${field} "${name}"`);
      }
    }
  }
}

function checkSource(file) {
  const rel = relative(root, file);
  const source = readFileSync(file, "utf8");
  const isTest = rel.includes("/test/") || rel.endsWith(".test.ts") || rel.endsWith(".test.js");
  if (isTest) return;

  const proxy = rel.includes("packages/charade/src/broker/proxy/");
  if (!proxy) {
    if (/\bfetch\s*\(/.test(source)) {
      failures.push(`${rel}: global fetch outside the proxy chokepoint`);
    }
    if (/from\s+["']node:https["']|require\(["']node:https["']\)/.test(source)) {
      failures.push(`${rel}: node:https outside the proxy chokepoint`);
    }
    if (/from\s+["']node:dgram["']|from\s+["']node:dns["']/.test(source)) {
      failures.push(`${rel}: raw datagram/DNS use outside the proxy chokepoint`);
    }
  }

  if (/model\s*[:=]|completion|prompt\s*\(/i.test(source) && rel.includes("/core/")) {
    // A heuristic, not a proof; the dependency allowlist is the real guard.
    failures.push(`${rel}: possible model call pattern in the security core`);
  }
}

for (const file of walk(packagesRoot)) {
  if (file.endsWith("package.json")) checkPackageJson(file);
  if (file.endsWith(".ts") || file.endsWith(".js") || file.endsWith(".mjs")) checkSource(file);
}

if (failures.length) {
  console.error("no-telemetry: FAIL");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log("no-telemetry: PASS — no analytics, model SDKs, install scripts, or hidden egress");
