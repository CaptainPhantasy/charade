#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const EXPECTED = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";
const root = fileURLToPath(new URL("../..", import.meta.url));
const license = readFileSync(join(root, "LICENSE"));
const actual = createHash("sha256").update(license).digest("hex");

if (actual !== EXPECTED) {
  console.error(`license: FAIL — Apache-2.0 canonical hash mismatch`);
  console.error(`  expected ${EXPECTED}`);
  console.error(`  actual   ${actual}`);
  process.exit(1);
}

for (const entry of readdirSync(join(root, "packages"), { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const copy = join(root, "packages", entry.name, "LICENSE");
  if (!existsSync(copy)) {
    console.error(`license: FAIL — packages/${entry.name}/LICENSE is missing`);
    process.exit(1);
  }
  const hash = createHash("sha256").update(readFileSync(copy)).digest("hex");
  if (hash !== EXPECTED) {
    console.error(`license: FAIL — packages/${entry.name}/LICENSE differs from the root`);
    process.exit(1);
  }
}

console.log("license: PASS — Apache-2.0 canonical text in root and packages");
