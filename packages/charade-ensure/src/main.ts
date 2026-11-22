#!/usr/bin/env node
import { detectCharade } from "./detect.js";

const json = process.argv.includes("--json");
const result = detectCharade();

if (json) {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} else {
  process.stdout.write("CHARADE ensure\n\n");
  process.stdout.write(`binary: ${result.binary.state}${result.binary.path ? ` (${result.binary.path})` : ""}\n`);
  process.stdout.write(`broker: ${result.broker.state}${result.broker.socket ? ` (${result.broker.socket})` : ""}\n`);
  for (const warning of result.warnings) {
    process.stdout.write(`warning: ${warning}\n`);
  }
  process.stdout.write("\nDoors:\n");
  for (const door of result.doors) {
    process.stdout.write(`  ${door.id}: ${door.title}\n    ${door.why}\n`);
    for (const command of door.commands) {
      process.stdout.write(`    $ ${command}\n`);
    }
  }
  process.stdout.write("\nNo installation was attempted. Nothing was changed.\n");
}

process.exitCode = result.exitCode;
