# CHARADE

**An open-source, telemetry-free secret platform.**

CHARADE is a vault, a proxy-first secret broker, a read-only keyring locator, and an
Admin TUI. It is built for every tool on the machine: agents, CLIs, scripts, CI,
browsers, and whatever comes next. TownMouse is not a dependency; it is at most one
late consumer.

> **Status: pre-alpha.** The repository is at Step 1 of the construction plan. It
> builds and tests, but it is not installable and does not yet store a credential.
> Nothing here should be used for real secrets yet.

## Principles

- The owner sets every limit and gate. No LLM, vendor, or default decides without
  the owner's choice to accept or deny.
- Values never enter an agent's context, environment, logs, transcripts, or
  screenshots on the default path. The proxy injects at the last hop.
- Grants are long and owner-set; leases are short and renew automatically. Work does
  not stop because a credential expired.
- Health is honest: a check that did not run is not a pass, and a broken dependency
  is never reported as healthy.
- No telemetry, no update check, no phone-home.

## Repository

```text
packages/charade/          core, broker, CLI, keyring (zero runtime deps)
packages/charade-ensure/   detection shim for other releases (zero deps)
packages/charade-tui/      Ink Admin TUI (added in Step 7)
docs/                      protocol, threat model, defaults, owner policy, ADRs, brand
tools/audit/               license, import-boundary, and no-telemetry guards
```

## Development

```bash
npm install --ignore-scripts
npm run check
```

`npm run check` verifies the Apache-2.0 license hash, import boundaries, the
no-telemetry guard, the build, and the tests. Requires Node.js 22 or newer.

## Documentation

- [Protocol v1](docs/protocol.md)
- [Threat model](docs/threat-model.md)
- [Defaults — proposed, not applied](docs/defaults.md)
- [Owner policy and authority](docs/owner-policy.md)
- [Brand](docs/brand.md)

## License

Apache-2.0. The canonical text is pinned by SHA-256 in `tools/audit/license.mjs`.
