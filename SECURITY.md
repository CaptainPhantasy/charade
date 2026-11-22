# Security Policy

## Status

CHARADE is pre-alpha. Do not use it for real credentials yet.

## Reporting a vulnerability

Report privately to the owner. Do not open a public issue with a secret, a token, a
hostname, or an exploit against a live system. Include the version, the platform,
the smallest reproduction, and the request ID or receipt ID if one exists. No secret
value is needed to report a problem; never paste one.

## What Charade protects

- Stored values at rest, encrypted with AES-256-GCM and OS or passphrase custody.
- Values on the default path, where the broker injects them and the consumer never
  receives them.
- Owner authority, through an Ed25519-signed policy and signed grants. There is no
  static admin token.
- Device-bound sessions and leases; a stolen token without the device key is not
  enough.
- An append-only, hash-chained receipt for every use.

## What Charade does not protect

See [docs/threat-model.md](docs/threat-model.md) for the full list. The short form:

- A process running as the same OS user with debugger or memory access.
- A compromised host or operating system.
- A malicious page reading a value the owner deliberately typed into it.
- A child process that receives a value through an explicit env exception and then
  prints it.
- Screenshots taken by the operating system of other windows.
- Keychain items, browser stores, process environments, ACLs, or memory that the
  keyring locator does not scan.
- Provider-side account limits, spend, and revocation behavior.

When Charade does not know something, it says so. A skipped check is not a pass.

## No telemetry

Charade has no analytics, no crash reporting, no update check, and no phone-home.
Outbound traffic exists only through a connector the owner has enabled. The build
runs a static no-telemetry check; the test suite adds runtime proofs.

## Supported versions

None are supported yet. The first supported release will be 0.1.0.
