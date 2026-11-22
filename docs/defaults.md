# CHARADE Defaults — Proposed, Not Applied

Every security-relevant default below is **proposed**. None takes effect until the
owner accepts it during `charade init` or changes it in the Admin TUI. Acceptance is
recorded as a signed policy receipt with the policy hash. Any later change is
re-presented; nothing is silently tightened or loosened.

| Area | Proposed default | Owner decision |
|---|---|---|
| Owner policy duration | 24 hours per grant | pending |
| Maximum grant duration | 7 days | pending |
| Lease TTL | 120 seconds; maximum 300 seconds | pending |
| Renewal point | Two-thirds of TTL; old token valid until original expiry | pending |
| Rotation overlap | 15 minutes (provider permitting) | pending |
| Env exception | Single use, 300 seconds maximum, local socket only | pending |
| Vault unlock | Passphrase; no automatic unlock | pending |
| OS custody | macOS Keychain or Linux Secret Service only after an explicit warning | pending |
| Auto-unlock on always-on nodes | Off by default; Keychain opt-in with a typed warning | pending |
| Hard stops | Money, publishing, sending, deleting, permission changes all on | pending |
| Unknown action class | Deny | pending |
| New consumer | Owner approval | pending |
| Member enrollment | Owner approval; mTLS required | pending |
| Remote admin | Off; local socket only | pending |
| Session idle / absolute | 15 minutes / 8 hours | pending |
| Receipt retention | 365 days; encrypted backups follow the vault | pending |
| Telemetry | Forbidden | pending |
| Update check | Never without explicit owner action | pending |
| Keyring roots | Current user's home only | pending |
| Keyring all-homes scan | Off; explicit `--all-homes` with a privacy warning | pending |
| Keyring value hints | Off in agent output; owner may request a hint | pending |
| TUI color | Monochrome-first; accent opt-in | pending |
| TUI motion | Off by default; header mascot only | pending |
| Plain TUI mode | Available; every action also exists as a CLI command | pending |
| Node floor | 22 | pending |
| Package scope | `@floydslabs/charade` (owner must confirm publish rights) | pending |

## Acceptance record

For each row, the owner chooses **Accept**, **Change**, or **Deny**. A denial means
the capability is unavailable, not that it runs with a hidden fallback. The accepted
set is signed into `owner-policy.json`; the signature covers the canonical JSON of
the whole policy.

## Defaults that are not negotiable

These are product invariants, not policy values:

- No static admin token.
- No telemetry or phone-home.
- No silent fallback to an empty registry, a permissive default, or a healthy
  status when a required check did not run.
- No LLM in v0.1.
- The owner's hard stops cannot be disabled by an agent or a vendor default.
