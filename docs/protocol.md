# CHARADE Protocol v1

**Status:** Draft, frozen for implementation
**Version:** 1.0
**Scope:** the contract between the broker, the CLI/TUI, consumers, and members

---

## 1. Principles

1. The owner is the only source of authority. The broker verifies authority; it
   cannot mint it.
2. Values never travel on the default path. The proxy injects them at the last hop.
   The environment exception is explicit, single-use, and receipted.
3. One writer owns state. The broker is the only process that writes the vault,
   grants, leases, receipts, and counters.
4. A missing or unreadable input is a denial, never a permissive default.
5. Every decision and every use produces a receipt.
6. Health is liveness plus honest readiness. A check that did not run is not a pass.

---

## 2. Transport

| Mode | Transport | Identity |
|---|---|---|
| Standalone | HTTP/1.1 over a Unix domain socket, `0600`, parent directory `0700` | Device key, then a short session token |
| Member | HTTP/1.1 over TLS 1.3 with mutual authentication | Device certificate + device key |
| Remote admin | mTLS with an owner-role device, plus an owner signature per action | Owner key + device certificate |

Default socket paths:

- Linux: `$XDG_RUNTIME_DIR/charade/broker.sock`
- macOS: `~/Library/Application Support/Charade/run/broker.sock`
- Override: `CHARADE_SOCKET`; if the path exceeds the platform `sun_path` limit,
  the broker refuses to start and asks for a shorter `CHARADE_SOCKET_DIR`.

Standalone mode binds **no TCP listener**. There is no silent TCP fallback.

Every response carries `X-Charade-Protocol: 1.0` and echoes
`X-Charade-Request-Id`. An unsupported major version returns HTTP `426` with
`charade.protocol_mismatch` and the supported version.

### 2.1 Canonical JSON

Signatures and hashes use canonical JSON:

- object keys sorted lexicographically;
- only null, booleans, strings, integers, arrays, and plain objects;
- finite integers only; floats, NaN, and Infinity are rejected;
- undefined object properties are omitted; undefined array entries are rejected;
- cycles are rejected.

The signature field is removed before canonicalization and appended after
verification. Domain-separation prefixes prevent cross-protocol reuse:

```text
charade-owner-policy-v1\0
charade-grant-v1\0
charade-session-v1\0<nonce>\0<deviceId>
```

---

## 3. Authority

### 3.1 Owner key and policy

`charade init` generates an Ed25519 owner keypair. The private key is encrypted
under a passphrase-derived key in a vault slot. The public key is stored in the
vault header and in `state/owner.pub`.

`owner-policy.json` is signed by the owner and loaded at broker start. If it is
missing, unsigned, corrupt, or expired, the broker starts but is **not ready** and
refuses grants and leases (`charade.owner_policy_missing`). An unsigned default is
inert.

Policy shape:

```json
{
  "schema": "charade.owner-policy/1",
  "policyVersion": 1,
  "ownerPublicKey": "base64url-ed25519",
  "limits": {
    "defaultGrantDurationSeconds": 86400,
    "maxGrantDurationSeconds": 604800,
    "defaultLeaseTtlSeconds": 120,
    "maxLeaseTtlSeconds": 300,
    "rotationOverlapSeconds": 900,
    "envExceptionMaxTtlSeconds": 300,
    "receiptRetentionDays": 365,
    "sessionIdleSeconds": 900,
    "sessionAbsoluteSeconds": 28800
  },
  "gates": {
    "hardStops": {
      "money": true,
      "publish": true,
      "send": true,
      "delete": true,
      "permissionChange": true
    },
    "newConsumers": "owner-approval",
    "memberEnrollment": "owner-approval",
    "rotation": "owner-or-agent-request",
    "envExceptions": "owner-per-use",
    "updateCheck": "never-without-consent",
    "telemetry": "forbidden"
  },
  "custody": { "autoUnlock": "passphrase" },
  "signature": "base64url-ed25519"
}
```

The policy hash is SHA-256 over canonical JSON without `signature`. Every grant
records the policy hash it was issued under. Tightening the policy takes effect at
grant verification and lease issuance without silently rewriting existing grants.

### 3.2 Sessions

`POST /v1/session/challenge` returns a nonce and challenge ID. The client signs the
domain-separated challenge with its device key (consumer) or owner key (owner) and
posts `POST /v1/session` with the challenge ID, signature, and device ID. The
broker verifies and returns a 32-byte session token, held in client memory only.

- Idle timeout: policy `sessionIdleSeconds` (default 15 minutes).
- Absolute maximum: policy `sessionAbsoluteSeconds` (default 8 hours).
- Admin mutations require a fresh typed confirmation for hard-stop classes.
  Non-interactive admin writes are refused.
- There is no static admin token, no admin-token file, and no admin-capable
  environment variable.

### 3.3 Devices and members

A consumer is enrolled once by the owner. Enrollment returns a one-time token; the
client generates a device keypair and proves possession on every session. A copied
token without the device key cannot open a session.

Member enrollment uses a single-use join token (10 minutes) containing the broker's
SPKI pin. The member generates a device key, receives a client certificate signed by
the broker CA, and never receives the vault. Revocation is by device ID and takes
effect for new requests immediately; in-flight requests are bounded by the connector
timeout and receipted.

---

## 4. Grants and leases

### 4.1 Grant

A grant is owner-signed and scoped:

```json
{
  "schema": "charade.grant/1",
  "grantId": "gr_...",
  "consumerId": "c_...",
  "deviceId": "d_...",
  "services": ["deepseek"],
  "methods": ["GET", "POST"],
  "paths": ["/anthropic/*"],
  "issuedAt": "2026-11-21T00:00:00Z",
  "expiresAt": "2026-11-22T00:00:00Z",
  "ceilings": { "callsPerDay": 2000 },
  "hardStops": { "money": true, "publish": true, "send": true, "delete": true, "permissionChange": true },
  "envAllowed": false,
  "policyHash": "sha256:...",
  "signature": "base64url-ed25519"
}
```

No grant exists until the owner accepts the offer and signs it. Duration presets are
1 hour, 8 hours, 24 hours, 7 days, and until revoked; the policy sets the maximum.

### 4.2 Lease

A lease is broker-issued under a valid grant:

- default TTL 120 seconds, maximum 300 seconds (policy);
- pinned to consumer, device, grant, services, methods, paths, and the exact secret
  version IDs at issue time;
- token is 32 random bytes; only its SHA-256 hash is stored;
- the lease record is durable before the token is returned.

### 4.3 Renewal and retry

- The client renews at two-thirds of TTL.
- Renewal returns a new token; the old token remains valid until its original
  expiry (bounded grace).
- An expired lease returns `charade.lease_expired` with `renewable: true`.
- The client may re-issue under the still-valid grant and retry **only idempotent
  requests**. Non-idempotent requests fail with `lease_expired_no_retry`; the
  caller decides.
- A broker restart does not end work: grants and leases are durable, sessions are
  re-established from the device key, and the unlock policy determines service.

### 4.4 Rotation

1. A consumer may propose a rotation; the proposal contains no value and changes no
   state.
2. The owner approves and supplies the new value through a masked prompt.
3. The broker writes the new version as `pending`, validates it with the connector's
   bounded read-only probe when available, then promotes it to `active`.
4. The old version becomes `previous` with `overlapUntil`.
5. New leases pin the new version; existing leases keep the old version until expiry
   or the overlap deadline.
6. Retired versions are removed from the vault payload on the next write; Buffers
   are zeroed where the runtime allows.

Charade's overlap is Charade-side only. A provider that invalidates the old key
immediately cannot be smoothed over; the TUI says so before approval.

---

## 5. Endpoints

### 5.1 Unauthenticated

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness and coarse readiness only: `{alive, ready, protocol, overall}`. No paths, counts, versions, or dependency names. HTTP 503 when not ready. |
| POST | `/v1/session/challenge` | Nonce for owner or consumer session; rate-limited. |

### 5.2 Consumer session

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/session` | Exchange a signed challenge for a session token |
| DELETE | `/v1/session` | Revoke own session |
| GET | `/v1/health` | Checks that affect this consumer's path |
| GET | `/v1/catalog` | Only the services this consumer may use |
| POST | `/v1/leases` | Issue a lease under a grant |
| POST | `/v1/leases/:id/renew` | Renew; rotate the token |
| POST | `/v1/leases/:id/revoke` | Self-revoke |
| `/v1/proxy/:service/*` | Proxy request; connector injects; receipt returned |
| POST | `/v1/rotations` | Propose a rotation (no value, no state change) |
| GET | `/v1/receipts` | This consumer's receipts |

### 5.3 Owner session

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/admin/consumers` | Create a consumer and one-time enrollment token |
| GET/DELETE | `/v1/admin/consumers/:id` | List/revoke |
| POST | `/v1/admin/devices/:id/revoke` | Revoke a device |
| POST/GET | `/v1/admin/grants` | Create/list owner-signed grants |
| POST | `/v1/admin/grants/:id/revoke` | Instant revocation |
| POST | `/v1/admin/kill` | Revoke sessions/leases for one consumer or all; typed confirmation |
| POST | `/v1/admin/rotations/:id/approve` | Apply a rotation; typed confirmation |
| POST | `/v1/admin/env-exceptions` | Create a single-use env exception; typed confirmation |
| GET | `/v1/admin/receipts[/:id]` | Bounded receipt queries |
| POST | `/v1/admin/receipts/verify` | Verify the hash chain |
| GET | `/v1/admin/health` | Full owner health report |
| GET | `/v1/events` | Owner SSE stream with `Last-Event-ID` replay |
| GET | `/v1/snapshot` | Resync snapshot |

### 5.4 Env exception

`POST /v1/env` is not a general endpoint. It requires:

- a consumer session;
- a lease whose grant has `envAllowed: true`;
- a single-use owner-created env exception;
- a local Unix socket connection (never a member or remote connection);
- a maximum TTL of 300 seconds;
- a receipt for creation and for use;
- `Cache-Control: no-store`.

The response contains only the named values, and the receipt records the names, not
the values.

### 5.5 Proxy

`/v1/proxy/:service/<remaining-path>?<query>` preserves the existing broker's
compatibility shape. The broker:

- verifies the lease names the same service;
- strips any client `Authorization` header;
- injects only the connector's declared auth;
- classifies the request into `read`, `write`, or `destructive` and enforces hard
  stops before any upstream work;
- resolves DNS once and pins it for the request;
- refuses redirects to undeclared origins and strips credentials on every hop;
- streams SSE/chunked responses without buffering;
- refuses WebSocket upstreams with `unsupported_transport` in v0.1;
- writes a durable `proxy.attempt` receipt before the upstream call and a
  `proxy.complete` receipt after.

---

## 6. Receipts

Every action produces a receipt: grant creation and revocation, lease issue, renew,
and revoke, every proxy attempt and completion, rotation proposal and approval, env
exception creation and use, keyring discovery and adoption proposals, session
creation and failure, device revocation, policy changes, and health break/recovery.

Receipts contain no values, request bodies, auth headers, or full upstream
responses. They form a SHA-256 hash chain; a signed daily anchor is written under
`state/receipts/anchors/`. Startup verifies the chain head against the last anchor
and reports `receipts_integrity: broken` if truncated.

Members queue signed receipts and forward them in bounded batches when online. The
broker verifies and appends them with `origin: member`. Queue depth is visible in
doctor and never silently lost.

---

## 7. Health

| Surface | Audience | Contents |
|---|---|---|
| `/health` | Unauthenticated | `alive`, `ready`, `protocol`, `overall` only |
| `/v1/health` | Consumer session | Checks affecting that consumer's path |
| `/v1/admin/health` | Owner session | Full component report |

Check statuses: `pass`, `fail`, `warn`, `skipped`, `not_applicable`, `unknown`.
Overall: `ok` only if all required checks pass; `degraded` if optional checks fail;
`broken` if any required check fails; `unknown` if any required check was skipped or
unknown without an owner-accepted justification.

Required checks include vault unlock, registry readable and parsing, owner policy
valid, grants store valid, receipts writable and chain valid, disk space, socket
permissions, clock sanity, and the device revocation store. Upstream reachability
is **not** checked on health (that would be hidden egress); it is `not_checked`
unless the owner runs `charade doctor --check-upstreams`.

A missing, empty, unparsable, or schema-invalid registry is `broken`; new leases are
refused and in-flight leases continue until expiry. There is no empty-registry
fallback.

---

## 8. Errors

Every error returns `code`, `whatHappened`, `whatNext`, `ownerOnly`, `retriable`,
and where available `requestId` and `receiptId`. The catalog lives in
`packages/charade/src/core/errors.ts`.

Notable codes:

- `charade.owner_policy_missing`
- `charade.owner_required`
- `charade.vault_locked`
- `charade.registry_unreadable`
- `charade.registry_invalid`
- `charade.grant_missing`
- `charade.grant_expired`
- `charade.grant_revoked`
- `charade.scope_denied`
- `charade.lease_expired`
- `charade.device_mismatch`
- `charade.device_revoked`
- `charade.action_denied`
- `charade.action_unknown`
- `charade.env_not_granted`
- `charade.protocol_mismatch`
- `charade.integrity_broken`

---

## 9. Versioning

The protocol major version changes only for an incompatible break. Minor versions
add capabilities; peers must ignore unknown response fields and refuse unknown
required request fields. The broker advertises the protocol on every response and in
`/health`. A mismatch is reported before any state change.
