# CHARADE Threat Model

**Status:** Draft for owner acceptance
**Scope:** v0.1 standalone and member modes

---

## 1. Assets

1. Stored credential values.
2. Owner authority: the Ed25519 private key, the signed policy, and signed grants.
3. Device keys and member certificates.
4. The receipt chain and its anchors.
5. Availability of long-running work.
6. The owner's reputation: no false claims of success or safety.

## 2. Adversaries

| Adversary | Capability | What Charade does |
|---|---|---|
| Same-user process or agent | Can read user files, connect to the socket, inspect memory with debugger rights | Values never enter consumer context; device-bound sessions; receipts; dedicated OS user recommended for always-on nodes |
| Stolen token or lease | Has a bearer secret but not the device key | Leases are short, pinned, hashed at rest, and device-bound; a stolen token without the device key cannot open a session |
| Malicious or compromised upstream | Controls responses to a connector | Only declared auth is injected; redirects refused or re-authorized; response bodies never become authority |
| Prompt injection in page content | Asks the agent to exfiltrate a value | The agent never holds the value on the proxy path; inject is one-use and origin-bound |
| Network attacker (member mode) | Can observe or alter traffic | TLS 1.3 with mutual authentication; SPKI pin in the join token; certificate revocation by device |
| Theft of a backup or removable drive | Has the encrypted vault file | AES-256-GCM at rest; key custody in the OS store or passphrase; recovery kit separate |
| Compromised broker host | Runs as the broker user | Cannot mint authority without the owner key; can proxy under existing grants until revoked; residual risk stated |
| Accidental misconfiguration | Wrong path, empty registry, missing policy | Fail loud and refuse leases; no permissive defaults |
| Provider-side revocation | Invalidates the old key immediately | Overlap cannot be forced on a provider; the TUI states it before approval |

## 3. Trust boundaries

- **Owner boundary:** the human, the owner key, and the local confirmation surface.
- **Consumer boundary:** any registered tool or agent. It holds a device key and a
  session, never a stored value on the default path.
- **Broker boundary:** the only process that resolves values. It runs as a
  dedicated user on always-on nodes.
- **Upstream boundary:** the service the credential belongs to. It is reached only
  through a connector with a declared auth shape.
- **Member boundary:** a member holds a device certificate and no vault.

## 4. In scope

- Credential confidentiality on the default proxy path.
- Owner authority over limits, grants, and hard stops.
- Device binding and instant revocation of new requests.
- Honest health and receipts.
- Crash consistency and recovery of the vault.
- Read-only keyring discovery with no value output.
- No telemetry or hidden egress.

## 5. Out of scope (stated, not hidden)

1. A process running as the same OS user with debugger or memory-inspection rights.
2. A compromised operating system, hypervisor, or firmware.
3. A malicious page reading a value the owner deliberately typed into it.
4. A child process that receives a value through an explicit env exception and then
   prints it.
5. Screenshots taken by the operating system of other windows.
6. Provider-side account limits, spend, and revocation behavior.
7. Coverage of Keychain items, browser password stores, process environments, ACLs,
   or memory by the keyring locator.
8. JavaScript string copies surviving in memory; Buffers are zeroed where possible.
9. Swap and core dumps.
10. A stolen owner key together with its passphrase.

## 6. Residual risks and mitigations

| Risk | Mitigation |
|---|---|
| Same-user read of the vault or custody item | Passphrase-first defaults; dedicated broker user; auto-unlock is an explicit owner choice with a warning |
| Linux Secret Service absent | `secret-tool` is required for that adapter; the exact package command is printed; passphrase fallback is explicit |
| macOS Keychain prompt automation | `expect` answers the `security` prompt from a 0600 temp file; the key is never in argv. Live set/get/delete was verified in Step 2. |
| Env exception pressure during migration | Single use, 300-second maximum, local socket only, receipted, counted on the dashboard |
| In-flight request during revocation | Bounded by the connector timeout and receipted; new requests stop immediately |
| Receipt durability vs latency | Two-phase receipts and group commit; integrity is reported, never assumed |
| Removable-drive-only repository | Add a git remote and CI in Step 1; the drive is a working copy, not the only copy |

## 7. Claims Charade will not make

- "No secret can ever leak." The default path is strict; exceptions and the
  out-of-scope list above remain.
- "The keyring finds every secret." It covers files matching its pattern set under
  explicit roots; coverage is printed.
- "Revocation stops an in-flight request instantly." It stops new requests; the
  bounded in-flight request completes and is receipted.
- "Rotation is always seamless." It is seamless only if the provider keeps the old
  key valid during the overlap.
- "Health means the service is working." Health means the components it checked are
  working; unchecked upstreams are reported as not checked.
