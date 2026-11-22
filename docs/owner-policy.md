# Owner Policy and Authority

## 1. Why cryptographic authority

Configuration alone cannot distinguish "the owner chose this limit" from "a default
or an agent chose it." Charade makes authority cryptographic: the owner holds an
Ed25519 keypair, signs the policy and every grant, and the broker only verifies.
A compromised broker can use existing grants but cannot mint a new one or change a
limit.

## 2. Key generation

`charade init` generates:

- a 32-byte owner private key (Ed25519 seed);
- the corresponding public key;
- a passphrase-derived key-encryption key using scrypt with
  `N=2^15, r=8, p=1, maxmem=64 MiB`;
- an encrypted owner-key slot in the vault.

The public key is written to `state/owner.pub` and into the vault header. The
private key never leaves the vault slot unencrypted and never enters an environment
variable, log, receipt, or TUI state.

## 3. Policy signing

1. Build the policy object with the `signature` field absent.
2. Canonicalize it with the rules in `protocol.md` §2.1.
3. Sign `charade-owner-policy-v1\0` + canonical JSON with Ed25519.
4. Append the base64url signature.
5. Store `policyHash = sha256(canonical JSON)`.

The broker verifies the signature against `ownerPublicKey` and checks that the
policy hash matches the grants it is asked to honor.

## 4. Grant signing

Each grant is signed the same way with the prefix `charade-grant-v1\0`. A grant
without a valid signature, a matching policy hash, and a future `expiresAt` is
inert.

## 5. Changes and revocation

- Policy changes are signed, receipted, and re-presented to the owner for
  acceptance.
- Grant revocation is immediate for new requests; in-flight requests are bounded by
  the connector timeout and receipted.
- Owner-key compromise: the owner creates a new keypair, signs a new policy, and
  revokes every grant. The old key is recorded as revoked in the receipt chain.
- Loss of the owner key: the recovery kit unlocks the vault; the owner creates a new
  key and re-signs the policy. Existing grants remain invalid until re-signed.

## 6. What the broker cannot do

- Create or alter a policy.
- Create or alter a grant.
- Disable a hard stop.
- Approve an env exception.
- Enroll a member or a consumer without an owner signature.
- Claim that a default is owner-accepted when no receipt exists.

## 7. What the owner must do

- Keep the passphrase and recovery kit separate.
- Review the policy at first run; do not accept a group of defaults without reading.
- Re-sign after a policy change.
- Confirm hard-stop actions at the moment they happen.
