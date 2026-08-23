# Wallet Lifecycle

> **Status: design + prototype.** The TypeScript protocol package implements
> the state transitions below over local state; the on-chain enforcement
> (KeymeshWallet contract) is a skeleton with execution disabled.

## States of a device

```
            authorizeDevice
  (absent) ────────────────► authorized
                               │    │
              revokeDevice     │    │ wallet recovery completes
                   ▼           │    ▼
              revoked          │  authorized (replacement device)
                                │
                                └──► revoked
```

- `authorized` devices may request transactions and sign authorizations.
- `revoked` devices lose all authority immediately and cannot be un-revoked;
  a replacement must be newly authorized.
- Revocation is the primary response to device loss or compromise.

## Wallet creation

1. User generates a device keypair locally (SDK boundary: key generation is
   delegated to a reviewed crypto provider — never implemented in-app).
2. The KeymeshWallet contract is deployed; the first device is authorized.
3. A default policy is installed:
   - normal transfers → device only
   - high-value transfers → device + guardian quorum
   - guardian/policy management → quorum + timelock
   - recovery → threshold + timelock
4. Guardians are registered with weights.

**Prototype note:** until contracts ship, the SDK creates wallets with a
deterministic placeholder address (`0x000…000`). This is asserted in tests on
purpose so no one mistakes it for a usable address.

## Device authorization & revocation

- Adding a device requires owner authority (Phase 1: existing-device signature
  plus policy timelock for management actions).
- Revocation is immediate — there is deliberately no delay on revocation, so a
  user who notices a stolen device can cut it off instantly.
- A wallet must always retain at least one authorized device path OR an active
  recovery to remain operable; losing all devices without guardians means
  relying entirely on recovery.

## Recovery as the safety net

If all devices are lost, recovery re-establishes control:

```
initiate (new device) → guardian approvals reach threshold
                      → timelock window elapses
                      → new device authorized
```

Details in [recovery.md](recovery.md).

## Invariants

1. A revoked device's signatures are invalid from the revocation timestamp
   onward (enforced by nonce/timestamp checks at verification time).
2. Guardian set changes cannot be performed by a single device alone once the
   default policy is active.
3. The SDK never sees private keys; devices hold their own keys and expose
   only signatures through the `Signer` interface.
