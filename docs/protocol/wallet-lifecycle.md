# Wallet Lifecycle

> **Status: Phase 1.1 implemented on-chain + prototype local state.** Device
> authorization, signature-verified execution, nonce, and expiry are enforced
> by the `KeymeshWallet` contract and driven by the SDK. Guardian/policy
> wiring remains design-stage; steps below say which is which.

## States of a device (on-chain: `KeymeshWallet`)

```
             registerDevice
  (absent) ────────────────► authorized
                               │    │
              revokeDevice     │    │ future recovery completion
                   ▼           │    ▼
              revoked          │  authorized (replacement device)
                               │
                               └──► revoked
```

- `authorized` devices may sign canonical transaction digests; the wallet
  executes only those. `msg.sender` is irrelevant — any relayer can submit.
- `revoked` devices lose all authority immediately and cannot be un-revoked;
  a replacement must be newly registered.
- Registration is manager-gated in Phase 1 (transitional control held by the
  deployer account). Revocation is allowed for the manager OR the device
  itself, so a device holder can cut their own key off. The last remaining
  device cannot be removed (keeps the wallet operable).
- A wallet must always retain at least one authorized device path OR an active
  recovery to remain operable; losing all devices without guardians means
  relying entirely on recovery.

## Wallet creation (implemented)

1. User generates a device keypair locally with an audited library
   (@noble/curves via viem accounts today).
2. The `KeymeshWallet` contract is deployed; the constructor pre-authorizes
   the first device (`Deploy.s.sol` takes `INITIAL_DEVICE_ADDRESS`).
3. Transaction authorization policy (Phase 1.1): every executed call needs one
   registered-device signature over the canonical digest. Class-based policy
   (high-value → guardian quorum) is future work via PolicyManager.
4. Guardians are not yet wired to the wallet on-chain.

## Execution rules (enforced by `execute()`)

All checks happen before any state change or external call:

1. `wallet == address(this)` and `chainId == block.chainid` (explicit domain
   binding — cross-wallet/cross-chain signatures fail loudly).
2. `block.timestamp <= expiry` (inclusive boundary: a transaction may execute
   at exactly its expiry second, not after).
3. `nonce == next expected` (strictly sequential; no gaps, no reuse).
4. Signature recovers over the canonical digest AND the recovered signer is a
   currently-registered device.
5. Only then: nonce increments, external call runs, `TransactionExecuted`
   emits. A failing target reverts the whole execution — including the nonce
   bump — so the signed request stays retryable until it succeeds or expires,
   mirroring how a dropped Ethereum transaction keeps its nonce.

## Recovery as the safety net (design-stage on-chain)

If all devices are lost, recovery re-establishes control:

```
initiate (new device) → guardian approvals reach threshold
                      → timelock window elapses
                      → new device authorized
```

Details in [recovery.md](recovery.md). The Rust/TS state machines exist and
are tested; the Solidity side is not yet connected to `KeymeshWallet`.

## Invariants

1. A revoked device's signatures fail from the revocation onward (checked at
   execution time against live device state).
2. Every signed digest binds wallet, chainId, and nonce — replay across any
   of these dimensions fails validation.
3. The SDK never persists private keys; keys are passed per-session by the
   embedding application (see security model for current caveats).
