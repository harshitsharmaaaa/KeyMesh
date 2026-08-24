# Wallet Lifecycle

> **Status: Phases 1.1 + 1.2 implemented on-chain.** Device authorization,
> signature-verified execution, nonce, expiry, guardian-governed device
> replacement, and bootstrap-only manager authority are enforced by the
> contracts and driven by the SDK. Transaction-policy enforcement remains
> design-stage; steps below say which is which.

## States of a device (on-chain: `KeymeshWallet`)

```
             registerDevice            applyRecoveredDevice (via RecoveryManager)
  (absent) ──────────────► authorized ◄──────────────────┐
                               │    │                    │
              revokeDevice     │    │ guardian quorum +  │ new device authorized,
              OR self-revoke   │    │ timelock           │ replaced device revoked
                               ▼    ▼                    │
                            revoked ─────────────────────┘ (old slot)
```

- `authorized` devices may sign canonical transaction digests; the wallet
  executes only those. `msg.sender` is irrelevant — any relayer can submit.
- `revoked` devices lose all authority immediately and cannot be un-revoked;
  a replacement must arrive through a fresh recovery or registration.
- A wallet may hold MULTIPLE devices simultaneously. Recovery replaces exactly
  one device slot (`replacedDevice → newDevice`); `replacedDevice = 0` models
  total loss of all devices (pure addition). The last-device guard applies to
  self/manager revocation, never to recovery application (which authorizes
  before revoking inside one atomic call).

## Who controls the device set

| Phase | Authority |
| ----- | --------- |
| Before recovery governance is initialized | The deployer-chosen `manager` (BOOTSTRAP-ONLY role) may register/revoke devices; devices may always revoke themselves. |
| After `initializeRecoveryGovernance()` | ONLY the RecoveryManager, via `applyRecoveredDevice`, which itself requires guardian quorum + elapsed timelock. Every manager path reverts `ManagerAuthorityRetired` — permanently, by construction (tested). |

## Wallet creation (implemented)

1. User generates a device keypair locally with an audited library
   (@noble/curves via viem accounts today).
2. The stack is deployed: `RecoveryManager` (which constructs its own
   `GuardianRegistry`) then `KeymeshWallet(manager, initialDevice,
   recoveryManager)`; the constructor pre-authorizes the first device.
3. The manager bootstraps recovery governance ONCE: initial guardians,
   quorum (≥ 1), timelock (≥ 1h; suggested 24h) — this also retires the
   manager's own authority. See [recovery.md](recovery.md).
4. Transaction authorization policy (Phase 1.1): every executed call needs one
   registered-device signature over the canonical digest. Class-based policy
   (high-value ⇒ guardian quorum) is future work via PolicyManager (Phase 1.3).

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
   bump — so the signed request stays retryable until it succeeds or expires.

The same signed path is reused for governance: a device signs a transaction
whose target is the RecoveryManager (`addGuardian`, `setQuorum`, …); the
wallet verifies the signature first, then forwards the call with
`msg.sender == wallet` as proof of device authority.

## Recovery as the safety net (implemented)

If a device is lost/stolen — or ALL of them are — recovery re-establishes
control:

```
initiate (guardian or device) → guardian approvals reach quorum snapshot
                              → timelock window elapses (public warning)
                              → finalize: authorize replacement (+ revoke replaced)
```

Full state machine, authority rules, cancellation semantics, attack scenarios:
[recovery.md](recovery.md).

## Invariants

1. A revoked device's signatures fail from revocation onward (checked at
   execution time against live device state).
2. Every signed digest binds wallet, chainId, and nonce — replay across any
   of these dimensions fails validation.
3. Creating or approving a recovery request never changes the device set;
   only finalization does, atomically.
4. After initialization there is NO account that can both move funds directly
   and change the device set.
5. The SDK never persists private keys; keys are passed per-session by the
   embedding application (see security model for current caveats).
