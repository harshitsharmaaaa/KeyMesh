# Recovery Protocol

> **Status: design + prototype.** Implemented as pure state machines in
> `crates/keymesh-core/src/recovery` (Rust, reference) and mirrored in
> `packages/protocol/src/recovery` (TypeScript) and
> `contracts/ethereum/src/RecoveryManager.sol` (skeleton). All three carry
> tests for the transitions below.

## Why recovery exists

Devices are lost and stolen. KeyMesh treats recovery as a first-class protocol
operation rather than a seed-phrase backup: control is re-established through
guardian consensus plus a mandatory delay, not through a secret written on
paper.

## State machine

```
                 initiateRecovery(newDevice)
        ┌────────┐ ─────────────────────────────► ┌─────────────────┐
        │  None  │                                │     Pending     │
        └────────┘                                └─────────────────┘
             ▲                                     │           │
             │                          threshold  │           │ cancel()
             │                          reached    ▼           │
             │                        ┌───────────────────┐      │
             │                        │  TimelockActive    │◄─────┘
             │                        └───────────────────┘
             │                             │          │
   complete() after timelock      complete() early│ cancel()
             │                             │          │
             ▼                             ▼          ▼
        ┌───────────┐                (reverts)   ┌───────────┐
        │ Completed │                              │ Cancelled │
        └───────────┘                              └───────────┘
```

Any non-terminal state can also transition to `Expired` (validity window).

## Steps

### 1. Initiation

A recovery request names the **new device** that will be authorized. Initiation
is currently permissionless in the contract skeleton (**TODO phase-1**:
restrict to owner/wallet devices); the state machine is already enforced.

Constraints:

- One active recovery per wallet.
- Timelock duration ≥ `MIN_TIMELOCK` (7 days).
- Required weight must be satisfiable by the registered guardian set.

### 2. Guardian approvals

Active guardians approve with their registry weight. Rules:

- Duplicate approvals are idempotent no-ops.
- Unregistered guardians are rejected (`NotRegisteredGuardian`).
- Approvals accumulate until `approvalsWeight >= requiredWeight`, at which
  point the timelock starts.

### 3. Timelock

The timelock is a public warning period:

- It starts only when the quorum is reached.
- Completion before it elapses reverts (`TimelockNotElapsed`).
- Any active guardian (phase 1: also owner devices) may cancel during the
  window — this is the mechanism that defeats hostile colluding guardians,
  provided at least one honest guardian observes the recovery in time.

### 4. Completion

After the timelock elapses, completion authorizes the new device on the wallet
(contract call wired in Phase 1). The recovery record becomes terminal.

## Cancelling

Cancellation resets the process; a new initiation collects approvals from
scratch. There is no "partial credit" across attempts, preventing an attacker
from slowly assembling a quorum across cancelled attempts.

## Test coverage map

| Behavior                          | Rust | TS | Solidity |
| --------------------------------- | ---- | -- | -------- |
| pending → timelock at threshold   | ✅   | ✅ | ✅       |
| duplicate approval no-op          | ✅   | ✅ | ✅       |
| unregistered guardian rejection   | n/a* | ✅ | ✅       |
| completion blocked pre-timelock   | ✅   | ✅ | ✅       |
| cancellation from active states   | ✅   | ✅ | ✅       |
| terminal states reject transitions| ✅   | ✅ | ✅       |
| zero threshold rejected           | ✅   | ✅ | ✅       |

\* The Rust core is guardian-set agnostic; registration checks belong to the
caller layer.
