# Recovery Protocol

> **Status: Phase 1.2 IMPLEMENTED on-chain and end-to-end verified.**
> Guardian registration, quorum-gated recovery requests, approvals,
> cancellation, a mandatory timelock, and atomic device replacement are
> enforced by `RecoveryManager` + `GuardianRegistry` + `KeymeshWallet` and
> driven by `@keymesh/sdk`. The Rust core (`crates/keymesh-core/src/recovery`)
> is the reference semantics; the TypeScript protocol package exposes the same
> on-chain domain types (`packages/protocol/src/recovery-onchain.ts`). All
> three carry tests.

## Why recovery exists

Devices are lost and stolen. KeyMesh treats recovery as a first-class protocol
operation rather than a seed-phrase backup: control is re-established through
guardian consensus plus a mandatory delay, not through a secret written on
paper.

## Authority separation (critical invariant)

```
Normal transactions          Device ECDSA over KEYMESH_TX_V1 -> KeymeshWallet.execute

Device-set changes           Guardians -> quorum -> timelock -> RecoveryManager
                             -> KeymeshWallet.applyRecoveredDevice
```

- Guardians **cannot sign normal transactions**; their only powers are to
  initiate and approve recoveries of their own wallet.
- Devices cannot approve recoveries; they can initiate and cancel them.
- No account can both move funds directly and govern recovery. This keeps the
  future TSS/MPC signing layer (which replaces single-device signing) fully
  independent from the recovery governance layer.

## State machine

Implemented exactly in all three languages (Solidity enum discriminants 0..5
match the Rust/TS constants):

```
                 initiateRecovery(newDevice)
        ┌────────┐ ────────────────────────────► ┌─────────┐
        │  None  │                               │ Pending │◄─┐
        └────────┘                               └─────────┘  │ re-initiate after
             ▲                                        │        │ terminal state
             │                              quorum    ▼        │ (fresh id, no
             │                              reached ┌─────────────────┐
             │                                      │  QuorumReached  │
             │                                      └─────────────────┘
             │                     block.timestamp >= executeAfter
             │                                      │      │       │
             │                                      │      │       │ cancel()
             │                              finalize│      │       ▼
             │                                      ▼      │  ┌───────────┐
             │                               ┌────────────┐│  │ Cancelled │
             │                               │ Executable ││  └───────────┘
             │                               └────────────┘│       ▲
             │                                 │      ▲    │ cancel()│
             │                          finalize│      │────┘         │
             │                                 ▼      └──────────────┘
             │                            ┌──────────┐
             └────────────────────────────│ Executed │   (terminal)
                                          └──────────┘
```

| State | Allowed actions | Forbidden actions | Transitions out |
| ----- | --------------- | ----------------- | --------------- |
| `None` | initiate | approve/cancel/finalize | → Pending |
| `Pending` | approve, cancel | initiate (one per wallet), finalize | → QuorumReached, Cancelled |
| `QuorumReached` | cancel | approve, initiate, finalize (timelock running) | → Executable, Cancelled |
| `Executable` | finalize, cancel | approve, initiate | → Executed, Cancelled |
| `Executed` | initiate (new request) | everything else | — |
| `Cancelled` | initiate (new request) | everything else | — |

Notes:

- `QuorumReached → Executable` is materialized lazily when
  `block.timestamp >= executeAfter` (**inclusive boundary**, matching the
  wallet's transaction-expiry rule). Views report the effective status.
- Terminal states keep their record on-chain under their id (auditable) but
  reject every action; a fresh initiation gets a NEW globally-unique id and
  starts approvals from zero. Stale approvals can never revive an old request.
- Requests snapshot the wallet's configured quorum and timelock at initiation;
  later configuration changes never weaken an in-flight recovery.

## Steps

### 0. Bootstrap (once)

The wallet's deployer-chosen `manager` calls
`bootstrapRecoveryGovernance(wallet, guardians[], quorum, timelockSeconds)`:

- Registers the initial unweighted guardian set (nonzero, unique addresses).
- Stores the quorum (`1 <= quorum <= guardian count`) and timelock
  (`>= MIN_TIMELOCK = 1 hour`; suggested default 24h) as the wallet's
  configuration.
- Calls `KeymeshWallet.initializeRecoveryGovernance()`, which **permanently
  retires the manager's authority** over devices
  (`ManagerAuthorityRetired` on every manager path afterwards). There is no
  manager backdoor once initialized — proven by tests.

Trust assumption: whoever holds the bootstrap manager key at deployment time
can choose the first guardians and must do so before initializing governance.
After initialization the role has zero power. Before initialization the
manager is, by definition, the wallet's temporary owner — document your
deployment ceremony accordingly.

### 1. Initiation

`initiateRecovery(wallet, replacedDevice, newDevice)` opens the single allowed
request per wallet. Authorized initiators:

- any **active guardian** of that wallet, or
- any currently **authorized device** of that wallet.

Everyone else reverts (`NotGuardianOrDevice`) — including retired managers and
guardians of *other* wallets. Constraints validated at initiation:

- `newDevice != 0`, `newDevice` not already authorized, `newDevice != replacedDevice`.
- `replacedDevice` (optional): if nonzero it must be currently authorized;
  `address(0)` models total loss of all devices (finalization then adds the
  replacement without revoking anything).
- Active guardian count must still satisfy the configured quorum.

Creating a request **never modifies the device set** — asserted by tests.

### 2. Guardian approvals

Active guardians call `approveRecovery(wallet)`; each approval is recorded
once per request id (`DuplicateApproval` otherwise). Non-guardians, guardians
of other wallets, and removed guardians revert. When distinct approvals reach
the snapshotted quorum, the timelock arms:
`executeAfter = now + timelockSnapshot`.

### 3. Timelock

A public warning period. Finalization before `executeAfter` reverts with
`TimelockNotElapsed`. The duration is ONE well-defined parameter per wallet
(configurable via device-signed `setRecoveryTimelock`, minimum
`MIN_TIMELOCK`); nothing hardcodes "24 hours".

Authorized devices may cancel at ANY live state (pending, quorum reached, or
executable-but-unexecuted). Guardians cannot cancel — a single compromised
guardian must not be able to grief honest recoveries; dissenting guardians
express disapproval by simply not approving.

### 4. Finalization

`finalizeRecovery(wallet)` is permissionless (any funded relayer may submit):
authorization was complete before the timelock even started. It atomically
applies to the wallet:

1. authorize `newDevice`,
2. revoke `replacedDevice` (when nonzero),
3. mark the request `Executed`.

Any failure (e.g. the replaced device was revoked mid-flight) reverts the
entire finalization including state changes — no partial updates. Afterwards
the old device's signatures fail (`UnauthorizedDevice`), the new device signs
normally, and replaying `finalizeRecovery` reverts forever.

## Guardian management after bootstrap

The device-holder controls who guards their wallet through normal signed
transactions routed via `KeymeshWallet.execute` to the RecoveryManager:

- `addGuardian(wallet, guardian)` / `removeGuardian(wallet, guardian)`
- `setQuorum(wallet, q)` (future requests), `setRecoveryTimelock(wallet, s)`

Edge case (documented, accepted): devices may remove guardians below the
configured quorum, which makes future initiations revert (`UnsatisfiableQuorum`)
until the quorum is lowered or guardians are restored. An active request is
unaffected (snapshot semantics); it can simply be cancelled.

## Attack scenarios and where they fail

| Scenario | Outcome |
| -------- | ------- |
| Stolen device | Owner/guardian opens recovery replacing it; stolen device revoked at finalization. Until then the stolen key retains normal-signing power (Phase limitation, see security-model). |
| Compromised single guardian | Cannot approve twice, cannot cancel others' recoveries, cannot move funds, cannot affect other wallets. |
| Compromised guardians up to quorum−1 | Quorum never reached; request inert until cancelled. |
| Quorum colluding guardians | Timelock forces a ≥ MIN_TIMELOCK public warning window; authorized devices can cancel until execution. |
| Attacker self-initiates recovery | Only reaches execution if enough real guardians approve AND nobody cancels during the window. Creating a request authorizes nothing. |
| Replay of a finalized recovery | Second `finalizeRecovery` reverts (`InvalidStateTransition(Executed)`); ids are never reused. |
| Cross-wallet replay/approval | Requests, guardians, and approvals are strictly per-wallet/per-id; tests prove wallet A actors cannot touch wallet B. |
| Premature execution | `TimelockNotElapsed` before `executeAfter` (inclusive boundary tested at exact equality). |
| Manager bypass after initialization | Every manager path reverts `ManagerAuthorityRetired`; tested. |

## Gas & storage notes

- Approvals use per-request mappings keyed by global monotonic ids; no approval
  lists are stored, so cancel/finalize never iterate over guardians.
- GuardianRegistry keeps a registration-order array for view enumeration with
  swap-and-pop removal (O(1) writes); iteration happens only in views/tests.
- Bootstrap validates guardian uniqueness with a bounded O(n²) check (n =
  initial guardian count, a one-time administrative action).

## Test coverage map

| Behavior | Rust | TS | Solidity |
| ---------------------------------------- | ---- | -- | -------- |
| pending → quorum → executable promotion  | ✅   | ✅ | ✅       |
| duplicate approval rejected              | ✅   | ✅ | ✅       |
| non-guardian / removed-guardian rejection| n/a* | ✅ | ✅       |
| completion blocked pre-timelock          | ✅   | ✅ | ✅       |
| inclusive timelock boundary              | ✅   |    | ✅       |
| cancellation from all live states        | ✅   | ✅ | ✅       |
| terminal states reject transitions       | ✅   | ✅ | ✅       |
| zero threshold rejected                  | ✅   | ✅ | ✅       |
| 1-of-1 / 2-of-3 / 3-of-5 quorums         | ✅†  | ✅† | ✅      |
| new device authorized / old revoked      | ✅   |    | ✅       |
| atomic revert on mid-flight revocation   |      |    | ✅       |
| old device cannot sign post-recovery     |      |    | ✅       |
| cross-wallet isolation                   |      |    | ✅       |
| manager bypass impossible post-bootstrap |      |    | ✅       |

\* The Rust core is guardian-set agnostic; registration checks belong to the
caller layer.
† Via parameterized configurations rather than fixed-size fixtures.
