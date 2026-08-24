# KeyMesh Architecture Overview

> **Status: Phases 1.1-1.3 implemented** — two real end-to-end paths
> (device-signed transactions AND guardian-quorum timelocked recovery with
> device replacement) plus prototype scaffolding for everything else.
> Components are labeled by maturity; nothing here is production-ready or
> audited.

## What is KeyMesh?

KeyMesh is a non-custodial protocol for digital-asset key management,
transaction authorization, and account recovery. Instead of a single private
key (lost = funds lost, stolen = funds gone), control over a wallet is shared
across:

- **Devices** — user-controlled endpoints that authorize everyday activity.
- **Guardians** — trusted parties whose weighted approvals unlock sensitive
  operations and recovery.
- **Policies** — on-chain rules deciding how much authorization each action
  class needs.
- **Timelocks** — mandatory delay windows that make hostile recoveries visible
  and cancellable.

The user always retains ultimate custody. Guardians can approve or reject;
they can never move funds directly.

## Layered structure

```
┌────────────────────────────────────────────────────────────┐
│ apps/dashboard        Next.js UI — no crypto, SDK only     │
├────────────────────────────────────────────────────────────┤
│ packages/sdk          Public API facade over the protocol  │
├────────────────────────────────────────────────────────────┤
│ packages/protocol     Domain models + state machines (TS)  │
│ packages/types        Shared primitives (hex, results)     │
├────────────────────────────────────────────────────────────┤
│ crates/keymesh-core   Security-critical core (Rust):       │
│                       recovery FSM, policy eval, canonical │
│                       serialization, crypto BOUNDARY       │
├────────────────────────────────────────────────────────────┤
│ contracts/ethereum    On-chain enforcement (Foundry):      │
│                       KeymeshWallet, GuardianRegistry,     │
│                       RecoveryManager, PolicyManager       │
└────────────────────────────────────────────────────────────┘
```

### Dependency rules

1. The dashboard imports `@keymesh/sdk` only — never `@keymesh/protocol`
   internals, and never cryptographic or authorization logic.
2. The SDK depends on `@keymesh/protocol` and `@keymesh/types`; nothing
   depends upward.
3. `crates/keymesh-core` has one hash dependency (`tiny-keccak`) so it can
   produce byte-identical canonical digests; asymmetric crypto stays behind
   the `CryptoProvider` trait (mock only today).
4. Contracts depend on OpenZeppelin (ECDSA, ReentrancyGuard) and forge-std;
   both are audited and pinned as git submodules.
5. The canonical transaction format is defined once
   ([protocol/canonical-transaction.md](../protocol/canonical-transaction.md))
   and implemented byte-for-byte in TypeScript, Rust, and Solidity. Shared
   test vectors in `packages/protocol/src/vectors.ts` pin all three; a
   mismatch anywhere is a protocol bug.

## How a Phase 1.1 transaction flows

```
apps/dashboard        user intent; NO crypto logic (server-side demo route)
    ↓
packages/sdk          build tx -> protocol encoding -> digest -> @noble/curves
    ↓                 ECDSA sign -> viem submit to KeymeshWallet.execute
packages/protocol     THE canonical format definition + shared vectors
    ↓
crates/keymesh-core   same encoding/digest in Rust (reference for signers)
    ↓
contracts/ethereum    KeymeshWallet: recover signer -> check device, wallet,
                      chainId, nonce, expiry -> effects-before-interaction
                      execution on Anvil
```

Any relayer may submit (`msg.sender` is irrelevant); authority comes solely
from a registered device's signature over the canonical digest.

## Component maturity

| Component             | State       | Notes                                                     |
| --------------------- | ----------- | --------------------------------------------------------- |
| Canonical TX format   | implemented | TS/Rust/Solidity byte-identical via shared vectors         |
| KeymeshWallet         | experimental| device auth + replay/expiry guards + recovery application entry; works on Anvil |
| RecoveryManager       | implemented (Phase 1.2) | guardian quorum + timelock + cancellation state machine, owns its GuardianRegistry |
| GuardianRegistry      | implemented (Phase 1.2) | per-wallet unweighted guardian sets; mutated only by RecoveryManager |
| SDK on-chain flow     | experimental| build/sign/execute + recovery & policy sessions; not production custody |
| Domain models (TS)    | prototype   | Zod-validated models incl. on-chain recovery domain types  |
| SDK local-state APIs  | prototype   | wallets/guardians/recovery over in-memory storage          |
| Dashboard             | prototype   | mock pages + real server-side demo routes (/demo txs, /recovery guardian flow) |
| Rust core             | prototype   | recovery/policy FSMs mirror contracts exactly + TX codec; mock crypto |
| PolicyManager         | implemented (Phase 1.3) | deterministic classification + per-digest guardian transaction authorizations; enforced inside execute() |
| Threshold signing/MPC | not started | later phase; recovery governance deliberately independent  |
| Solana adapter        | not started | later phase; chain-kind abstraction already exists         |

## How a Phase 1.2 recovery flows

```
apps/dashboard        /recovery page: state + actions only (server API route)
    |
packages/sdk          KeymeshRecoverySession: bootstrap / initiate / approve /
    |                 cancel / finalize + device-signed guardian management;
    |                 decodes custom errors into domain errors
contracts/ethereum    RecoveryManager (policy + FSM)
    |                  - bootstrap once by manager, then authority retired
    |                  - guardians approve -> quorum snapshot -> timelock
    |                 GuardianRegistry (per-wallet sets, RM-owned storage)
    |                 KeymeshWallet.applyRecoveredDevice: atomic swap,
    |                  callable ONLY by the RecoveryManager
```

Guardians interact as EOAs directly (approve/initiate); device-signed
governance travels through `KeymeshWallet.execute` exactly like normal
transactions, so `msg.sender == wallet` proves device authority to the
RecoveryManager. Finalization is permissionless — any relayer can submit an
already-approved, timelock-expired recovery.

## Chain abstraction

KeyMesh is Ethereum-first but designed to admit other chains:

- `ChainAdapter` (SDK) isolates submission mechanics behind a `chainKind`
  discriminator (`'evm' | 'solana'`).
- Protocol domain types are chain-neutral; EVM specifics (addresses, wei
  strings, chain ids) live at the edges.
- The Rust core's signing module separates *what* is signed (domain-separated
  payloads) from *how* it is signed (curve/provider).

Adding Solana later means: a new adapter implementation, an ed25519 provider,
and Solana-specific contract programs — without redesigning wallets, policies,
or recovery.

## How a Phase 1.3 governed transaction flows

```
device signs the canonical digest of a high-value transfer
    |
KeymeshWallet.execute  domain/expiry/nonce/signature checks
    |
PolicyManager.evaluateAuthorization  deterministic precedence:
    |   admin selector > restricted selector > restricted destination
    |   > value threshold > default mode
DEVICE_PLUS_GUARDIANS?
    |-- no --> execute immediately (effects-first, nonce consumed)
    |-- yes -> consume per-digest authorization (must be Authorized,
    |          created by a device request and approved by the guardian
    |          quorum; version-checked against the current policy)
    v
external call + TransactionExecuted
```

Policy ADMINISTRATION is itself guardian-gated structurally: mutating
PolicyManager always classifies DEVICE_PLUS_GUARDIANS, so a single device can
never weaken policy.
## Trust model summary

Full details: [security/security-model.md](../security/security-model.md) and
[security/threat-model.md](../security/threat-model.md). In short:

- Transaction authority remains one ECDSA key per device (Phase 1.1). A
  compromised device key can drain the wallet one valid transaction at a time;
  recovery revokes it only after quorum + timelock, not instantly.
- DEVICE-SET authority is guardian-governed (Phase 1.2): the deployer-chosen
  manager exists only to bootstrap the first guardians and initialize
  governance, at which point its authority is permanently retired on-chain.
  Guardians can never move funds; devices can never approve recoveries.
- The design goal is now partially realized: changing the authorization set
  requires either a live device signature (guardian management) or a public,
  timelocked guardian quorum. Taking over faster than the timelock allows
  would require breaking both layers at once. The protocol still does NOT
  protect funds against an actively compromised device.


