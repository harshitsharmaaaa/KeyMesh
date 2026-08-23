# KeyMesh Architecture Overview

> **Status: Phase 1.1 implemented** — one real end-to-end authorization path
> (SDK → canonical encoding → ECDSA device signature → Solidity recovery →
> execution on Anvil) plus prototype scaffolding for everything else.
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
| KeymeshWallet         | experimental| device auth + replay/expiry guards, works on Anvil         |
| SDK on-chain flow     | experimental| build/sign/execute session; not production custody         |
| Domain models (TS)    | prototype   | Zod-validated models and pure state transitions            |
| SDK local-state APIs  | prototype   | wallets/guardians/recovery over in-memory storage          |
| Dashboard             | prototype   | mock data through the SDK + server-side Anvil demo route   |
| Rust core             | prototype   | real FSMs/policy engine + implemented TX codec; mock crypto|
| GuardianRegistry      | skeleton    | surfaces + tests; not wired into the wallet yet            |
| RecoveryManager       | skeleton    | state machine + timelock tests; not wired to devices yet   |
| PolicyManager         | skeleton    | policy storage/tests; no enforcement path from execute()   |
| Threshold signing/MPC | not started | Phase 2                                                    |
| Solana adapter        | not started | Phase 2; chain-kind abstraction already exists             |

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

## Trust model summary

Full details: [security/security-model.md](../security/security-model.md) and
[security/threat-model.md](../security/threat-model.md). In short:

- Phase 1.1 authority = one ECDSA key per device. A compromised device key can
  drain the wallet one valid transaction at a time; there is no threshold yet.
- Device-set management (register/revoke) is gated on a transitional
  deployer-chosen `manager` account — explicitly a Phase 1 control, to be
  replaced by guardian/recovery governance. No permanent admin exists and none
  should be added.
- The design goal remains: no single party can take over faster than the
  timelock allows once guardians/recovery are wired in. The protocol does NOT
  protect against a compromised device, and today nothing else protects you
  either.
