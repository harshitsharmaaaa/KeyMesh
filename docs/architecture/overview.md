# KeyMesh Architecture Overview

> **Status: intended architecture.** This document describes the design the
> repository is being built toward. Components marked **prototype** are
> scaffolding with explicit boundaries, not finished systems.

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
   internals.
2. The SDK depends on `@keymesh/protocol` and `@keymesh/types`; nothing
   depends upward.
3. `crates/keymesh-core` has zero dependencies while in prototype; crypto
   libraries will be added in Phase 2 after review.
4. Contracts depend on nothing third-party yet; OpenZeppelin adoption is a
   planned Phase 1 hardening step (see `contracts/ethereum/README.md`).
5. TypeScript and Rust implement mirrored semantics for state machines. Rust
   is the reference; TS mirrors it so client-side previews cannot drift from
   on-chain enforcement. A conformance test suite tying them together is a
   Phase 1 deliverable.

## Component maturity

| Component             | State     | Notes                                              |
| --------------------- | --------- | -------------------------------------------------- |
| Domain models (TS)    | prototype | Zod-validated models and pure state transitions    |
| SDK                   | prototype | Local-state client; signer/chain adapters are TODO |
| Dashboard             | prototype | Mock data through the SDK surface                  |
| Rust core             | prototype | Real FSMs + policy engine; mock crypto behind trait|
| Ethereum contracts    | skeleton  | Surfaces + tests; execution disabled               |
| Threshold signing/MPC | not started | Phase 2                                          |
| Solana adapter        | not started | Phase 2; chain-kind abstraction already exists   |

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

- No single party (including all guardians colluding before a timelock)
  can take over a wallet faster than the timelock allows.
- The protocol assumes honest majority of guardian weight, secure devices,
  and correct contracts. It explicitly does NOT protect against a compromised
  device combined with fast guardian collusion inside one timelock window.
