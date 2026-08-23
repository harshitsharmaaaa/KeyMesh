# KeyMesh

> Non-custodial digital asset key management, transaction authorization, and
> recovery — using threshold-style cryptography, guardian quorums, and
> timelocked recovery. Ethereum-first.

**Status: Phase 1.1 implemented / prototype overall.** One real end-to-end
authorization path exists: SDK → canonical `KEYMESH_TX_V1` encoding → keccak
digest → ECDSA device signature → Solidity recovery → execution on local
Anvil. Everything else (guardians, recovery wiring, policy enforcement,
threshold signing) is scaffolding with honest maturity labels. This codebase
is **not audited** and **not production-ready**; threshold cryptography
(TSS/MPC) does **not** exist yet.
See [docs/security/security-model.md](docs/security/security-model.md).

## What is KeyMesh?

A wallet's authority is distributed across:

- **Devices** you control (authorize everyday transactions),
- **Guardians** you trust (weighted approvals for sensitive actions), and
- **Policies + Timelocks** that decide how much approval each action class
  needs and how long hostile actions stay cancellable.

```
Normal transaction      -> device signature
High-value transaction  -> device signature + guardian quorum
Recovery                -> guardian threshold -> timelock -> new device
```

Guardians can approve or cancel — they can never move funds directly. There is
no seed phrase to lose.

## Architecture

```
apps/dashboard      Next.js UI — talks ONLY to the SDK
packages/sdk        Public TypeScript API (@keymesh/sdk)
packages/protocol   Domain models, state machines, validation (@keymesh/protocol)
packages/types      Shared primitives (@keymesh/types)
packages/config     Shared tooling config (@keymesh/config)
crates/keymesh-core Rust core: recovery FSM, policy engine,
                    canonical serialization, crypto BOUNDARY
contracts/ethereum  Foundry contracts: KeymeshWallet, GuardianRegistry,
                    RecoveryManager, PolicyManager
docs/               Architecture, protocol specs, security model
```

Design rules: the UI never touches crypto; the SDK never stores keys; the Rust
core owns canonical digests but keeps asymmetric crypto behind a provider
boundary; unimplemented capabilities revert or are labeled `prototype` rather
than faked.

Details: [docs/architecture/overview.md](docs/architecture/overview.md).

## Repository structure

```text
keymesh/
├── apps/dashboard/          # Next.js dashboard (mock data via SDK)
├── packages/
│   ├── sdk/                 # @keymesh/sdk public API
│   ├── protocol/            # @keymesh/protocol domain layer
│   ├── types/               # @keymesh/types primitives
│   └── config/              # @keymesh/config shared tsconfigs
├── crates/keymesh-core/     # Rust protocol core (cargo test)
├── contracts/ethereum/      # Foundry contracts (forge test)
├── docs/
│   ├── architecture/
│   ├── protocol/
│   ├── security/            # threat-model.md, security-model.md
│   └── development/
├── scripts/
├── .github/workflows/ci.yml
└── turbo.json               # build/test/lint/typecheck/format/dev pipelines
```

## Prerequisites

| Tool    | Needed for        | Check             |
| ------- | ----------------- | ----------------- |
| Bun ≥1.1| everything JS/TS  | `bun --version`   |
| Rust ≥1.75 | crates/        | `cargo --version` |
| Foundry | contracts/        | `forge --version` |

## Installation

```sh
bun install
cd contracts/ethereum && forge install foundry-rs/forge-std --no-commit && cd ../..
cp .env.example .env.local   # placeholders only; never commit real values
```

## Development

```sh
bun run dev        # dashboard at http://localhost:3100
bun run test       # workspace tests (turbo)
bun run lint       # Biome lint
bun run format     # Biome format
bun run typecheck  # tsc per package
bun run build      # production build

# Phase 1.1 end-to-end: starts Anvil, deploys, registers a device,
# signs and executes a real transfer through the SDK (public fixture keys)
bun run integration:anvil
```

## Testing

```sh
# TypeScript (Vitest): canonical vectors, protocol validation, SDK behavior,
# policy engine, recovery transitions
bun run test

# Rust: recovery FSM, policy evaluation, canonical codec + digest vectors
cargo test --manifest-path crates/keymesh-core/Cargo.toml
cargo fmt --check --manifest-path crates/keymesh-core/Cargo.toml

# Solidity (Foundry): cross-language digest vectors, execution, replay/expiry,
# device access control
forge build --root contracts/ethereum
forge test --root contracts/ethereum
```

## Building

```sh
bun run build                                   # all workspaces (Next.js etc.)
forge build --root contracts/ethereum           # contracts
cargo build --manifest-path crates/keymesh-core/Cargo.toml
```

## Rust development

The security-critical core lives in `crates/keymesh-core`. It implements the
canonical transaction codec (byte-identical to TS/Solidity, pinned by shared
vectors) with a single hash dependency (`tiny-keccak`); asymmetric signing
stays behind the `CryptoProvider` trait, whose only bundled implementation is
a labeled insecure test mock. State machines take time as input (clock
injection) so tests are deterministic.

See [crates/keymesh-core/README.md](crates/keymesh-core/README.md).

## Foundry development

Contracts live in `contracts/ethereum`. `KeymeshWallet` executes real
device-signed transactions (canonical digest recovery, device set, sequential
nonce, expiry, wallet/chain binding, reentrancy guard) and is covered by
Foundry tests plus the Anvil integration script. Guardian/recovery/policy
modules remain skeletons pending wiring.

See [contracts/ethereum/README.md](contracts/ethereum/README.md).

## Security notes

- **The dashboard never touches private keys.** Its demo route runs
  server-side with PUBLIC Anvil fixture keys; nothing key-shaped is stored in
  browser state.
- The SDK session accepts a device private key as an explicit caller-supplied
  parameter for local development. Production custody (secure enclaves,
  threshold shares) does not exist yet and must not be improvised on top of it.
- No custom cryptography exists here, and none will be written from scratch:
  @noble/curves (signing), OpenZeppelin ECDSA (recovery), tiny-keccak (digests).
- Every module carries an explicit maturity label (`prototype`, `experimental`,
  `implemented`). Trust code by its label, not its file name.
- Nothing in this repository has been independently audited.
- Read [docs/security/threat-model.md](docs/security/threat-model.md) before
  contributing to security-relevant areas.

## Roadmap

**Phase 1 — Ethereum wallet (current focus)**
1. ~~Ethereum wallet contract: device-signed execution~~ ✅ Phase 1.1
2. Guardian system: on-chain registration + weighted approvals end-to-end ← next
3. Recovery state machine wired across TS/Rust/Solidity (+conformance tests)
4. Transaction policy enforcement on-chain (class thresholds via PolicyManager)
5. Manager-gated device management replaced by guardian/recovery governance
6. Testing: property/fuzz suites, invariant tests, coverage gates

**Phase 2 — Advanced cryptography & multi-chain**
1. Threshold signing / MPC integration (audited stacks only)
2. Solana adapter (chain-kind abstraction already exists)
3. Advanced cryptography: key-share rotation, proactive refresh
4. Security hardening: audits, fuzzing campaigns, formal specs where warranted

## License

MIT OR Apache-2.0 (to be finalized).
