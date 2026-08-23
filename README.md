# KeyMesh

> Non-custodial digital asset key management, transaction authorization, and
> recovery — using threshold-style cryptography, guardian quorums, and
> timelocked recovery. Ethereum-first.

**Status: foundation / prototype.** This repository is a clean starting point
with real state machines and tests, not a finished protocol. Security-critical
cryptography (threshold signing / MPC) is deliberately **not implemented yet**
— boundaries, interfaces, and honest maturity labels are in place instead.
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

Design rules: the UI never touches crypto; the SDK never holds keys; the Rust
core is dependency-free while in prototype; unimplemented capabilities revert
or are labeled `prototype` rather than faked.

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
```

## Testing

```sh
# TypeScript (Vitest): protocol validation, SDK behavior, policy engine,
# recovery transitions, serialization helpers
bun run test

# Rust: recovery FSM, policy evaluation, canonical codec, error handling
cargo test --manifest-path crates/keymesh-core/Cargo.toml

# Solidity (Foundry): guardians, recovery state machine, timelock,
# access control, invalid transitions
forge test --root contracts/ethereum
```

## Building

```sh
bun run build                                   # all workspaces (Next.js etc.)
forge build --root contracts/ethereum           # contracts
cargo build --manifest-path crates/keymesh-core/Cargo.toml
```

## Rust development

The security-critical core lives in `crates/keymesh-core`. It is intentionally
zero-dependency during prototyping. State machines take time as input (clock
injection) so tests are deterministic. The crypto module exposes the trait a
future reviewed TSS/MPC implementation must satisfy; the bundled mock is for
tests only and labeled accordingly.

See [crates/keymesh-core/README.md](crates/keymesh-core/README.md).

## Foundry development

Contracts live in `contracts/ethereum`. The skeleton defines surfaces and
enforces the recovery/timelock semantics; fund-moving execution is disabled on
purpose until Phase 1 lands signing verification.

See [contracts/ethereum/README.md](contracts/ethereum/README.md).

## Security notes

- **No private keys or seed phrases are ever handled by the SDK or dashboard.**
  Devices hold their own keys behind the `Signer` interface.
- No custom cryptography exists here, and none will be written from scratch.
- Every module carries an explicit maturity label (`prototype`, `experimental`,
  `production-grade`). Trust code by its label, not its file name.
- Read [docs/security/threat-model.md](docs/security/threat-model.md) before
  contributing to security-relevant areas.

## Roadmap

**Phase 1 — Ethereum wallet (current focus)**
1. Ethereum wallet contract: device/threshold-authorized execution
2. Guardian system: on-chain registration + weighted approvals end-to-end
3. Recovery state machine wired across TS/Rust/Solidity (+conformance tests)
4. Transaction policy enforcement on-chain
5. Timelock enforcement integrated with PolicyManager
6. Real secp256k1 signing via reviewed libraries; replay protection on-chain
7. Testing: property/fuzz suites, invariant tests, coverage gates

**Phase 2 — Advanced cryptography & multi-chain**
1. Threshold signing / MPC integration (audited stacks only)
2. Solana adapter (chain-kind abstraction already exists)
3. Advanced cryptography: key-share rotation, proactive refresh
4. Security hardening: audits, fuzzing campaigns, formal specs where warranted

## License

MIT OR Apache-2.0 (to be finalized).
