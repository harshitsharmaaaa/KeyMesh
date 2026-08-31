# KeyMesh

> Non-custodial digital asset authorization, transaction policy management, and threshold cryptography (CGGMP'24 Threshold ECDSA) — research-grade architecture for Ethereum.

```text
RELEASE READINESS: READY FOR FINAL PORTFOLIO FREEZE
```

> **IMPORTANT SECURITY DISCLAIMER**  
> KeyMesh is a **research-grade experimental digital-asset authorization protocol**.  
> It has **NOT** undergone an independent external security audit, formal verification, or legal license audit.  
> It **MUST NOT** be used for production digital asset custody, mainnet deployment, or real financial funds.

---

## What is KeyMesh?

KeyMesh distributes authority over digital asset transactions across:
- **Devices** (authorize everyday transactions via ECDSA / Secp256k1 signatures),
- **Policies** (classify transaction risk via structural limits, destinations, and selector rules), and
- **Guardians + Timelocks** (quorum-governed recovery state machine that atomically replaces compromised devices).

```text
Normal transaction      -> Device / Threshold ECDSA signature
High-value transaction  -> Device signature + Guardian quorum approval
Recovery                -> Guardian quorum -> Timelock window -> Atomic device replacement
```

---

## Why KeyMesh Exists

Traditional self-custody wallets rely on seed phrases or single private keys, creating single points of failure. Multi-signature smart contracts introduce higher gas costs and lack standardized transaction authorization policies. 

KeyMesh provides:
1. **No Master Seed Phrase:** Authority is divided across active devices and guardian quorums.
2. **Canonical Digest Encoding (`KEYMESH_TX_V1`):** Byte-identical transaction binding across TypeScript, Rust, and Solidity.
3. **Provably Powerless Deployment Manager:** Post-initialization, contract ownership is zeroed (`address(0)`).
4. **Real Threshold ECDSA (CGGMP'24):** Non-custodial 2-of-3 threshold ECDSA generating standard $(r, s, v)$ signatures verified by standard Ethereum `ecrecover`.

---

## Architecture

```text
                    KEYMESH AUTHORIZATION
                               │
        ┌──────────────────────┼──────────────────────┐
        ↓                      ↓                      ↓
     Signing                 Policy                Recovery
        │                      │                      │
        ↓                      ↓                      ↓
   Device/TSS            PolicyManager          RecoveryManager
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               ↓
                         Authorization
                               ↓
                          KeymeshWallet
                            (Solidity)
```

### Component Breakdown

* **`apps/dashboard`**: Next.js dashboard UI.
* **`packages/sdk`**: `@keymesh/sdk` public TypeScript API.
* **`packages/protocol`**: Domain state models, policy evaluation, canonical serialization.
* **`crates/keymesh-core`**: Rust core logic (`tiny-keccak` canonical digest codec, policy engine, recovery FSM).
* **`crates/keymesh-tss`**: Real Threshold ECDSA implementation via `synedrion 0.3` CGGMP'24 ($N=3, T=2$).
* **`crates/keymesh-tss-proto`**: Historical $k256$ threshold prototype baseline.
* **`contracts/ethereum`**: Foundry smart contracts (`KeymeshWallet`, `GuardianRegistry`, `RecoveryManager`, `PolicyManager`).

---

## Capabilities & Separation Matrix

KeyMesh clearly delineates operational states across four explicit categories:

| Category | Components | Status |
|----------|------------|--------|
| **`REAL`** | `KEYMESH_TX_V1` codec, `KeymeshWallet.sol`, `RecoveryManager.sol`, `PolicyManager.sol`, `synedrion 0.3` CGGMP'24 threshold ECDSA (`crates/keymesh-tss`) | Production-spec code; tested in CI |
| **`SIMULATED`** | `crates/keymesh-tss-proto` historical prototype | Historical baseline (internal secret reconstruction) |
| **`LOCAL`** | Anvil Integration Suite (`bun run integration:anvil`) | Deterministic local deployment & verification |
| **`DEFERRED`** | Multi-process production participant network (`ADR-002`), Public testnet TSS E2E | Explicitly deferred architectural scope |

---

## Threat Model & Security Properties

* **Single Device Theft:** A stolen device cannot execute high-value transactions or alter policies without guardian quorum approval.
* **Guardian Quorum Limits:** Guardians cannot move funds directly; they can only approve specific digests or initiate recovery.
* **Device Recovery Window:** During the recovery timelock delay, active devices can unilaterally cancel hostile recovery requests.
* **Replay Protection:** Sequential monotonic nonces + explicit chain ID binding + domain tag `KEYMESH_TX_V1`.
* **No Key Reconstruction (TSS):** Under CGGMP'24 interactive signing, secret shares remain distributed across participants and are never reconstructed centrally.

See [docs/security/README.md](docs/security/README.md), [docs/security/threat-model.md](docs/security/threat-model.md), and [docs/security/invariant-matrix.md](docs/security/invariant-matrix.md).

---

## Repository Structure

```text
KeyMesh/
├── apps/
│   └── dashboard/            # Next.js UI dashboard
├── packages/
│   ├── sdk/                  # TypeScript SDK (@keymesh/sdk)
│   ├── protocol/             # Domain layer & canonical serialization
│   ├── types/                # Shared TypeScript primitives
│   └── config/               # Workspace configuration
├── crates/
│   ├── keymesh-core/         # Rust protocol core & FSMs
│   ├── keymesh-tss/          # Real CGGMP'24 threshold ECDSA (synedrion 0.3)
│   └── keymesh-tss-proto/    # Historical k256 threshold prototype
├── contracts/
│   └── ethereum/             # Foundry contracts (Solidity)
├── docs/
│   ├── architecture/         # Architecture overview & Mermaid diagrams
│   ├── demo/                 # 5-minute quickstart demo guide
│   ├── protocol/             # Protocol specs & canonical codecs
│   └── security/             # Invariant matrix, threat models, security summary
└── scripts/                  # Anvil end-to-end integration scripts
```

---

## Quick Start & 5-Minute Demo

### Prerequisites

| Tool | Minimum Version | Usage |
|------|-----------------|-------|
| **Bun** | $\ge 1.1$ | TypeScript workspace execution |
| **Rust** | $\ge 1.75$ | Core crates & TSS compilation |
| **Foundry** | Latest | Solidity compilation & testing |

### Installation

```bash
bun install
cd contracts/ethereum && forge install foundry-rs/forge-std --no-commit && cd ../..
```

### 5-Minute Integration Demo

Run the automated 15-step local integration suite against Anvil:

```bash
bun run integration:anvil
```

Detailed walkthrough instructions: [docs/demo/README.md](docs/demo/README.md).

---

## Testing

```bash
# Workspace TypeScript tests
bun run test

# Rust Core & TSS light test suites
cargo test --manifest-path crates/keymesh-core/Cargo.toml
cargo test --manifest-path crates/keymesh-tss/Cargo.toml

# Foundry contract test suite (Solidity)
forge test --root contracts/ethereum
```

*Note: Heavy prime-generation TSS DKG tests in `crates/keymesh-tss` are isolated via `#[ignore]` on Windows local environments and run automatically on **Linux CI (`.github/workflows/tss.yml`)**.*

---

## Key Limitations & Testnet Status

* **Distributed Synedrion Runtime:** Multi-process participant transport and consensus engine deferred (`ADR-002`).
* **Public Testnet TSS E2E:** Public testnet broadcast of threshold signatures not observed.
* **No External Audit:** Codebase has not undergone independent security audit or formal verification.
* **Linux Required for Heavy TSS:** Heavy prime generation for Paillier keys requires Linux CI execution.

---

## License

Dual-licensed under MIT OR Apache-2.0.

---

## Future Work

1. Production multi-process participant network daemon (`keymesh-tss-node`).
2. Hardware Security Module (HSM) enclave integration for participant key shares.
3. Solana chain adapter integration.
