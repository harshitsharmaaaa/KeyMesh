# KeyMesh 5-Minute Technical & Security Walkthrough

> **Scope:** Reproducible walkthrough demonstrating policy classification, guardian governance, timelocked recovery, and threshold ECDSA signing.

---

## 1. Quick Local Environment Setup

Ensure `Bun`, `Rust`, and `Foundry` are installed.

```bash
# 1. Install dependencies
bun install

# 2. Build TypeScript workspaces, Rust core, and Foundry contracts
bun run build
cargo build --manifest-path crates/keymesh-core/Cargo.toml
forge build --root contracts/ethereum

# 3. Run complete test suites
bun run test
cargo test --manifest-path crates/keymesh-core/Cargo.toml
forge test --root contracts/ethereum
```

---

## 2. Running the Anvil End-to-End Integration Demo

KeyMesh includes a real end-to-end integration pipeline against a local Anvil node.

```bash
# Execute local end-to-end integration demo
bun run integration:anvil
```

### What the 15-Step Demo Demonstrates

1. **Local Anvil Initialization:** Starts a local Anvil chain node (`chainId: 31337`).
2. **Contract Deployment:** Deploys `GuardianRegistry`, `PolicyManager`, `RecoveryManager`, and `KeymeshWallet`.
3. **Manager Deprecation:** Calls `initialize()`, setting manager to `address(0)` — provably power-deprived.
4. **Device Authorization:** Registers primary EOA device signature authority.
5. **Canonical Transaction Encoding:** Encodes transfer payload into `KEYMESH_TX_V1` byte format.
6. **Device Signing & Execution:** Signs canonical digest with device key and executes transaction via `KeymeshWallet.execute()`.
7. **Policy Classification & Enforcement:** Evaluates `PolicyManager` rules (`ALLOW`, `DEVICE_ONLY`, `DEVICE_PLUS_GUARDIANS`).
8. **Guardian Authorization Workflow:** Demonstrates value-threshold policy trigger requiring guardian digest approvals.
9. **Guardian Recovery Initiation:** Triggers `RecoveryManager.initiateRecovery()` for compromised device.
10. **Quorum Approval Collection:** Collects weighted guardian approvals to reach `QuorumReached`.
11. **Timelock Window:** Advances Anvil block timestamp past mandatory recovery timelock window.
12. **Atomic Device Replacement:** Finalizes recovery via `finalizeRecovery()`, revoking old device and registering new device atomically.
13. **Old Device Rejection:** Verifies old revoked device can no longer execute transactions.
14. **New Device Execution:** Verifies newly recovered device executes canonical transactions successfully.

---

## 3. Running Threshold ECDSA (TSS) Verification

To verify real CGGMP'24 threshold ECDSA signature generation and verification:

```bash
# Run isolated threshold signing tests
cargo test --manifest-path crates/keymesh-tss/Cargo.toml -- --nocapture
```

On Linux or heavy CI environments, run full DKG and resharing tests:

```bash
cargo test --manifest-path crates/keymesh-tss/Cargo.toml -- --ignored --nocapture
```

---

## 4. Architectural Capability Matrix

| Component | Status | Category | Details |
|-----------|--------|----------|---------|
| **`KEYMESH_TX_V1` Codec** | Real | `REAL` | Byte-identical canonical digest in TS, Rust, Solidity |
| **`KeymeshWallet.sol`** | Real | `REAL` | Device execution, nonces, domain binding |
| **`RecoveryManager.sol`** | Real | `REAL` | Quorum timelocked recovery state machine |
| **`PolicyManager.sol`** | Real | `REAL` | Value thresholds, selector/destination classification |
| **`crates/keymesh-tss`** | Real | `REAL` | Synedrion CGGMP'24 2-of-3 threshold ECDSA |
| **`crates/keymesh-tss-proto`** | Historical | `SIMULATED` | Historical `k256` prototype baseline |
| **Anvil Integration Engine** | Local Test | `LOCAL` | Full integration harness over local RPC |
| **Distributed Participant Network** | Deferred | `DEFERRED` | Production multi-process participant transport (`ADR-002`) |
