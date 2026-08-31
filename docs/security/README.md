# KeyMesh Security Summary

> **Release Readiness:** READY FOR FINAL PORTFOLIO FREEZE (Research-Grade Architecture)

This document provides a consolidated entry point for security reviewers, auditing engineers, and researchers evaluating KeyMesh.

---

## 1. Security Architecture & System Overview

KeyMesh implements a non-custodial digital asset authorization system on Ethereum where authority is distributed across:
1. **Device Signatures (`SingleEcdsaProvider` / `ThresholdEcdsaProvider`)**: Fast, primary transaction authorization.
2. **Policy Engine (`PolicyManager`)**: Structural policy evaluation (value limits, destination/selector restrictions, administrative action gating).
3. **Guardian Recovery (`RecoveryManager` + `GuardianRegistry`)**: Quorum-governed, timelocked recovery state machine allowing atomic device replacement without key seed exposure.

```
                                  KEYMESH AUTHORIZATION
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    ↓                      ↓                      ↓
         Device / Threshold Signing   Policy Classification   Guardian Governance
                    │                      │                      │
            KEYMESH_TX_V1            PolicyManager          RecoveryManager
          (Canonical Digest)        (Rules & Scoping)      (Quorum & Timelock)
                    │                      │                      │
                    └──────────────────────┼──────────────────────┘
                                           ↓
                                    KeymeshWallet
                                 (solidity execution)
```

---

## 2. Trust Boundaries & Security Claims

### Core Security Invariants

* **No Seed Phrase Loss Risk:** Wallet authority is held by registered devices and guardian quorums; no single master key exists.
* **Manager Isolation:** The deployment/bootstrap manager is provably revoked (`initialize()` sets manager to `address(0)`); it has zero operational power post-bootstrap.
* **Canonical Digest Binding:** All transaction signatures commit to the domain-separated `KEYMESH_TX_V1` byte layout (`wallet`, `chainId`, `nonce`, `to`, `value`, `data`, `expiry`).
* **Independent Authorization Precedence:**
  1. Structural Admin Selectors → `DEVICE_PLUS_GUARDIANS`
  2. Restricted Selectors → `DEVICE_PLUS_GUARDIANS`
  3. Restricted Destinations → `DEVICE_PLUS_GUARDIANS`
  4. Value > Threshold → `DEVICE_PLUS_GUARDIANS`
  5. Default Policy Mode → wallet configuration
* **Recovery Timelock Window:** Recovery requests require guardian threshold approval AND a mandatory timelock delay during which active devices can unilaterally cancel hostile requests.

---

## 3. TSS / MPC Architecture Security Summary

KeyMesh incorporates threshold ECDSA via two distinct cryptographically isolated layers:

1. **`crates/keymesh-tss` (Real Threshold ECDSA — CGGMP'24):**
   * Built on `synedrion 0.3` CGGMP'24 protocol.
   * Produces standard low-$s$ Secp256k1 ECDSA signatures $(r, s, v)$ verifiable on-chain via standard `ecrecover`.
   * **No Application-Level Reconstruction:** Private key shares $x_i$ remain distributed across participants. Secret key $x$ is never reconstructed centrally during signing.
   * Verified by heavy integration tests (`manul::TestRuntime`) on Linux CI.

2. **`crates/keymesh-tss-proto` (Historical Prototype — `k256`):**
   * Pre-CGGMP21 2-of-3 Shamir-based prototype.
   * Retained for educational tracing and regression baseline; explicitly documented as simulated MPC.

---

## 4. Threat Model & Status

See [docs/security/threat-model.md](../threat-model.md) and [docs/security/tss-threat-model.md](../tss-threat-model.md) for detailed descriptions.

| Threat Category | Status | Mitigations / Evidence |
|-----------------|--------|────────────────────────|
| **Single Device Theft** | `MITIGATED` | Stolen device cannot bypass guardian policy rules or execute high-value txs alone. Recovery allows device revocation. |
| **Guardian Quorum Abuse** | `MITIGATED` | Guardians cannot spend funds; they can only approve recovery or high-value txs. Active device can cancel recovery during timelock. |
| **Transaction Tampering** | `TESTED` | Digest binding includes all payload parameters. Mismatch invalidates signature. |
| **Replay & Cross-Chain** | `TESTED` | Monotonic sequential nonces + explicit `chainId` + domain tag `KEYMESH_TX_V1`. |
| **Coordinator Forgery (TSS)** | `TESTED` | Coordinator holds no threshold share and cannot forge participant signatures (`NET-INV-06`). |
| **Stale Share Signing (TSS)** | `TESTED` | Monotonic key lifecycle versioning; stale shares rejected (`LIFE-INV-04`). |
| **Distributed Participant Network** | `DEFERRED` | Production multi-process participant transport and consensus deferred (`ADR-002`). |

---

## 5. Security Testing, Fuzzing & Invariants

* **Foundry Fuzz & Invariants:** Invariant test suites (`KeymeshWalletInvariant.t.sol`, `RecoveryManagerInvariant.t.sol`, `GuardianRegistryInvariant.t.sol`, `CanonicalEncodingFuzz.t.sol`).
* **Rust Core Property Tests:** Deterministic state machine and canonical serialization coverage in `crates/keymesh-core`.
* **TSS Invariant Matrix:** 36 formal invariants tracked across core TSS, Network, and Lifecycle layers (`docs/security/invariant-matrix.md`).

---

## 6. Known Audit & Protocol Findings

Tracked in [docs/security/findings.md](../findings.md):
* **F-0001 (`LOW`):** Fixed — replaced `vitest/fast-check` dependency issue with deterministic coverage.
* **F-0002 (`LOW`):** Fixed — corrected malformed hex address in vector fixture.
* **F-0003 (`INFO`):** Acknowledged — `crates/keymesh-tss-proto` historical prototype internal reconstruction limitation; replaced by `synedrion` in `crates/keymesh-tss`.
* **F-0004 (`MEDIUM`):** Fixed — Windows dev test timeout resolved by isolating heavy synedrion tests to `--ignored` and Linux CI.

---

## 7. Explicit Security Disclaimer

> **IMPORTANT NOTICE**
> 
> KeyMesh is a **research-grade experimental digital-asset authorization protocol**.
> It has **NOT** undergone an independent external security audit, formal verification, or legal license audit.
> It **MUST NOT** be used for production digital asset custody, mainnet deployment, or real financial funds.
