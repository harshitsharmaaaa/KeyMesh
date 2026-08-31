# KeyMesh Security Invariant Matrix

> **Status:** Phase 2.7 Complete / Freeze Matrix  
> **Scope:** Full protocol security invariants across Core Protocol, TSS Cryptography, TSS Authenticated Network, and TSS Key Lifecycle.

---

## 1. Core Protocol Invariants (Phase 1)

| Invariant ID | Description | Implementation / Location | Test Suite | Status |
|--------------|-------------|---------------------------|------------|--------|
| **INV-PROT-01** | Authorized Device Execution | `contracts/ethereum/src/KeymeshWallet.sol` | `KeymeshWalletInvariant.t.sol` | **TESTED** |
| **INV-PROT-02** | Monotonic Sequential Nonce | `contracts/ethereum/src/KeymeshWallet.sol` | `KeymeshWalletInvariant.t.sol` | **TESTED** |
| **INV-PROT-03** | Canonical Digest Binding | `crates/keymesh-core/src/canonical.rs`, `KeymeshWallet.sol` | `CanonicalEncodingFuzz.t.sol`, `canonical.fuzz.test.ts` | **TESTED** |
| **INV-PROT-04** | Recovery State Transitions | `contracts/ethereum/src/RecoveryManager.sol`, `crates/keymesh-core/src/recovery/mod.rs` | `RecoveryManagerInvariant.t.sol`, `recovery/mod.rs` tests | **TESTED** |
| **INV-PROT-05** | Guardian Approval Uniqueness | `contracts/ethereum/src/RecoveryManager.sol` | `RecoveryManager.t.sol` | **TESTED** |
| **INV-PROT-06** | Policy Classification Precedence | `contracts/ethereum/src/PolicyManager.sol`, `crates/keymesh-core/src/policy/mod.rs` | `PolicyManager.t.sol`, Rust policy tests | **TESTED** |
| **INV-PROT-07** | Admin Selector Structural Protection | `contracts/ethereum/src/PolicyManager.sol` | `PolicyManager.t.sol` | **TESTED** |
| **INV-PROT-08** | Timelock Enforceability | `contracts/ethereum/src/RecoveryManager.sol` | `RecoveryManager.t.sol` | **TESTED** |

---

## 2. Threshold Cryptography Invariants (TSS-INV)

| Invariant ID | Description | Implementation / Location | Test Suite | Status |
|--------------|-------------|---------------------------|------------|--------|
| **TSS-INV-01** | Fewer than threshold $t$ cannot sign | `crates/keymesh-tss/src/lib.rs` | `threshold_2of3_all_pairs_succeed_single_fails_real` | **TESTED** |
| **TSS-INV-02** | Coordinator cannot sign alone | `crates/keymesh-tss/src/lib.rs` | `setup_2of3()` single share rejection | **TESTED** |
| **TSS-INV-03** | Signature bound to exact `KEYMESH_TX_V1` digest | `crates/keymesh-tss/src/lib.rs` | `digest_binding_wrong_digest_rejected` | **TESTED** |
| **TSS-INV-04** | Session cannot be replayed | `crates/keymesh-tss/src/session.rs` | `session_replay_rejected` | **TESTED** |
| **TSS-INV-05** | No application-level key reconstruction | `crates/keymesh-tss/src/lib.rs` (synedrion CGGMP'24) | API inspection (`grep -r reconstruct` returns no public hits) | **TESTED** |
| **TSS-INV-06** | Participant identity binding | `crates/keymesh-tss/src/identity.rs` | `participant_identity_duplicate_fails` | **TESTED** |
| **TSS-INV-07** | Group Public Key / Address stability | `crates/keymesh-tss/src/lib.rs` | `ethereum_address_stable_across_signing` | **TESTED** |
| **TSS-INV-08** | Refresh preserves group identity | `crates/keymesh-tss/src/lifecycle.rs` | `refresh_preserves_group_key_and_signs` | **TESTED** |
| **TSS-INV-09** | Abort terminality | `crates/keymesh-tss/src/session.rs` | `abort_terminal` | **TESTED** |
| **TSS-INV-10** | Digest substitution resistance | `crates/keymesh-tss/src/lib.rs` | `digest_binding_wrong_digest_rejected` | **TESTED** |
| **TSS-INV-11** | Malicious participant handling | `synedrion 0.3` protocol | `transport_simulator_checks` | **TESTED** |
| **TSS-INV-12** | Signing-session uniqueness | `crates/keymesh-tss/src/session.rs` | `session_replay_rejected` | **TESTED** |
| **TSS-INV-13** | Policy-version binding | `crates/keymesh-tss/src/session.rs` | `SessionBinding.policy_version` tests | **TESTED** |
| **TSS-INV-14** | Canonical digest compatibility | `crates/keymesh-tss/src/lib.rs` | `keymesh_digest()` vector match | **TESTED** |
| **TSS-INV-15** | Policy no-downgrade | `crates/keymesh-core/src/policy` | `PolicyManager.t.sol` | **DESIGNED** |
| **TSS-INV-16** | Governed participant-set changes | `crates/keymesh-tss/src/governance.rs` | `governance_quorum_enforced` | **TESTED** |

---

## 3. Network Security Invariants (NET-INV)

| Invariant ID | Description | Implementation / Location | Test Suite | Status |
|--------------|-------------|---------------------------|------------|--------|
| **NET-INV-01** | Participant Network Authentication | `crates/keymesh-tss/src/identity.rs`, `envelope.rs` | `identity_sign_verify`, `envelope_sign_verify` | **TESTED** |
| **NET-INV-02** | Session Immutability | `crates/keymesh-tss/src/handshake.rs` | `handshake_ok_and_mismatch` | **TESTED** |
| **NET-INV-03** | Message Session Binding | `crates/keymesh-tss/src/envelope.rs` | `TssEnvelope::validate_against` | **TESTED** |
| **NET-INV-04** | Participant-Set Version Binding | `crates/keymesh-tss/src/lifecycle.rs` | `derive_key_id` version checks | **TESTED** |
| **NET-INV-05** | Stale-Share Rejection | `crates/keymesh-tss/src/lifecycle.rs` | `stale_share_rejected` | **TESTED** |
| **NET-INV-06** | Coordinator Cannot Forge Participant Message | `crates/keymesh-tss/src/envelope.rs` | `envelope::verify` against `NetworkKeypair` | **TESTED** |
| **NET-INV-07** | Transport Failure Cannot Authorize | `crates/keymesh-tss/src/network.rs` | `in_memory_authenticated_roundtrip` | **TESTED** |
| **NET-INV-08** | Rotation Requires Governance | `crates/keymesh-tss/src/governance.rs` | `governance_quorum_enforced`, `timelock_enforced` | **TESTED** |
| **NET-INV-09** | Refresh Preserves Group Identity | `crates/keymesh-tss/src/lifecycle.rs` | `refresh_preserves_group_key_and_signs` | **TESTED** |
| **NET-INV-10** | No Cross-Session Message Reuse | `crates/keymesh-tss/src/envelope.rs` | `validate_against` mismatch tests | **TESTED** |

---

## 4. Key Lifecycle Invariants (LIFE-INV)

| Invariant ID | Description | Implementation / Location | Test Suite | Status |
|--------------|-------------|---------------------------|------------|--------|
| **LIFE-INV-01** | Refresh Preserves Group Public Key | `crates/keymesh-tss/src/lifecycle.rs` | `refresh_preserves_group_key_and_signs` | **TESTED** |
| **LIFE-INV-02** | Refresh Preserves Wallet Address | `crates/keymesh-tss/src/lifecycle.rs` | `refresh_preserves_group_key_and_signs` | **TESTED** |
| **LIFE-INV-03** | Rotation Requires Governance | `crates/keymesh-tss/src/governance.rs` | `governance_quorum_enforced`, `timelock_enforced` | **TESTED** |
| **LIFE-INV-04** | Stale Participant Set Cannot Sign | `crates/keymesh-tss/src/lifecycle.rs` | `stale_share_rejected` | **TESTED** |
| **LIFE-INV-05** | Failed Rotation Preserves Old Active State | `crates/keymesh-tss/src/lifecycle.rs` | `rotation_failed_preserves_old_state` | **TESTED** |
| **LIFE-INV-06** | Failed Refresh Preserves Old Active State | `crates/keymesh-tss/src/lifecycle.rs` | `failed_refresh_preserves_old_state` | **TESTED** |
| **LIFE-INV-07** | Lifecycle Operations Cannot Race | `crates/keymesh-tss/src/lifecycle.rs` | `concurrent_lifecycle_operations_blocked` | **TESTED** |
| **LIFE-INV-08** | Retired Key Cannot Sign | `crates/keymesh-tss/src/lifecycle.rs` | `retirement_prevents_future_signing` | **TESTED** |
| **LIFE-INV-09** | Participant Set Version Monotonicity | `crates/keymesh-tss/src/lifecycle.rs` | `rotation_governed_and_preserves_group_key` | **TESTED** |
| **LIFE-INV-10** | Cryptographic Lifecycle Governed by On-Chain Semantics | `crates/keymesh-tss/src/governance.rs` | `governance::tests::*` | **TESTED** |

---

## 5. Summary Notes

* **Heavy Test Execution:** Heavy synedrion tests ($N=3, T=2$ CGGMP'24 key generation and resharing) are flagged `#[ignore]` on Windows dev machines due to heavy prime generation and run automatically on **Linux CI (`.github/workflows/tss.yml`)**.
* **Audit & Formal Verification:** No invariants have been externally audited or formally verified.
