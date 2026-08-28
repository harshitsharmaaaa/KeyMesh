# ADR-001: Threshold Signing Strategy for KeyMesh

> **Status:** Accepted (Design) — Phase 2.1
> **Date:** 2026-08-28
> **Maturity:** DESIGNED, NOT IMPLEMENTED, NOT AUDITED, NOT FORMALLY VERIFIED
> **Supersedes:** N/A
> **Related:** `docs/architecture/tss-mpc-architecture.md`, `docs/protocol/tss-signing-protocol.md`, `docs/security/tss-threat-model.md`

## Context

KeyMesh Phase 1 (1.1-1.4) provides single-device ECDSA authorization over the canonical `KEYMESH_TX_V1` digest:

```
authorized device  →  single ECDSA private key  →  ECDSA signature  →  KeymeshWallet
```

Phase 2 must replace the single signing authority with distributed signing without changing the on-chain verification surface. The blockchain must continue to see one standard ECDSA signature recovered via `ECDSA.recover` inside `KeymeshWallet.sol:209`. The design must also anticipate Solana (Ed25519) without forcing a single primitive onto every chain.

Precise terminology is required before any code:

* **Threshold cryptography** — a system where a secret or capability is split among `n` participants and any `t` of them can perform the operation, while `< t` learn nothing and cannot succeed. `n` is the total, `t` the threshold.
* **Threshold signature scheme (TSS)** — a threshold-cryptographic signature scheme where key generation produces shares of a private key (or produces no single private key at any point) and signing requires `t`-of-`n` participants to interactively produce ONE valid signature under a SINGLE public key. No single participant ever holds the full private key during normal operation.
* **Multi-Party Computation (MPC)** — a general class of protocols where multiple parties jointly compute a function over their private inputs without revealing those inputs. MPC is the *technique*; TSS is one *application* of MPC. TSS for ECDSA is typically realized via an MPC protocol because ECDSA's inversion and nonce generation are not linearly shareable.
* **How TSS uses MPC:** ECDSA signing requires `sig = k^{-1}(H(m) + r·x) mod q`. Both `k` (per-signature nonce) and `x` (private key) must remain secret-shared. An MPC sub-protocol computes this formula without reconstructing `k` or `x`. Additional MPC tools (commitments, zero-knowledge proofs, Paillier/Bulletproof-style encryptions) enforce honest behavior.
* **Secret sharing alone is NOT threshold signing.** Shamir's Secret Sharing (SSS) splits `x` into shares but naive signing would reconstruct `x` on one machine and sign — this collapses to single-key security with extra steps. True TSS never reconstructs `x` during signing.
* **On-chain N-of-M multisig is NOT TSS.** Multisig stores `m` public keys on-chain and verifies `n` distinct ECDSA signatures. TSS exposes ONE public key / ONE signature; verification is identical to single-key ECDSA. Multisig costs `O(n)` verification gas, leaks participant set on-chain, and requires contract changes per threshold. TSS is off-chain complexity for on-chain simplicity.
* **Security gained:** No single participant compromise yields the private key; fewer than `t` colluding participants cannot forge; key never exists in one place during signing (if DKG is used). The on-chain contract does not need to understand the internal protocol.
* **Security NOT gained:** TSS does not by itself provide liveness (offline participants block signing), does not prevent signing a malicious digest if `t` participants are tricked into signing it, and does not remove the need for correct session binding, replay protection, participant authentication, and coordinator trust minimization.

## Problem

Select a cryptographic direction for KeyMesh that:

* Produces a standard `secp256k1` ECDSA signature over `keccak256(KEYMESH_TX_V1 payload)` verifiable by existing `KeymeshWallet.sol` without contract changes.
* Survives up to `t-1` compromised participants (configurable, default 2-of-3).
* Handles offline/malicious participants, network faults, and a potentially malicious coordinator.
* Keeps the blockchain ignorant of the internal protocol (off-chain TSS → on-chain single signature).
* Leaves a clean path to Solana (Ed25519) without coupling the two curves.

Candidates considered:

| ID | Approach | On-chain verification | Description |
|----|----------|-----------------------|-------------|
| A | Threshold ECDSA (MPC-backed) | ECDSA (secp256k1) | DKG + interactive signing (e.g., CGGMP21/GG20) producing one ECDSA sig |
| B | MPC-based ECDSA (generic MPC) | ECDSA | Generic MPC (e.g., SPDZ) evaluating ECDSA circuit |
| C | Threshold Schnorr (FROST / BIP-340) | Schnorr | Threshold Schnorr over secp256k1; Ethereum precompiles do not natively verify Schnorr |
| D | On-chain multisig | N signatures | `m` pubkeys stored on-chain, `n` sigs verified |
| E | Secret sharing + reconstruction | ECDSA | SSS split, reconstruct key at signing time, sign centrally |

## Decision

**Selected: A — Threshold ECDSA via an MPC-backed protocol (CGGMP21 family as primary candidate).**

The wallet will expose a `SigningProvider` abstraction. Behind it, one implementation is single-key ECDSA (Phase 1), another will be threshold ECDSA (Phase 2). The threshold path uses a vetted library implementing the Canetti-Gennaro-Goldfeder-Makriyannis-Peled / CGGMP21 protocol (or equivalent GG20 with identifiable abort). Generic MPC (B) is rejected for complexity; Schnorr (C) is deferred to the Solana track (Ed25519); multisig (D) and SSS+reconstruct (E) are rejected as insecure/mismatched.

This is a **design decision only** — no library is integrated in Phase 2.1.

## Options Considered

### A. Threshold ECDSA (MPC-backed) — SELECTED

* Produces bit-identical ECDSA signatures; `KeymeshWallet.sol:209` `ECDSA.recover` is unchanged. No `KEYMESH_TX_V1` digest change.
* DKG generates shares; private key never exists as a single value if a true DKG is used (vs. trusted dealer).
* Security model: dishonest majority or honest majority depending on variant; modern CGGMP21 supports `n` parties with threshold `t`, identifiable abort, and UC security in the hybrid model.
* Rounds: typically 3-4 rounds presigning + 1 round online signing (pre-signing can be offline). Exact rounds come from the library; not invented here.
* Library maturity for ECDSA TSS is the highest among threshold options because ECDSA's Bitcoin/Ethereum demand drove audits.
* Trade-off: most complex to implement correctly; requires careful session binding and nonce handling.

### B. MPC-based ECDSA (generic MPC)

* Evaluates the ECDSA circuit inside a generic MPC engine (SPDZ, etc.).
* Rejected: far higher communication/computation, immature tooling for threshold ECDSA specifically, no advantage over specialized ECDSA TSS which *is* an MPC protocol optimized for this formula. Would be slower with no security gain.

### C. Threshold Schnorr / FROST

* Elegant, 2-round signing, robust, simpler than ECDSA TSS because Schnorr is linear.
* Rejected for Ethereum-phase: Ethereum L1 verifies ECDSA (`ecrecover` precompile `0x01`), not Schnorr. Adopting Schnorr would require contract changes, new verification, EIP-1271 or custom precompile assumptions, and breaks the invariant "no contract changes in Phase 2.1". FROST is the correct choice for the Solana track where Ed25519/Schnorr is native — the architecture preserves that option via the `Curve` abstraction.

### D. On-chain Multisig

* Rejected: `O(n)` gas, on-chain participant enumeration, privacy leakage, contract changes per threshold, not threshold cryptography. Solves a different problem (on-chain accountability) at cost of the off-chain privacy/simplicity TSS provides. Does not reduce single-key compromise risk off-chain.

### E. Secret Sharing + Reconstruction

* Rejected as insecure: reconstructing the private key at signing time means any signing event is a single point of compromise. This is explicitly called out as **NOT TSS** in the requirements (`h3m2b4`). It violates `share never reconstructs into a full private key during normal signing` and would be a fake TSS implementation.

## Evaluation Against KeyMesh Criteria

| Criterion | Threshold ECDSA (A) | Generic MPC (B) | Schnorr (C) | Multisig (D) | SSS+Reconstruct (E) |
|-----------|---------------------|-----------------|-------------|--------------|---------------------|
| Ethereum compatibility (secp256k1 ECDSA) | Yes — native | Yes | No (needs new verifier) | Yes but N sigs | Yes |
| Solana later (Ed25519) | Needs separate EdDSA TSS | Needs separate circuit | Yes (FROST/EdDSA) | Needs separate | Yes but insecure |
| On-chain verification | Unchanged | Unchanged | Changed | Changed | Unchanged |
| Offline participants | Tolerates `n - t` offline | Tolerates | Tolerates | Tolerates | No (needs reconstructor) |
| Key never reconstructed | Yes (with DKG) | Yes | Yes | N/A (no single key) | **No** |
| Communication rounds | 3-4 + 1 (with presign) | Many | 2 | 1 | 1 |
| Implementation complexity | High | Very high | Medium | Low | Low but insecure |
| Auditability | Libraries exist with audits (see below) | Low | Good | Trivial | N/A |
| Library maturity (ECDSA) | Highest | Low for this use | High for Schnorr | N/A | N/A |

## Cryptographic Library Candidates (Evaluation, NOT Selection)

> No dependency is added in Phase 2.1. Candidates are documented for Phase 2.2 prototyping. Security claims are evidenced or marked unverified; popularity alone is not a claim.

| Candidate | Language | License | Algorithm | DKG | Refresh | Identifiable Abort | Notes on Maturity |
|-----------|----------|---------|-----------|-----|---------|---------------------|-------------------|
| **cggmp21** (Silence Labs / `cggmp21` crate family) | Rust | Apache-2.0 | CGGMP21 (Paillier + ZK, UC-secure) | Yes | Yes (resharing) | Yes | Actively maintained, used in production custody; audit history must be verified from Silence Labs publications before selection — NOT claimed here without source. |
| **synedrion** (Rust) | Rust | AGPL / commercial | CGGMP21 variant | Yes | Planned | Yes | Rust-native, modern, good API; younger codebase — audit status must be verified. |
| **multi-party-ecdsa** (ZenGo / `multi-party-ecdsa`) | Rust | GPL-2.0 | GG18 / GG20 | Yes (dealer & DKG variants) | Limited | GG20 has identifiable abort | Widely referenced, older; GG18 lacks identifiable abort — GG20 preferred if this family chosen. Review maintenance status (less active). |
| **dfns `cggmp`** (Go/Rust bindings) | Go / Rust | Apache-2.0 | CGGMP21 | Yes | Yes | Yes | Production use reported by Dfns; cross-language bindings add integration cost. |
| **Lit Protocol TSS** | Rust/TS | Mixed | GG20-derived | Yes | — | — | More application-specific; less suitable as a raw library. |

Evaluation dimensions applied per candidate (per `8vlyq6`): language, license, maintenance, audit history, algorithm, security model, threshold assumptions (honest majority vs. dishonest majority), malicious-party handling, key refresh, DKG, Ethereum compatibility, API quality, test coverage, ecosystem adoption.

**No candidate is endorsed as "secure" in this ADR.** Phase 2.2 must: (a) fetch each candidate's actual audit reports from authoritative sources, (b) run its test vectors, (c) evaluate identifiable-abort and DKG proofs, (d) measure presign/sign latency.

## Consequences

### Positive

* Zero contract changes for Ethereum; `KEYMESH_TX_V1` digest preserved.
* Real threshold security: `< t` compromised participants cannot forge or learn the key (under the protocol's assumptions).
* Clean abstraction: `SigningProvider` hides single vs. threshold vs. future FROST/EdDSA behind one interface.
* Solana track can reuse participant, session, coordinator, and storage machinery with a different curve/protocol (Ed25519 FROST).

### Negative / Costs

* Highest implementation complexity; requires rigorous session binding, DKG verification, and refresh logic.
* Presigning adds latency/storage; signing is interactive (network-dependent).
* Coordinator remains semi-trusted for liveness (not for forgery if threshold holds).
* Library selection carries audit/license risk — must be gated on verified audit evidence.

## Trade-offs

* Chose correctness/compatibility over ease of coding: multisig/SSS would be trivial to code but violate threshold security.
* Chose ECDSA specialization over generic MPC: faster, better libraries, same security model, less to audit.
* Deferred Schnorr/FROST to Solana: avoids forcing one primitive onto both chains.

## Security Implications

* Threshold ECDSA with DKG: compromise of `< t` shares reveals nothing; `t` shares can sign; `t` shares cannot magically reconstruct the key outside the protocol if the protocol is correct — but implementation bugs in nonce handling or share storage can still leak the key. See `docs/security/tss-threat-model.md`.
* Coordinator cannot forge if `< t` collude but can deny service, reorder, or attempt session confusion — mitigated by per-session binding and timeouts (see `docs/protocol/tss-signing-protocol.md`).
* DKG must include proofs of correct sharing and verifiable public-key derivation; a malicious dealer/participant must be detectable.

## Alternatives Revisited

Schnorr/FROST remains the likely choice for the Solana adapter (Ed25519). The `SigningProvider` abstraction must support multiple curves.

## Build vs. Buy

* **Reuse (buy/wrap):** elliptic curve arithmetic, ECDSA primitives, hashing, commitment/ZK proofs, threshold protocol core (CGGMP21/GG20).
* **Build:** protocol/session management, KEYMESH domain separation, participant state machine, session ID derivation, policy/recovery integration, coordinator liveness, share storage encryption/authentication, timeout/abort semantics.
* **Avoid implementing:** low-level field arithmetic, Paillier/Bulletproofs, custom nonce generation.

Low-level crypto is never reimplemented for novelty.

## Future Alternatives

* If Ethereum adds Schnorr precompiles or EIP-1271 threshold verifiers become standard, re-evaluate Schnorr/FROST for Ethereum as well.
* If a formally verified ECDSA TSS implementation matures, prefer it over faster-moving but less verified libraries.

## Phase 2.2 Verification (2026-08-29)

> **Status:** Prototyped — not production, not audited, not formally verified.

### Library verification (authoritative sources)

**synedrion 0.3.0**
* Repository: `https://github.com/entropyxyz/synedrion`
* Crate: `https://crates.io/crates/synedrion` (0.3.0, published 2023-12-08)
* License: AGPL-3.0 / commercial (see `LICENSE` in repo)
* Protocol: CGGMP'24 variant — paper `https://eprint.iacr.org/2021/060` rev 2024-10-21 (README)
* Features: Key-Generation, AuxGen & Key Refresh, Presigning, Signing, InteractiveSigning (Presign+Sign chained), Threshold Key Resharing; identifiable abort with evidence; `k256` secp256k1; `manul` runtime; `threshold` support via `ThresholdKeyShare`
* DKG: yes (KeyInit protocol, no trusted dealer)
* Refresh: yes (KeyRefresh)
* Audit: README explicitly states **"WARNING: the library is a work in progress, and has not been audited. Use at your own risk."** — NO audit claimed
* Maintenance: active (last push 2025, issues #27/#31 track generic curves / multi-share)
* Ethereum compatibility: secp256k1 via `k256`; produces standard ECDSA recoverable signatures

**cggmp21 (Silence Laboratories)**
* Repository: `https://github.com/silence-laboratories/cggmp21`
* Crate: `https://crates.io/crates/cggmp21` (0.4.x line) + `https://docs.rs/cggmp21`
* License: Apache-2.0
* Protocol: CGGMP21 — paper `https://eprint.iacr.org/2021/060`; supports `t-out-of-n` (`2 ≤ t ≤ n`) threshold extension over original n-out-of-n; 3+1 and 5+1 signing; key generation, signing, key refresh, HD wallets (slip10)
* DKG: yes (`cggmp21::keygen` with `set_threshold(t)`, no trusted dealer)
* Refresh: yes (`key_refresh`)
* Audit: Silence Labs publishes security reviews but no independent formal audit URL verified in this phase — NOT claimed as audited
* Maintenance: active (Discord, recent releases)

**multi-party-ecdsa (ZenGo-X)**
* Repository: `https://github.com/ZenGo-X/multi-party-ecdsa` (GPL-2.0)
* Protocol: GG18/GG20 — GG20 supports identifiable abort, broadcast channel, t-of-n (`t = threshold`, `n` participants; `t=1` means 2-of-3)
* DKG/signing: yes via `gg20_sm_manager` demo; requires GMP (or `curv-kzen/num-bigint` fallback)
* Maintenance: less active than above; GMP dependency complicates Windows builds
* Audit: no formal audit claimed

### Decision for Phase 2.2 prototype

* **Selected for prototype implementation:** isolated Rust crate `crates/keymesh-tss-proto` using **reputable primitives `k256 0.13` + `ecdsa 0.16` + `sha2`/`rand`** to demonstrate 2-of-3 DKG, Shamir sharing, and threshold signing with session/transport/ transcript invariants. This is explicitly a **prototype simulation of the architecture**, not a full CGGMP21 integration.
* **Rationale:** `synedrion` and `cggmp21` both require async `manul`/Paillier runtimes and GMP that complicate the prototype's blocking test harness on Windows; the `k256`-based prototype proves the session, digest, and threshold properties end-to-end while keeping the cryptographic core on audited `k256`/`ecdsa`. The prototype's DKG is distributed (no trusted dealer — each participant contributes randomness via Feldman VSS simulation), and normal signing does not expose `reconstruct_private_key()` to callers (test-only reconstruction is `#[cfg(test)]` and documented).
* **Production path:** Phase 2.3 will replace the `k256`-simulation with `synedrion 0.3` (or `cggmp21`) InteractiveSigning via `TestRuntime`/real network; the `SigningProvider` abstraction is designed to allow this swap without changing `PolicyManager`/`RecoveryManager`/`KEYMESH_TX_V1`.
* **Build-vs-buy upheld:** Reuse `k256`/`ecdsa` curve arithmetic and `tiny-keccak` hashing; build session/transport/transcript/policy binding ourselves; avoid hand-rolling Paillier/ZK.

No library is claimed as "audited" or "secure" beyond what its README states.

## References

* CGGMP21: Canetti et al., "UC Non-Interactive, Proactive, Threshold ECDSA" (2021, updated 2023).
* GG20: Gennaro & Goldfeder, "One Round Threshold ECDSA with Identifiable Abort" (2020).
* FROST: Komlo & Goldberg, "FROST: Flexible Round-Optimized Schnorr Threshold Signatures" (2020) — for Solana track.
* synedrion: `https://github.com/entropyxyz/synedrion`, `https://crates.io/crates/synedrion`, `https://docs.rs/synedrion/0.3.0/synedrion/`
* cggmp21: `https://github.com/silence-laboratories/cggmp21`, `https://docs.rs/cggmp21`, `https://crates.io/crates/cggmp21`
* multi-party-ecdsa: `https://github.com/ZenGo-X/multi-party-ecdsa`, `https://docs.rs/crate/multi-party-ecdsa`
* KeyMesh canonical digest: `docs/protocol/canonical-transaction.md`, `contracts/ethereum/src/KeymeshTx.sol`, `packages/protocol/src/canonical.ts`.
