# TSS/MPC Threat Model — KeyMesh Phase 2.1

> **Status:** DESIGNED — Phase 2.1 design only. NOT IMPLEMENTED, NOT AUDITED, NOT FORMALLY VERIFIED.
> **Scope:** Future threshold signing layer that produces ONE standard ECDSA signature over the canonical `KEYMESH_TX_V1` digest for `KeymeshWallet`. The blockchain remains unaware of the internal MPC/TSS protocol.
> **Baseline:** Phase 1 (single-device ECDSA) threat model remains authoritative (`docs/security/threat-model.md`). This document extends it.

## 1. System Under Analysis

```
Transaction Authorization (PolicyManager)
         │
         ▼
   Signing Provider  ← abstraction: single-key vs. threshold
         │
    ┌────┴────┐
    │         │
 Single   Threshold ECDSA (CGGMP21/GG20 family, off-chain)
 ECDSA          │
                ▼
          ONE valid ECDSA signature  →  KeymeshWallet.execute  →  Ethereum
```

* Signing happens off-chain; on-chain verification is unchanged.
* The signing provider is oblivious to the rest of KeyMesh except for the digest, nonce, wallet, chainId, policy version, and session ID it is asked to sign.
* Coordinator (if present) relays messages but must not be able to forge, learn the key, or bypass quorum.

## 2. Adversary Model

### 2.1 Honest-but-Curious Participant

* **Capability:** Follows the protocol byte-for-byte, but records every message and tries to infer the private key, shares of others, or long-term nonce material.
* **Goal:** Learn `x` or any share `x_i` belonging to another participant; link digests to identities.
* **Assumption:** Protocol provides privacy against `< t` such observers: transcript reveals nothing about the key beyond the final signature (zero-knowledge / semantic security of encryption layer). `t` observers can reconstruct — this is the threshold bound, stated honestly.

### 2.2 Malicious Participant

* **Capability:** Deviates arbitrarily: sends malformed messages, wrong rounds, invalid proofs, equivocated messages to different subsets, attempts to bias `k` or `r`.
* **Goal:** Forge a signature without quorum, cause an invalid signature to be accepted, bias the nonce to leak key material, or permanently stall the protocol.
* **Defense:** Identifiable abort (GG20/CGGMP21) — honest participants detect which party sent an invalid proof/message and abort with evidence. No valid signature is produced if any proof fails. Bias attacks are prevented by committed nonce generation + ZK proofs per round.

### 2.3 Compromised Participant

* **Capability:** Attacker controls the machine and extracts the local key share `x_i` and any ephemeral state not yet zeroized. May also control that participant's network.
* **Goal:** Combine stolen shares to forge; leak share for future forgery after refresh.
* **Threshold bound (example 2-of-3):** Secure if `≤ 1` participant compromised; **not secure if `≥ 2` compromised.** This bound is explicit and not overstated. With proactive refresh, a mobile adversary must compromise `t` participants *within one refresh epoch*.

### 2.4 Network Attacker

* **Capability (Dolev-Yao):** Intercept, delay, reorder, drop, replay, modify messages between participants and coordinator. Controls the network but not participant machines.
* **Goal:** Replay a signing session, substitute a digest, confuse session binding, cause nonce reuse.
* **Defense:** Application-level authentication and session binding (not TLS alone); every protocol message is authenticated and bound to `sessionId` + `digest` + `chainId` + `wallet` + `nonce`; replay across sessions/wallets fails authentication.

### 2.5 Malicious Coordinator

* **Capability:** Controls message relay; may attempt to confuse participants, fork sessions, change the transaction digest, replay messages, reorder rounds, or withhold messages (DoS).
* **Limitations (by design):** Coordinator **cannot** learn the private key, sign alone, change the transaction digest without detection (digest is session-bound and participants verify it), or bypass quorum (signature aggregation requires `t` valid share contributions verified by proofs).
* **Residual power:** Coordinator **can** deny service (refuse to relay), delay sessions, or attempt to partition participants — these are liveness failures, not forgery. Mitigations: timeouts, abort semantics, participant-set rotation via governance.

### 2.6 Collusion

* Up to `t - 1` participants may collude with any of the above (network attacker, coordinator).
* **Security holds** while `< t` participants are compromised/colluding.
* **Security fails** when `≥ t` collude — they can produce a valid signature on any digest. This is inherent to threshold cryptography and is documented, not hidden.

## 3. Trust Model

| Component | Trust | Why |
|-----------|-------|-----|
| Blockchain (Ethereum L1 consensus, `KeymeshWallet`, `PolicyManager`, `RecoveryManager`, `GuardianRegistry`) | **Trusted** (as trust anchor) | Ordered, public, censorship-resistant execution; contracts enforce nonce/expiry/device/authorization. Compromise of L1 is out of scope. |
| KeyMesh protocol (canonical `KEYMESH_TX_V1` encoding, digest, nonce model) | **Trusted** (if implemented correctly) | Deterministic, domain-separated, cross-language pinned. A bug here is a security bug — hence Phase 1.4 vectors. |
| Device / participant key-share storage (OS, secure storage, optional HSM/TEE) | **Partially trusted** | Must provide confidentiality + integrity for the share at rest; compromise of a single device leaks one share only. No single device is trusted with the full key. |
| Participant nodes (honest participants) | **Partially trusted** | Each is trusted to keep its share, follow the protocol, and not collude beyond threshold. `< t` may be compromised without forgery. |
| Guardians / Recovery governance | **Partially trusted** | Guardians authorize participant-set changes, not signatures. Compromise of `< quorum` guardians cannot change the signing set. Separate from signing quorum. |
| Coordinator | **Untrusted for safety, partially trusted for liveness** | Cannot forge or learn key; can deny service. Treated as untrusted relay with application-level defenses against digest/session confusion. |
| RPC provider / relayer | **Untrusted** | Can censor or give stale reads; cannot forge `ecrecover` without the key. Mitigated by wallet/chainId binding, multi-provider guidance, client-side validation. |
| Network | **Untrusted** | Dolev-Yao model; all protocol messages are application-authenticated. |
| Operating system / browser | **Untrusted** | Keylogger or memory dump on a participant leaks that participant's share; threshold limits blast radius to one share. |

## 4. Threat Catalog

For each threat: capability → attack → impact → mitigation → remaining assumption.

### 4.1 Single Participant Compromise

* **Capability:** Extract `x_i` from one participant's storage/memory.
* **Attack:** Attacker holds 1 share; attempts to forge or combine with network transcript.
* **Impact:** No forgery; no key leakage beyond one share (under threshold assumption).
* **Mitigation:** Threshold `t ≥ 2`; share encryption at rest; zeroization of ephemeral nonces; proactive refresh limits exposure window.
* **Assumption:** `< t` participants compromised; storage encryption key not co-located in same breach.

### 4.2 Multiple Participant Compromise (≥ t)

* **Capability:** Extract `t` shares (e.g., 2 of 3).
* **Attack:** Reconstruct or directly produce signatures on arbitrary digests.
* **Impact:** Full forgery — equivalent to private-key compromise.
* **Mitigation:** Diversify participant infrastructure/jurisdictions; hardware-backed storage; proactive refresh; honest-majority operational guidance. No cryptographic mitigation beyond threshold.
* **Assumption:** This case is **explicitly out of the security guarantee**; operational controls are the only defense.

### 4.3 Malicious Participant (Byzantine)

* **Capability:** Send invalid proofs, wrong round, equivocated messages.
* **Attack:** Bias `k`, produce invalid signature share, stall protocol.
* **Impact:** Denial of service; if undetected, potential key leakage via biased nonce.
* **Mitigation:** Per-round ZK proofs + commitments; identifiable abort — honest participants attribute failure to the malicious party and abort; session never yields a valid signature.
* **Assumption:** At least `t` honest participants remain for liveness; proofs are verified before aggregation.

### 4.4 Offline Participant

* **Capability:** Participant is unreachable before or mid-session.
* **Attack:** Natural failure or intentional DoS.
* **Impact:** Signing stalls if fewer than `t` remain; no forgery.
* **Mitigation:** Threshold tolerates `n - t` offline; timeouts trigger abort/retry with alternate subset; coordinator rotates participants if supported by library.
* **Assumption:** Enough honest participants are online within timeout.

### 4.5 Network Attacker (Intercept / Modify)

* **Capability:** Full Dolev-Yao on the wire.
* **Attack:** Modify or inject protocol messages.
* **Impact:** If unauthenticated, could substitute shares or proofs.
* **Mitigation:** Every message is authenticated with participant long-term identity keys (distinct from signing shares); session binding prevents cross-session injection. TLS is defense-in-depth, not the sole defense.
* **Assumption:** Participant identity keys remain uncompromised; application-level MAC/signature verified before processing.

### 4.6 Message Replay

* **Capability:** Capture valid round messages and replay in a new session.
* **Attack:** Replay a prior signing session's messages to get a signature on a new digest.
* **Impact:** Forgery if binding is weak.
* **Mitigation:** Messages are bound to `sessionId` (unique, non-timestamp), `digest`, `wallet`, `chainId`, `nonce`, `policyVersion`, `signingProtocolVersion`; replay across any of these fails verification. Session IDs are never reused.
* **Assumption:** Session ID generation is collision-resistant; binding is checked.

### 4.7 Message Substitution

* **Capability:** Replace a message's digest or payload while preserving authentication.
* **Attack:** Trick participant into signing a different transaction.
* **Impact:** Signature on attacker-chosen digest.
* **Mitigation:** Participants verify that the digest they are asked to sign matches the one bound in session establishment; any substitution fails session-digest consistency check.
* **Assumption:** Participant displays/verifies the intended transaction before signing (human/authorization layer).

### 4.8 Session Confusion / Forking (Malicious Coordinator)

* **Capability:** Fork a session into two with different digests; interleave messages.
* **Attack:** Cause participants to sign different digests thinking they are one session.
* **Impact:** Equivocation, potential double-sign or confused quorum.
* **Mitigation:** Coordinator cannot forge participant authentication; participants reject messages whose session binding does not match the established session; session ID is derived deterministically from `(wallet, nonce, digest, policyVersion, random)` and signed by participants during establishment.
* **Assumption:** At least `t` participants cross-check session establishment.

### 4.9 Nonce Reuse (k reuse)

* **Capability:** Force or trick the protocol into reusing the per-signature nonce `k`.
* **Attack:** Two signatures with same `k` under same key leak `x` directly.
* **Impact:** Catastrophic — full private key recovery from two signatures.
* **Mitigation:** Threshold protocol generates `k` as secret-shared random with commitments; `k` is never reconstructed; deterministic derivation is per-session and zeroized after use; presigning nonces are single-use and never re-randomized.
* **Assumption:** RNG is sound on each honest participant; library's nonce generation is correct (audited).

### 4.10 Signing Same Digest Twice

* **Capability:** Request two signing sessions for the same `digest` (same wallet/nonce).
* **Attack:** Obtain two signatures with different `k` on same digest.
* **Impact:** Not key-leaking (different `k`), but wastes quorum and may confuse authorization (though on-chain nonce prevents replay).
* **Mitigation:** On-chain nonce ensures only one execution; off-chain coordinator deduplicates session IDs per `(wallet, nonce)`; second session for same digest is rejected or yields a distinct signature that still only executes once.
* **Assumption:** Coordinator enforces at-most-one active session per `(wallet, nonce)`.

### 4.11 Conflicting Signing Requests

* **Capability:** Issue two different digests for the same `(wallet, nonce)` concurrently.
* **Attack:** Race to get the "wrong" transaction signed.
* **Impact:** If both get signed, only one executes (nonce), but the other signature is a valid authorization that could be submitted later if nonce handling is weak.
* **Mitigation:** Wallet nonce strictly sequential; only the first execution succeeds; the second signature becomes permanently invalid (`InvalidNonce`). Authorization layer should not approve conflicting digests.
* **Assumption:** Policy/authorization check happens before signing (see architecture).

### 4.12 Malicious Key-Generation Coordinator / Dealer

* **Capability:** Coordinator of DKG biases key generation or injects a backdoored share.
* **Attack:** Learn the key, create a trapdoor, or make the key unrecoverable.
* **Impact:** Key compromise or loss of funds.
* **Mitigation:** Verifiable DKG: each participant proves correct Feldman/VSS sharing; public key is derived deterministically and verified by all participants against commitments. No trusted dealer; coordinator is untrusted relay.
* **Assumption:** At least `t` honest participants verify DKG proofs.

### 4.13 Malicious Recovery Participant

* **Capability:** Guardian or device that participates in participant-replacement governance colludes.
* **Attack:** Approve a malicious participant set change.
* **Impact:** Attacker-controlled participant joins the signing set.
* **Mitigation:** Participant-set changes are governed by `RecoveryManager` / `PolicyManager` guardian quorum + timelock, same as today. Signing shares and recovery governance are separate concerns — recovery changes who holds shares, not the shares themselves without resharing.
* **Assumption:** Recovery governance threshold holds.

### 4.14 Participant Impersonation

* **Capability:** Attacker claims to be participant `B`.
* **Attack:** Inject messages as `B` to influence signing.
* **Impact:** Forgery or DoS if authentication is weak.
* **Mitigation:** Long-term identity keys per participant (distinct from signing shares); messages signed/MACed under identity keys; identity registry governed by recovery.
* **Assumption:** Identity keys are not co-located with signing shares in a way that one breach yields both.

### 4.15 Share Leakage (At Rest or In Transit)

* **Capability:** Read unencrypted share from disk, backup, or log.
* **Attack:** Combine leaked shares.
* **Impact:** Forgery if `t` shares leak.
* **Mitigation:** Shares encrypted at rest with participant-local keys (OS keychain / HSM / TEE when available); no share ever logged; backups are encrypted; refresh limits exposure window.
* **Assumption:** Platform keychain/HSM correctly isolates the wrapping key.

### 4.16 Key-Share Replacement (Stealth Resharing)

* **Capability:** Attacker with temporary access replaces a share with one they control, without changing the public key.
* **Attack:** Future threshold now includes attacker.
* **Impact:** Persistent compromise.
* **Mitigation:** Share refresh requires `t` honest participants; any refresh is authenticated and versioned; participants verify refresh proofs and public-key preservation.
* **Assumption:** Refresh protocol's verifiability (CGGMP21 reshare proofs).

### 4.17 Rollback / State Desynchronization

* **Capability:** Force a participant to revert to an old share version.
* **Attack:** Make honest participant use stale share, causing signing to fail or leak via version mismatch.
* **Impact:** DoS or potential inconsistency.
* **Mitigation:** Versioned share state; participants reject messages for old share versions; refresh commits are atomic.
* **Assumption:** Share versioning is enforced.

### 4.18 Partial Protocol Execution

* **Capability:** Abort mid-protocol after some participants committed nonces.
* **Attack:** Collect partial transcript, retry with different digest.
* **Impact:** If nonces are reused across retries, key leakage.
* **Mitigation:** Single-use presigning nonces; abort zeroizes presign state; retry generates fresh nonces — never reuse `k`.
* **Assumption:** Ephemeral state is zeroized on abort.

### 4.19 Participant Equivocation

* **Capability:** Send different round messages to different subsets.
* **Attack:** Split-view attack.
* **Impact:** Inconsistent signature shares.
* **Mitigation:** Coordinator broadcasts commitments; participants verify consistency via hashes/commitments; identifiable abort attributes equivocation.
* **Assumption:** Broadcast channel (coordinator) is not trusted to suppress evidence — participants gossip or coordinator misbehavior is attributable.

### 4.20 Denial of Service

* **Capability:** Flood coordinator, spam sessions, exhaust participant resources.
* **Attack:** Prevent legitimate signing.
* **Impact:** Liveness failure.
* **Mitigation:** Rate limiting, per-wallet session caps, timeouts, proof-of-authorization (policy layer) before signing session starts.
* **Assumption:** DoS is a liveness, not safety, violation — documented as acceptable to fail closed (no signature rather than wrong signature).

## 5. Assumptions Summary

| Layer | Assumption |
|-------|------------|
| Cryptographic | ECDSA (secp256k1) and hash (keccak-256) are secure; RNG is sound; library proofs are correct |
| Threshold | `< t` participants compromised; honest participants follow the protocol; at least `t` honest for liveness |
| System | Participant storage encryption holds for at least `t` honest; identity keys isolated from shares |
| Network | Application-level authentication checked even if TLS is bypassed |
| Operational | Guardian diversity; share refresh performed within epoch; signing authorization precedes signing |

## 6. Out of Scope

* Compromise of Ethereum consensus or `ecrecover` precompile.
* Coercion beyond timelock visibility.
* Privacy of transaction contents (public chain).
* Side-channel leakage beyond constant-time and zeroization guidance (not formally verified in Phase 2.1).

## 7. Review Cadence

Revisit this document when: the threshold protocol library is selected, DKG proofs change, coordinator trust is re-evaluated, a new chain adapter is added, or any dependency with privilege changes. Every claim here is **DESIGNED** — not yet **IMPLEMENTED**, **TESTED**, **AUDITED**, or **FORMALLY VERIFIED**.
