# TSS/MPC Architecture — KeyMesh Phase 2.1 (Design)

> **Status:** DESIGNED — Phase 2.1 design only. NOT IMPLEMENTED, NOT AUDITED, NOT FORMALLY VERIFIED.
> **Decision:** ADR-001 selects threshold ECDSA (CGGMP21/GG20 family) as the cryptographic direction; this document designs the surrounding system.
> **Invariant source:** `docs/security/tss-invariants.md`
> **Protocol spec:** `docs/protocol/tss-signing-protocol.md`
> **Threat model:** `docs/security/tss-threat-model.md`

## 1. System Overview

Threshold signing is **off-chain**. The blockchain sees one standard ECDSA signature recovered via `ECDSA.recover` in `KeymeshWallet.sol:209`. No contract changes, no new digest.

```
                    KEYMESH AUTHORIZATION
                           │
                           ▼
                    Transaction digest  (KEYMESH_TX_V1 canonical)
                           │
                           ▼
                    Signing session  (sessionId bound to wallet/nonce/digest/policyVersion)
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
         Participant A  Participant B  Participant C   (n=3, t=2 example)
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                 Threshold signing protocol (CGGMP21/GG20, off-chain)
                           │
                           ▼
                  ONE valid ECDSA signature (r,s,v low-s)
                           │
                           ▼
                     Ethereum  (KeymeshWallet.execute verifies via ecrecover)
```

The rest of KeyMesh does not know whether signing was single-key or threshold:

```
Transaction Authorization
          │
          ▼
     Signing Provider  (abstraction)
          │
      ┌───┴────┐
      │        │
      ▼        ▼
Single ECDSA  Threshold ECDSA  (future: Threshold EdDSA for Solana)
```

## 2. Component Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                        KeyMesh Application Layer                      │
│  PolicyManager (authorization)   RecoveryManager (participant governance) │
│         │                                   │                        │
│         └──────────────┬────────────────────┘                        │
│                        ▼                                             │
│              Signing Provider (interface)                               │
│    ┌───────────────────┼───────────────────┐                          │
│    │                   │                   │                          │
│ SingleKeyProvider  ThresholdProvider   (Future) EdDSAProvider        │
│    │                   │                                          │
│    │           ┌───────┴────────┐                                    │
│    │           │  Coordinator   │  (relay, untrusted for safety)     │
│    │           │  Session Mgr   │  (lifecycle, timeouts, abort)      │
│    │           └───────┬────────┘                                    │
│    │         ┌─────────┼─────────┐                                   │
│ Participant A  Participant B  Participant C  (each: share + identity key + storage) │
│    └─────────────────────────────────────────────────────────────────┘
│                        │                                             │
│                        ▼                                             │
│              KeymeshWallet (on-chain)  — ecrecover over KEYMESH_TX_V1 │
└──────────────────────────────────────────────────────────────────────┘
```

### Boundaries

* **PolicyManager** — knows nothing about threshold internals; it authorizes *what* can be signed, not *how*.
* **RecoveryManager** — governs *who* is in the participant set; it does not hold shares.
* **Coordinator** — relays, never learns the key, cannot forge.
* **KeymeshWallet** — verifies one ECDSA signature; blind to TSS.

## 3. Participant Model

* **Participant** = a logical signing node holding one share `x_i` of the threshold key and one long-term **identity key** (e.g., ed25519 or secp256k1 key distinct from the signing share) for authenticating protocol messages.
* **Identity vs. share:** Separate keys so compromise of the network identity does not automatically yield the signing share (defense in depth), and vice versa. Identity keys are governed by `RecoveryManager` (guardian quorum + timelock) when participants rotate.
* **Environments (not mandated):** Device, HSM/TEE when available, server, encrypted local storage. See §7.
* **Threshold:** `n` total, `t` required. Default guidance `2-of-3` for MVP; `3-of-5` for higher security; `n - t` offline tolerated.

## 4. Coordinator Model

* **Selected:** Wallet/device-anchored **central coordinator** for MVP (the wallet owner or their primary device acts as coordinator). Fully decentralized / leader-election is deferred — it adds complexity without improving the threshold guarantee.
* **Trust:** Untrusted for safety. Coordinator powers:
  * ✅ Relay messages, assign `sessionId`, enforce timeouts, abort/retry.
  * ❌ Cannot learn the private key, sign alone, change the transaction digest (session binding detects it), bypass `t` (aggregation verifies proofs).
* **Powers that remain:** DoS (withhold messages), delay, reorder — these are liveness failures, mitigated by timeouts and participant-set rotation via governance.

## 5. Key Lifecycle

```
KEY GENERATION (DKG)
      ↓
KEY SHARE DISTRIBUTION  (verified via commitments/proofs)
      ↓
KEY ACTIVATION          (public key derived → Ethereum address confirmed)
      ↓
SIGNING                 (threshold protocol per transaction)
      ↓
KEY REFRESH             (resharing, public key unchanged)
      ↓
PARTICIPANT REPLACEMENT (guardian-governed resharing/rotation)
      ↓
KEY RECOVERY            (guardian quorum + timelock → new participant set)
      ↓
KEY RETIREMENT          (wallet migration or deprecation)
```

| Stage | Inputs | Participants | Outputs | Crypto Material | Persistent State | Guarantees | Failure Behavior |
|-------|--------|--------------|---------|-----------------|------------------|------------|-------------------|
| **Key Generation (DKG)** | `n`, `t`, participant identities | All `n` | Verified shares `x_i`, group public key `X` | Shares, commitments, ZK proofs | Shares encrypted at rest; public key published | No trusted dealer; malicious DKG participant detected | Abort, zeroize, retry with fresh randomness |
| **Share Distribution** | DKG commitments | All `n` | Each `P_i` holds `x_i` | Encrypted `x_i` | Per-participant share store | Only `P_i` can decrypt `x_i` | Undelivered share → DKG abort |
| **Activation** | Group public key `X` | Wallet + all `n` | Ethereum address `addr = keccak256(X)[12:]` | `X` | Wallet ↔ `X` binding | Address deterministic from `X` | Mismatch → activation rejected |
| **Signing** | `digest`, `sessionId`, policy binding | Any `t` of `n` | ECDSA `(r,s,v)` | Secret-shared `k`, share proofs | Presign tuples (single-use) | `< t` cannot forge; `k` never reconstructed | Abort → zeroize presign, new `sessionId` |
| **Key Refresh** | Existing shares, new randomness | All `n` (or `t` if proactive) | New shares `x_i'` same `X` | Resharing proofs | New share versions | Public key unchanged | Failure → old shares remain valid |
| **Participant Replacement** | Governance approval + resharing | Old/new sets | New shares for new set, same or new `X` | Resharing/rotation proofs | New participant registry | Gated by guardian quorum | Rollback to old set |
| **Key Recovery** | Guardian quorum + timelock | Guardians + new participants | New participant set (reshared or rotated) | New DKG or resharing | Updated registry + share versions | Governance threshold holds | Recovery FSM remains authoritative |
| **Retirement** | Guardian-governed migration | Governance | Key material destroyed | Zeroization proofs (operational) | Tombstone | No residual signing capability | — |

## 6. DKG Lifecycle

* **How shares are created:** Verifiable DKG (Feldman VSS / CGGMP21 DKG): each participant acts as dealer for a random polynomial, commits to coefficients, proves correctness via ZK; shares are combined. No single dealer.
* **Correct behavior proofs:** Per-dealer commitments + Schnorr-style ZK proofs that shares lie on the committed polynomial.
* **Participant authentication:** Every DKG message signed under long-term identity keys; identity registry is the source of truth.
* **Malicious detection:** Any participant whose proof fails is flagged (identifiable abort); honest participants abort DKG and attribute failure.
* **Public key derivation:** `X = Σ X_i` where each `X_i` is derived from verified commitments; all participants compute and cross-check `X` before activation.
* **Group signing address:** `address = keccak256(uncompressed X)[12:]` (same as Ethereum address derivation from secp256k1 pubkey, as used by `KeymeshWallet`). Verification: wallet confirms `X` maps to its expected address before activation; mismatch is a hard error.

```
threshold public key (X, secp256k1)
       ↓  keccak256(X) low 20 bytes
Ethereum address  →  KeymeshWallet instance → isDeviceAuthorized(X-derived address) conceptually
```

At activation, the threshold address is registered as the wallet's authorized device (via `RecoveryManager` governance if rotating from a single key).

## 7. Key Share Storage

* **Possible environments:** Device secure storage, HSM/TEE when available, server encrypted volume, encrypted local storage (e.g., OS keychain + file). No hardware mandate — the design must be secure on all, stronger on HSM/TEE.
* **Share encryption:** At-rest shares encrypted with a participant-local wrapping key (platform keychain, HSM, or OS-provided). Wrapping key never leaves the participant's security boundary.
* **Share authentication:** MAC over the encrypted share; integrity verified before every use; tampered share → participant refuses to sign and signals refresh.
* **Access control:** Share accessible only to the signing process; no share in logs, crash dumps, or backups unencrypted.
* **Backup:** Encrypted backup optional; restoring requires the wrapping key; backup channel authenticated.
* **Rotation:** Via refresh (same `X`) or replacement (governed).
* **Destruction:** Zeroization on share deletion, device decommission, or retirement; memory zeroized on drop.
* **Compromise consequence:** Leakage of one share leaks only that share. `< t` leaks do not yield forgery; the protocol's security degrades gracefully until `t` leaks. Refresh bounds exposure to one epoch.

## 8. Signing Session Model

A signing session is uniquely associated with:

```
wallet
transaction digest  (KEYMESH_TX_V1: wallet|chainId|nonce|to|value|data|expiry)
nonce
policy version  (PolicyManager.policyVersion(wallet))
authorization state (Authorized vs. Pending — must be Authorized)
signing protocol version (e.g., "cggmp21/v1")
session ID  (256-bit random + deterministic binding)
```

**Session ID derivation (design):**

```
sessionId = keccak256(
  wallet || chainId || nonce || digest || policyVersion || signingProtocolVersion || random(32 bytes)
)
```

* `random` is 256-bit CSPRNG from coordinator; uniqueness is probabilistic (collision negligible) and deterministic binding makes collisions harmless — they would be distinct sessions with different `random`.
* `sessionId` is never derived from timestamp alone.

**Replay prevention:** Every protocol message includes `sessionId`; participants reject messages whose `sessionId` mismatches the established session or whose `digest`/`wallet`/`nonce` binding mismatches.

## 9. Signing Protocol Lifecycle (Conceptual)

Exact rounds come from the selected library; the conceptual flow below maps to CGGMP21's presign + sign:

```
REQUEST  (PolicyManager authorizes digest; coordinator creates sessionId)
  ↓
AUTHENTICATE PARTICIPANTS  (verify identity keys, check authorization state)
  ↓
SESSION ESTABLISHMENT  (participants confirm digest + sessionId + policyVersion)
  ↓
ROUND 1 — Presign (if not precomputed): commit to nonce shares, ZK proofs
  ↓
ROUND 2 — Presign: Paillier/Bulletproof-style proofs, nonce derivation
  ↓
ROUND 3 — Presign: finalize presign tuple (single-use, stored encrypted)
  ↓
SIGNATURE SHARE GENERATION  (online round: each participant produces share over digest using presign tuple)
  ↓
SIGNATURE AGGREGATION  (coordinator aggregates t shares, verifies proofs)
  ↓
FINAL ECDSA SIGNATURE  (r,s,v) low-s canonicalized
  ↓
VERIFY  (ecrecover → wallet address; PolicyManager checks still Authorized; KeymeshWallet.execute consumes nonce)
```

*Presigning* (rounds 1-3) can be done offline before the transaction is known, reducing online latency to 1 round. The design encourages presign pooling.

`DESIGN DECISION REQUIRED` marks where the library fixes the exact message types — the interface is not invented here.

## 10. Participant Failure Handling

| Failure | Detection | Expected State | Recovery Action | Security Impact |
|---------|-----------|----------------|-----------------|-----------------|
| Participant offline before session | Timeout on session establishment | `SigningAborted` | Retry with alternate subset (any `t` honest) | None (liveness) |
| Disappears mid-session | Round timeout | `SigningAborted` | Zeroize presign, new `sessionId`, fresh nonces | No `k` reuse if zeroized |
| Sends invalid message/proof | Proof verification | `SigningFailed` (identifiable) | Abort, evidence recorded, optionally rotate participant via governance | No forgery |
| Times out | Timer per round | `SigningAborted` | Retry with fresh presign | No state corruption |
| Sends conflicting messages (equivocation) | Commitment cross-check | `SigningFailed` (identifiable) | Abort, attribute, governance action | No forgery |

No partial state may produce an invalid signature — aggregation verifies all proofs before emitting `(r,s,v)`.

## 11. Malicious Participant Handling

| Misbehavior | Effect |
|-------------|--------|
| Invalid message / invalid proof | Rejected; attributable abort |
| Wrong round / wrong session | Rejected (session + round binding) |
| Wrong digest | Rejected (digest binding) |
| Duplicate message | Rejected (deduplication) |
| Conflicting message (equivocation) | Detected via commitments; attributable abort |

**Policy:** Reject participant's message, abort session, record evidence (the invalid message + proof transcript). Optionally restart with another `t`-subset. Do not claim Byzantine tolerance beyond identifiable abort — liveness requires `t` honest online.

## 12. Participant Authentication

* **Participant identity:** Long-term identity key per participant (distinct from signing share), registry governed by `RecoveryManager`.
* **Session identity:** `sessionId` derived as above; no timestamp-only binding.
* **Message sequence:** Round number + `sessionId` in every message.
* **Message authentication:** Each message signed/MACed under identity key; verified before any cryptographic processing.
* **Replay prevention:** Application-level binding to `(sessionId, digest, wallet, nonce, chainId, policyVersion, signingProtocolVersion)` — TLS alone does not solve this.
* **Application-level:** Even with TLS, an attacker who compromises the coordinator must not be able to replay across sessions — hence the inner authentication.

## 13. Coordinator Design

* **Choice:** Central coordinator anchored to wallet/device for MVP.
* **Alternative deferred:** Leader election / fully decentralized coordination — more complex, not needed for threshold safety.
* **Coordinator MUST NOT:** Learn the private key, sign alone, change the transaction digest (detected via session binding), bypass quorum.
* **Coordinator powers:** Assign `sessionId`, relay, enforce timeouts, aggregate, submit to chain. All powers are observable; misbehavior is attributable via transcripts.

## 14. Abort and Recovery Semantics

```
SigningStarted
    ├─→ SigningCompleted  (t valid shares → aggregated signature → verified)
    ├─→ SigningAborted    (timeout, offline, retryable — presign zeroized)
    └─→ SigningFailed     (malicious proof, attributable — evidence recorded)
```

* Terminal states are monotonic; no transition from `Aborted`/`Failed` to `Completed`.
* Session state cleaned up; `sessionId` retired (never reused).
* An aborted signing never becomes on-chain authorized: nonce not consumed, `PolicyManager` authorization not consumed, no external call.

## 15. Key Refresh

Conceptually:

```
Shares A/B/C
      ↓  refresh protocol (resharing, verifiable)
New shares A'/B'/C'
      ↓
same public key X
same Ethereum address (keccak256(X))
```

* **Property:** Public key / address unchanged after successful refresh. Participants verify `X` unchanged before committing.
* **When:** Proactively on an epoch (e.g., monthly) or on demand after suspected compromise.
* **How:** CGGMP21 resharing: participants re-randomize shares with new polynomials that sum to same secret; proofs verify preservation.
* **Replacement without address change:** Possible via resharing when participant set changes but `X` preserved.
* **Failure:** If refresh fails, old shares remain valid — no half-state.

## 16. Participant Replacement

```
A B C
  ↓  B compromised
remove B
  ↓
A C D   (D is new participant)
```

* **Complete resharing required?** For address preservation, yes — resharing among the new set. For address rotation, a fresh DKG is performed.
* **Public key changes?** No if resharing; yes if rotation. The design prefers resharing (preserves wallet address); rotation is the escape hatch for catastrophic compromise.
* **Threshold changes?** Possible during resharing (e.g., `2-of-3 → 3-of-5`); must be governed.
* **Recovery governance required?** Yes — `RecoveryManager` guardian quorum + timelock authorizes participant-set changes, same as device replacement today.

## 17. Integration with KeyMesh Recovery

Separate concerns:

```
RecoveryManager
    ↓  changes authorization / participant governance (who may sign, who is guardian)
    ——————————————————
TSS key lifecycle
    ↓  changes cryptographic shares (how signing happens)
```

* Recovery changes who is in the participant set; TSS lifecycle changes the shares those participants hold.
* A recovery that replaces a participant triggers a resharing (or rotation) in the TSS layer, but the two state machines remain distinct.
* Recovery's guardian model is independent of the signing threshold — guardians are not signing participants (though an entity could be both, as separate roles).

## 18. Integration with PolicyManager

```
Transaction
    ↓
PolicyManager  (classify → DEVICE_ONLY or DEVICE_PLUS_GUARDIANS)
    ↓  authorization requirements (per-digest, version-bound)
Signing layer  (single-key or threshold — unaware of policy internals)
    ↓  TSS/MPC (if threshold)
ONE ECDSA sig → KeymeshWallet.execute → PolicyManager.consumeAuthorization
```

* `PolicyManager` semantics unchanged by threshold deployment; it remains unaware of the internal TSS protocol.
* The future flow remains: transaction → policy evaluation → authorization requirements → signing layer → TSS/MPC.
* The signing layer checks that a `DEVICE_PLUS_GUARDIANS` transaction has an `Authorized` authorization before starting a signing session.

## 19. Ethereum Compatibility

```
canonical KEYMESH digest  (keccak256(KEYMESH_TX_V1 payload))
        ↓
ECDSA signature (r,s,v low-s)  ← threshold protocol produces this
        ↓
existing KeymeshWallet  (ECDSA.recover, no changes)
```

* **Contract changes required:** `hh7e9v` — **No changes** for the basic threshold path. `KeymeshWallet` continues to verify one ECDSA signature. `KEYMESH_TX_V1` digest preserved; no second incompatible digest.
* **Future minimal interface changes (only if needed):** A signer abstraction (`isDeviceAuthorized` could conceptually check `thresholdAddress`) but the address derivation already makes this unnecessary — the threshold public key maps to one Ethereum address that is the authorized device.
* **Preservation:** Do not create a second digest; threshold signatures are over the same digest.

## 20. Future Solana Compatibility

Not implemented; analysis:

* **What can be shared:** Participant infrastructure, coordinator, session lifecycle, identity keys, storage encryption, refresh/replacement governance, `PolicyManager`/`RecoveryManager` patterns.
* **What must be chain-specific:** Curve and protocol — Ethereum needs ECDSA (secp256k1, CGGMP21), Solana needs EdDSA (ed25519, FROST or EdDSA TSS). The field `Curve` already exists in `crates/keymesh-core/src/crypto/mod.rs:27`.
* **Threshold EdDSA/Schnorr needed:** Yes — FROST or a threshold EdDSA scheme for Solana. ECDSA TSS cannot be reused for Ed25519.
* **Participant architecture multi-curve:** Yes — the same participant set can hold shares for multiple curves (separate DKGs per curve). A wallet could have an Ethereum threshold key (secp256k1) and a Solana threshold key (ed25519) managed by the same participants.

Do not force one primitive onto every chain — Ethereum gets CGGMP21 ECDSA, Solana gets FROST/EdDSA.

## 21. Cryptographic Library Evaluation

See ADR-001 for candidate table and evaluation. Summary:

* **Primary candidate:** `cggmp21` (Silence Labs) — CGGMP21, Rust, active.
* **Alternatives:** `synedrion`, `multi-party-ecdsa` (ZenGo GG18/GG20), `dfns cggmp`.
* **Dimensions evaluated:** Language, license, maintenance, audit history, algorithm, security model, threshold assumptions, malicious handling, key refresh, DKG, Ethereum compatibility, API quality, test coverage, ecosystem adoption.
* **No library claimed secure by popularity alone; audit status must be verified from authoritative sources in Phase 2.2.**

## 22. Build vs. Buy

* **Build ourselves:** Protocol/session management, authorization binding, KEYMESH domain separation, participant state machine, policy/recovery integration, coordinator liveness, share storage encryption/auth.
* **Reuse mature libraries:** Elliptic curve arithmetic, ECDSA primitives, hashing, commitments, ZK proofs, threshold cryptographic core.
* **Avoid implementing:** Low-level field arithmetic, Paillier, nonce generation.
* **Principle:** Never reimplement low-level primitives for educational novelty.

## 23. Cryptographic Assumptions

* **Cryptographic:** ECDSA (secp256k1) hardness, keccak-256 collision resistance, RNG soundness, library ZK proof soundness.
* **System:** Share storage encryption holds for `t` honest; identity keys isolated; network authentication checked; coordinator cannot forge.
* **Operational:** `< t` participants compromised per epoch; guardian diversity; refresh within epoch; transaction intent verified before signing.

## 24. Failure Model

| Failure | Detection | Expected State | Recovery Action | Security Impact |
|---------|-----------|----------------|-----------------|-----------------|
| Participant offline | Timeout | `SigningAborted` | Retry with alternate subset | Liveness |
| Participant malicious | Proof failure | `SigningFailed` (attributable) | Abort, evidence, governance rotation | No forgery |
| Coordinator offline | Timeout | `SigningAborted` | Retry with new coordinator | Liveness |
| Network partition | Timeout / commitment mismatch | `SigningAborted` | Heal then retry with fresh nonces | Liveness |
| Message replay | Session/digest binding | Rejected | — | No forgery |
| Message reordering | Round check | Rejected | — | No forgery |
| Share corruption | MAC failure | Refuse to sign | Refresh | Liveness |
| Participant replacement | Governance event | Resharing | Verify new shares | No silent address change |
| Key refresh failure | Proof failure | Old shares remain valid | Retry refresh | No forgery |
| Partial signing session | Timeout | `SigningAborted`, zeroize | New session, fresh nonces | No `k` reuse |

## 25. Performance Model (Theoretical, Not Benchmarked)

Do not fabricate numbers — dimensions only.

| Dimension | Factor | Note |
|-----------|--------|------|
| Number of participants `n` | 3-5 typical | Larger `n` → more bandwidth |
| Threshold `t` | 2-of-3 default | Higher `t` → more round trips |
| Protocol rounds | 3-4 presign + 1 online (CGGMP21) | Exact per library |
| Messages | `O(n)` per round (broadcast via coordinator) | Coordinator fan-out |
| Bandwidth | Commitments + proofs per round | Dominated by ZK proofs |
| Latency | Network RTT × rounds + presign availability | Presign pooling hides most latency |
| CPU | ZK proof generation/verification | Per participant |
| Memory | Presign tuple store | Bounded (single-use tuples) |
| Storage | Encrypted shares + presign pool | Small (KB per share) |

Actual measurements are **Phase 2.7** work; this model guides sizing only.

## 26. Security Invariants for TSS

See `docs/security/tss-invariants.md` — 16 design invariants (TSS-INV-01 … TSS-INV-16), all **DESIGNED** at this phase.

## 27. Future Interface Design

Conceptual (not yet implemented; no cryptographic implementation):

```ts
// packages/protocol/src/signing/types.ts  (future)
// No private key handling, no fake MPC.

type ParticipantId = string;              // identity key fingerprint
type SigningProtocolVersion = string;     // e.g., "cggmp21/v1"
type SessionId = `0x${string}`;           // 32 bytes, see §8

interface SigningProvider {
  // Key lifecycle
  createKey(params: { n: number; t: number; participants: ParticipantId[] }): Promise<PublicKey>;
  registerParticipant(id: ParticipantId): Promise<void>;
  removeParticipant(id: ParticipantId): Promise<void>;
  refreshShares(): Promise<void>;

  // Signing sessions
  startSigningSession(input: { wallet: Address; digest: Hex; nonce: bigint; policyVersion: number }): Promise<SessionId>;
  submitRoundMessage(sessionId: SessionId, msg: RoundMessage): Promise<void>;
  abortSigningSession(sessionId: SessionId, reason: string): Promise<void>;
  finalizeSignature(sessionId: SessionId): Promise<Hex>; // ECDSA (r,s,v) hex

  // Verification
  verifySignature(digest: Hex, signature: Hex, publicKey: Hex): Promise<boolean>;
}
```

Separation: key lifecycle vs. participant management vs. signing sessions vs. verification.

---

## Claim Level

TSS/MPC = **DESIGNED** · NOT IMPLEMENTED · NOT TESTED · NOT AUDITED · NOT FORMALLY VERIFIED

This document is a design that a cryptography engineer can review and challenge; no code in this phase implements threshold signing.
