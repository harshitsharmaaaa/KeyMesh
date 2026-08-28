# TSS Signing Protocol Specification — KeyMesh Phase 2.1 (Design)

> **Status:** DESIGNED — Phase 2.1 design only. NOT IMPLEMENTED, NOT AUDITED, NOT FORMALLY VERIFIED.
> **Decision:** ADR-001 (threshold ECDSA, CGGMP21/GG20 family). Exact cryptographic message equations are deferred to the selected library — this spec defines the KEYMESH layer above it.
> **Related:** `docs/architecture/tss-mpc-architecture.md`, `docs/security/tss-threat-model.md`, `docs/security/tss-invariants.md`

## 1. Protocol Version

* **Signing protocol version:** `signingProtocolVersion = "cggmp21/v1"` (placeholder; must match the library's actual version string when integrated). Included in `sessionId` derivation and verified per session.
* **Canonical digest version:** `KEYMESH_TX_V1` (unchanged). See `docs/protocol/canonical-transaction.md`, `contracts/ethereum/src/KeymeshTx.sol:18`, `packages/protocol/src/canonical.ts:36`.
* **Versioning rule:** Bumping either digest or signing protocol version forces a new `sessionId` and invalidates presign tuples from prior versions.

## 2. Session Identity

### 2.1 Session ID

```
sessionId = keccak256(
  abi.encodePacked(
    wallet,                 // 20 bytes
    chainId,                // uint256 BE
    nonce,                  // uint256 BE
    digest,                 // 32 bytes (KEYMESH_TX_V1)
    policyVersion,          // uint64 BE
    signingProtocolVersion, // bytes, e.g. "cggmp21/v1"
    random                  // 32 bytes CSPRNG from coordinator
  )
)
```

* 256-bit, collision-resistant, non-timestamp. Uniqueness is probabilistic (2^-256).
* Deterministic binding: changing any input changes `sessionId`.
* `sessionId` is never reused, even after `SigningAborted`/`SigningFailed`.

### 2.2 Participant Identity

* **ParticipantId** = fingerprint of long-term identity key (distinct from signing share). Example: `keccak256(identityPubkey)` truncation or ed25519 key id.
* Registry: `RecoveryManager` + identity registry (guardian-governed). Participants authenticate messages by signing under identity keys.

### 2.3 Transaction Binding

Participants receive the full `KeymeshTransaction` fields (or at least `(wallet, chainId, nonce, to, value, data, expiry)`) before signing, re-derive the digest independently, and verify it matches the `digest` in `sessionId`. Blind signing of opaque hashes is forbidden.

## 3. Message Types

> Exact payload formats for `Round1`/`Round2`/`Round3` are **DESIGN DECISION REQUIRED** — they come from the chosen library (CGGMP21 presign/sign). The KEYMESH layer wraps them with session binding.

| Message Type | Direction | Authenticated | Bound To | Single-Use |
|--------------|-----------|---------------|----------|------------|
| `SessionEstablish` | Coordinator → participants | Yes (coordinator identity) | `sessionId`, `digest`, `policyVersion` | No (one per session) |
| `SessionConfirm` | Participant → coordinator | Yes (participant identity) | `sessionId`, `digest` | No |
| `RoundMessage` (presign r1) | Participant → coordinator → participants | Yes | `sessionId`, round number | Presign tuple single-use |
| `RoundMessage` (presign r2) | Participant → coordinator → participants | Yes | `sessionId`, round number | Single-use |
| `RoundMessage` (presign r3) | Participant → coordinator → participants | Yes | `sessionId`, round number | Single-use |
| `ShareMessage` (online sign) | Participant → coordinator | Yes | `sessionId`, `digest` | One per session |
| `Abort` | Any → all | Yes | `sessionId`, reason | Terminal |
| `AggregatedSignature` | Coordinator → chain / participants | Verifiable via `ecrecover` | `digest` | One per session |

Every message carries `(sessionId, round, sender ParticipantId)` and is signed/MACed under the sender's identity key. Verification precedes any cryptographic processing.

## 4. Message Sequencing

```
Coordinator                         Participants
    │                                    │
    ├─ SessionEstablish (digest,        ─┤  Verify digest, policyVersion, authorization
    │   policyVersion, sessionId)        │
    │                                    ├─ SessionConfirm (optional ack)
    │◄───────────────────────────────────┤
    │                                    │
    │  (Presign, may be offline/precomputed)
    │                                    │
    ├─ Round1 (commitments, ZK proofs) ─┤  Verify per-participant proofs
    │◄─ Round1 responses ────────────────┤
    ├─ Round2 (Paillier proofs, etc.)   ─┤
    │◄─ Round2 responses ────────────────┤
    ├─ Round3 (finalize presign tuple)  ─┤
    │◄─ Round3 responses ────────────────┤  Presign tuple stored (single-use, encrypted)
    │                                    │
    │  (Online, after transaction known) │
    │                                    │
    ├─ ShareMessage (digest, proof)    ─┤  One online round
    │◄─ ShareMessages (t participants) ──┤
    │                                    │
    ├─ Aggregation (verify t proofs)    ─┤
    ├─ (r,s,v) low-s canonicalized      ─┤
    ├─ Verify ecrecover → wallet         ─┤
    └─ Submit to KeymeshWallet.execute  ─┘
```

* **Rounds:** Presign = 3 rounds (CGGMP21 typical); online sign = 1 round. If presign tuples are precomputed, online signing is 1 round. Library may vary — this sequence is conceptual.
* **Timeout:** Per-round timer (e.g., 5s); on timeout → `SigningAborted`, presign zeroized, retry with new `sessionId`.
* **Ordering:** Strict round order; out-of-order or duplicate round messages rejected (TSS-INV-06).

## 5. Transaction Binding

* **Session establishment:** Coordinator discloses `KeymeshTransaction` fields; participants re-derive `digest = keccak256(KEYMESH_TX_V1 payload)` via the canonical encoder (same code as `packages/protocol/src/canonical.ts` / `crates/keymesh-core/src/transaction` / `contracts/ethereum/src/KeymeshTx.sol`).
* **Share generation:** Participants verify `(wallet, chainId, nonce, digest, policyVersion)` before producing a share. Mismatch → reject, no share produced (TSS-INV-07, TSS-INV-11).
* **Aggregation:** Coordinator verifies that all shares correspond to the same `digest`/`sessionId` before combining.

## 6. Failure Semantics

| Event | State Transition | Presign State | Evidence |
|-------|------------------|---------------|----------|
| Timeout waiting for round | `SigningStarted → SigningAborted` | Zeroized | `Abort{sessionId, reason: "timeout", round}` |
| Invalid proof from `P_i` | `SigningStarted → SigningFailed` | Zeroized | `Abort{sessionId, reason: "invalid_proof", culprit: P_i, transcript}` (identifiable abort) |
| Wrong digest / session / round | Rejected, then `SigningFailed` or `Aborted` depending on whether it is attributable | Zeroized | Same as above |
| Coordinator crash | Timeout → `SigningAborted` | Zeroized | Retry with new coordinator/sessionId |
| All shares valid | `SigningStarted → SigningCompleted` | Consumed (single-use) | Aggregated `(r,s,v)` |

*No late message can resurrect a terminal session.* `sessionId` is retired on terminal transition.

## 7. Abort Semantics

* **States:** `SigningStarted`, `SigningCompleted`, `SigningAborted`, `SigningFailed` (see architecture doc §14).
* **Monotonic:** Terminal states reject every transition; `SigningAborted`/`SigningFailed` can never become `SigningCompleted` (TSS-INV-10).
* **Cleanup:** Presign tuples zeroized; session keys zeroized; `sessionId` never reused.
* **Retry:** New `sessionId`, fresh `random`, fresh presign nonces — never reuse `k` (TSS-INV-13).
* **Aborted signing is not on-chain authorized:** Nonce not consumed, `PolicyManager` authorization not consumed, no `TransactionExecuted` event.

## 8. Signature Output

* **Format:** Standard Ethereum ECDSA `(r, s, v)` where `r,s` are 32 bytes, `v ∈ {27,28}`, `s` canonicalized to low-`s` (`s ≤ secp256k1n/2`) as in Phase 1.
* **Verification:** `ECDSA.recover(digest, (r,s,v)) == thresholdAddress` and `thresholdAddress` is an authorized device of `KeymeshWallet`. No contract changes.
* **Aggregation:** Coordinator combines `t` share contributions and verifies per-share ZK proofs before emitting the final signature. Invalid share proofs → `SigningFailed`.

```ts
// Conceptual output (not yet implemented)
type ThresholdSignature = {
  r: `0x${string}`; // 32 bytes
  s: `0x${string}`; // 32 bytes, low-s
  v: 27 | 28;
  digest: `0x${string}`;
  sessionId: `0x${string}`;
};
```

## 9. Open Design Decisions

These fields are **DESIGN DECISION REQUIRED** and must be fixed in Phase 2.2 when the library is selected:

* [ ] Exact presign/online message byte formats (library-defined).
* [ ] Concrete `signingProtocolVersion` string (library version).
* [ ] Presign tuple storage format and encryption.
* [ ] Coordinator discovery / failover for the device-anchored coordinator.
* [ ] Timeout values per round.

No cryptographic message equations are invented here — they belong to the audited library.

## 10. Non-Goals of This Spec

* Re-deriving CGGMP21/GG20 internals (Paillier, ZK proofs, etc.).
* Implementing the protocol (Phase 2.1 is design only).
* Changing `KEYMESH_TX_V1` or `KeymeshWallet` verification.

## 11. Traceability

Every section maps to invariants and threat-model entries:

* Session binding (§2.1) → TSS-INV-04/06/07, threats 4.6-4.8.
* Transaction binding (§5) → TSS-INV-03/07/11/15, threat 4.11.
* Abort semantics (§7) → TSS-INV-10, failure matrix.
* Signature output (§8) → Ethereum compatibility (architecture doc §19).
