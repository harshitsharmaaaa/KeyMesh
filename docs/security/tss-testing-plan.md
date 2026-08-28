# TSS Testing Plan — Future (Phase 2.2+)

> **Status:** DESIGNED — no tests are implemented in Phase 2.1. This plan defines what MUST be tested before threshold signing ships.
> **Principle:** Every invariant in `docs/security/tss-invariants.md` maps to at least one test category below. No invariant is "tested by inspection."

## 1. Unit Tests

* **Scope:** Pure functions, state machines, serialization.
* **Targets:**
  * `SigningProvider` abstraction: single-key vs. threshold dispatch.
  * Session-ID derivation determinism and collision resistance.
  * Canonical digest re-derivation inside participant logic.
  * Participant identity key generation / verification.
  * Share storage encryption roundtrip (encrypt → decrypt → zeroize).
  * Policy-version binding check.
  * Low-`s` canonicalization of produced signatures.
* **Assertion style:** Deterministic vectors, no network, no crypto library integration yet.
* **Location (future):** `packages/protocol/src/signing/` and `crates/keymesh-core/src/signing/` unit tests.

## 2. Protocol Transcript Tests

* **Scope:** Golden transcripts for the chosen threshold protocol (CGGMP21/GG20).
* **Vectors:**
  * DKG transcript (3 parties, `t=2`) → expected public key.
  * Presigning transcript → presign tuple hash.
  * Signing transcript for `KEYMESH_TX_V1` vector 1 → expected ECDSA `(r,s,v)` and verified `ecrecover`.
* **Cross-language:** Same vectors asserted in TypeScript, Rust, and Solidity `TransactionDigest` style — any mismatch is a protocol bug.

## 3. Cross-Language Vectors

* **Canonical digest:** Reuse existing `vectors.ts` vectors 1-3; threshold path must produce signatures over identical digests.
* **Signature verification:** Threshold-produced `(r,s,v)` verified by `KeymeshWallet` logic in all three languages (TS `@noble/curves` verify, Rust `k256` verify, Solidity `ECDSA.recover`).
* **Negative vector:** Corrupted signature (flipped bit) must fail in all three.

## 4. Negative Tests

* **Single-share forgery:** Attempt signing with `< t` participants — must abort, no valid signature.
* **Coordinator-only forgery:** Coordinator alone attempts to produce signature — must fail.
* **Wrong digest:** Participant asked to sign `D2` after session bound to `D1` — must reject before share generation.
* **Wrong session/wallet/chainId/nonce:** Replay across any field — rejected.
* **Malformed proof:** Inject invalid ZK proof — identifiable abort, attributed participant.
* **Duplicate message / wrong round / wrong session:** All rejected.

## 5. Participant Failure Tests

* **Offline before session:** `n=3, t=2` with one offline — signing succeeds with remaining two.
* **Offline before session (below threshold):** `n=3, t=2` with two offline — signing fails, terminal `SigningAborted`, no invalid signature.
* **Disappears mid-session:** Participant drops after round 1 — timeout → abort → retry with alternate subset succeeds.
* **Timeout:** Round 2 not received within timeout — abort, presign zeroized, new session with fresh nonces.
* **Conflicting messages:** Participant sends two different round-2 messages — equivocation detected, abort, evidence recorded.

## 6. Malicious Participant Tests

* **Invalid proof / wrong round / wrong digest / duplicate message:** Each triggers identifiable abort, never a valid signature.
* **Bias attack (nonce manipulation):** Malicious participant attempts to bias `k` — honest participants detect via commitments; abort.
* **Equivocation (split view):** Send different messages to different subsets — detected via broadcast commitments.

## 7. Replay / Session Confusion Tests

* **Cross-transaction replay:** Transcript from signing `D1` replayed to sign `D2` — rejected (session/digest binding).
* **Cross-wallet replay:** Transcript from wallet `A` replayed for wallet `B` — rejected (wallet binding + `ecrecover` mismatch).
* **Cross-session replay:** Same `sessionId` reused — rejected (session ID retired after terminal state).
* **Coordinator forking:** Coordinator forks session into two digests — participants detect via session-establishment cross-check.

## 8. Key Refresh Tests

* **Refresh preserves public key:** Before/after refresh, `keccak256(pubkey)` / Ethereum address identical.
* **Old shares invalid after commit:** Signing with stale share version rejected.
* **Refresh failure atomicity:** Mid-refresh failure leaves old shares valid; no half-refreshed state can sign.
* **Mobile adversary window:** Refresh epoch shorter than expected compromise interval (operational test).

## 9. Participant Replacement Tests

* **Governance-gated:** Replacement without guardian quorum + timelock is rejected.
* **Resharing preserves key:** Replace `B` with `D` in `A,B,C → A,C,D` via resharing — address unchanged.
* **Rotation changes key:** Full DKG rotation — address changes, `RecoveryManager` flow required, old signatures invalid for new wallet.

## 10. Fuzzing

* **Canonical encoding fuzz:** Mutate every field of `KeymeshTransaction` independently — digest must change; signature must not verify on mutated digest.
* **Session-ID fuzz:** Randomize `(wallet, chainId, nonce, digest, policyVersion, random)` — session binding must hold.
* **Message fuzz:** AFL/libFuzzer-style mutation of protocol messages — malformed messages must be rejected before aggregation.
* **Handler:** `foundry` fuzz for contract boundary; `cargo-fuzz` for Rust codec; Vitest property tests for TS.

## 11. Property Testing

* **Properties (over arbitrary valid transactions):**
  * `hash(canonical(tx)) == digest` in all three languages.
  * `verify(pubkey, digest, sign(shares, digest)) == true` iff `≥ t` honest shares.
  * `verify(pubkey, digest', sign(shares, digest)) == false` for `digest' != digest`.
  * `address(thresholdPubkey) == wallet` derived address.
* **Tooling:** `proptest` (Rust), `fast-check` (TS), Foundry invariant.

## 12. Integration Tests

* **End-to-end (Anvil):** DKG → participant set → policy-gated transaction → threshold-sign → `KeymeshWallet.execute` succeeds; then replay same digest → `InvalidNonce`; then wrong digest → `UnauthorizedDevice`.
* **Recovery integration:** Guardian quorum approves participant replacement → resharing → new signing succeeds with new set, old set cannot sign.
* **Policy integration:** `DEVICE_PLUS_GUARDIANS` transaction without guardian authorization → signing session rejected before share generation.

## 13. Network Fault Injection

* **Chaos:** Delay, reorder, drop, duplicate messages (via test harness shim, not real network partitioning).
* **Partition:** Split `A|B,C` — signing stalls, then heals, then succeeds; no invalid signature produced during partition.
* **Coordinator crash:** Kill coordinator mid-session — participants time out, abort, and can retry with new coordinator.

## 14. Formal / Audit Hooks (Future)

* **Model checking:** TLA+ or similar for session state machine (monotonic terminal states, no resurrection).
* **Symbolic proof:** Dolev-Yao model for session binding (Tamarin/ProVerif) — optional, not gating.
* **External audit:** Required before mainnet; this plan is input to the audit scope.

## 15. Coverage Gates

* **Unit + transcript:** 100% of session state transitions.
* **Negative + malicious:** Every invalid transition in `tss-invariants.md` has a negative test.
* **Fuzz:** Minimum 256 runs × 128k calls per invariant suite (mirrors Phase 1.4 gates).
* **Integration:** Anvil end-to-end for every lifecycle stage (DKG, signing, refresh, replacement) plus failure paths.

## 16. Non-Goals for Testing

* Do not test the internal security of the chosen library's curve arithmetic beyond transcript vectors — that is the library's audit responsibility.
* Do not implement real network chaos in CI beyond harness-level fault injection.

---

## Traceability Matrix (Invariant → Test Category)

| Invariant | Categories |
|-----------|------------|
| TSS-INV-01, 02 | Negative, malicious, property |
| TSS-INV-03, 07, 15 | Cross-language, negative, fuzz, property |
| TSS-INV-04, 06 | Replay/session-confusion, property |
| TSS-INV-05 | Code audit + runtime attestation (no reconstruction path) |
| TSS-INV-08, 09 | Refresh, replacement, integration |
| TSS-INV-10 | Participant failure, integration, model checking |
| TSS-INV-11 | Malicious, negative |
| TSS-INV-12 | Malicious (identifiable abort) |
| TSS-INV-13 | Nonce-reuse negative, presign single-use |
| TSS-INV-14, 16 | Policy integration, negative |

## Execution Order (Phase 2.2+)

```
2.2  Cryptographic prototype        → unit + transcript + cross-language
2.3  Protocol/session implementation→ negative + failure + replay
2.4  SDK integration                → policy/recovery integration
2.5  Ethereum E2E                   → Anvil integration
2.6  Adversarial testing            → fuzz + property + fault injection
2.7  Performance evaluation         → latency/bandwidth/CPU (see architecture doc)
```
