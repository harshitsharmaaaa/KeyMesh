# TSS Security Review Checklist — Phase 2.1 (Design Review)

> **Status:** DESIGNED, NOT IMPLEMENTED, NOT AUDITED, NOT FORMALLY VERIFIED.
> Use this checklist to review the design documents and later to gate the implementation (Phase 2.6). Every item must be evidenced or marked `DESIGN DECISION REQUIRED`.

## How to Use

* For design review (Phase 2.1): check that each question is answered in `tss-mpc-architecture.md` / `tss-signing-protocol.md` / `tss-threat-model.md` / ADR-001.
* For implementation review (Phase 2.6): check that code + tests evidence each answer; failures are security bugs.

---

## 1. Distributed Key Generation (DKG)

- [ ] Is the DKG a true DKG (no trusted dealer) or is a dealer explicitly documented and justified?
- [ ] Does each participant prove correct Feldman/VSS sharing with ZK proofs verified by all others?
- [ ] Is the public key derived deterministically from commitments and verified by every participant before activation?
- [ ] Can a malicious DKG participant be detected and attributed (identifiable abort)?
- [ ] Is participant authentication during DKG bound to long-term identity keys (distinct from signing shares)?
- [ ] What happens if DKG fails mid-protocol — is state zeroized and retried with fresh randomness?
- [ ] How is the Ethereum address derived from the threshold public key? Is it `keccak256(pubkey)[12:]` verified off-chain and on-chain?

## 2. Threshold Corruption

- [ ] Is the threshold `t` vs. total `n` explicit and enforced? (Default `2-of-3` documented.)
- [ ] Is it stated that `< t` colluding participants cannot forge and `≥ t` can? (No overstated claims.)
- [ ] Are proactive refresh epochs documented to bound mobile-adversary exposure?
- [ ] Are participant diversity requirements (infrastructure, jurisdiction) documented as operational controls?

## 3. Participant Authentication

- [ ] Are participant identity keys distinct from signing shares?
- [ ] Is every protocol message signed/MACed under the identity key and verified before processing?
- [ ] Is the identity registry governed by `RecoveryManager` (guardian quorum + timelock)?
- [ ] Can a participant be impersonated by replaying an old identity signature across sessions?

## 4. Session Binding

- [ ] Is `sessionId` defined as a collision-resistant, non-timestamp value binding `(wallet, chainId, nonce, digest, policyVersion, signingProtocolVersion, random)`?
- [ ] Is `sessionId` included in every authenticated message and verified?
- [ ] Is cross-session replay (same messages, different `sessionId`) rejected?
- [ ] Is cross-wallet replay (same `sessionId` payload, different wallet) rejected?
- [ ] Is session ID never reused, even after abort?

## 5. Nonce Handling (ECDSA `k`)

- [ ] Is per-signature nonce `k` secret-shared and never reconstructed?
- [ ] Are presigning tuples single-use and zeroized on abort/retry?
- [ ] Is `k` reuse impossible across sessions, retries, and concurrent sessions for the same digest?
- [ ] Is RNG soundness per participant documented as an assumption with operational guidance?

## 6. Message Replay / Substitution

- [ ] Are messages bound to both `sessionId` AND `digest`?
- [ ] Does a participant re-derive the `KEYMESH_TX_V1` digest from disclosed fields before signing?
- [ ] Can the coordinator substitute the digest without detection? (Must be impossible.)
- [ ] Are duplicate messages in the same round rejected?
- [ ] Are out-of-order rounds rejected?

## 7. Coordinator Compromise

- [ ] What can a malicious coordinator do? (Enumerate: deny service, delay, reorder, fork sessions.) What can it NOT do? (Learn key, sign alone, change digest, bypass `t`.)
- [ ] Is coordinator behavior attributable via participant evidence (identifiable abort, transcript)?
- [ ] Are timeouts and retry semantics defined so coordinator DoS is liveness-only?

## 8. Share Leakage

- [ ] Where do shares live? (Device, HSM/TEE when available, encrypted local storage — no mandate, but properties defined.)
- [ ] How are shares encrypted at rest? (Wrapping key isolation, OS keychain/HSM.)
- [ ] Are shares ever logged, backed up unencrypted, or included in crash dumps?
- [ ] Is share access zeroized on drop and after presign abort?

## 9. Key Refresh

- [ ] Does refresh preserve the public key / Ethereum address? How is this verified by participants?
- [ ] Is refresh authenticated and versioned? Can a stale share version be used to sign?
- [ ] Is proactive refresh scheduled and bounded (epoch documented)?
- [ ] What happens if refresh fails mid-protocol — do old shares remain valid?

## 10. Participant Replacement

- [ ] Does replacement require guardian-governed authorization (quorum + timelock)?
- [ ] Is replacement implemented as resharing (public key preserved) vs. rotation (public key changes) — and is the distinction documented?
- [ ] Can replacement silently change wallet identity? (Must be impossible without governance.)
- [ ] Is the interaction with `RecoveryManager` (authorization) vs. TSS lifecycle (shares) kept separate?

## 11. Signature Malleability

- [ ] Are signatures canonicalized to low-`s` (as in Phase 1) before submission?
- [ ] Is `ecrecover` malleability handled by the existing `KeymeshWallet` checks? (Threshold layer must not produce high-`s`.)
- [ ] Is signature aggregation verified before submission to on-chain `execute`?

## 12. Nonce Generation / Randomness

- [ ] Is randomness sourced from OS CSPRNG per participant, not a shared seed?
- [ ] Is there a negative test for weak RNG (e.g., mocked deterministic RNG must not produce predictable `k`)?

## 13. Abort Handling / Failure Recovery

- [ ] Are states `SigningStarted → SigningAborted / SigningCompleted / SigningFailed` monotonic with no resurrection?
- [ ] Is session state cleaned up and session ID retired on abort?
- [ ] Is retry defined as new session with fresh `sessionId` and fresh presign nonces?
- [ ] Does an aborted signing never become on-chain authorized (nonce not consumed, authorization not consumed)?

## 14. Side Channels

- [ ] Are constant-time comparisons required for secret material?
- [ ] Is share/nonce memory zeroized on drop?
- [ ] Are timing oracles in proof verification considered? (Document assumption.)

## 15. Integration Boundaries

- [ ] Does `PolicyManager` remain unaware of threshold internals? (No policy semantics change.)
- [ ] Does `RecoveryManager` govern participant-set changes, not share material directly?
- [ ] Does `KeymeshWallet` require zero contract changes to verify threshold signatures? (Preserve `KEYMESH_TX_V1`.)
- [ ] Is transaction intent disclosed to participants before signing (no blind signing of opaque hash)?

## 16. Solana / Multi-Curve Future

- [ ] Is it documented what is shared vs. chain-specific (participant infra, session machinery shared; curve/protocol per chain)?
- [ ] Is Schnorr/FROST for Ed25519 explicitly deferred to Solana track, not forced onto Ethereum?

## 17. Library Vetting

- [ ] For the selected library (Phase 2.2), is there a verified audit report from an authoritative source (not popularity)?
- [ ] Are language, license, maintenance, honest/dishonest majority model, and identifiable-abort properties evidenced?

## 18. Claim Level Honesty

- [ ] Is every guarantee labeled `DESIGNED` / `IMPLEMENTED` / `TESTED` / `AUDITED` / `FORMALLY VERIFIED`?
- [ ] At Phase 2.1 close, is it stated that TSS is `DESIGNED` and NOT `IMPLEMENTED`/`AUDITED`?

---

## Sign-off

| Reviewer | Date | Verdict |
|----------|------|---------|
|          |      |         |
