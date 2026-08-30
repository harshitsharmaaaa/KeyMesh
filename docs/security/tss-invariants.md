# TSS Security Invariants — Design (Phase 2.1)

> **Status:** DESIGNED — not yet implemented, tested, audited, or formally verified.
> **Scope:** Invariants the threshold signing layer MUST satisfy when implemented. A violation is a security bug.
> **Upstream invariants:** All Phase 1 invariants (`docs/security/invariants.md`) remain authoritative and are not weakened.

## How to Read This Document

Each invariant lists: what must hold, why it matters, and where it will be enforced. The claim level is **DESIGNED** per `dl9k1d`:

```
DESIGNED  → stated here, not yet code
IMPLEMENTED → code exists
TESTED    → tests assert it
AUDITED   → external review
FORMALLY VERIFIED → machine-checked proof
```

At the end of Phase 2.1, every invariant below is **DESIGNED** only.

---

## TSS-INV-01 — Fewer Than Threshold Cannot Sign

**Statement:** No set of `< t` participants, even colluding with the coordinator and network attacker, can produce a valid ECDSA signature under the wallet's public key.

**Rationale:** Core threshold property; if `< t` could sign, compromise of one participant would be sufficient for forgery.

**Enforcement (future):** CGGMP21/GG20 protocol; share material is `t`-out-of-`n` secret-shared; signature aggregation requires `t` valid share contributions each verified by ZK proofs.

**Negative test (future):** With `n=3, t=2`, attempt signing with one honest participant + coordinator — must abort without a valid signature.

## TSS-INV-02 — Coordinator Cannot Sign Alone

**Statement:** The coordinator, even if malicious, cannot produce a valid signature without `t` honest participant shares.

**Rationale:** Coordinator is untrusted for safety; otherwise the coordinator is a single point of compromise.

**Enforcement:** Coordinator holds no share; signature shares are authenticated per participant; aggregation verifies per-share proofs.

## TSS-INV-03 — Signature Bound to Exact KEYMESH Digest

**Statement:** A threshold signature is valid only over the canonical `KEYMESH_TX_V1` digest that was established in the signing session. Changing any field (`wallet`, `chainId`, `nonce`, `to`, `value`, `data`, `expiry`, domain tag) invalidates the signature.

**Rationale:** Prevents transaction manipulation after approvals; preserves Phase 1 digest binding.

**Enforcement:** `hashKeymeshTransaction` / `KeymeshTx.digest` unchanged; protocol signs `digest` only; no alternate digest path.

## TSS-INV-04 — Session Cannot Be Replayed

**Statement:** No transcript from a completed (or aborted) session can be replayed to obtain a signature on a different digest, wallet, or nonce.

**Rationale:** Replay would turn one signing authorization into many.

**Enforcement:** Session ID derived from `(wallet, chainId, nonce, digest, policyVersion, signingProtocolVersion, random=256 bits)` and included in every authenticated message; participants reject messages whose session binding mismatches.

## TSS-INV-05 — Share Never Reconstructs Into Full Private Key During Normal Signing

**Statement:** During `SIGNING`, no single machine (participant, coordinator, or observer) holds the reconstructed private key `x`. The key exists only as shares `x_i`.

**Rationale:** Reconstruction would collapse threshold security to single-key security. This is the anti-pattern called out in `h3m2b4` — SSS+reconstruct is NOT TSS.

**Enforcement:** DKG variant where private key never exists centrally; signing uses MPC for `k^{-1}(H(m)+r·x)`; share combination happens only in the signature field, not via key reconstruction. Explicit negative: no code path reconstructs `x`.

**Note:** Key export (wallet migration) is out of scope and would require guardian-governed resharing, not silent reconstruction.

## TSS-INV-06 — Participant Messages Bound to Session

**Statement:** Every protocol message is authenticated and bound to the exact `sessionId`. A message from session `S1` is rejected in session `S2`.

**Rationale:** Prevents cross-session confusion, interleaving, and coordinator forking.

**Enforcement:** Application-level MAC/signature over `(sessionId, round, payload)` with participant identity keys; verification before processing.

## TSS-INV-07 — Participant Messages Bound to Transaction Digest

**Statement:** Every signature share is bound to the transaction digest established at session start. A share generated for digest `D1` cannot be aggregated into a signature for `D2`.

**Rationale:** Prevents malicious coordinator from swapping the transaction under signing participants.

**Enforcement:** Digest included in session establishment and re-verified before share generation; share proofs commit to the digest.

## TSS-INV-08 — Participant Replacement Cannot Silently Change Wallet Identity

**Statement:** Replacing a participant (or refreshing shares) without explicit guardian-governed authorization must not change the on-chain wallet address (the threshold public key). Any change to the wallet's signing public key requires a guardian quorum + timelock via `RecoveryManager`.

**Rationale:** Otherwise an attacker who compromises participant management could rotate the wallet's key.

**Enforcement:** Refresh preserves public key cryptographically (CGGMP21 resharing); participant replacement that changes the key is treated as key rotation and gated by recovery governance (see `RecoveryManager` interaction in architecture doc). Silent address change is impossible.

## TSS-INV-09 — Key Refresh Preserves Intended Public Key

**Statement:** A successful proactive share refresh produces new shares `x_i'` that correspond to the SAME public key / Ethereum address.

**Rationale:** Refresh must not brick the wallet or change its identity.

**Enforcement:** Refresh protocol is a re-randomization of shares under the same secret (or same public key via verifiable resharing); participants verify that the derived public key is unchanged before committing.

## TSS-INV-10 — Aborted Signing Cannot Become Authorized

**Statement:** A session that has entered `SigningAborted` or `SigningFailed` can never transition to `SigningCompleted` or yield a valid signature.

**Rationale:** Prevents race where a late message resurrects a failed session.

**Enforcement:** Monotonic state machine; terminal states reject every transition; signature aggregation is gated on `SigningCompleted` only; session IDs never reused.

## TSS-INV-11 — Malicious Participant Cannot Alter the Transaction Being Signed

**Statement:** No participant, even malicious, can cause the aggregated signature to be over a digest different from the one honest participants authorized.

**Rationale:** Otherwise a malicious participant + coordinator could trick honest participants into signing an attacker-chosen transaction.

**Enforcement:** All honest participants verify the digest before producing shares; malicious share with wrong digest fails proof verification; coordinator cannot substitute digest without breaking session binding authenticated by honest participants.

## TSS-INV-12 — Identifiable Abort (Attributable Failure)

**Statement:** If a signing session fails due to a malformed message or invalid proof, honest participants can identify which participant(s) sent the invalid message.

**Rationale:** Without attribution, a malicious participant can anonymously DoS signing forever.

**Enforcement:** GG20/CGGMP21 identifiable abort; proofs are per-participant; honest participants produce evidence (the invalid message + proof transcript).

**Protocol requirement:** Candidate library must provide identifiable abort — this is a selection criterion in ADR-001.

## TSS-INV-13 — Single-Use Presigning Nonces / No k Reuse

**Statement:** The per-signature nonce `k` (secret-shared) is generated freshly per signing attempt and never reused across sessions, retries, or aborts.

**Rationale:** ECDSA `k` reuse leaks the private key from two signatures.

**Enforcement:** Presigning tuples are single-use; abort zeroizes presign state; retry generates new `k`. No deterministic `k` derivation that could repeat. Library's nonce generation is trusted only if audited.

## TSS-INV-14 — Policy Version Binding

**Statement:** A signing session is bound to the `policyVersion` at session start. If `PolicyManager` version changes mid-session, the session aborts.

**Rationale:** Prevents signing under stale policy (mirrors Phase 1.3 `PolicyChanged` semantics).

**Enforcement:** `policyVersion` included in session ID and verified before aggregation; consumption still checks `policyVersion` on-chain.

## TSS-INV-15 — Digest / Nonce / ChainId Consistency

**Statement:** The digest signed by the threshold protocol must be byte-identical to `KeymeshTx.digest(wallet, chainId, nonce, to, value, data, expiry)` as verified by `KeymeshWallet.execute`.

**Rationale:** Prevents the threshold layer from signing a semantically different message that still recovers to the wallet address but executes differently.

**Enforcement:** Session establishment payload is the full `KeymeshTransaction` (or its digest with fields disclosed for verification); participants re-derive the digest independently before signing. No "pre-hashed" opaque digest without field visibility.

## TSS-INV-16 — No Downgrade via Signing Path

**Statement:** The existence of a threshold path does not allow a single device/participant to bypass `DEVICE_PLUS_GUARDIANS` policy. Threshold signing respects `PolicyManager.evaluateAuthorization`.

**Rationale:** Otherwise threshold deployment would weaken Phase 1.3 anti-downgrade.

**Enforcement:** `evaluateAuthorization` remains the gate before signing; threshold signing is the mechanism, not the policy. Policy classification unchanged.

---

## Claim Level at Phase 2.1

| Invariant | Status |
|-----------|--------|
| TSS-INV-01 … TSS-INV-16 | **DESIGNED** |

No invariant above is implemented, tested, audited, or formally verified at Phase 2.1.

## Phase 2.2 Prototype Status

> **Maturity:** PROTOTYPED, TESTED (for selected invariants). NOT AUDITED, NOT FORMALLY VERIFIED.
> **Prototype:** `crates/keymesh-tss-proto` (isolated, k256-based 2-of-3 simulation; production will use synedrion/cggmp21 CGGMP21). No `KeymeshWallet` changes.

| ID | Invariant | Status | Evidence |
|----|-----------|--------|----------|
| TSS-INV-01 | fewer than threshold cannot sign | **TESTED** | `proto_tests::threshold_2of3_all_pairs_succeed_single_fails`, `no_exposed_reconstruct_in_public_api` — 1 share → Err |
| TSS-INV-02 | coordinator cannot sign alone | **TESTED** | Same: coordinator holds no share; single-share attempt fails; transport verifies |
| TSS-INV-03 | digest binding | **TESTED** | `signature_bound_to_keymesh_digest_modified_digest_fails`, `produced_signature_is_standard_ecdsa` |
| TSS-INV-04 | session cannot be replayed | **TESTED** | `replayed_session_fails`, `abort_cannot_finalize_and_reuse_fails` |
| TSS-INV-05 | share never reconstructs into full private key during normal signing | **DESIGNED + TESTED (boundary)** | No public `reconstruct_private_key()`; only `#[cfg(test)] reconstruct_secret_for_test`; `grep` for `reconstruct_private_key/combine_all_shares` yields no hits in `crates/keymesh-tss-proto/src` public path; signing reconstructs internally and zeroizes — documented as prototype limitation, production synedrion will not reconstruct |
| TSS-INV-06 | no cross-wallet signing (participant messages bound to session) | **TESTED** | SessionId includes wallet/chainId/nonce; `wrong_participant_identity_fails`, `replayed_session_fails` |
| TSS-INV-07 | no silent address change | **DESIGNED** | Refresh not implemented (see below); DKG produces deterministic address; replacement requires governance (documented) |
| TSS-INV-08 | refresh preserves key if implemented | **DESIGNED — NOT IMPLEMENTED** | Refresh is DESIGNED in architecture docs; prototype does not implement (no fake refresh) |
| TSS-INV-09 | abort cannot become authorization | **TESTED** | `abort_cannot_finalize_and_reuse_fails` — monotonic `SigningSessionStatus` |
| TSS-INV-10 | digest substitution rejected | **TESTED** | `signature_bound_to_keymesh_digest_modified_digest_fails` — TSS-INV-10/03 |
| TSS-INV-11 | participant authentication | **TESTED** | `wrong_participant_identity_fails` — duplicate/unknown participant → Err; transport `verify_binding` |
| TSS-INV-12 | single-use signing material (no k reuse) | **TESTED** | `k` is RFC6979 deterministic but session_id + digest binding ensures fresh; `replayed_session_fails` + transport single-use checks; no k reuse across sessions |
| TSS-INV-13 | policy-version binding at boundary | **DESIGNED + TESTED (binding)** | `SessionBinding.policy_version` included in `derive_session_id`; signing checks session_id matches binding |
| TSS-INV-14 | canonical digest consistency | **TESTED** | `keymesh_digest_flow`, `TSSPrototype.t.sol` digest pin `0xef48...` |
| TSS-INV-15 | no policy downgrade | **DESIGNED** | PolicyManager unchanged; signing does not bypass policy (boundary test in proto) |
| TSS-INV-16 | participant-set changes require governance | **DESIGNED** | Documented: RecoveryManager governs replacement; prototype placeholder only |

**Remaining:** No invariant is AUDITED or FORMALLY VERIFIED. Mapping to `docs/security/tss-testing-plan.md` categories is preserved.

## Phase 2.3 Real Threshold-ECDSA Status

> **Maturity:** REAL PROTOTYPE (isolated `crates/keymesh-tss` via `synedrion 0.3` CGGMP'24), NOT PRODUCTION, NOT AUDITED, NOT FORMALLY VERIFIED.
> **Separation:** `crates/keymesh-tss-proto` remains as Phase 2.2 simulation for comparison (see ADR-001). Real signing operates on distributed `ThresholdKeyShare`/`AuxInfo` via `manul::TestRuntime` InteractiveSigning — no application-level reconstruction.

| ID | Invariant | Phase 2.3 Status | Evidence |
|----|-----------|------------------|----------|
| TSS-INV-01 | fewer than threshold cannot sign | **TESTED** | `tests_real::threshold_2of3_all_pairs_succeed_single_fails_real` — `setup_2of3()` + `threshold_sign` with 1 share → Err |
| TSS-INV-02 | coordinator cannot sign alone | **TESTED** | Coordinator holds no share; `threshold_sign` requires ≥t `ThresholdKeyShare` + `AuxInfo`; single-share → Err |
| TSS-INV-03 | digest binding | **TESTED** | `final_signature_low_s_and_recovers_real`, `digest_binding_wrong_digest_rejected` — `verify_signature` fails on wrong digest |
| TSS-INV-04 | session cannot be replayed | **TESTED** | `session_replay_rejected` — `derive_session_id` includes wallet/chainId/nonce/digest/policyVersion/random; mismatch → Err |
| TSS-INV-05 | no application-level key reconstruction | **TESTED** | No public `reconstruct_secret`/`combine_shares` in `crates/keymesh-tss/src`; `grep -r reconstruct` yields only `#[cfg(test)]` in proto; signing uses `ThresholdKeyShare`/`AuxInfo` distributed state; documented F-0003 remains historical, new path does not reconstruct |
| TSS-INV-06 | participant identity binding | **TESTED** | `participant_identity_duplicate_fails` — duplicate/unknown → Err; synedrion `TestVerifier` per participant |
| TSS-INV-07 | address stability | **TESTED** | `ethereum_address_stable_across_signing`, `dkg_succeeds_and_group_key_stable` — group VK same across participants and signings |
| TSS-INV-08 | refresh preservation | **DESIGNED — NOT IMPLEMENTED** | Refresh via `KeyRefresh` exists in synedrion but not wired in prototype; honestly NOT TESTED |
| TSS-INV-09 | abort terminality | **TESTED** | `abort_terminal` — monotonic `SigningSessionStatus`; `transport` checks |
| TSS-INV-10 | digest substitution resistance | **TESTED** | `digest_binding_wrong_digest_rejected` — session binding prevents substitution |
| TSS-INV-11 | malicious participant handling | **TESTED** | synedrion provides identifiable abort; prototype tests duplicate/wrong-round/malformed via `transport` + `threshold_sign` Err |
| TSS-INV-12 | signing-session uniqueness | **TESTED** | `session_replay_rejected`, `transport_simulator_checks` — session_id + digest binding |
| TSS-INV-13 | policy-version binding | **TESTED** | `SessionBinding.policy_version` in `derive_session_id`; signing checks |
| TSS-INV-14 | canonical digest compatibility | **TESTED** | `keymesh_digest()` is `0xef48…` KEYMESH_TX_V1 vector 1; `verify_signature` + `TSSPrototype.t.sol` pin |
| TSS-INV-15 | no downgrade | **DESIGNED** | PolicyManager unchanged; signing does not bypass `evaluateAuthorization` |
| TSS-INV-16 | governed participant-set changes | **DESIGNED** | Resharing exists in synedrion (`KeyResharing`) but not wired to `RecoveryManager`; interface placeholder |

Heavy synedrion DKG/signing tests are `#[ignore]` on Windows local — run on Linux CI (`cargo test -- --ignored` in `.github/workflows/tss.yml`). No invariant is AUDITED or FORMALLY VERIFIED.

## Phase 2.5 Network & Lifecycle Status

> **Maturity:** TESTNET-INTEGRATED (real `crates/keymesh-tss` + authenticated transport `crates/keymesh-tss/src/network.rs` + `crates/keymesh-tss/src/identity.rs`/`envelope.rs`/`handshake.rs`/`storage.rs`/`lifecycle.rs`), NOT PRODUCTION, NOT AUDITED, NOT FORMALLY VERIFIED.
> **Transport:** `TssTransport` trait with `InMemoryAuthenticatedTransport` (tokio mpsc, `authenticate` + `verify_binding`) ready for `TcpAuthenticatedTransport` (TLS/mTLS placeholder). Envelope `TssEnvelope { protocol_version, session_id, wallet, chain_id, participant_id, round, digest }` signed via `NetworkKeypair` and verified against `ParticipantIdentity` (network identity separate from `ThresholdKeyShare`).

| ID | Invariant | Phase 2.5 Status | Evidence |
|----|-----------|------------------|----------|
| NET-INV-01 | participant authentication | **TESTED** | `identity::tests::network_identity_sign_verify`, `envelope::tests::envelope_sign_verify_and_binding` — network signature over `to_sign_bytes()` verified against `ParticipantIdentity` |
| NET-INV-02 | session immutability | **TESTED** | `handshake::tests::handshake_ok_and_mismatch` — `handshake_validate` checks wallet/chain/digest/nonce/policyVersion/protocolVersion, `SessionBinding` immutable |
| NET-INV-03 | message session binding | **TESTED** | `envelope::TssEnvelope::validate_against`, `transport::SimulatedTransport::verify_binding` — cross-session replay → Err |
| NET-INV-04 | participant-set version binding | **TESTED** | `lifecycle::KeyLifecycle::is_stale`, `derive_key_id` includes threshold+version; `ThresholdParticipantSet::verify_wallet_identity` |
| NET-INV-05 | stale-share rejection | **TESTED** | `lifecycle::KeyLifecycle` — stale version check, `participant_set_version` in `key_id`; mixed old/new set would fail `validate_against` |
| NET-INV-06 | coordinator cannot forge participant message | **TESTED** | `envelope::verify` requires participant's `NetworkKeypair` signature; coordinator holds no participant private network key |
| NET-INV-07 | transport failure cannot authorize | **TESTED** | `network::tests::in_memory_authenticated_roundtrip`, `not_authenticated_rejects`; `SimulatedTransport` drop/duplicate/reorder/modify → `check_no_duplicate`/`check_round_order`/`verify_binding` Err; `handshake` before TSS |
| NET-INV-08 | rotation requires governance | **DESIGNED** | `lifecycle::KeyLifecycle::rotate` returns "not yet wired to RecoveryManager — honestly NOT IMPLEMENTED"; `RecoveryManager` remains authority, TSS only reshares |
| NET-INV-09 | refresh preserves group identity | **DESIGNED — NOT IMPLEMENTED** | `lifecycle::KeyLifecycle::refresh` returns NOT IMPLEMENTED (synedrion `KeyRefresh` exists but not wired); honestly documented |
| NET-INV-10 | no cross-session message reuse | **TESTED** | `envelope::validate_against` + `transport::verify_binding` + `handshake_validate` — old session message → new session → Err |

**Note:** Refresh/rotation are honestly `NOT IMPLEMENTED` in Phase 2.5 prototype (see `lifecycle.rs`); production will use synedrion `KeyRefresh`/`KeyResharing` with governance. Share storage `EncryptedShareStore` (ChaCha20Poly1305, 0o600, zeroize) ensures only own share loaded (`participant/src/bin/participant.rs` — never `[shareA,shareB,shareC]`).

## Phase 2.6 Key Lifecycle Status

> **Maturity:** REAL LIFECYCLE (isolated `crates/keymesh-tss` via `synedrion 0.3` `KeyResharing`+`AuxGen`), NOT PRODUCTION, NOT AUDITED, NOT FORMALLY VERIFIED.
> **Refresh:** REAL via resharing to same set (preserves VK); `KeyRefresh` for `ThresholdKeyShare` is `NOT SUPPORTED BY LIBRARY` (only for `KeyShare` n-of-n)
> **Rotation:** REAL via `KeyResharing` with guardian quorum + timelock (`governance.rs`); `TestRuntime` isolated, not multi-process production

| ID | Invariant | Phase 2.6 Status | Evidence |
|----|-----------|------------------|----------|
| LIFE-INV-01 | refresh preserves group public key | **TESTED** | `tests_lifecycle::refresh_preserves_group_key_and_signs` — `vk_before == vk_after` after `KeyLifecycle::refresh()` via `KeyResharing` |
| LIFE-INV-02 | refresh preserves wallet address | **TESTED** | Same test — `ethereum_address` unchanged |
| LIFE-INV-03 | rotation requires governance | **TESTED** | `governance_quorum_enforced`, `timelock_enforced`, `stale_single_guardian_cannot_complete` — `TssRotationRequest` quorum 2-of-3 + 3600s timelock |
| LIFE-INV-04 | stale participant set cannot sign | **TESTED** | `stale_share_rejected`, `old_share_mixed_with_new_rejected_via_version` — `check_signing_allowed(old_version) → Err(StaleVersion)` |
| LIFE-INV-05 | failed rotation preserves old active state | **TESTED** | `rotation_failed_preserves_old_state` — invalid threshold → `state==Active`, version unchanged |
| LIFE-INV-06 | failed refresh preserves old active state | **TESTED** | `failed_refresh_preserves_old_state` — no material → Active preserved |
| LIFE-INV-07 | lifecycle operations cannot race unsafely | **TESTED** | `concurrent_lifecycle_operations_blocked` — `Refreshing`/`Rotating` → `can_mutate()=false`, `check_signing_allowed` blocks |
| LIFE-INV-08 | retired key cannot sign | **TESTED** | `retirement_prevents_future_signing` — `retire()` → `Retired` terminal, `check_signing_allowed → Err(Retired)` |
| LIFE-INV-09 | participant set version is monotonic | **TESTED** | `rotation_governed_and_preserves_group_key` — version 1→2, keyId changes, old version rejected |
| LIFE-INV-10 | cryptographic lifecycle cannot bypass RecoveryManager | **TESTED** | `governance::tests::*` + `lifecycle::begin_rotation` checks `is_executable` (quorum+timelock), stale version, group key binding |
| NET-INV-08 | rotation requires governance | **TESTED** (was DESIGNED) | Now real: `TssRotationRequest` with `RecoveryManager` timelock semantics |
| NET-INV-09 | refresh preserves group identity | **TESTED** (was DESIGNED) | Real resharing refresh preserves VK/addr |

Heavy refresh/rotation tests are `#[ignore]` on Windows — run on Linux CI with `cargo test -- --ignored`.

## Lifecycle Threat Model

See `docs/security/tss-lifecycle-threat-model.md` for stale-share, half-rotation, coordinator-forge threats.

## Testing Plan Reference

Each invariant maps to tests in `docs/security/tss-testing-plan.md`:

* TSS-INV-01/02 → threshold corruption + coordinator-forgery negative tests
* TSS-INV-03/07/15 → digest-binding and cross-field fuzz
* TSS-INV-04/06/10 → replay and session-confusion suites
* TSS-INV-05 → no-reconstruction audit (code + runtime attestation)
* TSS-INV-08/09 → refresh and replacement integration tests
* TSS-INV-12 → malicious-participant identifiable-abort tests
* TSS-INV-13 → nonce-reuse and presign single-use tests
* TSS-INV-14/16 → policy-version and downgrade tests
