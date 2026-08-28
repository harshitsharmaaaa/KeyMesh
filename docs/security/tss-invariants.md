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

No invariant above is implemented, tested, audited, or formally verified at this phase.

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
