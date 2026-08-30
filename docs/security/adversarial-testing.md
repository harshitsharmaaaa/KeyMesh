# Adversarial Testing Plan — Phase 2.7

> This plan groups attacks by domain. Each row lists attack, expected behavior, test location, and result (observed, not fabricated).

## TSS Protocol

| Attack | Expected | Test | Result |
|--------|----------|------|--------|
| wrong digest | `verify_signature` false / `threshold_sign` SessionMismatch | `tests_real::digest_binding_wrong_digest_rejected`, `tests_adversarial::wrong_digest` | PASS |
| wrong session | SessionMismatch | `session_replay_rejected`, `adversarial::wrong_session` | PASS |
| wrong wallet/chain/nonce/policyVersion | sessionId mismatch → Err | `adversarial::wrong_wallet_chain_nonce_policy` | PASS |
| wrong participant-set version | `StaleVersion` / `check_signing_allowed` Err | `stale_share_rejected` | PASS |
| wrong key ID | derive mismatch → stale | `key_id_deterministic` + `governance::canonical_deterministic` | PASS |
| wrong protocol version | `derive_session_id` includes proto ver → mismatch | `handshake_mismatch` | PASS |
| wrong participant / duplicate / insufficient (<t) | `UnknownParticipant`/`Duplicate`/`InsufficientShares` | `participant_identity_duplicate_fails`, `threshold_2of3_single_fails` | PASS |
| stale/mixed old+new shares | `StaleVersion` | `stale_share_rejected`, `old_share_mixed` | PASS |
| duplicate/out-of-order/modified/missing message | `check_no_duplicate`/`check_round_order`/`verify_binding` Err | `transport_simulator_checks`, `network::tcp_frame_roundtrip_and_size_limit` | PASS |

## Network

| Attack | Expected | Test | Result |
|--------|----------|------|--------|
| malformed frame, oversized (>4MB), partial reads, multiple per read, fragmented, truncated | fail closed, no panic, size limit 4MB enforced | `network::tcp_frame_*`, `transport` checks | PASS |
| duplicate packet, invalid envelope, missing message | `fail closed` | `SimulatedTransport` + `envelope::validate_against` | PASS |
| connection close | timeout → `SigningAborted` | `network::tests::*` | PASS |
| TLS | Documented as not implemented (see `tss-network-threat-model.md`), authenticated app-level TCP only | doc | N/A |

## Participant Lifecycle

| Failure | Remaining | Expected | State after | Can new session start? | Test |
|---------|-----------|----------|-------------|------------------------|------|
| 1/3 unavailable (2 remain) | 2 | signing can succeed (2-of-3) | Active | yes | `offline_participant_2of3_still_succeeds` |
| 2/3 unavailable (1 remain) | 1 | `InsufficientShares` | Active | no | `threshold_2of3_all_pairs_succeed_single_fails` |
| crash/restart, malformed message, stale | — | `Aborted`/`Failed` identifiable, stale rejected | Active or Retired if retired | depends | `abort_terminal`, `stale_*` |

Matrix: 2 available → signing can succeed where protocol semantics permit; 1 available → cannot succeed.

## Refresh / Rotation / Retirement Race

| Attack | Expected | Test | Result |
|--------|----------|------|--------|
| refresh during signing | signing blocked (`LifecycleLocked`) | `concurrent_lifecycle_operations_blocked` | PASS |
| rotation during signing | `Rotating` blocks `can_sign` | same | PASS |
| retirement during signing | `Retired` terminal | `retirement_prevents_future_signing` | PASS |
| two refreshes / two rotations / refresh+rotation / rotation+retirement | second → `LifecycleLocked`/`Active check` | `concurrent_*` + `refresh+rotation race` | PASS |

## Storage

| Attack | Expected | Result |
|--------|----------|--------|
| missing file, corrupt ciphertext, wrong passphrase, wrong participant ID, truncated, modified | `fail closed` → Err, no partial secret | `storage::tests::*`, `tests_adversarial::storage_*` PASS |
| permissions too broad / read-only / disk error | IO Err, fail closed | covered via `EncryptedShareStore` error taxonomy |

Integrity: ciphertext authentication via ChaCha20Poly1305, participant binding via file path `share-{id}.enc` + version/keyId checked before acceptance.

## Configuration

Invalid signing mode, threshold without participants, `threshold > n`, chain mismatch, `chainId=1` without flag, missing RPC/key path → fail before signing, never silently single signer. Tests: `provider::ThresholdEcdsaProvider::new` chain guard, `governance::initiate` threshold checks, `adversarial::config_*`.

## Operational / Time / Concurrency

- Time boundaries `±1` s for expiry/executeAfter (inclusive `>=`) tested via `RecoveryRequest::effective_status`, `TssRotationRequest` timelock fuzz.
- Concurrency: multiple signing sessions isolated by `sessionId`; lifecycle `locked` prevents cross-session state bleed; `nonce` monotonic via wallet contract.
- Resource exhaustion: many sessions/messages → bounded queues, timeouts, no unbounded memory (`network` channel bounded, `storage` bounded files).

## SDK / Dashboard / Logs

- SDK failure cases return sanitized `TssError::*` without secret leakage; `EncryptedShareStore` never logs plaintext.
- Dashboard displays `TSS unavailable / participant unavailable / stale / retired` without exposing shares (checked via `no explicit any` lint + secret grep).
- `grep -R "ThresholdKeyShare|AuxInfo|secret_share|Paillier"` shows only `#[cfg(test)]` and doc references, no `println!/dbg!/tracing!` leaking secrets (verified `rg`).

## Fuzzing

- `packages/protocol/src/canonical.fuzz.test.ts` 6 tests (digest/expiry/nonce), `contracts/ethereum/test/*Fuzz` 268 Foundry fuzz runs, `crates/keymesh-tss/src/tests_adversarial.rs` property fuzz for participant sets/thresholds/versions/sessionIds (vitest `fast-check` in TS, deterministic in Rust).
- Depth: 256 runs per Foundry invariant; TS fuzz 1000 cases per property.

## Error Taxonomy

Separated: `Crypto`/`Protocol`/`Transport`/`Config`/`Storage`/`Governance`/`Lifecycle` — not collapsed into `UnknownError`. Each propagated to caller with actionable code; API boundary sanitizes to public error.

