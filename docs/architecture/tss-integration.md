# TSS Integration Architecture — Phase 2.4

> **Status:** INTEGRATED FOR TESTNET — isolated, not production, not audited
> **Real crate:** `crates/keymesh-tss` (synedrion 0.3 CGGMP'24, 2-of-3)
> **Proto crate:** `crates/keymesh-tss-proto` (k256 simulation, kept for comparison — NOT used by threshold provider)

## Overview

```
                 KEYMESH TRANSACTION
                         │
                         ▼
                  KEYMESH_TX_V1 (canonical, keccak256)
                         │
                         ▼
                  PolicyManager
                         │
                         ▼
                 Authorization Layer (DEVICE_ONLY / DEVICE_PLUS_GUARDIANS)
                         │
                         ▼
                  SigningProvider
                    /          \
                   /            \
        SingleEcdsaProvider   ThresholdEcdsaProvider
                                  │
                                  ▼
                            crates/keymesh-tss
                                  │
                          2-of-3 participants (A,B,C)
                                  │
                                  ▼
                           one ECDSA signature (r,s,v low-s)
                                  │
                                  ▼
                           Ethereum testnet → KeymeshWallet.ecrecover
```

**Rule:** `PolicyManager` and `RecoveryManager` are unaware of TSS internals. TSS is a signing mechanism, not an authorization mechanism.

## Provider Boundary

```rust
trait SigningProvider {
  fn kind() -> "single" | "threshold";
  fn protocol_version() -> &str;
  fn capabilities() -> Vec<String>;
}
SingleEcdsaProvider  — default, Phase 1 path, no DKG
ThresholdEcdsaProvider — wraps `crates/keymesh-tss`:
  - holds ThresholdKeyMaterial (participants + group key)
  - exposes ThresholdParticipantSet { threshold, total, participant_ids, group_public_key }
  - sign(binding, subset, session_id) → threshold_sign via synedrion InteractiveSigning
  - verify(digest, sig) → ecrecover
```

High-level `sign()` is separated from lifecycle: `setup_2of3()` (DKG), `derive_session_id(binding)`, `threshold_sign` are explicit. No hidden one-line `sign(digest)` that hides DKG/participant selection.

## Signing Context

Canonical context (Phase 2.1 binding, reused):

```
wallet: Address 20B
chainId: u64
nonce: u64
digest: [u8;32]  KEYMESH_TX_V1 keccak
policyVersion: u64
signingProtocolVersion: "synedrion/0.3-cggmp24"
random: [u8;32] CSPRNG
sessionId: keccak256(wallet|chainId|nonce|digest|policyVersion|version|random)
```

Session is immutable for digest/wallet/chainId/nonce/policyVersion. Terminal states `COMPLETED/ABORTED/FAILED` never return to `SIGNING`.

## Participant Model

```
Participant A/B/C
  - TestSigner / TestVerifier (manul dev, in-process; production will use real identity keys)
  - ThresholdKeyShare (synedrion, t-of-n)
  - AuxInfo (synedrion)
GroupPublicKey { verifying_key, ethereum_address = keccak256(uncompressed)[12..] }
```

Secret shares never cross TypeScript boundary — Rust boundary owns `ThresholdKeyShare`/`AuxInfo` as opaque handles.

## Participant Selection & Set Registry

`ThresholdParticipantSet { protocol_version, threshold=2, total=3, participant_ids=[0,1,2], group_public_key }`

* `verify_wallet_identity(expected_wallet)` checks `group_address == wallet`
* Selection `A+B, A+C, B+C` only if subset is valid for key; `threshold_sign` checks `len ≥ t`, duplicate, unknown, outside authorized set → Err
* No fallback to single participant

## Group Key Identity

TSS group key determines wallet signer. For Phase 2.4 testnet: **deploy a dedicated wallet whose expected signer is the TSS group address** (option B in task §17). Avoids changing production `KeymeshWallet` semantics. Verified via `ethereum_address_from_verifying_key`.

## Session Creation & Status

`SigningSession::new(binding, participants, threshold)` → `derive_session_id` → `SigningSession { session_id, binding, participants, threshold, status: Started }`

States: `Created/Started → Authenticating → Signing → Completed | Aborted | Failed` (monotonic, terminal never resurrects). `COMPLETED/ABORTED/FAILED` are terminal.

## Failure Mapping

`TssError` → domain errors: `InsufficientShares`, `DuplicateParticipant`, `UnknownParticipant`, `SessionMismatch`, `SigningFailed`, `Aborted`, `WrongChain`, `MainnetNotAllowed`. Raw synedrion/manul details are not leaked across every API, but diagnostic `format!("{e:?}")` is preserved for debugging.

## Testnet

* Env: `KEYMESH_TESTNET_RPC_URL`, `KEYMESH_TESTNET_CHAIN_ID`, `KEYMESH_ENABLE_TSS_TESTNET=true`, `KEYMESH_SIGNING_MODE=threshold` (default `single`)
* `.env.example` placeholders only
* No mainnet by default: `chain_id == 1` → `ThresholdEcdsaProvider::new` returns `SessionMismatch("mainnet not allowed")` unless `KEYMESH_ENABLE_MAINNET_TSS=true`
* Deployment: `forge build → deploy KeymeshWallet for TSS group address → configure testnet → init participant set → execute test transaction`
* Transaction: simple value transfer, empty calldata, `KEYMESH_TX_V1` digest, `PolicyManager` then `ThresholdEcdsaProvider` (2 participants) → `one ECDSA sig` → broadcast → `KeymeshWallet.ecrecover` → execute, nonce increment, event.

## Recovery & Rotation

`RecoveryManager` governs participant-set changes; future `KeyResharing` (synedrion) will be triggered by governed rotation `A B C → A C D` with same group address where supported. Currently `AVAILABLE IN LIBRARY, NOT INTEGRATED`.

## Security & Observability

Never logs: private share, Paillier secret, nonce k. Safe logs: session_id, participant_ids, round, digest, wallet, chainId, success/failure. Feature flag: `KEYMESH_SIGNING_MODE=single` default, `threshold` explicit, unsupported chain → fail closed, no silent fallback.

## Distinction

```
local prototype: crates/keymesh-tss-proto (k256 simulation, Shamir/Lagrange reconstruction — NOT real TSS)
testnet integration: crates/keymesh-tss (synedrion CGGMP'24, distributed, no reconstruction)
production: NOT YET (single remains default)
```
