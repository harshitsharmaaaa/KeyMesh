# Security Freeze — Phase 2.7

> Freeze date: 2026-05-13 (Phase 2.7)
> Status: FROZEN — no semantic changes without security review and dedicated fix branch.

## Frozen Semantics

### KEYMESH_TX_V1
- Current: `keccak256("KEYMESH_TX_V1" || wallet || chainId || nonce || to || value || data || expiry)` via `tiny-keccak` in `crates/keymesh-core` and `@noble/hashes` in TS, byte-identical vectors (`0xef48...`).
- Invariant: TSS-INV-03/15, digest binding.
- Tests: `packages/protocol/src/canonical.test.ts`, `vectors.ts`, `crates/keymesh-core/src/transaction`, `TSSPrototype.t.sol`.

### Nonce semantics
- `uint256 nonce` per wallet, monotonic, consumed by `KeymeshWallet.execute`; replay requires new nonce/session.
- Tests: `contracts/ethereum/test/*`, `protocol.test.ts`.

### Expiry semantics
- Inclusive check `block.timestamp <= expiry`; `expiry == 0` means no expiry. Adversarial `expiry±1` tested.
- Tests: `policy.test.ts`, Foundry `expiry` cases.

### Device authorization
- Single authorized device checked via `isDeviceAuthorized`; threshold address derived `keccak256(vk)[12..]` maps to one device address, not bypass.
- Tests: wallet tests + `ThresholdParticipantSet::verify_wallet_identity`.

### Guardian recovery
- Guardian quorum (count-based, 1 guardian = 1 approval) + timelock `MIN 3600s`, snapshot quorum/timelock at initiation, `None→Pending→QuorumReached→Executable→Executed/Cancelled`, `executeAfter` inclusive.
- Tests: `crates/keymesh-core/src/recovery`, `RecoveryManager.t.sol`.

### Policy precedence / versioning
- `PolicyManager` classifies `DEVICE_ONLY` vs `DEVICE_PLUS_GUARDIANS`; `policyVersion` bound into `sessionId` and on-chain `consumeAuthorization`.
- Tests: `policy.test.ts`, `session::derive_session_id`, Foundry policy tests.

### TSS session binding
- `sessionId = keccak256(wallet||chainId||nonce||digest||policyVersion||protocolVersion||random 32)`; every message bound to `sessionId+digest`.
- Invariant TSS-INV-04/06/07/14.
- Tests: `threshold_sign` session mismatch, `envelope`/`handshake`.

### Participant-set versioning
- `participantSetVersion` initial 1, increments on valid rotation only; monotonic; stale fails.
- Invariant LIFE-INV-09.
- Tests: `KeyLifecycle::derive_key_id`, `lifecycle::tests`, `tests_lifecycle`.

### Key ID
- `keyId = keccak256(vk || protocolVersion || threshold || version)`; deterministic cross-language (`@keymesh/protocol` `deriveKeyId`).
- Tests: `key_id_deterministic`, TS lifecycle vectors.

### Refresh semantics
- Same participant set, reshared via real `KeyResharing` (threshold refresh via same-set resharing; `KeyRefresh` only for `KeyShare` is library limitation documented), preserves `vk`/`address`, version unchanged, `AuxGen` regenerated, failure → old active preserved.
- Invariant LIFE-INV-01/02/06.
- Tests: `refresh_preserves_group_key_and_signs`.

### Rotation semantics
- New participant set via `KeyResharing` with `OldHolder+NewHolder`, preserves `vk`, version++, `keyId` changes, requires `TssRotationRequest` quorum+timelock, old participant cannot sign after, stale rejected.
- Invariant LIFE-INV-03/04/05/09/10.
- Tests: `rotation_governed_and_preserves_group_key`, addition/removal/threshold-change.

### Retirement
- `Retired` terminal; `check_signing_allowed` → `Retired` error, `refresh/rotation/new session` blocked, persisted authoritative.
- Invariant LIFE-INV-08.
- Tests: `retirement_prevents_future_signing`.

## Change Policy
Any change to above requires: issue with invariant reference, updated tests, `docs/security/findings.md` entry, maintainer review, and version bump. No silent weakening.
