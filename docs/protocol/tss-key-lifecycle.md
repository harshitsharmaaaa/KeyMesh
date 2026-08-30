# TSS Key Lifecycle — Phase 2.6

> **Status:** IMPLEMENTED (real synedrion 0.3), NOT AUDITED, NOT FORMALLY VERIFIED
> **Library:** synedrion 0.3.0 / manul 0.2.1 / CGGMP'24 / secp256k1 / 2-of-3

## Overview

```
DKG
 ↓
ACTIVE
 ↓
REFRESH  ──→ ACTIVE          (same participants, reshared via KeyResharing)
 ↓
ROTATION ──→ ACTIVE          (new participants, verifiable resharing)
 ↓
RETIREMENT                   (terminal, no signing)
```

Governance decides WHO participates; TSS decides HOW shares are re-randomized.

```
RecoveryManager (guardian quorum + timelock)
        ↓
authorized participant-set change
        ↓
TSS lifecycle operation (KeyResharing / AuxGen)
```

## Key Identifier

- Group public key `vk` = same across refresh/rotation where supported
- Ethereum address = `keccak256(vk)[12..]` unchanged after refresh/rotation
- `keyId = keccak256(vk || "synedrion/0.3-cggmp24" || threshold || participantSetVersion)`
- Participant-set version monotonic: 1 → 2 → 3 …
- Signing binds to current `participantSetVersion`; stale fails.

## Refresh

- Same participant set `A B C → A' B' C'`
- Real protocol: `KeyResharing` to same set (all participants act as OldHolder+NewHolder) + `AuxGen`
- `KeyRefresh` exists in synedrion for `KeyShare` (n-of-n) but not directly for `ThresholdKeyShare`; threshold refresh via resharing is secure verifiable redistribution with ZK proofs and preserves VK (tested).
- Failure preserves old shares (atomic, before commit).

Library API inspected:
- `KeyRefresh::new(all_ids)` → `KeyShareChange + AuxInfo` for `KeyShare` only; fields private, no `ThresholdKeyShare::update`
- `KeyResharing::new(old_holder, new_holder, new_holders, new_threshold)` → `Option<ThresholdKeyShare>` — preserves `verifying_key` when `old_holders` quorum honest
- `ThresholdKeyShare::verifying_key()`, `to_key_share()`, `from_key_share()`
- `AuxGen::new(ids)` → `AuxInfo` per participant, subsettable for signing

## Rotation / Resharing

- Participant set changes: `A B C → A C D` (governance approval)
- Old holders (at least `old_threshold` of them) run `KeyResharing` with `NewHolder{verifying_key, old_threshold, old_holders}` and `new_holders` set
- Removed participant runs as OldHolder-only (gets `None`), new participant runs as NewHolder-only (gets new share via direct messages), overlapping runs as both
- Group key unchanged, version increments, keyId changes
- Threshold change supported via `new_threshold` param if library succeeds; otherwise `NOT IMPLEMENTED` for that combination

## Governance

- Uses `RecoveryManager` timelock semantics (MIN 3600s, quorum snapshot at initiation)
- Separate domain `TssRotationRequest` (not `applyRecoveredDevice`)
- States: `Pending → QuorumReached → Executable → Resharing → Completed` with `Cancelled/Failed` terminals
- Quorum example: 2-of-3 guardians required; single guardian / coordinator / participant alone cannot execute

## Failure Semantics

- Refresh/rotation failures leave old material authoritative; state returns to `Active`
- No half-old half-new state (atomic commit after crypto success)
- Signing blocked in `Refreshing/Rotating/Retired`

## Retirement

- Marks lifecycle `Retired`, `check_signing_allowed` rejects; secure deletion deferred (operational)

## SDK

```
tss.getParticipantSet() → {participants, threshold, total, version}
tss.getKeyId() → 0x...
tss.getKeyMetadata() → {keyId, groupPublicKey, ethereumAddress, threshold, total, version, protocolVersion, state}
tss.refresh() → {before, after} (group key preserved)
tss.initiateRotation(input) → TssRotationRequest (Pending)
tss.approveRotation(id, guardian) → quorum → timelock
tss.finalizeRotation(id) → resharing → version++
tss.retire()
```

Never exposes secret shares, Paillier secrets, or private scalars.

## Known Limitations

- `KeyRefresh` for threshold is `NOT SUPPORTED` directly; refresh via `KeyResharing` is `IMPLEMENTED` (real ZK resharing, preserves key)
- Custom distributed runtime not built (Phase 2.5C decision); tests use `manul::TestRuntime`
