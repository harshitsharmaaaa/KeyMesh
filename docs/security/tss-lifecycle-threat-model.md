# TSS Lifecycle Threat Model — Phase 2.6

## Assets
- Threshold shares `x_i`, AuxInfo (Paillier, RP params)
- Group verifying key, Ethereum address
- Governance quorum, timelock

## Threats

| Threat | Mitigation |
|--------|------------|
| Governance bypass (participant self-promotion) | `TssRotationRequest` requires guardian quorum + timelock; coordinator/participant alone → Governance error |
| Stale share replay | `participantSetVersion` monotonic; `check_signing_allowed` rejects stale version; old + new share mix rejected |
| Half-rotation state | Atomic commit: crypto failure → old set remains authoritative |
| Silent address change | Refresh/rotation verify `group key == before` before commit; change requires new version+keyId |
| Concurrent refresh+rotation race | Single lifecycle lock; `Refreshing`/`Rotating` blocks other mutations and signing |
| Retired key reuse | `Retired` terminal; `check_signing_allowed` returns `Retired` error |
| Coordinator forge | Old share invalid after rotation (new polynomial); envelope `ParticipantIdentity` network sig required |

## Timelock Rationale
Delay gives guardians/users time to detect malicious participant-set change and cancel before `Resharing` executes. Mirrors `RecoveryManager.MIN_TIMELOCK`.
