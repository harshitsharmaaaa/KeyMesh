# TSS Key Lifecycle Architecture — Phase 2.6

```
                    KEYMESH GOVERNANCE
                           │
                    RecoveryManager
                           │
                 guardian quorum + timelock (3600s)
                           │
                           ▼
                  Participant-set change
                           │
                           ▼
                    TSS Key Lifecycle
                    /              \
                   /                \
             Refresh              Rotation
                │                    │
                ▼                    ▼
          same participants      new participants
          new shares              reshared key material (KeyResharing)
                │                    │
                └──────────┬─────────┘
                           ▼
                     same group key (verifying_key)
                     same Ethereum address
                           │
                           ▼
                    Threshold signing (InteractiveSigning)
```

## Implementation Notes

- Rust: `crates/keymesh-tss/src/lifecycle.rs` (`TssKeyState`, `KeyLifecycle`) + `governance.rs` (`TssRotationRequest`)
- No `KeymeshWallet` or `PolicyManager` changes; `KEYMESH_TX_V1` unchanged
- Concurrency: one lifecycle mutation at a time (`can_mutate()` + locked flag); signing uses snapshot of version/keyId

## Locking

```
Active ──signing allowed──
  ├── refresh requested → Refreshing (signing blocked)
  └── rotation requested → Rotating (signing blocked)

Refreshing/failed → Active (old material remains)
Rotating/failed → Active (old participant set remains)
Retired → terminal, signing never again
```
