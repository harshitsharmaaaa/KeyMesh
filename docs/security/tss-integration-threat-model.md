# TSS Integration Threat Model — Phase 2.4

| ID | Attack | Impact | Mitigation | Test | Remaining Assumption |
|----|--------|--------|------------|------|----------------------|
| I-01 | provider falls back to single signer | silently weakens threshold | default=single, threshold explicit `KEYMESH_SIGNING_MODE=threshold`, no silent fallback, unsupported chain → fail closed | `SigningMode::from_env`, `ThresholdEcdsaProvider::new` mainnet check | operator must set flag correctly |
| I-02 | TSS group key mismatch | wallet expects wrong signer | `ThresholdParticipantSet::verify_wallet_identity` checks `group_address == wallet` | `ethereum_address_stable_across_signing` | deployment must use correct group address |
| I-03 | chain mismatch | sign for wrong chain | binding chainId vs provider chainId check in `sign()` | `threshold_sign` chain check | RPC must not be spoofed |
| I-04 | testnet/mainnet confusion | threshold on mainnet without audit | `chain_id==1` rejected unless `KEYMESH_ENABLE_MAINNET_TSS=true` | `ThresholdEcdsaProvider::new` | env must be set correctly |
| I-05 | coordinator digest substitution | sign wrong digest | session_id includes digest, `derive_session_id` check, participant verifies | `digest_binding_wrong_digest_rejected`, `session_replay_rejected` | coordinator is local, not trusted for safety |
| I-06 | stale participant set | use old shares after rotation | participant set registry bound to group key, set versioning (future) | `dkg_succeeds_and_group_key_stable` | rotation not yet integrated |
| I-07 | secret-share leakage via SDK | TS receives private scalar | Rust boundary owns `ThresholdKeyShare`/`AuxInfo` opaque, TS never gets shares | `no_reconstruction_exposed` | host must not log secrets |
| I-08 | session replay | reuse old session | session_id includes random + digest + nonce, terminal states never resurrect, `verify_binding` | `session_replay_rejected`, `abort_terminal` | randomness must be fresh |
| I-09 | participant-set downgrade | threshold lowered silently | threshold is part of participant set, verified at DKG, no silent change | `ThresholdParticipantSet` | governance must authorize changes |
| I-10 | policy bypass via provider | TSS signs without PolicyManager | provider is called only after `PolicyManager` authorization; `policyVersion` in binding | `policy_version` in SessionBinding | caller must check policy first |
| I-11 | recovery bypass via provider | TSS rotation bypasses RecoveryManager | rotation is `AVAILABLE IN LIBRARY, NOT INTEGRATED`; future via `KeyResharing` governed by RecoveryManager | documented | not yet implemented |
| I-12 | unsafe testnet config (secrets, RPC) | leaked keys, wrong network | `.env.example` placeholders only, no committed secrets, deployment artifact without keys | manual review | operator hygiene |
