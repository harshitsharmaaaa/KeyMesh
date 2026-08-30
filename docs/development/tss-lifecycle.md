# TSS Lifecycle Development — Phase 2.6

## Running lifecycle tests

```bash
cargo test --manifest-path crates/keymesh-tss/Cargo.toml --lib -- --ignored  # heavy DKG/resharing (Linux CI)
cargo test --manifest-path crates/keymesh-tss/Cargo.toml --lib -- governance --nocapture  # light governance only
```

Heavy tests are `#[ignore]` on Windows; run on Linux CI with `--ignored`.

## Library inspection

- `synedrion 0.3.0` docs: `~/.cargo/registry/src/.../synedrion-0.3.0/src/{lib,protocols,key_refresh,key_resharing,entities}`
- `KeyRefresh` → `KeyShareChange` (n-of-n) not `ThresholdKeyShare` → refresh via `KeyResharing` to same set
- `KeyResharing` preserves VK when honest threshold quorum provides correct polynomials

## Performance (observed, not benchmarked)

- `setup_2of3` (KeyInit+KeyResharing+AuxGen) ~ few seconds on dev machine (Paillier heavy)
- Refresh (resharing to same 3) similar to AuxGen + 1 resharing round
- Rotation (3→3) similar
- Linux required for heavy Paillier; Windows runs light checks
