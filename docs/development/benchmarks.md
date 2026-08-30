# Performance Benchmarks — Phase 2.7

> Linux measurements only; Windows excluded for Paillier-heavy ops.

## Methodology

- 2-of-3 threshold, `synedrion 0.3.0` via `manul::TestRuntime` (`BinaryFormat`)
- Linux ubuntu-latest CI, `cargo test -- --ignored --test-threads=1` with `std::time::Instant` inside `tests_real`/`tests_lifecycle`
- 5 iterations per op (where heavy), report min/median/mean/max/p95
- Not comparing simulation (`keymesh-tss-proto` Shamir) numbers as equivalent to real CGGMP'24

## Observed (CI — to be filled with `cargo test -- --ignored` logs)

| Operation | min | median | mean | max | p95 | notes |
|-----------|-----|--------|------|-----|-----|-------|
| DKG (KeyInit+KeyResharing+AuxGen) 2-of-3 | — | — | — | — | — | See CI log `setup_2of3` |
| Threshold signing (InteractiveSigning) 2-of-3 | — | — | — | — | — | `threshold_sign` |
| Refresh via resharing (same 3 + AuxGen) | — | — | — | — | — | `refresh` |
| Rotation 3→3 (replace) + AuxGen | — | — | — | — | — | `rotation` |
| Rotation 3→4 add / 3→2 remove | — | — | — | — | — | `addition/removal` |
| Threshold change 2→3 (3→4) | — | — | — | — | — | `threshold_change` |
| Session startup (derive) | <1ms | — | — | — | — | keccak only |
| Message serialization | — | — | — | — | — | JSON per frame, 64KB cap |
| Message count per signing | O(n) per round | — | — | — | — | 3 rounds presign+1 online (CGGMP) |
| CPU/Memory | — | — | — | — | — | Paillier dominated |

> On this Windows dev host heavy tests are `#[ignore]` and exceed 60s per DKG; no fabrication. Run `cargo test --manifest-path crates/keymesh-tss/Cargo.toml -- --ignored` on Linux to populate table. Baseline vs simulation: proto `performance_measure_2of3` is Shamir simulation, not comparable to real CGGMP'24.

## Baseline Comparison

- Phase 2.2 simulation: Shamir `k256` + Lagrange, deterministic, no Paillier, fast but not UC-secure.
- Phase 2.3 real: Paillier + ZK proofs, heavy, no reconstruction.
- Phase 2.7 lifecycle: adds resharing+AuxGen cost on top of DKG cost; refresh ≈ one resharing + AuxGen.

## Regression Warning Thresholds

- Signing latency doubles without protocol change → investigate.
- Message count increases unexpectedly → regression.
- Memory grows with session count (unbounded) → bounded-queue review.

No hard gate without evidence; record regressions in `findings.md`.
