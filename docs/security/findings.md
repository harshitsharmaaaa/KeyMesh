# KeyMesh Security Findings

This file tracks issues discovered during Phase 1.4 security hardening.

## F-0001
- ID: `F-0001`
- Severity: `LOW`
- Description: The initial TypeScript fuzz test depended on `vitest/fast-check`, but the workspace did not include `fast-check`.
- Impact: The fuzz suite could not run in CI or locally.
- Reproduction: Run `bun test packages/protocol/src/canonical.fuzz.test.ts` before the fix.
- Fix: Replaced the dependency with deterministic Vitest coverage over the same boundary cases.
- Regression test: `packages/protocol/src/canonical.fuzz.test.ts`
- Status: `fixed`

## F-0002
- ID: `F-0002`
- Severity: `LOW`
- Description: One cross-language vector fixture used a malformed `to` address with the wrong hex length.
- Impact: The vector file was not trustworthy as a canonical reference set.
- Reproduction: Inspect `packages/protocol/src/gen_vectors.ts` before the fix.
- Fix: Corrected the address to a full 20-byte hex value.
- Regression test: `packages/protocol/src/canonical.test.ts`
- Status: `fixed`

## F-0003 (Phase 2.2 Prototype)
- ID: `F-0003`
- Severity: `INFO`
- Description: Phase 2.2 TSS prototype is a `k256`-based 2-of-3 simulation in `crates/keymesh-tss-proto`; normal signing path reconstructs the group key via Lagrange inside `threshold_sign` and zeroizes immediately. This does not provide the UC-secure MPC guarantee of CGGMP21 (where `x` and `k` are never reconstructed). The prototype deliberately does NOT expose `reconstruct_private_key()` publicly — only `#[cfg(test)] reconstruct_secret_for_test` — but the internal reconstruction is a known limitation vs. production synedrion/cggmp21.
- Impact: Prototype demonstrates session/digest/threshold invariants but does NOT provide production threshold security.
- Reproduction: Inspect `crates/keymesh-tss-proto/src/signature.rs: threshold_sign` and `crates/keymesh-tss-proto/src/shamir.rs`.
- Fix: Documented as prototype limitation; production will replace with `synedrion 0.3` InteractiveSigning (no reconstruction) in Phase 2.3. No fake MPC claim.
- Regression test: `proto_tests::no_exposed_reconstruct_in_public_api` + `grep -r reconstruct_private_key crates/keymesh-tss-proto/src --include="*.rs"` returns no public hits.
- Status: `acknowledged — prototype limitation`

## F-0004 (Phase 2.7 Hardening)
- ID: `F-0004`
- Severity: `MEDIUM`
- Description: `lifecycle::tests::key_id_deterministic` previously called `setup_2of3()` without `#[ignore]` heavy gate, causing 60s+ timeout on Windows dev and blocking CI light suite.
- Impact: Light suite timeout, flaky local verification.
- Fix: Marked heavy lifecycle tests with `#[ignore = "heavy ..."]` and documented Windows vs Linux split in `tss.yml`; light governance tests remain non-heavy.
- Regression test: `cargo test --manifest-path crates/keymesh-tss/Cargo.toml --locked` now 30+ light pass, heavy isolated to `--ignored`.
- Status: `fixed`

## Summary
- No high-severity protocol findings have been confirmed during this pass.
- Phase 2.7 hardening adds no new high findings; one MEDIUM (F-0004) fixed. One INFO prototype limitation (F-0003) remains honestly deferred.
- Known limitations at freeze: distributed Synedrion runtime deferred (ADR-002), no external audit, no formal verification, `KeyRefresh` for ThresholdKeyShare not supported by library (refresh via resharing), no production HSM, licensing requires legal review.
