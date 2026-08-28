# keymesh-tss — Phase 2.3 Real Threshold ECDSA

Isolated crate for real threshold ECDSA via `synedrion 0.3` (CGGMP'24).

* DKG: synedrion `KeyInit` (no trusted dealer, distributed)
* Signing: `InteractiveSigning` (presign+sign) via `manul::TestRuntime`
* Threshold: 2-of-3 via `ThresholdKeyShare`
* No application-level private key reconstruction — signing operates on distributed `KeyShare`/`AuxInfo` state.

Maturity: **REAL PROTOTYPE**, NOT PRODUCTION, NOT AUDITED.

See `crates/keymesh-tss-proto` for Phase 2.2 simulation (kept for comparison).
