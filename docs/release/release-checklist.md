# Release Checklist — Phase 2.7

> Freeze: `docs/security/security-freeze.md` controls semantics.

- [ ] `bun install --frozen-lockfile` clean
- [ ] `bun run format:check` green
- [ ] `bun run lint` green
- [ ] `bun run typecheck` green
- [ ] `bun run test` green (84 tests: types 10, protocol 47, sdk 27)
- [ ] `cargo fmt --check` green (keymesh-core, keymesh-tss, keymesh-tss-proto)
- [ ] `cargo test --locked` green (core 52, proto 21, tss light 30+ heavy ignored on Windows)
- [ ] `cargo clippy --all-targets --locked -- -D warnings` green
- [ ] `forge build` / `forge test` green (268 contracts tests, fuzz/invariants)
- [ ] TSS heavy Linux suite green (`cargo test -- --ignored --test-threads=1` on ubuntu)
- [ ] Adversarial/security suites green
- [ ] No secrets committed (`git diff --check`, no `ThresholdKeyShare` dumps)
- [ ] Dependencies pinned (`bun.lock`, `Cargo.lock`, `foundry.lock`, submodules)
- [ ] Findings reviewed (`docs/security/findings.md` triaged)
- [ ] Threat model reviewed (`threat-model.md` + `tss-*.md`)
- [ ] Invariants classified (DESIGNED/PROTOTYPED/TESTED, no false AUDITED)
- [ ] Docs current (`security-freeze`, `adversarial-testing`, `tss-key-lifecycle`, `tss-lifecycle-threat-model`, `release-checklist`, `performance` notes)
- [ ] Network limitations documented (app-level auth TCP, no mTLS, production runtime deferred per ADR-002)
- [ ] License review pending/completed (see `docs/security/license-review.md`)
- [ ] Testnet status documented (`DEFERRED` — distributed runtime limitation, not fabricating Sepolia tx)
- [ ] Production status: `TSS/MPC = real crypto, experimental/testnet-oriented, not audited, not formally verified`
- [ ] Clean-checkout verified (`rm -rf node_modules && bun install && cargo check && forge build` in fresh clone)
- [ ] `bun run verify:security` documented (see `package.json` script)
