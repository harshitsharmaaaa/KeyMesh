# KeyMesh Security Testing Strategy

> **Status: Phase 1.4** — Multi-layer testing approach to establish confidence
> in the existing protocol before Phase 2 (TSS/MPC) begins.

---

## Objective

Answer the question: **Can we trust the existing KEYMESH protocol semantics before changing its cryptographic signing mechanism?**

The protocol must demonstrate:
- Correct state transitions
- Authorization isolation
- Replay resistance
- Policy consistency
- Recovery correctness
- Atomicity
- Cross-wallet isolation
- No privilege escalation

**Prefer finding bugs over adding abstractions.**

---

## Testing Layers

### Layer 1: Existing Unit Tests (Baseline)
**Status:** Complete — All 241 tests passing
- TypeScript: 71 tests (protocol, canonical, types, SDK)
- Rust: 48 tests (policy, recovery, transaction, crypto)
- Foundry: 122 tests (wallet, policy, recovery, guardian, digest)
- Integration: Anvil end-to-end PASS

**Rule:** Never remove or weaken existing tests.

---

### Layer 2: Property/Invariant Tests (Foundry Invariant Framework)
**Goal:** Prove invariants hold across arbitrary operation sequences.

**Approach:**
1. Create handler contracts that model protocol state
2. Define allowed operations (valid + invalid)
3. After each random operation sequence, assert invariants
4. Use bounded fuzzing for CI stability

**Invariant Suites:**
- `KeymeshWalletInvariant.t.sol`
- `RecoveryManagerInvariant.t.sol`
- `PolicyManagerInvariant.t.sol`
- `AuthorizationInvariant.t.sol`
- `CanonicalEncodingInvariant.t.sol`

**Model State:** Each handler maintains a shadow state mirroring the contract, updated on each operation, with assertions comparing expected vs actual.

---

### Layer 3: Fuzz Tests (Foundry Built-in Fuzzing)
**Goal:** Generate arbitrary valid and invalid inputs to find edge cases.

**Approach:**
- `testFuzz_*` functions with `uint256`, `address`, `bytes`, `bytes32` parameters
- Foundry generates random values within type bounds
- Use `vm.assume()` to constrain to valid ranges where needed
- Target specific properties per fuzz suite

**Fuzz Suites:**
- `KeymeshWalletFuzz.t.sol` — execute, device management
- `RecoveryManagerFuzz.t.sol` — recovery lifecycle, guardian sets
- `PolicyManagerFuzz.t.sol` — classification, configuration
- `CanonicalEncodingFuzz.t.sol` — digest computation
- `GuardianRegistryFuzz.t.sol` — guardian set operations

**CI Bounds:** 5,000 runs, depth 50
**Local Bounds:** 50,000+ runs, depth 200+

---

### Layer 4: Differential Tests (Cross-Language)
**Goal:** Prove Rust, TypeScript, and Solidity implementations produce identical results for identical inputs.

**Comparisons:**
| Component | TypeScript | Rust | Solidity |
|-----------|------------|------|----------|
| Canonical encoding | `encodeCanonicalTransaction` | `encode_canonical` | `KeymeshTx.digest` |
| Policy classification | `classifyTransaction` | `classify` | `evaluateAuthorization` |
| Recovery transitions | `recovery.ts` (prototype) | `RecoveryRequest` | `RecoveryManager` |

**Method:**
1. Shared test vectors in `packages/protocol/src/vectors.ts`
2. Each language implements vector validation
3. Random input generation with cross-language verification
4. Any mismatch = protocol bug (not test artifact)

---

### Layer 5: Integration Tests (Preserved)
**Goal:** End-to-end validation on Anvil.

**Existing Flow:** `bun run integration:anvil` — 18-step recovery + transaction flow

**Rule:** Do not replace. Extend only if new scenarios need E2E validation.

---

## Invariant Formalization

**Document:** `docs/security/invariants.md`

Every invariant:
1. Has a clear statement
2. Maps to explicit protocol requirement
3. Is tested by at least one test layer
4. Has a regression test if ever violated

**Categories:**
1. Device Authorization
2. Nonce Monotonicity
3. Transaction Digest Binding
4. Canonical Encoding
5. Recovery State Machine
6. Guardian Sets
7. Policy Classification
8. Policy Versioning
9. Per-Digest Authorization
10. Authorization Atomicity
11. Cross-Wallet Isolation
12. Privilege Escalation
13. Policy Anti-Downgrade
14. Time Boundaries
15. Arithmetic/Bounds
16. Reentrancy
17. Cross-Language Consistency

---

## Cross-Language Consistency

**Principle:** Single source of truth per component.

| Component | Authority | Consumers |
|-----------|-----------|-----------|
| Canonical TX format | `docs/protocol/canonical-transaction.md` | TS, Rust, Solidity |
| Policy classification | `docs/protocol/policies.md` | TS, Rust, Solidity |
| Recovery FSM | `docs/protocol/recovery.md` | TS, Rust, Solidity |

**Process for mismatch:**
1. Isolate the divergence
2. Determine authoritative specification
3. Fix ALL implementations
4. Add permanent test vector
5. Document in findings

---

## Regression Strategy

**Before any change:**
1. Run full baseline suite (record counts)
2. Make change
3. Run full suite again
4. Compare results

**Baseline (Phase 1.3 final):**
- TypeScript: 71 passing
- Rust: 48 passing
- Foundry: 122 passing
- Integration: PASS
- Build: PASS
- Lint: PASS
- Typecheck: PASS
- Format: PASS

**After Phase 1.4:** Counts may increase. Never decrease.

---

## Bug Classification & Handling

When a test fails:

| Classification | Action |
|----------------|--------|
| **Real security bug** | Reproduce → Regression test → Fix → Full suite |
| **Real availability bug** | Reproduce → Regression test → Fix → Full suite |
| **Real correctness bug** | Reproduce → Regression test → Fix → Full suite |
| **Documented trade-off** | Verify test matches docs; if so, fix test |
| **False positive** | Fix test harness |
| **Test harness issue** | Fix test |

**Never change intended protocol behavior merely because a property was written incorrectly.**

---

## Documentation Requirements

### Created in Phase 1.4:
1. `docs/security/invariants.md` — All protocol invariants
2. `docs/security/fuzzing.md` — Fuzzing strategy & configuration
3. `docs/security/testing-strategy.md` — This document
4. `docs/security/review-checklist.md` — External review prep
5. `docs/security/findings.md` — Discovered issues tracker

### Updated:
1. `docs/security/threat-model.md` — Reflect tested invariants
2. `docs/security/security-model.md` — Update enforcement status
3. `docs/architecture/overview.md` — Note testing maturity
4. `README.md` — Security testing section

---

## CI Integration

**Current Structure (3 jobs):**
1. TypeScript (format, lint, typecheck, test, build)
2. Rust (fmt, test, clippy)
3. Foundry (build, test)

**Additions:**
- Invariant tests in Foundry job
- Fuzz tests in Foundry job (bounded)
- Property tests in Rust job (if proptest added)
- Differential validation in TypeScript job

**All new tests must run in CI.** No local-only security checks.

---

## Gas Regression

**Measure before and after hardening:**
- `execute()` normal
- `execute()` policy-governed
- Guardian approval
- Recovery finalization
- Policy update

**Record in:** Test output + `docs/security/findings.md`

**Goal:** Identify accidental regressions, not optimize.

---

## Static/Security Analysis

**Use existing toolchain:**
- `forge build` — Compilation warnings
- `forge test` — Test coverage
- `forge inspect` — Contract metadata
- `cargo clippy -- -D warnings` — Rust lints
- `bun run lint` — TypeScript/JS linting

**Do not add heavy tools** unless they run deterministically in CI.

---

## External Review Preparation

**Goal:** External security engineer can understand security model without reverse engineering.

**Deliverable:** `docs/security/review-checklist.md` covering:
- Architecture overview
- Trust assumptions
- Privileged roles
- State machines
- Authorization flow
- Policy precedence
- Recovery lifecycle
- Canonical encoding
- Replay protection
- Known risks/limitations
- Test commands
- Deployment assumptions

---

## Definition of Done (Phase 1.4)

- [ ] Security invariants documented (`invariants.md`)
- [ ] Device authorization invariants tested (invariant + fuzz)
- [ ] Nonce invariants tested (invariant + fuzz)
- [ ] Canonical digest properties tested (invariant + fuzz + differential)
- [ ] Cross-language vectors expanded
- [ ] Recovery state machine fuzzed (invariant + fuzz)
- [ ] Guardian invariants fuzzed (invariant + fuzz)
- [ ] Policy precedence fuzzed (invariant + fuzz + differential)
- [ ] Value threshold boundaries tested (fuzz)
- [ ] Destination restrictions fuzzed (fuzz)
- [ ] Selector boundaries tested (fuzz)
- [ ] Policy version invalidation tested (invariant + fuzz)
- [ ] Per-digest authorization replay tested (invariant + fuzz)
- [ ] Authorization atomicity tested (invariant + fuzz)
- [ ] Cross-wallet isolation tested (invariant + fuzz)
- [ ] Manager privilege retirement tested (invariant + fuzz)
- [ ] Policy anti-downgrade tested (invariant + fuzz)
- [ ] Timestamp boundaries tested (fuzz)
- [ ] Arithmetic/bounds tested (fuzz)
- [ ] Reentrancy/adversarial calls tested (invariant + fuzz)
- [ ] Foundry invariant tests implemented
- [ ] Rust property tests implemented (where justified)
- [ ] TypeScript property/boundary tests implemented (where justified)
- [ ] Gas regression measurements recorded
- [ ] CI runs new security tests
- [ ] Security documentation updated
- [ ] External review checklist created
- [ ] Findings tracked
- [ ] No TSS/MPC implemented
- [ ] Phase 1.1/1.2/1.3 functionality intact

---

## Verification Commands

```bash
# Full verification suite
bun --version
bun install --frozen-lockfile
bun run format:check
bun run lint
bun run typecheck
bun run test
bun run build

cargo fmt --check
cargo test --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings

forge build
forge test

bun run integration:anvil
```

**Fuzz parameters recorded in test output.**

---

## Final Report Template

When complete, provide:

### Security Work Completed
- Exact tests/invariants added

### Bugs Discovered
- Only real findings with: severity, root cause, impact, fix, regression test

### Invariants Covered
- List of important properties now tested

### Fuzzing Statistics
- Foundry fuzz runs
- Foundry invariant runs
- Rust property-test cases
- TypeScript property/boundary cases

### Differential Verification
- Components compared (Rust/TS/Solidity)
- What was proven equivalent

### Gas Results
- execute, guardian approval, recovery finalization, policy update

### Test Results
- TypeScript: X passing
- Rust: X passing
- Foundry: X passing
- Integration: PASS/FAIL
- Build/Lint/Typecheck/Format/Clippy: PASS/FAIL

### Findings Summary
- Remaining risks

### Known Limitations
- Honest about: no audit, no formal verification, ECDSA single-device, guardian assumptions, bounded sets

### Next Milestone Readiness
- Ready for Phase 2 (TSS/MPC)? Yes/No with justification