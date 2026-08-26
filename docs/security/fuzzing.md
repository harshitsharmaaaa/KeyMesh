# KeyMesh Fuzzing Strategy

> **Status: Phase 1.4** — This document describes the multi-layer fuzzing approach
> for security hardening. Each layer targets specific invariant categories.

---

## Layer 1: Existing Unit Tests (Preserved)

All existing tests from Phases 1.1-1.3 are preserved as the baseline.
- 71 TypeScript tests
- 48 Rust tests
- 122 Foundry tests
- Integration: PASS

---

## Layer 2: Property/Invariant Tests (Foundry Invariant Framework)

Using Foundry's invariant testing (`forge test --match-contract Invariant`).

### Handler Contracts

Each invariant test suite uses a handler contract that:
1. Maintains a model state mirroring the protocol
2. Performs random valid/invalid operations
3. Asserts invariants after each operation sequence

### Invariant Suites

| Suite | Target Contract | Key Invariants |
|-------|-----------------|----------------|
| `KeymeshWalletInvariant` | KeymeshWallet | Device auth, nonce monotonicity, digest binding, atomicity |
| `RecoveryManagerInvariant` | RecoveryManager | State machine, quorum, timelock, cross-wallet isolation |
| `PolicyManagerInvariant` | PolicyManager | Classification precedence, version invalidation, anti-downgrade |
| `AuthorizationInvariant` | PolicyManager + KeymeshWallet | Per-digest lifecycle, replay resistance, consumption |
| `CanonicalEncodingInvariant` | KeymeshTx (library) | Determinism, injectivity, cross-language |

### Handler Operations

Common operations across handlers:
```solidity
// KeymeshWallet handler
executeValidTx()
executeInvalidSig()
executeUnauthorizedDevice()
executeWrongNonce()
executeExpired()
executeRevertingTarget()
registerDevice()
revokeDevice()
applyRecoveredDevice()

// RecoveryManager handler
initiateRecovery()
approveRecovery()
cancelRecovery()
finalizeRecovery()
addGuardian()
removeGuardian()
setQuorum()
setTimelock()

// PolicyManager handler
configurePolicy()
setDefaultMode()
setValueThreshold()
setTransactionQuorum()
setDestinationRestriction()
setSelectorRestriction()
requestAuthorization()
approveTransaction()
cancelAuthorization()
consumeAuthorization()
```

### Model State Tracking

Each handler tracks:
- Device set per wallet
- Nonce per wallet
- Guardian set per wallet
- Active recovery per wallet (id, status, approvals)
- Policy config per wallet
- Pending authorizations per digest
- Expected vs actual state after each op

---

## Layer 3: Fuzz Tests (Foundry Fuzzing)

Using Foundry's built-in fuzzing (`testFuzz_*` functions).

### Fuzz Targets

| Fuzz Suite | Target | Parameters Fuzzed |
|------------|--------|-------------------|
| `KeymeshWalletFuzz.t.sol` | KeymeshWallet.execute | nonce, to, value, data, expiry, signature |
| `RecoveryManagerFuzz.t.sol` | RecoveryManager lifecycle | guardian sets, quorum, timelock, approval order |
| `PolicyManagerFuzz.t.sol` | PolicyManager classification | value, destination, selector, calldata, config |
| `CanonicalEncodingFuzz.t.sol` | KeymeshTx.digest | wallet, chainId, nonce, to, value, data, expiry |
| `GuardianRegistryFuzz.t.sol` | GuardianRegistry | add/remove sequences, duplicates, zero addresses |

### Fuzzing Parameters

```solidity
// Bounded for CI stability
uint256 constant FUZZ_RUNS = 10000;
uint256 constant FUZZ_DEPTH = 100;
```

### Key Fuzz Properties

#### Canonical Encoding
- `testFuzz_DeterministicEncoding` — same input → same output
- `testFuzz_Injectivity` — different field → different digest
- `testFuzz_BoundaryValues` — 0, 1, MAX, MAX-1 for all integers
- `testFuzz_DataLengths` — 0, 1, 4, MAX, MAX+1 bytes

#### Device Authorization
- `testFuzz_AuthorizedDevice` — valid device → success when policy allows
- `testFuzz_RevokedDevice` — always fails
- `testFuzz_UnknownDevice` — always fails
- `testFuzz_ZeroAddress` — never valid

#### Nonce Monotonicity
- `testFuzz_NonceOnlyIncreasesOnSuccess` — failed = unchanged, success = +1
- `testFuzz_ReplayRejected` — same nonce/digest rejected
- `testFuzz_FailedTargetNonceUnchanged` — revert bubbles, nonce preserved

#### Policy Classification
- `testFuzz_PrecedenceOrder` — admin > selector > destination > value > default
- `testFuzz_ValueBoundary` — threshold-1, threshold, threshold+1, 0, MAX
- `testFuzz_SelectorBoundary` — empty, 1, 2, 3, 4, >4 bytes
- `testFuzz_RestrictedSets` — 0, 1, MAX, MAX+1 entries

#### Recovery State Machine
- `testFuzz_StateTransitions` — arbitrary action sequences
- `testFuzz_TimelockBoundary` — executeAfter-1, executeAfter, executeAfter+1
- `testFuzz_GuardianQuorum` — approval order, duplicates, revocation

---

## Layer 4: Differential Tests

Comparing implementations across languages for identical inputs.

### Canonical Encoding Differential

| Input | TypeScript | Rust | Solidity |
|-------|------------|------|----------|
| All test vectors | ✅ | ✅ | ✅ |
| Random valid transactions | ✅ | ✅ | ✅ |
| Boundary values | ✅ | ✅ | ✅ |

**Test Method:** Shared vectors in `packages/protocol/src/vectors.ts` + `crates/keymesh-core/src/transaction/tests.rs` + `TransactionDigest.t.sol`

### Policy Classification Differential

| Input | TypeScript `classifyTransaction` | Rust `classify` | Solidity `evaluateAuthorization` |
|-------|----------------------------------|-----------------|----------------------------------|
| All configs + tx combinations | ✅ | ✅ | ✅ |

### Recovery State Machine Differential

| Input | TypeScript model | Rust `RecoveryRequest` | Solidity `RecoveryManager` |
|-------|------------------|------------------------|----------------------------|
| All action sequences | ✅ | ✅ | ✅ |

---

## Layer 5: Integration Tests (Preserved)

Existing Anvil end-to-end flow preserved:
```bash
bun run integration:anvil
```

---

## Fuzzing Configuration

### CI Configuration (Bounded)
```yaml
# .github/workflows/ci.yml additions
- name: Foundry Invariant Tests
  working-directory: contracts/ethereum
  run: forge test --match-contract Invariant --fuzz-runs 1000 --fuzz-depth 50

- name: Foundry Fuzz Tests
  working-directory: contracts/ethereum
  run: forge test --match-contract Fuzz --fuzz-runs 5000
```

### Local Intensive Fuzzing
```bash
# More aggressive local runs
cd contracts/ethereum
forge test --match-contract Invariant --fuzz-runs 100000 --fuzz-depth 200
forge test --match-contract Fuzz --fuzz-runs 50000
```

### Seed Reproduction
```bash
# Reproduce specific failure
forge test --match-contract Invariant --fuzz-seed <SEED> -vvv
```

---

## Fuzz Test Naming Convention

```
testFuzz_<PropertyName>_<Scenario>
testInvariant_<InvariantName>_<Component>
```

Examples:
- `testFuzz_NonceMonotonicity_ExecuteSequences`
- `testFuzz_DigestBinding_FieldMutations`
- `testInvariant_DeviceAuthorization_Wallet`
- `testInvariant_RecoveryStateMachine_Transitions`

---

## Property Classification

When fuzzing discovers a failure:

| Severity | Criteria |
|----------|----------|
| **CRITICAL** | Funds loss, privilege escalation, state corruption |
| **HIGH** | Authorization bypass, replay, nonce manipulation |
| **MEDIUM** | Availability issue, incorrect classification, gas DoS |
| **LOW** | Edge case UX, non-exploitable inconsistency |
| **TEST/ASSUMPTION** | Test bug, incorrect invariant, documented trade-off |

---

## Regression Strategy

For every discovered defect:
1. **Reproduce deterministically** — isolate minimal failing case
2. **Add regression test** — unit test covering exact scenario
3. **Fix the defect** — minimal change to restore invariant
4. **Rerun full suite** — ensure no regressions

**Never hide failures.** Document in `docs/security/findings.md`.

---

## Gas Regression Tracking

Measure and record gas for key operations before/after changes:
- Normal `execute()` (device only)
- Policy-governed `execute()` (with guardian auth)
- Guardian approval
- Recovery finalization
- Policy update

Record in test output and `docs/security/findings.md`.

---

## Tooling

### Foundry (Primary)
- Built-in fuzzing: `vm.assume`, `vm.fuzz`
- Invariant testing: `Invariant` contract, `setUp`, `invariant_*`
- Cheat codes: `vm.warp`, `vm.roll`, `vm.prank`

### Rust (proptest)
- Added to `crates/keymesh-core/Cargo.toml` if justified
- Property tests for: encoding, classification, recovery FSM

### TypeScript (fast-check / manual)
- Boundary parameterized tests
- Cross-language vector validation

---

## Reporting

For each fuzzing run, record:
- Runs configured
- Depth configured
- Seed (if relevant)
- Failures discovered
- Classification of each failure
- Fix status