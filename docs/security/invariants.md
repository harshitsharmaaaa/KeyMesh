# KeyMesh Protocol Security Invariants

> **Status: Phase 1.4** — Formalized for fuzzing and invariant testing.
> This document lists every protocol invariant that must hold under arbitrary
> operation sequences. Each invariant corresponds to an explicit protocol
> requirement and is tested by the security test suites.

---

## 1. Device Authorization Invariants

### 1.1 Authorized Device Execution
**Invariant:** A transaction can execute only if the recovered signer is an active authorized device.

| Scenario | Expected Result |
|----------|-----------------|
| Authorized device + policy satisfied | Success |
| Revoked device | Always fails |
| Unknown device (never registered) | Always fails |
| Zero address | Never becomes valid device |

**Post-Recovery:**
| Scenario | Expected Result |
|----------|-----------------|
| Old (replaced) device | Cannot execute |
| New (recovery) device | Can execute if policy allows |

**Tests:** `KeymeshWalletInvariant.t.sol`, `KeymeshWallet.t.sol`

---

### 1.2 Device Set Integrity
**Invariant:** The device set is modified only through:
- Bootstrap manager registration (pre-initialization only)
- Self-revocation by device
- `applyRecoveredDevice` from RecoveryManager (atomic add + revoke)

**Tests:** `KeymeshWalletGovernanceTest.t.sol`, `RecoveryManager.t.sol`

---

## 2. Nonce Monotonicity Invariants

### 2.1 Sequential Nonce Progression
**Invariant:** For every wallet, nonce only increases after successful execution.

| Scenario | Nonce Change |
|----------|--------------|
| Failed execution (signature, policy, expiry, revert) | Unchanged |
| Successful execution | Increases exactly by 1 |
| Replay attempt | Rejected (`InvalidNonce`) |
| Skipped nonce | Rejected (`InvalidNonce`) |

**Tests:** `KeymeshWalletInvariant.t.sol` fuzz suite

---

### 2.2 Nonce Binding to Digest
**Invariant:** The canonical digest includes the nonce; changing nonce changes the digest.

**Tests:** Cross-language vectors, `TransactionDigest.t.sol`

---

## 3. Transaction Digest Binding Invariants

### 3.1 Canonical Digest Completeness
**Invariant:** Every signature is bound to all fields in the KEYMESH_TX_V1 encoding:
- `wallet` (20 bytes)
- `chainId` (uint256 BE)
- `nonce` (uint256 BE)
- `to` (20 bytes)
- `value` (uint256 BE)
- `dataLen` (uint32 BE)
- `data` (raw bytes)
- `expiry` (uint256 BE)
- Domain separator `KEYMESH_TX_V1`

**Property:** Changing ANY signed field must invalidate the original signature.

**Fuzz Targets:** Each field independently mutated.

**Tests:** `CanonicalEncodingFuzz.t.sol`, cross-language vectors

---

### 3.2 Calldata Boundary Handling
**Invariant:** Calldata encoding handles all boundary cases:
- Empty data (0 bytes)
- 1-byte data
- 4-byte data (selector boundary)
- Large data (up to MAX_DATA_BYTES)
- Oversized data (> MAX_DATA_BYTES) → rejects

**Tests:** `CanonicalEncodingFuzz.t.sol`, `TransactionDigest.t.sol`

---

## 4. Canonical Encoding Invariants

### 4.1 Determinism
**Invariant:** Same transaction object → same encoding → same digest.

### 4.2 Injectivity
**Invariant:** Different protected field → different digest.

### 4.3 Cross-Language Consistency
**Invariant:** TypeScript encoding = Rust encoding = Solidity digest for all test vectors.

**Test Vectors:**
| Vector | Description |
|--------|-------------|
| zero transaction | All zeros (except required fields) |
| max integer fields | chainId, nonce, value, expiry at bounds |
| max data size | 128 KB data |
| empty data | Zero-length calldata |
| one-byte data | Minimal calldata |
| large calldata | Near-max calldata |
| min chainId | 1 (mainnet) |
| max chainId | 2^64-1 |

**Tests:** `packages/protocol/src/vectors.ts`, `crates/keymesh-core/tests`, `TransactionDigest.t.sol`

---

## 5. Recovery State Machine Invariants

### 5.1 State Definitions
```
None → Pending → QuorumReached → Executable → Executed
                      ↘ Cancelled ↗
```
- `None`: No active request (or terminal request finalized)
- `Pending`: Open, collecting approvals
- `QuorumReached`: Quorum met, timelock running
- `Executable`: Timelock elapsed (inclusive: `now >= executeAfter`)
- `Executed`: Terminal, device replaced
- `Cancelled`: Terminal, cancelled by device

### 5.2 Valid Transitions
| From State | Action | To State | Conditions |
|------------|--------|----------|------------|
| None | Initiate | Pending | No live request, valid config |
| Pending | Approve | Pending/QuorumReached | Active guardian, not duplicate |
| Pending/QuorumReached/Executable | Cancel | Cancelled | Authorized device |
| QuorumReached | (time passes) | Executable | `now >= executeAfter` (inclusive) |
| Executable | Finalize | Executed | Permissionless |

### 5.3 Invalid Transitions (Must Revert)
- Skip required authorization
- Skip timelock
- Resurrect terminal state (Executed/Cancelled)
- Double execute
- Double cancel
- Approve from non-Pending state
- Finalize from non-Executable state
- Initiate when live request exists

### 5.4 Snapshot Semantics
**Invariant:** Quorum and timelock are snapshotted at initiation; later config changes cannot weaken in-flight recovery.

### 5.5 Guardian Approval Uniqueness
**Invariant:** Each guardian can approve at most once per request.

### 5.6 Quorum Counting
**Invariant:** Quorum counts distinct guardians (one approval each, unweighted).

**Tests:** `RecoveryManagerInvariant.t.sol`, `RecoveryManager.t.sol`, Rust `recovery/mod.rs` tests

---

## 6. Guardian Set Invariants

### 6.1 No Duplicates
**Invariant:** No duplicate active guardians per wallet.

### 6.2 Valid Quorum
**Invariant:** `1 <= quorum <= active_guardian_count` always holds.

### 6.3 Wallet Isolation
**Invariant:** Guardian state is strictly per-wallet; operations on wallet A cannot affect wallet B.

### 6.4 Availability Trade-off (Documented)
**Invariant:** Removing guardians below quorum can disable future recoveries.
- This is a DOCUMENTED AVAILABILITY TRADE-OFF, not a vulnerability.
- The device-holder controls guardian removal.

**Tests:** `GuardianRegistryInvariant.t.sol`, `RecoveryManager.t.sol` (cross-wallet isolation)

---

## 7. Policy Classification Invariants

### 7.1 Documented Precedence (First Match Wins)
1. **Admin selector** (structural) → `DEVICE_PLUS_GUARDIANS`
2. **Restricted selector** → `DEVICE_PLUS_GUARDIANS`
3. **Restricted destination** → `DEVICE_PLUS_GUARDIANS`
4. **Value > threshold** → `DEVICE_PLUS_GUARDIANS`
5. **Default mode** → wallet's configured default

**Invariant:** This precedence order NEVER changes. Implementation must match documentation exactly.

### 7.2 Unconfigured Wallet Behavior
**Invariant:** Version 0 wallets behave exactly like Phase 1.1 (DEVICE_ONLY), EXCEPT rule 1 (admin selector).

### 7.3 Value Threshold Boundary
**Invariant:** `value <= threshold` → default rule (inclusive boundary).
- `threshold` → DEVICE_ONLY (if default is DEVICE_ONLY)
- `threshold + 1` → DEVICE_PLUS_GUARDIANS

### 7.4 Selector Classification
**Invariant:** Empty or shorter-than-4-byte calldata never matches a selector rule.

### 7.5 Admin Selector Anti-Downgrade
**Invariant:** PolicyManager admin selectors are STRUCTURALLY classified `DEVICE_PLUS_GUARDIANS`.
- Single device alone CANNOT weaken policy
- Attempting to add/remove admin selector restriction reverts

**Tests:** `PolicyManagerInvariant.t.sol`, `PolicyManager.t.sol`

---

## 8. Policy Version Invariants

### 8.1 Version Bump
**Invariant:** Every policy mutation increments `policyVersion` exactly once.

### 8.2 Authorization Invalidation
**Invariant:** A pending transaction authorization created under version N becomes invalid after ANY policy change.
- Request snapshots version at creation
- Approval re-checks version
- Consumption re-checks version

### 8.3 Nonce Consumption Layer
**Invariant:** Governed policy changes themselves consume a wallet nonce, invalidating pre-change payloads at the nonce layer first.

**Tests:** `PolicyManagerInvariant.t.sol` (version race tests)

---

## 9. Per-Digest Authorization Invariants

### 9.1 Single Consumption
**Invariant:** For every transaction digest, at most one successful consumption.

### 9.2 Lifecycle
**Invariant:** One digest → one authorization lifecycle → at most one successful execution.

States: `None → Pending → Authorized → Executed`
Terminal: `Cancelled`, `Executed`

### 9.3 Digest Binding
**Invariant:** Authorization cannot be copied between:
- Wallets
- Nonces
- Transactions
- Policy versions

**Tests:** `PolicyManagerInvariant.t.sol`, `PolicyManager.t.sol`

---

## 10. Authorization Atomicity Invariants

### 10.1 Failed Transaction State
**Invariant:** For any failed transaction:
- Nonce unchanged
- Authorization remains usable if failure is retryable (target revert)
- Policy state unchanged
- Device state unchanged
- Guardian state unchanged

### 10.2 Successful Transaction State
**Invariant:** For any successful transaction:
- Nonce consumed exactly once
- Authorization consumed exactly once
- External call executed exactly once

### 10.3 Failure Modes Tested
- Invalid signature
- Unauthorized device
- Policy mismatch
- Insufficient guardians
- Expired authorization
- Reverted target call
- Malformed transaction

**Tests:** `KeymeshWalletInvariant.t.sol`, `PolicyManagerInvariant.t.sol`

---

## 11. Cross-Wallet Isolation Invariants

**Invariant:** Operations on Wallet A never affect Wallet B.

| Operation | Isolation |
|-----------|-----------|
| Guardian A approves recovery for Wallet B | Rejected |
| Policy A affects Wallet B | Impossible |
| Recovery A affects Wallet B | Impossible |
| Device A executes on Wallet B | Rejected |
| Authorization A executes on Wallet B | Rejected |

**Tests:** Cross-wallet tests in `RecoveryManager.t.sol`, `PolicyManager.t.sol`, new invariant tests

---

## 12. Privilege Escalation Invariants

### 12.1 Manager Authority Retirement
**Invariant:** Post-bootstrap manager CANNOT:
- Register device
- Revoke device
- Bypass recovery
- Modify policy
- Approve transaction
- Cancel arbitrary recovery

### 12.2 Zero/Unknown Addresses
**Invariant:** Zero address and unknown addresses never gain privileges.

### 12.3 Former Roles
**Invariant:** Former manager, former guardian, revoked device have no residual authority.

**Tests:** `KeymeshWalletGovernanceTest.t.sol`, `RecoveryManager.t.sol`, new privilege escalation tests

---

## 13. Policy Anti-Downgrade Invariant

**Invariant:** PolicyManager mutations themselves require `DEVICE_PLUS_GUARDIANS`.

| Attempted Mutation | Single Device Alone | Result |
|--------------------|---------------------|--------|
| Increase threshold | Cannot | Reverts |
| Decrease threshold | Cannot | Reverts |
| Remove destination restriction | Cannot | Reverts |
| Remove selector restriction | Cannot | Reverts |
| Change default mode | Cannot | Reverts |

**Tests:** `PolicyManagerInvariant.t.sol` (anti-downgrade fuzz)

---

## 14. Time-Boundary Invariants

### 14.1 Recovery Timelock (Inclusive)
**Invariant:** `executeAfter` boundary is inclusive.
- `now < executeAfter` → Not executable
- `now >= executeAfter` → Executable

### 14.2 Transaction Expiry (Inclusive)
**Invariant:** Transaction valid while `block.timestamp <= expiry`.
- `now <= expiry` → Valid
- `now > expiry` → Expired

### 14.3 Boundary Fuzzing
**Test Points:**
- `executeAfter - 1`
- `executeAfter`
- `executeAfter + 1`
- `expiry - 1`
- `expiry`
- `expiry + 1`

**Tests:** `RecoveryManagerInvariant.t.sol`, `KeymeshWalletInvariant.t.sol`

---

## 15. Arithmetic and Bounds Invariants

**Invariant:** No overflow, underflow, truncation, or cast bugs in:
- `value` (u128 in Rust, uint256 in Solidity)
- `chainId` (u64 in Rust, uint256 in Solidity)
- `nonce` (u64 in Rust, uint256 in Solidity)
- `expiry` (u64 in Rust, uint256 in Solidity)
- `timelock` (u64 in Rust, uint64 in Solidity)
- `guardian threshold` (u32 in Rust, uint256 in Solidity)
- `policy thresholds` (uint256)
- `set sizes` (bounded by constants)
- `data length` (u32 in Rust, uint32 in Solidity)

**Tests:** Fuzz tests with boundary values (0, 1, MAX, MAX-1)

---

## 16. External Call / Reentrancy Invariants

### 16.1 Reentrancy Protection
**Invariant:** ReentrancyGuard protects all state-changing external calls.

### 16.2 State Integrity Under Reentrancy
**Invariant:** Even under adversarial reentrancy:
- State cannot be corrupted
- Nonce cannot be consumed twice
- Authorization cannot be consumed twice
- Device state cannot be partially changed

**Tests:** Adversarial contracts in `KeymeshWalletInvariant.t.sol`, `RecoveryManagerInvariant.t.sol`

---

## 17. Cross-Language Consistency Invariants

### 17.1 Canonical Encoding
**Invariant:** TypeScript = Rust = Solidity for all test vectors.

### 17.2 Policy Classification
**Invariant:** TypeScript `classifyTransaction` = Rust `classify` = Solidity `evaluateAuthorization` for identical inputs.

### 17.3 Recovery Transitions
**Invariant:** Rust state machine = Solidity state machine for identical action sequences.

**Tests:** Differential test suites in each language + shared vectors

---

## 18. Testing Coverage Matrix

| Invariant Category | Unit Tests | Fuzz Tests | Invariant Tests | Differential |
|--------------------|------------|------------|-----------------|--------------|
| Device Authorization | ✅ | ✅ | ✅ | ✅ |
| Nonce Monotonicity | ✅ | ✅ | ✅ | - |
| Digest Binding | ✅ | ✅ | - | ✅ |
| Canonical Encoding | ✅ | ✅ | - | ✅ |
| Recovery FSM | ✅ | ✅ | ✅ | ✅ |
| Guardian Sets | ✅ | ✅ | ✅ | - |
| Policy Classification | ✅ | ✅ | ✅ | ✅ |
| Policy Versioning | ✅ | ✅ | ✅ | - |
| Per-Digest Auth | ✅ | ✅ | ✅ | - |
| Atomicity | ✅ | ✅ | ✅ | - |
| Cross-Wallet | ✅ | ✅ | ✅ | - |
| Privilege Escalation | ✅ | ✅ | ✅ | - |
| Anti-Downgrade | ✅ | ✅ | ✅ | - |
| Time Boundaries | ✅ | ✅ | ✅ | - |
| Arithmetic/Bounds | ✅ | ✅ | - | ✅ |
| Reentrancy | ✅ | ✅ | ✅ | - |

---

## 19. Known Untested Areas / Limitations

1. **No external audit** — All testing is internal
2. **No formal verification** — Properties tested via fuzzing, not proven
3. **ECDSA single-device signing** — No threshold cryptography yet
4. **Guardian governance assumptions** — Trust model documented in threat-model.md
5. **Bounded policy sets** — MAX_RESTRICTED_DESTINATIONS (256), MAX_RESTRICTED_SELECTORS (64)
6. **No velocity limits** — Compromised device can drain until recovery completes
7. **No guardian privacy** — All approvals public on-chain
8. **Rust crypto mock** — Production signing paths not in Rust core yet

---

## 20. Invariant Test Commands

```bash
# Foundry invariant tests
cd contracts/ethereum && forge test --match-contract Invariant -vvv

# Foundry fuzz tests
cd contracts/ethereum && forge test --match-contract Fuzz -vvv

# Rust property tests
cd crates/keymesh-core && cargo test --all-features --locked

# TypeScript property/boundary tests
cd packages/protocol && bun test

# Cross-language differential
cd packages/protocol && bun test -- --reporter=verbose
cd crates/keymesh-core && cargo test --all-features --locked
cd contracts/ethereum && forge test -vvv

# Full CI suite
bun run format:check && bun run lint && bun run typecheck && bun run test && bun run build
cd crates/keymesh-core && cargo fmt --check && cargo test --all-features --locked && cargo clippy --all-targets --all-features --locked -- -D warnings
cd contracts/ethereum && forge build && forge test
bun run integration:anvil
```