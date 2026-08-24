# Transaction Authorization Policies

> **Status: Phase 1.3 IMPLEMENTED on-chain and end-to-end verified.**
> `PolicyManager` classifies every transaction deterministically, and
> guardian-gated transfers require a per-digest authorization approved by the
> wallet's active guardians. The Rust core (`crates/keymesh-core/src/policy`)
> mirrors classification semantics; the TypeScript protocol package exposes
> the same model (`packages/protocol/src/policy.ts`).

## Separation of concerns (protocol invariant)

```text
Device signing    proves WHO authorized a request.
PolicyManager     determines WHAT authorization is required.
RecoveryManager   changes WHO controls the wallet.
```

These are separate contracts with separate state machines. A policy change is
not a recovery; an approval is not a signature; neither can substitute for the
other.

## Policy model

Per-wallet configuration (`IPolicyManager.PolicyConfig`):

| Field                     | Meaning                                                        |
| ------------------------- | -------------------------------------------------------------- |
| `defaultMode`             | Applied when no stronger rule matches                          |
| `valueThreshold`          | Wei; value STRICTLY ABOVE requires guardians                    |
| `guardianApprovalsRequired` | Quorum snapshotted into new authorization requests            |
| `version`                 | Bumped on every configuration change; 0 = unconfigured         |

Authorization modes (`IPolicyManager.AuthorizationMode`):

| Mode                   | Value | Meaning                                              |
| ---------------------- | ----- | ---------------------------------------------------- |
| `DEVICE_ONLY`          | 0     | registered-device signature suffices                |
| `DEVICE_PLUS_GUARDIANS`| 1     | device signature + per-digest guardian authorization |

The enum is extensible (future `TSS`, `MPC`) but existing values are frozen.

Restricted sets:

- **Destinations**: bounded at 256 addresses per wallet.
- **Selectors**: bounded at 64 four-byte selectors per wallet.

Both force `DEVICE_PLUS_GUARDIANS` regardless of value or default mode.

## Classification precedence

First match wins (deterministic, no ambiguity):

1. **Structural admin rule** — calldata whose selector mutates the
   PolicyManager itself, executed against the PolicyManager address →
   `DEVICE_PLUS_GUARDIANS`. This rule holds EVEN FOR UNCONFIGURED WALLETS and
   cannot be configured away: a single stolen device must never be able to
   weaken policy (anti-downgrade invariant).
2. Restricted calldata selector → `DEVICE_PLUS_GUARDIANS`.
3. Restricted destination → `DEVICE_PLUS_GUARDIANS`.
4. `value > valueThreshold` → `DEVICE_PLUS_GUARDIANS`.
5. Otherwise → the wallet's `defaultMode`.

Boundary semantics: `value <= threshold` follows rules 1–4's fall-through
(i.e., stays with the default rule); only strictly greater values escalate.
Empty calldata or calldata shorter than 4 bytes never matches selector rules.
Unconfigured wallets (version 0) classify everything as `DEVICE_ONLY`
except rule 1, preserving exact Phase 1.1 behavior until governance opts in.

## Policy ownership & governance

All configuration functions require `msg.sender == wallet`, i.e. they execute
through `KeymeshWallet.execute` with a valid device signature over the
canonical digest. Because those selectors are structurally
`DEVICE_PLUS_GUARDIANS` (precedence rule 1), such executions additionally need
a guardian-approved transaction authorization bound to that exact digest.

Progression:

```text
Phase 1.3  wallet/device-governed changes + mandatory guardian co-approval
Future     guardian-governed policy proposals independent of devices
Later      programmable governance modules
```

The Phase 1.2 bootstrap manager has NO authority here and is never consulted.

Bootstrap quorum: requests opened while the wallet is unconfigured clamp to
ONE guardian approval minimum — never zero (otherwise one guardian could
auto-authorize anything before configuration).

## Versioning & race semantics

Every configuration mutation increments the wallet's policy version. Requests
snapshot the version at request time; BOTH approval and execution re-check it:

```text
request under version N
        ↓ any config change bumps to N+1
remaining approvals revert PolicyChanged(N, N+1)
execution of the old digest reverts (nonce layer first, version second)
```

Chosen behavior: pending authorizations are INVALIDATED by any relevant policy
change — never silently grandfathered. Defense in depth: because every
governed change itself consumes a wallet nonce, the old signed payload usually
fails `InvalidNonce` first; the version check remains as the second,
independent layer.

## Transaction authorization lifecycle

Bound identity: the canonical `KEYMESH_TX_V1` digest — which already covers
wallet, chainId, nonce, to, value, data, expiry — plus defensive wallet
binding inside the record. An approval can therefore never be transferred to
a different transaction, wallet, chain, or nonce.

```text
None ──requestAuthorization(device)──► Pending
Pending ──quorum approvals───────────► Authorized
Authorized ──execute consumes────────► Executed   (terminal)
Pending/Authorized ──cancel(device)──► Cancelled  (terminal)

Forbidden: approve from None/Authorized/Executed/Cancelled;
           finalize from None/Pending/Cancelled;
           re-request under an existing digest (fresh nonce ⇒ fresh digest);
           consume twice; consume from another wallet.
```

Authority:

- `requestAuthorization`: an authorized DEVICE of the wallet (EOA call).
- `approveTransaction`: active guardians of that wallet only, once each.
- `cancelAuthorization`: authorized devices only — guardians cannot cancel
  (mirrors the recovery model: dissent = withhold approval).
- `consumeAuthorization`: ONLY the wallet contract, during `execute()`,
  effects-before-interaction.

No separate EXPIRED state exists: the request binds the canonical digest,
which embeds the transaction's own expiry; `execute()`'s existing temporal
check rejects expired payloads deterministically.

## Execution integration

`KeymeshWallet.execute` order (Phase 1.1 properties preserved):

1. wallet/chain domain binding
2. expiry (inclusive boundary)
3. sequential nonce
4. ECDSA recover over canonical digest
5. device authorization
6. **policy evaluation** → if `DEVICE_PLUS_GUARDIANS`,
   consume the per-digest authorization (effects-first)
7. nonce increment
8. external call (failing target reverts everything above — atomicity)
9. `TransactionExecuted`

Wallets deployed with `policyManager = address(0)` skip step 6 entirely
(explicit escape hatch, used by some Phase 1.1 unit tests).

## Failure modes

| Attempt | On-chain outcome |
| ------- | ---------------- |
| Device-only signature on guardian-gated transfer | `AuthorizationRequired(digest)` |
| Request exists, quorum not reached | `InsufficientGuardianApprovals(digest, approvals, required)` |
| Non-guardian approves | `NotRegisteredGuardian` |
| Same guardian approves twice | `TransactionAuthorizationAlreadyApproved` |
| Approval after cancellation / consumption / wrong wallet binding | `TransactionAuthorizationNotFound` |
| Any policy change between approval phases | `PolicyChanged(oldVersion, newVersion)` |
| Replay of consumed authorization | nonce mismatch first, then `AuthorizationNotConsumable(Executed)` |
| Cancelled request executes | `AuthorizationNotConsumable(Cancelled)` |
| Cross-wallet approval | `TransactionAuthorizationNotFound` (record bound to its own wallet) |

## Gas notes

Classification uses mappings only; the admin-selector check compares against
six constants. Restricted sets are bounded. No state-changing path iterates
over guardians or history. Requests store a fixed-size record keyed by digest;
approvals use per-digest mappings, so cancellation/consumption never loops.
