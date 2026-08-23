# KeyMesh Protocol Overview

> **Status: design specification.** Describes the protocol the implementation
> targets. Anything not yet implemented is marked explicitly.

## Protocol model

A KeyMesh wallet is a policy-enforced account whose authority is distributed
across devices and guardians.

### Actors

| Actor       | Description                                                                 |
| ----------- | --------------------------------------------------------------------------- |
| Owner       | The human controlling the wallet through devices                            |
| Device      | An authorized endpoint (laptop, phone, hardware key) with its own keypair    |
| Guardian    | A trusted party (address or contract) with an approval weight               |
| Policy      | Per-wallet rules mapping action classes to required weights + timelocks     |
| Contracts   | On-chain enforcement: KeymeshWallet, GuardianRegistry, RecoveryManager, PolicyManager |

### Core lifecycle (conceptual)

```
1. Wallet creation          deploy KeymeshWallet, authorize first device
2. Device authorization     additional devices added; old devices revocable
3. Guardian registration    guardians registered with weights on-chain
4. Transaction policies     thresholds per transaction class configured
5. Recovery initiation      new-device recovery opened for a wallet
6. Recovery approvals       guardian quorum accumulates weight
7. Recovery timelock        mandatory delay after quorum is reached
8. Recovery completion      new device authorized after timelock elapses
9. Device revocation        lost/stolen devices removed from authority set
```

### Authorization model

```
Normal transaction
    -> device authorization only

High-value transaction
    -> device authorization + guardian quorum (weight threshold)

Guardian / policy management
    -> device authorization + guardian quorum + timelock

Recovery
    -> threshold guardian approvals
    -> timelock window
    -> new device authorized
```

### Guarantees intended by the design (not all enforced yet)

- No single device can authorize high-value actions alone.
- Guardians cannot move funds; they can only approve/reject/cancel.
- A hostile recovery takes at least one timelock window, during which any
  active guardian can cancel it.
- All state transitions are deterministic and mirrored between the Rust core,
  TypeScript protocol package, and Solidity contracts. Conformance tests are a
  Phase 1 deliverable.

## Serialization & signing

- Canonical binary encoding lives in `crates/keymesh-core/src/serialization`
  (big-endian integers, u32 length prefixes, fixed u8 discriminants). Signatures
  cover canonical encodings so there is exactly one valid byte string per
  message.
- Signing payloads are domain-separated (`KEYMESH/tx-auth/v1`,
  `KEYMESH/recovery/v1`, `KEYMESH/device-reg/v1`) to prevent cross-protocol
  replay. Versioned domains allow future format changes without breaking old
  signatures.

See also: [wallet-lifecycle.md](wallet-lifecycle.md),
[recovery.md](recovery.md), [transaction-policy.md](transaction-policy.md).
