# KeyMesh Protocol Overview

> **Status: Phase 1.1 implemented + design specification.** The device-signed
> Ethereum transaction path is real (see
> [canonical-transaction.md](canonical-transaction.md)). Guardian/recovery
> enforcement on-chain remains design-stage; anything not yet implemented is
> marked explicitly.

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
  TypeScript protocol package, and Solidity contracts.

**Enforced today (Phase 1.1):** a transaction executes only when its ECDSA
signature recovers to a registered device over the canonical
`KEYMESH_TX_V1` digest, with wallet/chainId binding, sequential nonce, and
inclusive expiry checked on-chain. Cross-language conformance vectors pin the
format in all three implementations.

## Serialization & signing

- The signed-transaction encoding is specified once in
  [canonical-transaction.md](canonical-transaction.md) and implemented
  byte-for-byte in TypeScript (`packages/protocol/src/canonical.ts`), Rust
  (`crates/keymesh-core/src/transaction`), and Solidity
  (`contracts/ethereum/src/KeymeshTx.sol`). Shared vectors live in
  `packages/protocol/src/vectors.ts`.
- Transaction signatures are domain separated by the `KEYMESH_TX_V1` domain
  tag plus `wallet` and `chainId` fields inside every digest. Future message
  classes (recovery approvals, device registration) will get their own
  versioned domains (`KEYMESH_*_V1` pattern) before any of them is signed.

See also: [wallet-lifecycle.md](wallet-lifecycle.md),
[recovery.md](recovery.md), [transaction-policy.md](transaction-policy.md).
