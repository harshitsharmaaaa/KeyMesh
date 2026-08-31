# KeyMesh Architecture & Component Overview

> **Status:** Phase 2.7 Complete / Freeze Architecture

KeyMesh distributes authority over digital asset transactions across device signatures, policy engines, and guardian recovery quorums.

---

## 1. System Overview Architecture

```mermaid
graph TD
    Client["Client / SDK / Dashboard"] -->|KEYMESH_TX_V1| SigningLayer["Signing Layer (SigningProvider)"]
    
    subgraph SigningLayer ["Signing Layer (SigningProvider)"]
        SingleECDSA["SingleEcdsaProvider"]
        ThresholdECDSA["ThresholdEcdsaProvider (CGGMP'24)"]
    end

    SigningLayer -->|ECDSA Signature (r, s, v)| KeymeshWallet["KeymeshWallet.sol (On-Chain)"]

    subgraph Governance ["On-Chain Security & Governance"]
        PolicyMgr["PolicyManager.sol"]
        RecoveryMgr["RecoveryManager.sol"]
        GuardianReg["GuardianRegistry.sol"]
    end

    KeymeshWallet -->|Classify Policy| PolicyMgr
    RecoveryMgr -->|Manage Quorums| GuardianReg
    RecoveryMgr -->|Apply Replaced Device| KeymeshWallet
```

---

## 2. Transaction Authorization Flow

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Caller / User
    participant SDK as KeyMesh SDK
    participant Policy as PolicyManager
    participant Provider as SigningProvider (Device/TSS)
    participant Wallet as KeymeshWallet

    Caller->>SDK: Create Transaction (to, value, data)
    SDK->>Policy: Classify Payload (getMode)
    Policy-->>SDK: PolicyMode (ALLOW, DEVICE_ONLY, DEVICE_PLUS_GUARDIANS)
    
    alt PolicyMode == DEVICE_PLUS_GUARDIANS
        SDK->>Policy: Submit Guardian Approval Request
        Note over Policy: Guardian Quorum Approves Digest
    end

    SDK->>Provider: Request Signature for KEYMESH_TX_V1 Digest
    Provider-->>SDK: ECDSA Signature (r, s, v)
    SDK->>Wallet: execute(to, value, data, expiry, signature)
    
    Wallet->>Policy: Verify Transaction Authorization
    Policy-->>Wallet: Authorization OK
    Wallet->>Wallet: ecrecover(KEYMESH_TX_V1) == active device
    Wallet->>Wallet: Execute Low-Level Call & Increment Nonce
```

---

## 3. Guardian Recovery & Device Replacement Flow

```mermaid
sequenceDiagram
    autonumber
    participant Guardian as Guardian / Device
    participant Recovery as RecoveryManager
    participant Registry as GuardianRegistry
    participant Wallet as KeymeshWallet

    Guardian->>Recovery: initiateRecovery(wallet, oldDevice, newDevice)
    Note over Recovery: State: Pending (Timelock set)
    
    loop Collect Approvals
        Guardian->>Recovery: approveRecovery(wallet, oldDevice, newDevice)
        Recovery->>Registry: verifyGuardian(wallet, msg.sender)
    end
    
    Note over Recovery: Quorum Met -> State: QuorumReached
    
    opt Active Device Cancellation
        Guardian->>Recovery: cancelRecovery(wallet, oldDevice, newDevice)
        Note over Recovery: State: Cancelled (Terminal)
    end

    Note over Recovery: Wait Mandatory Timelock Window -> State: Executable
    
    Recovery->>Recovery: finalizeRecovery(wallet, oldDevice, newDevice)
    Recovery->>Wallet: applyRecoveredDevice(oldDevice, newDevice)
    Note over Wallet: Revoke oldDevice, Register newDevice atomically
```

---

## 4. Threshold Cryptography Architecture (CGGMP'24)

```mermaid
flowchart TD
    Digest["KEYMESH_TX_V1 Canonical Digest"] --> Provider["ThresholdEcdsaProvider"]
    
    subgraph ThresholdMPC ["Synedrion CGGMP'24 Threshold ECDSA (2-of-3)"]
        Coord["Session Coordinator / Transport"]
        P1["Participant 1 (Share x1)"]
        P2["Participant 2 (Share x2)"]
        P3["Participant 3 (Share x3)"]
        
        Coord <--> P1
        Coord <--> P2
        Coord <--> P3
    end

    Provider --> ThresholdMPC
    ThresholdMPC -->|Interactive MPC Signing| ECDSA["ECDSA Signature (r, s, v)"]
    ECDSA --> Ethereum["On-Chain ecrecover (KeymeshWallet)"]
```

---

## 5. TSS Key Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> Uninitialized
    Uninitialized --> Active: KeyGen (CGGMP'24 DKG)
    
    state Active {
        [*] --> Ready
        Ready --> Refreshing: KeyRefresh (Resharing to same set)
        Refreshing --> Ready: Preserves Public Key & Address
        
        Ready --> Rotating: KeyResharing (Governed Set Rotation)
        Rotating --> Ready: Monotonic Version Increment
    }

    Active --> Retired: Key Retirement / Finalization
    Retired --> [*]
```
