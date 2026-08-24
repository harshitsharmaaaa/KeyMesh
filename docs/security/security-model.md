# KeyMesh Security Model

> **Status: honest baseline.** This document states what KeyMesh is designed
> to protect against, what it explicitly does not, and which assumptions the
> guarantees depend on. Nothing here should be read as a claim that the current
> codebase is production-ready — see maturity labels throughout the repo.

## What KeyMesh is designed to protect against

| Threat                                        | Mechanism                                   | Enforced today? |
| --------------------------------------------- | ------------------------------------------- | --------------- |
| Replay of an executed transaction             | sequential wallet nonce checked on-chain    | yes (Phase 1.1, KeymeshWallet) |
| Cross-wallet / cross-chain signature reuse    | wallet + chainId bound inside signed digest | yes (Phase 1.1) |
| Eternal signatures                            | expiry field, valid while now <= expiry     | yes (Phase 1.1) |
| Transaction mutation after signing            | canonical encoding covers every field       | yes (Phase 1.1, cross-language vectors) |
| Unauthorized key authorizing a transfer        | on-chain device set + ECDSA recovery         | yes (Phase 1.1, single-key devices only) |
| Reentrancy during execution                   | OpenZeppelin ReentrancyGuard + effects-before-interaction | yes (Phase 1.1) |
| Single lost/stolen device draining a wallet   | value threshold + guardian co-approval      | PARTIAL (Phase 1.3): applies only to wallets that CONFIGURE a threshold; unconfigured wallets stay device-only |
| Loss of ALL devices                           | guardian recovery with timelock             | YES (Phase 1.2): `replacedDevice = 0` adds a fresh device after quorum + timelock |
| Hostile recovery takeover                     | mandatory ≥1h timelock + device cancellation | YES (Phase 1.2, RecoveryManager) |
| Stolen device weakening policy to bypass approvals | structural admin rule: policy mutations always need guardian co-approval | YES (Phase 1.3, tested) |
| Guardian approval reused for a different transfer | per-digest binding + single consumption | YES (Phase 1.3) |
| Stolen/compromised device keeping authority   | guardian quorum → timelock → atomic replacement | YES (Phase 1.2): old device revoked at finalization |
| Manager backdoor after initialization          | bootstrap-only role; `ManagerAuthorityRetired` on every manager path | YES (Phase 1.2, tested) |
| Guardian moving funds / signing transactions   | guardians can only initiate/approve recoveries of their own wallet | YES (Phase 1.2) |
| Seed-phrase theft                             | no seed phrase exists in the protocol model | by design |

## What KeyMesh does NOT protect against

1. **Any theft from a compromised device.** Normal transfers need exactly one
   registered-device signature. There is no velocity limit and no delay: a
   stolen device key can drain the wallet until revoked or replaced by
   recovery. This is the single most important limitation of Phases 1.1–1.2.
   Recovery revokes the thief's device only AFTER quorum + timelock — faster
   than that, nothing stops the drain.
2. **Full guardian collusion within one timelock window combined with an
   absent user** (and no honest device-holder cancelling). Timelocks make this
   *visible* and cancellable, not impossible.
3. **Coercion.** Timelocks raise the cost of wrench attacks but cannot prevent
   them.
4. **Compromised user operating environment.** A keylogger on the owner's
   machine defeats any client-side protocol.
5. **Chain-level failures.** Re-orgs beyond confirmation assumptions, consensus
   failures, or gas market conditions are out of scope.
6. **Privacy.** All authorization and recovery activity is public on-chain.

## Current implementation status (do not skip this section)

- **Phase 1.1 works end-to-end**: SDK → canonical `KEYMESH_TX_V1` encoding →
  keccak-256 digest → ECDSA device signature (@noble/curves secp256k1,
  deterministic RFC-6979 nonces, low-s) → Solidity `ECDSA.recover` → device /
  nonce / expiry / domain validation → execution on local Anvil.
- **Phase 1.3 works end-to-end**: deterministic policy classification inside
  `execute()` (value threshold, restricted destinations/selectors), guardian
  transaction authorizations bound to the exact canonical digest, policy
  versioning that invalidates pending authorizations on any change, and a
  structural anti-downgrade rule making every policy mutation require guardian
  co-approval. Verified by Foundry tests and Anvil integration steps.
- **Phase 1.2 works end-to-end**: guardian bootstrap (manager bootstraps once,
  then its authority is permanently retired) → recovery request by guardian or
  device → duplicate-proof guardian approvals → quorum detection → mandatory
  per-wallet timelock (inclusive boundary) → permissionless finalization that
  atomically authorizes the replacement device and revokes the replaced one →
  old-device signatures rejected, new-device signatures accepted. Verified by
  96 Foundry tests, 42 Rust tests, TypeScript tests, and the automated Anvil
  integration script covering all 18 recovery steps (`bun run integration:anvil`).
- **This is NOT threshold cryptography.** One device = one secp256k1 key.
  Guardians are plain addresses with plain approvals. TSS/MPC does not exist
  anywhere in this repository yet, and no code pretends otherwise.
- **The Rust crypto module remains a labeled insecure mock** behind the
  `CryptoProvider` trait for protocol paths other than transaction digests;
  Rust produces real keccak-256 canonical digests but performs no signing.
- **Guardian-set management post-bootstrap is device-controlled** (device-signed
  calls to the RecoveryManager). Devices may remove guardians below quorum,
  which disables future recoveries until restored — an availability trade-off,
  documented in [protocol/recovery.md](../protocol/recovery.md).
- **Nothing here has been independently audited.** The contracts use audited
  building blocks (OpenZeppelin ECDSA, ReentrancyGuard) but the composition
  has not been reviewed by anyone outside this repository.
- The dashboard renders mock data except `/demo` (Phase 1.1 transactions) and
  `/recovery` (Phase 1.2 guardian recovery), both of which run REAL flows
  server-side against local Anvil using PUBLIC fixture keys only.

Any security claim about KeyMesh applies to the *implemented primitives and
their tests* — not to production readiness.

## Trust assumptions

1. **Ethereum security.** The chain provides ordered, censorship-resistant
   (eventually) execution and public state. Contracts are trust anchors.
2. **Contract correctness.** Deployed bytecode does what these documents say.
   This requires audits before mainnet usage; none has occurred.
3. **Canonical serialization correctness.** Signatures cover canonical bytes;
   a bug in the encoder would be a security bug. It is tested, but treat
   cross-language conformance tests as mandatory before signing ships.
4. **Bootstrap ceremony honesty.** Whoever holds the manager key between
   wallet deployment and governance initialization chooses the first guardians
   AND decides when to initialize. Initialization must happen before real value
   is entrusted; afterwards the role is provably inert.

## Recovery assumptions

1. The user can reach their guardians out-of-band when needed.
2. At least one honest actor observes a hostile recovery inside the timelock
   window and cancels it (any authorized device can cancel; guardians express
   dissent by withholding approvals).
3. Guardians understand their responsibilities: availability during windows,
   verifying recovery claims through a second channel, never approving under
   urgency pressure (urgency is itself a social-engineering signal).
4. Quorum configuration reflects genuine redundancy: with N guardians the
   quorum should be well below N so single points of failure cannot lock the
   wallet, but above any plausible correlated-compromise set.

## Guardian assumptions

1. Guardian keys are held competently (hardware wallets recommended).
2. Guardian sets reflect genuine trust; they are set by the wallet's devices
   (after bootstrap) and visible on-chain. Guardians are unweighted: one
   guardian = one approval.
3. Guardians are independent — correlated compromise (same password manager,
   same jurisdiction, same household) undermines threshold math. Guidance:
   diversify guardians across infrastructure and relationships.
4. A guardian's authority is strictly scoped: initiate/approve recoveries for
   their own wallet only. They cannot cancel, cannot sign transactions, and
   cannot affect other wallets (tested).

## Cryptographic assumptions

1. Standard curve security: secp256k1 remains unbroken; discrete log hardness
   holds for chosen parameters.
2. Only audited implementations are used: @noble/curves (TypeScript signing),
   OpenZeppelin `ECDSA` (Solidity recovery), `tiny-keccak` (Rust digests).
   No custom primitives exist, and none will be written from scratch.
3. Deterministic mock implementations stay compile-time separated from
   production paths before any mainnet-facing release (feature-flagged off).

## Failure containment philosophy

- Prefer *visible delayed failure* over silent instant failure: timelocks turn
  takeovers into observable events.
- Prefer *no capability* over simulated capability: unimplemented operations
  revert rather than approximating.
- Every guarantee above is falsifiable by tests; where a guarantee is not yet
  testable end-to-end, it is marked "pending" or "design only" rather than
  implied.


