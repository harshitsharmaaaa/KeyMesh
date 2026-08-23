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
| Single lost/stolen device draining a wallet   | high-value guardian quorum                  | NO — design only; a stolen device key can drain today |
| Loss of ALL devices                           | guardian recovery with timelock             | state machines implemented + tested (Rust/TS); contract wiring pending |
| Hostile guardian takeover                     | mandatory ≥7-day public timelock + cancel   | contract skeleton enforces timelock; not wired to devices |
| Seed-phrase theft                             | no seed phrase exists in the protocol model | by design |

## What KeyMesh does NOT protect against

1. **Any theft from a compromised device.** Normal transfers need exactly one
   registered-device signature. There is no velocity limit, no threshold, and
   no delay: a stolen device key can drain the wallet until revoked. This is
   the single most important limitation of Phase 1.
2. **Manager compromise (transitional).** Device registration/revocation is
   gated on the deployer-chosen `manager` account. Whoever controls it can add
   their own device. This is an explicit Phase 1 control that guardian/recovery
   governance must replace before any real value is at stake.
3. **Full guardian collusion within one timelock window combined with an
   absent user** (once recovery ships). Timelocks make this *visible*, not
   impossible.
4. **Coercion.** Timelocks raise the cost of wrench attacks but cannot prevent
   them.
5. **Compromised user operating environment.** A keylogger on the owner's
   machine defeats any client-side protocol.
6. **Chain-level failures.** Re-orgs beyond confirmation assumptions, consensus
   failures, or gas market conditions are out of scope.
7. **Privacy.** All authorization activity is public on-chain.

## Current implementation status (do not skip this section)

- **Phase 1.1 works end-to-end**: SDK → canonical `KEYMESH_TX_V1` encoding →
  keccak-256 digest → ECDSA device signature (@noble/curves secp256k1,
  deterministic RFC-6979 nonces, low-s) → Solidity `ECDSA.recover` → device /
  nonce / expiry / domain validation → execution on local Anvil. Verified by
  Foundry tests, Rust tests, TypeScript tests sharing fixed vectors, and an
  automated Anvil integration script (`bun run integration:anvil`).
- **This is NOT threshold cryptography.** One device = one secp256k1 key.
  TSS/MPC does not exist anywhere in this repository yet.
- **The Rust crypto module remains a labeled insecure mock** behind the
  `CryptoProvider` trait for protocol paths other than transaction digests;
  Rust produces real keccak-256 canonical digests but performs no signing.
- **Device-set management uses a transitional manager account**, documented in
  [wallet-lifecycle.md](../protocol/wallet-lifecycle.md).
- **Nothing here has been independently audited.** The contract uses audited
  building blocks (OpenZeppelin ECDSA, ReentrancyGuard) but the composition
  has not been reviewed by anyone outside this repository.
- The dashboard still renders mock data; its demo route runs real transactions
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

## Recovery assumptions

1. The user can reach their guardians out-of-band when needed.
2. At least one honest guardian observes a hostile recovery inside the
   timelock window and cancels it.
3. Guardians understand their responsibilities: availability during windows,
   verifying recovery claims through a second channel, never approving under
   urgency pressure (urgency is itself a social-engineering signal).

## Guardian assumptions

1. Guardian keys are held competently (hardware wallets recommended).
2. Guardian weight distribution reflects genuine trust; weights are set by
   the wallet owner and visible on-chain.
3. Guardians are independent — correlated compromise (same password manager,
   same jurisdiction, same household) undermines threshold math. Guidance:
   diversify guardians across infrastructure and relationships.

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
