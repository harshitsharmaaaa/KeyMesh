# KeyMesh Security Model

> **Status: honest baseline.** This document states what KeyMesh is designed
> to protect against, what it explicitly does not, and which assumptions the
> guarantees depend on. Nothing here should be read as a claim that the current
> codebase is production-ready — see maturity labels throughout the repo.

## What KeyMesh is designed to protect against

| Threat                                        | Mechanism                                   | Enforced today? |
| --------------------------------------------- | ------------------------------------------- | --------------- |
| Single lost/stolen device draining a wallet    | high-value guardian quorum                  | design + policy eval; contract enforcement pending |
| Loss of ALL devices                            | guardian recovery with timelock             | state machines implemented + tested (Rust/TS); contract skeleton |
| Hostile guardian takeover                      | mandatory ≥7-day public timelock + cancel   | contract skeleton enforces timelock |
| Silent rule weakening                          | management actions quorum+timelocked        | policy defaults |
| Signature reuse across action types            | domain-separated signing payloads           | payload construction implemented; real signing pending |
| Transaction parameter tampering post-approval  | canonical serialization bound to request ids| canonical encoding implemented |
| Seed-phrase theft                              | no seed phrase exists in the protocol model | by design |

## What KeyMesh does NOT protect against

1. **Fast small-value theft from a compromised device.** Normal transfers need
   only device authorization. Until velocity limits exist (planned), a stolen
   device can drain funds one normal transaction at a time until revoked.
2. **Full guardian collusion within one timelock window combined with an
   absent user.** If every honest guardian fails to cancel during the window,
   a hostile recovery completes. Timelocks make this *visible*, not impossible.
3. **Coercion.** Timelocks raise the cost of wrench attacks but cannot prevent
   them.
4. **Compromised user operating environment.** A keylogger on the owner's
   machine defeats any client-side protocol.
5. **Chain-level failures.** Re-orgs beyond confirmation assumptions, consensus
   failures, or gas market conditions are out of scope.
6. **Privacy.** All authorization activity is public on-chain.
7. **Malicious guardian reading data.** Guardians observe the actions they
   approve; guardian anonymity is not provided.

## Current implementation status (do not skip this section)

- **No production cryptography exists in this repository.** The Rust crate's
  crypto module is a labeled insecure mock behind a trait boundary.
- **Contracts cannot move funds.** `KeymeshWallet.execute` deliberately reverts.
- **The SDK performs no network calls and handles no private keys.**
- **The dashboard displays mock data only.**

Any security claim about KeyMesh applies to the *design* documents, not to the
present code.

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

1. Standard curve security: secp256k1 and ed25519 remain unbroken; discrete
   log hardness holds for chosen parameters.
2. No custom primitives will ever ship. Phase 2 selects audited libraries
   (`k256`/`secp256k1` class) and established TSS stacks; all cryptographic
   decisions get documented here with rationale.
3. Deterministic mock implementations are compile-time separated from
   production paths before any mainnet-facing release (feature-flagged off).

## Failure containment philosophy

- Prefer *visible delayed failure* over silent instant failure: timelocks turn
  takeovers into observable events.
- Prefer *no capability* over simulated capability: unimplemented operations
  revert rather than approximating.
- Every guarantee above is falsifiable by tests; where a guarantee is not yet
  testable end-to-end, it is marked "pending" rather than implied.
