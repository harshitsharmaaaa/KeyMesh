# TSS Provider Protocol — Phase 2.4

## SigningProvider

```
SigningProvider
  ├── SingleEcdsaProvider  — default, Phase 1 ECDSA
  └── ThresholdEcdsaProvider — real synedrion 0.3, 2-of-3, via crates/keymesh-tss
```

Both consume `SessionBinding { wallet, chainId, nonce, digest, policyVersion, signingProtocolVersion, random }` and produce `ThresholdSignature { r,s,v }`.

## ThresholdEcdsaProvider

Wraps `crates/keymesh-tss`:

```
new(material: ThresholdKeyMaterial, chain_id) -> Result<Self>  // rejects mainnet unless enabled
participant_set() -> ThresholdParticipantSet
group_address() -> [u8;20]
sign(binding, subset, session_id) -> Result<ThresholdSignature>  // validates chain, threshold, session_id==derive(binding), subset
verify(digest, sig) -> bool  // ecrecover vs group key
```

Lifecycle remains explicit: `setup_2of3()` (DKG), `derive_session_id`, `threshold_sign` — not hidden behind single `sign(digest)`.

## Session Binding

`sessionId = keccak256(wallet|chainId|nonce|digest|policyVersion|version|random)` — immutable digest/wallet/chainId/nonce/policyVersion. See `docs/protocol/tss-signing-protocol.md`.

## Errors

`InsufficientShares`, `DuplicateParticipant`, `UnknownParticipant`, `SessionMismatch`, `WrongChain`, `MainnetNotAllowed`, `SigningFailed`.

## TypeScript Boundary

`packages/protocol/src/tss-provider.ts` defines `ThresholdConfig`, `SessionContext`, `SigningProvider` interface. Rust boundary owns secret shares; TS never receives private scalars.
