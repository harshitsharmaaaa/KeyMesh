# ADR-002: TSS Runtime Strategy

## Status

Accepted

## Context

KEYMESH has a real threshold-ECDSA provider in `crates/keymesh-tss`, but the current execution path still uses `manul::dev::run_sync(...)` to run all participants in-process. The question is whether KEYMESH should build a custom participant-level runtime around `manul::session::Session`, switch TSS libraries, or defer distributed runtime work.

## Decision

**Option C: defer distributed runtime.**

## Why

- The installed `manul` API is public and useful, but it is not a maintained participant-process runtime.
- `run_sync(...)` is explicitly a dev helper for one-process execution.
- Building a correct distributed driver would require a substantial new protocol-engine layer.
- The risk of getting round progression, failure handling, concurrency, or replay behavior wrong is high.
- The safest path is to keep the current isolated real TSS implementation intact until a supported runtime model exists.

## Trade-offs

### Benefits

- preserves the current real cryptographic implementation
- avoids inventing a new CGGMP'24-like runtime
- keeps the signing protocol semantics unchanged
- avoids a large new security review surface

### Costs

- distributed participant-process TSS remains deferred
- local Anvil and Sepolia flows through multi-process threshold signing are not yet available

## Security implications

- fewer moving parts in the near term
- no partial runtime that might misroute or replay messages
- no unsafe persistence or reconnect semantics invented by KEYMESH

## Licensing implications

- `synedrion` is `AGPL-3.0-or-later`
- `manul` is `AGPL-3.0-or-later`
- product/legal implications require professional legal review

## Implementation roadmap

1. Keep the isolated real TSS provider unchanged.
2. Keep the TCP transport prototype and envelope/session validation.
3. Reassess runtime options only if a supported participant-level API appears.
4. If a new library is adopted later, migrate only the runtime boundary, not the cryptography.
