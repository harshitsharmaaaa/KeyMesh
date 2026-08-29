# TSS Runtime Feasibility

## Decision

**Option C: keep the current isolated TSS implementation and defer distributed runtime.**

## Source evidence

Inspected source:

- `synedrion 0.3.0`
- `manul 0.2.1`

Relevant public APIs:

- `manul::session::Session`
- `manul::session::SessionParameters`
- `manul::protocol::EntryPoint`
- `manul::protocol::Round`
- `manul::dev::run_sync`
- `synedrion::KeyInit`
- `synedrion::KeyResharing`
- `synedrion::AuxGen`
- `synedrion::InteractiveSigning`

What the source shows:

- `manul` is a Sans-I/O protocol framework.
- `run_sync(...)` is a dev helper that executes all parties in one process.
- `Session` is public, but the installed API does not expose a maintained participant-process runtime.
- `InteractiveSigning` is an entry point meant to be driven by `manul` session machinery.

What is missing:

- a documented, stable external participant driver
- supported state persistence/resume semantics
- supported participant-level transport hooks for independent OS processes
- an official runtime model for disconnect/reconnect/retry

## Responsibility matrix

| Responsibility | Library support | KEYMESH work | Risk |
|---|---|---|---|
| participant initialization | partial | yes | medium |
| session initialization | partial | yes | medium |
| message receive | partial | yes | medium |
| message validation | partial | yes | medium |
| message queueing | no | yes | high |
| message dispatch | partial | yes | high |
| round progression | partial | yes | high |
| timeouts | no | yes | high |
| duplicate handling | partial | yes | high |
| missing messages | partial | yes | high |
| out-of-order messages | partial | yes | high |
| participant failure | no | yes | high |
| session abort | partial | yes | high |
| session completion | partial | yes | high |
| error propagation | partial | yes | medium |
| participant restart | no | yes | high |
| session cleanup | partial | yes | medium |
| concurrent sessions | no | yes | high |

## Recommendation

Do not build a custom runtime yet.

The smallest safe engineering decision is to defer distributed participant networking until a supported runtime model is proven or a different library exposes one.

## Complexity assessment

Option A would be **very large**.

The dominant work is not transport alone. It is:

- participant state management
- round and message scheduling
- failure semantics
- restart policy
- concurrency isolation
- persistence boundary
- security review for a new protocol engine

## License observations

`synedrion` and `manul` are both `AGPL-3.0-or-later`.

Engineering observation:

- that license may matter for future product distribution or network deployment

Not legal advice:

- this is a licensing observation, not a legal conclusion
- professional review is required for product decisions

## Current safe path

- keep `crates/keymesh-tss` intact
- keep `crates/keymesh-tss-proto` as reference simulation
- preserve the authenticated TCP prototype
- defer distributed runtime until a supported external driver exists
