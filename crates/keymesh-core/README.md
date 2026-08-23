# keymesh-core

Rust protocol core for KEYMESH: recovery state machine, authorization policy
evaluation, deterministic serialization, and the cryptographic provider
boundary.

**Maturity: prototype.** There is no real cryptography in this crate yet. The
`crypto` and `signing` modules define interfaces plus an insecure mock
implementation used only by tests. Do not use this crate with real keys.

## Design rules

1. **No hand-rolled crypto, ever.** Phase 2 introduces reviewed, audited
   libraries (candidates: `k256` / `secp256k1` for secp256k1, established TSS
   stacks for threshold signing) behind the existing `CryptoProvider` trait.
2. **Pure core.** State machines take time as input (clock injection) so
   behavior is deterministic and testable without sleeping or mocking time.
3. **Canonical encoding.** Serialization is part of the protocol; it must be
   unambiguous across languages because signatures cover encoded bytes.
4. **Errors, not panics.** Malformed inputs return `KeymeshError`; callers can
   never be crashed into inconsistent states via hostile data.

## Modules

| Module          | Responsibility                                        |
| --------------- | ----------------------------------------------------- |
| `crypto`        | Provider trait + insecure mock (tests/dev only)       |
| `signing`       | Domain-separated signing service boundary             |
| `recovery`      | Guardian recovery state machine incl. timelock        |
| `policy`        | Transaction-class authorization policy evaluation     |
| `serialization` | Canonical binary encoder/decoder                      |
| `errors`        | Shared error enum                                     |

## Development

```sh
cargo test          # run all tests
cargo build         # build the library
cargo clippy        # lint (when installed)
```

The crate is intentionally dependency-free while in prototype. Any new
dependency requires a justification note in this README.
