# License Review — Engineering Finding (requires legal review)

## Dependencies

| Dependency | Version | License | Pin reason | Advisories |
|------------|---------|---------|------------|------------|
| synedrion | 0.3.0 | AGPL-3.0? (check crate license: MIT OR Apache-2.0 per Cargo.toml? actually synedrion 0.3 is MPL-2.0) | CGGMP'24 threshold implementation, pinned for crypto correctness | no known RustSec at freeze |
| manul | 0.2.1 | MIT OR Apache-2.0 | TestRuntime for protocol, pinned | — |
| k256 | 0.13 | MIT/Apache | secp256k1 curve | — |
| tokio | 1.x | MIT | async transport | — |
| serde/serde_json | 1.x | MIT/Apache | serialization | — |
| chacha20poly1305 | 0.10 | MIT/Apache | EncryptedShareStore | — |
| zeroize | 1.7 | Apache/MIT | secret hygiene | — |
| tiny-keccak | 2.x | CC0 | keccak | — |
| OpenZeppelin (contracts) | via forge-std submodule | MIT | wallet/policy/recovery | — |
| Foundry | v1.7.1 | MIT/Apache | contract build/test | — |
| Bun | 1.3.9 | MIT | JS runtime, pinned in devEngines | — |
| Rust | 1.88.0 (core toolchain) | MIT/Apache | stable | — |

## Engineering Finding

- synedrion/manul licensing requires professional legal review before distribution, especially if copyleft (verify from authoritative crates.io/license file). Current `crates/keymesh-tss/Cargo.toml` declares `MIT OR Apache-2.0` for KEYMESH, but transitive deps may impose additional obligations.
- No legal conclusion is made here. Distribution, commercial use, or closed-source packaging must be reviewed by counsel with actual license texts and compliance notices.

> `engineering finding` — requires professional legal review before distribution.
