# Contributing to KeyMesh

Thanks for contributing. This is security-oriented infrastructure, so the
rules below are stricter than average — they exist to keep the codebase
auditable.

## Ground rules

1. **Never commit secrets.** No private keys, seed phrases, or real
   credentials — not in code, tests, fixtures, or `.env` files. Only
   `.env.example` placeholders belong in git.
2. **No custom cryptography.** Do not implement hash functions, curves,
   signatures, or "toy MPC". Cryptographic work happens behind the existing
   provider boundaries using reviewed libraries.
3. **Label maturity honestly.** Every module states `prototype`,
   `experimental`, or `production-grade`. If your change is a prototype, say
   so in the module header and docs. Never make scaffolding look finished.
4. **Unimplemented ≠ faked.** Missing capability? Revert, return an error, or
   leave a labeled TODO boundary. Never simulate success.
5. **Tests are not optional.** State machines, policy evaluation, and
   serialization changes need tests in *all* affected implementations (TS,
   Rust, Solidity) to prevent drift.

## Workflow

```sh
# 1. Branch
git checkout -b feat/short-description

# 2. Develop + test as you go
bun run test
cargo test --manifest-path crates/keymesh-core/Cargo.toml

# 3. Before every commit
bun run format && bun run lint && bun run typecheck
```

## Commit style

Conventional commits:

```
feat(protocol): add expiry handling to transaction requests
fix(recovery-core): reject completion while timelock is active
docs(security): expand replay-attack section of threat model
test(sdk): cover guardian removal errors
```

Scope names: `protocol`, `sdk`, `types`, `dashboard`, `recovery-core`,
`contracts`, `ci`, `docs`.

## Pull requests

- Keep PRs focused; one logical change per PR.
- Fill in: what changed, why, how you tested it.
- CI must pass (lint, typecheck, tests, builds, cargo, forge).
- Changes touching `crates/`, `contracts/`, or anything crypto-adjacent
  require an explicit security note in the description ("what could an attacker
  do with this change?").

## Code style

- TypeScript: Biome rules (root `biome.json`). Single quotes, semicolons,
  trailing commas es5.
- Rust: `cargo fmt`; `cargo clippy -- -D warnings` clean.
- Solidity: `forge fmt`.
- Docs: line-oriented markdown; keep tables aligned; update maturity labels
  whenever status changes.

## Reporting vulnerabilities

Do **not** open public issues for security problems. Contact the maintainers
directly (add contact channel before open-sourcing). Include reproduction steps
and impact assessment.
