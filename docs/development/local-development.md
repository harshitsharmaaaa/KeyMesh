# Local Development Guide

## Prerequisites

| Tool     | Version  | Check            | Install                        |
| -------- | -------- | ---------------- | ------------------------------ |
| Bun      | ≥ 1.1    | `bun --version`  | https://bun.sh                 |
| Rust     | ≥ 1.75   | `cargo --version`| https://rustup.rs              |
| Foundry  | latest   | `forge --version`| https://book.getfoundry.sh     |
| Node     | ≥ 20     | `node --version` | (Bun usually suffices)         |

Rust and Foundry are only needed for their respective directories; TypeScript
development works with Bun alone.

## First-time setup

```sh
git clone <repo> && cd keymesh
bun install                       # JS/TS dependencies + lockfile
cd contracts/ethereum
forge install foundry-rs/forge-std --no-commit
cd ../..
```

## Daily commands

```sh
bun run dev        # dashboard dev server (http://localhost:3100)
bun run test       # all workspace tests via turbo
bun run lint       # biome lint across workspaces
bun run format     # biome format across workspaces
bun run typecheck  # tsc per package
bun run build      # production builds

cargo test --manifest-path crates/keymesh-core/Cargo.toml    # Rust tests
forge test --root contracts/ethereum                          # Solidity tests
```

Turbo caches everything: re-runs with unchanged inputs are instant.

## Workspace map

| Path                  | Package             | Purpose                              |
| --------------------- | ------------------- | ------------------------------------ |
| `apps/dashboard`      | `@keymesh/dashboard`| Next.js UI (mock data, SDK-only)     |
| `packages/sdk`        | `@keymesh/sdk`      | Public client facade                 |
| `packages/protocol`   | `@keymesh/protocol` | Domain models + state machines       |
| `packages/types`      | `@keymesh/types`    | Hex/result/error primitives          |
| `packages/config`     | `@keymesh/config`   | Shared tsconfig presets              |
| `crates/keymesh-core` | —                   | Rust protocol core                   |
| `contracts/ethereum`  | —                   | Foundry contracts                    |

## Conventions

- **Formatting/lint:** Biome (`biome.json` at repo root). Run `bun run format`
  before committing; CI enforces it.
- **Commits:** conventional commits (`feat:`, `fix:`, `docs:`, `test:`,
  `refactor:`, `chore:`).
- **Tests live next to code** for TS (`*.test.ts`) and inside modules for Rust;
  Foundry tests in `contracts/ethereum/test`.
- **Maturity labels:** any new module that is not production-grade must say so
  at the top of its file/docs. Never let a prototype look finished.

## Environment variables

Copy `.env.example` to `.env.local` for local overrides. Placeholders only are
committed; never commit real keys. Currently used values:

- `DEPLOYER_PRIVATE_KEY` — Foundry scripts on local/test networks **only**.
- `NEXT_PUBLIC_CHAIN_ID`, `NEXT_PUBLIC_RPC_URL` — future dashboard wiring.

## Troubleshooting

**`@keymesh/*` imports don't resolve** → run `bun install` from the repo root
(workspaces must be linked).

**Turbo runs nothing** → check you're at the repo root; turbo walks the
workspace graph from `package.json`.

**`forge: command not found`** → Foundry not installed or not on PATH; see
prerequisites. TS work does not require it.

**Vitest can't find tests** → tests must match `src/**/*.test.ts`.

## Before opening a PR

```sh
bun run format && bun run lint && bun run typecheck && bun run test && bun run build
cargo test --manifest-path crates/keymesh-core/Cargo.toml
forge test --root contracts/ethereum   # if contracts changed
```
