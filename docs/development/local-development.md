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
cargo fmt --manifest-path crates/keymesh-core/Cargo.toml     # Rust formatting
forge test --root contracts/ethereum                          # Solidity tests
```

Turbo caches everything: re-runs with unchanged inputs are instant.

## Phase 1.1: end-to-end Anvil integration

One command runs the full device-signed flow against a disposable local chain:

```sh
bun run integration:anvil
```

The script (`packages/sdk/scripts/anvil-integration.ts`) starts Anvil itself,
builds the contracts, deploys `KeymeshWallet`, registers a second device, then
creates → signs → executes a real 0.1 ETH transfer through the SDK and asserts:

- recipient balance changed,
- wallet nonce incremented,
- `TransactionExecuted` event decoded from the receipt,
- replaying the same signed payload reverts (`InvalidNonce`),
- an unregistered key's signature reverts (`UnauthorizedDevice`),
- a revoked device's signature reverts.

It uses only the well-known PUBLIC Anvil fixture keys. Never point this script
at a real network. Port can be changed with `KEYMESH_ANVIL_PORT`.

If Foundry binaries are not on `PATH`, scripts fall back to
`~/.foundry/bin/{anvil,forge}`.

### Dashboard demo of the same flow

```sh
anvil            # terminal 1 (or any node on 127.0.0.1:8545)
forge build --root contracts/ethereum   # once; produces out/ artifacts
bun run dev      # terminal 2
```

Open <http://localhost:3100/demo> and click **Run demo transaction**. The
Next.js route (`app/api/keymesh-demo/route.ts`) runs entirely server-side: it
deploys a fresh wallet, funds it, then drives create → sign → execute through
`@keymesh/sdk` and returns each step for display. Keys are PUBLIC fixture keys
that never reach the browser. RPC override: `KEYMESH_DEMO_RPC_URL`.

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
cargo fmt --check --manifest-path crates/keymesh-core/Cargo.toml
forge build --root contracts/ethereum && forge test --root contracts/ethereum   # if contracts changed
bun run integration:anvil                                                       # if SDK/contracts changed
```
