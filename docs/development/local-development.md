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

## Phase 1.1 + 1.2: end-to-end Anvil integration

One command runs BOTH real flows against a disposable local chain:

```sh
bun run integration:anvil
```

The script (`packages/sdk/scripts/anvil-integration.ts`) starts Anvil itself,
builds the contracts, and deploys the full stack (RecoveryManager + owned
GuardianRegistry + KeymeshWallet). It then asserts:

Phase 1.1 (device-signed transactions):

- create + sign + execute a real transfer through the SDK,
- recipient state changed, nonce incremented, event decoded from the receipt,
- replaying the same signed payload reverts.

Phase 1.2 (guardian recovery), in order:

- bootstrap guardians (3 guardians, quorum 2) and verify the guardian set,
- manager authority retired post-bootstrap (device registration reverts),
- recovery request opened by a healthy device naming the replacement device,
- non-guardian approval rejected; duplicate approval rejected,
- two guardian approvals reach quorum and arm the timelock,
- finalization before the deadline reverts,
- Anvil time advances past the deadline -> status becomes executable,
- finalization authorizes the new device and revokes the stolen one,
- transaction signed with the NEW device executes on-chain,
- old-device signature rejected (`UnauthorizedDevice`),
- second finalization rejected forever (no replay).

It uses only deterministic LOCAL fixture keys. Never point this script at a
real network. Port can be changed with `KEYMESH_ANVIL_PORT`.

If Foundry binaries are not on `PATH`, scripts fall back to
`~/.foundry/bin/{anvil,forge}`.

### Dashboard demos of both flows

```sh
anvil            # terminal 1 (or any node on 127.0.0.1:8545)
forge build --root contracts/ethereum   # once; produces out/ artifacts
bun run dev      # terminal 2
```

- <http://localhost:3100/demo> - Phase 1.1: click **Run demo transaction**.
  The route (`app/api/keymesh-demo/route.ts`) deploys a fresh wallet, funds
  it, then drives create -> sign -> execute through `@keymesh/sdk`.
- <http://localhost:3100/recovery> - Phase 1.2: a live guardian-recovery
  console backed by `app/api/keymesh-recovery/route.ts`. It deploys a fresh
  stack, registers guardians via bootstrap, and exposes real actions:
  **Initiate recovery**, **Approve recovery**, **Cancel recovery**,
  **Finalize recovery**, plus live guardian count, quorum, approvals, status,
  and timelock state read back from the contracts through the SDK.

Both routes run entirely server-side; keys are PUBLIC local fixtures that
never reach the browser. RPC override: `KEYMESH_DEMO_RPC_URL`.

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

