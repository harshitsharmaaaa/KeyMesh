# KeyMesh Security Review Checklist

Use this checklist for external review of the KEYMESH v1 protocol.

## Architecture
- Device signing is ECDSA-based and wallet-scoped.
- Policy authorization is separate from device authorization.
- Recovery authority is separate from transaction authorization.
- The transitional manager is bootstrap-only and retires after recovery initialization.

## Trust assumptions
- Ethereum finality and contract execution are trusted.
- secp256k1 and the OpenZeppelin primitives are trusted.
- Guardians are assumed to be independent enough for quorum to matter.
- The bootstrap manager is trusted only until recovery governance is initialized.

## Privileged roles
- Bootstrap manager: initial device registration only, before recovery initialization.
- Authorized device: transaction execution, recovery initiation/cancellation, policy mutation via wallet execution.
- Guardian: recovery approval and transaction authorization approval.
- RecoveryManager: the only contract allowed to mutate guardian state.

## State machines
- Wallet nonce is sequential and consumed only after successful execution.
- Recovery lifecycle: `None -> Pending -> QuorumReached -> Executable -> Executed`, with cancellation from live states.
- Transaction authorization lifecycle: `None -> Pending -> Authorized -> Executed`, with `Cancelled` as a terminal branch.

## Authorization flow
- Device signature is required for transaction execution.
- Policy evaluation determines whether guardian authorization is required.
- Guardian authorization, when required, is bound to the exact transaction digest.

## Policy precedence
1. Admin selector
2. Restricted selector
3. Restricted destination
4. Value threshold
5. Default mode

## Recovery lifecycle
- Guardian approvals are distinct and count once each.
- Quorum and timelock are snapshotted at initiation.
- Timelock is inclusive at `now >= executeAfter`.
- Finalization is permissionless after timelock.

## Canonical encoding
- `KEYMESH_TX_V1` binds wallet, chainId, nonce, destination, value, data, and expiry.
- Changing any signed field must change the digest.

## Replay protection
- Sequential nonce prevents transaction replay.
- Policy version changes invalidate pending authorizations.
- A digest may be consumed at most once.

## Known risks
- A compromised device can still spend until revoked or replaced.
- Guardian collusion within the timelock window can complete a recovery.
- Bounded storage sets limit the size of restricted destinations and selectors.

## Known limitations
- No external audit.
- No formal verification.
- No TSS/MPC in Phase 1.
- No privacy guarantees.

## Test commands
- `bun run format:check`
- `bun run lint`
- `bun run typecheck`
- `bun run test`
- `bun run build`
- `cargo fmt --check`
- `cargo test`
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `forge build`
- `forge test`
- `bun run integration:anvil`

## Deployment assumptions
- Initial guardian setup happens before trusting the wallet with value.
- Chain IDs and wallet addresses must be correct in signed payloads.
- CI must run the security suites; local-only checks are not sufficient.
