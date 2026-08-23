# contracts/ethereum

Ethereum smart contracts for the KeyMesh protocol (Foundry).

**Maturity: experimental.** `KeymeshWallet` implements real device-signed
execution (Phase 1.1) and is tested against Anvil; the guardian/recovery/policy
modules are still prototype skeletons not wired into the wallet. Not audited.

## Layout

```
src/
  KeymeshErrors.sol        Shared custom errors
  KeymeshTx.sol            Canonical KEYMESH_TX_V1 encoding + digest library
  interfaces/              IKeymeshWallet, IGuardianRegistry, IRecoveryManager, IPolicyManager
  KeymeshWallet.sol        Device authorization + signature-verified execution
  GuardianRegistry.sol     Per-wallet guardian sets with weights (skeleton)
  RecoveryManager.sol      Recovery state machine + mandatory timelock (skeleton)
  PolicyManager.sol        Per-wallet authorization policies (skeleton)
test/
  TransactionDigest.t.sol  Cross-language digest vectors (must match TS/Rust)
  KeymeshWallet.t.sol      Execution, replay/expiry/domain, device access control
script/Deploy.s.sol        Local/test deployment wiring
```

## Commands

```sh
forge install   # first time: fetches dependencies into lib/ (already vendored here)
forge build
forge test
forge test -vvv               # with traces
forge coverage
anvil                          # local node in a second terminal
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast
```

The full SDK-level flow against Anvil (deploy → register → sign → execute →
replay/revocation checks) runs from the repo root: `bun run integration:anvil`.

## Dependencies

- `openzeppelin-contracts` — `ECDSA` recovery, `ReentrancyGuard`. Audited;
  pinned via git submodule.
- `forge-std` — test framework.

Remappings in `remappings.txt`. Add new dependencies only with justification
recorded here.

## Authorization model (Phase 1)

- Execution authority = an ECDSA signature over the canonical
  [KEYMESH_TX_V1](../../../docs/protocol/canonical-transaction.md) digest that
  recovers to a currently registered device address. `msg.sender` is
  irrelevant; any relayer may submit.
- Device registration is gated on the deployer-chosen `manager` account — an
  explicitly TRANSITIONAL control. Devices may revoke themselves. The last
  remaining device cannot be removed. No permanent admin exists and none
  should be added; Phase 2 replaces the manager with guardian/recovery
  governance.
- Replay protection: strictly sequential per-wallet nonce, expiry (valid while
  `block.timestamp <= expiry`), plus wallet/chainId binding inside the digest.
- Failure semantics: validation failures leave zero state changes; a failing
  target reverts the whole execution including the nonce bump, so the signed
  request remains retryable until it succeeds or expires.

The device set is stored as a plain address mapping today, but `execute()`
only depends on "signature recovers to an authorized signer" — the seam where
threshold/TSS signers will plug in later.

## Security notes

- Timelocks: recovery enforces a minimum 7-day window (`MIN_TIMELOCK`) to give
  guardians time to detect and cancel hostile recoveries (module not yet wired).
- Access control: guardian/policy mutations are restricted to the wallet
  contract itself (`msg.sender == wallet`), which will be enforced structurally
  once KeymeshWallet calls these modules directly.
- Nothing here has been independently audited; see
  `docs/security/security-model.md` for what is and isn't protected.
