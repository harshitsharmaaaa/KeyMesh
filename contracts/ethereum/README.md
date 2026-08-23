# contracts/ethereum

Ethereum smart contracts for the KeyMesh protocol (Foundry).

**Maturity: prototype skeletons.** The contracts define the intended surfaces
and state machines. Execution paths that would move funds are deliberately
disabled (`KeymeshWallet.execute` reverts) until signature verification and
policy enforcement land in Phase 1.

## Layout

```
src/
  KeymeshErrors.sol        Shared custom errors
  interfaces/              IKeymeshWallet, IGuardianRegistry, IRecoveryManager, IPolicyManager
  KeymeshWallet.sol        Device authorization skeleton; execution disabled
  GuardianRegistry.sol     Per-wallet guardian sets with weights
  RecoveryManager.sol      Recovery state machine + mandatory timelock
  PolicyManager.sol        Per-wallet authorization policies
test/                      Foundry tests (state machines, access control, timelock)
script/Deploy.s.sol        Local/test deployment wiring
```

## Commands

```sh
forge install   # first time: fetches dependencies into lib/
forge build
forge test
forge test -vvv               # with traces
forge coverage
anvil                          # local node in a second terminal
forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast
```

## Dependency policy

The skeleton is intentionally dependency-free so the protocol semantics stay
readable and auditable. When Phase 1 begins:

1. `forge install foundry-rs/forge-std` (tests) and
   `forge install OpenZeppelin/openzeppelin-contracts` — both well-audited.
2. Replace the inline owner check in `KeymeshWallet` with OpenZeppelin
   `AccessControl`-style roles or an ERC-4337-compatible authorization layer.
3. Add any new dependency only with justification recorded here.

> NOTE: tests import `forge-std`. Run `forge install foundry-rs/forge-std --no-commit`
> before running `forge test` for the first time.

## Security notes

- Timelocks: recovery enforces a minimum 7-day window (`MIN_TIMELOCK`) to give
  guardians time to detect and cancel hostile recoveries.
- Access control: guardian/policy mutations are restricted to the wallet
  contract itself (`msg.sender == wallet`), which will be enforced structurally
  once KeymeshWallet calls these modules directly.
- No admin keys: nothing here has privileged upgrade paths; keep it that way.

See `docs/security/threat-model.md` for the full analysis and known gaps.
