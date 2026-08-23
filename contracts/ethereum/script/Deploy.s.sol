// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";

/// @notice Deploys the KeyMesh prototype contract set to a local/test network.
/// @dev PROTOTYPE: deployment wiring is minimal; Phase 1 replaces direct
///      ownership with protocol-level authorization before any real usage.
contract Deploy is Script {
    function run() external returns (GuardianRegistry registry, RecoveryManager recovery, PolicyManager policy, KeymeshWallet wallet) {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        registry = new GuardianRegistry();
        recovery = new RecoveryManager(registry);
        policy = new PolicyManager();

        // Prototype wallet controlled by the deployer; Phase 1 removes this.
        wallet = new KeymeshWallet(deployer);

        // Register the wallet's initial guardian set (deployer as weight-1
        // stand-in until guardian onboarding exists).
        registry.addGuardian(address(wallet), deployer, 1);

        vm.stopBroadcast();
    }
}
