// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";

/// @notice Deploys the KeyMesh contract set to a local/test network.
/// @dev Phase 1.1 wiring: the deployer is the wallet `manager` (transitional
///      device-set control) and supplies the initial device address.
///      Set INITIAL_DEVICE_ADDRESS to a key you control (e.g. an Anvil
///      account); it becomes the first authorized signer.
contract Deploy is Script {
    function run()
        external
        returns (GuardianRegistry registry, RecoveryManager recovery, PolicyManager policy, KeymeshWallet wallet)
    {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address manager = vm.addr(deployerKey);
        address initialDevice = vm.envOr({
            name: "INITIAL_DEVICE_ADDRESS",
            defaultValue: manager
        });

        vm.startBroadcast(deployerKey);

        registry = new GuardianRegistry();
        recovery = new RecoveryManager(registry);
        policy = new PolicyManager();
        wallet = new KeymeshWallet(manager, initialDevice);

        console2.log("manager:         ", manager);
        console2.log("initial device:  ", initialDevice);
        console2.log("KeymeshWallet:   ", address(wallet));

        vm.stopBroadcast();
    }
}
