// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";

/// @notice Deploys the KeyMesh contract set to a local/test network and
///         bootstraps guardian recovery governance.
/// @dev Phase 1.2 + 1.3 wiring:
///       1. RecoveryManager (owns its GuardianRegistry) + PolicyManager
///          (bound to the same RecoveryManager for guardian checks).
///       2. KeymeshWallet trusting the RecoveryManager and consulting the
///          PolicyManager on every execution.
///       3. `bootstrapRecoveryGovernance` installs the initial guardian set,
///          quorum, and timelock — this also permanently retires the
///          manager's authority over the device set.
///       Policy configuration itself is opt-in afterwards: an unconfigured
///      wallet behaves exactly like Phase 1.1 (device signature suffices).
///
///      Environment:
///       - DEPLOYER_PRIVATE_KEY   (required) funds and signs deployment.
///       - INITIAL_DEVICE_ADDRESS (optional, defaults to the deployer).
///       - GUARDIAN_ADDRESSES     (optional, comma-separated). Defaults to a
///         deterministic LOCAL-TEST guardian trio. Never reuse these keys on
///         a network with real value.
contract Deploy is Script {
    function run()
        external
        returns (
            GuardianRegistry registry,
            RecoveryManager recovery,
            PolicyManager policy,
            KeymeshWallet wallet
        )
    {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address manager = vm.addr(deployerKey);
        address initialDevice = vm.envOr({name: "INITIAL_DEVICE_ADDRESS", defaultValue: manager});
        uint256 quorum = vm.envOr({name: "RECOVERY_QUORUM", defaultValue: uint256(2)});
        uint64 timelockSeconds =
            uint64(vm.envOr({name: "RECOVERY_TIMELOCK_SECONDS", defaultValue: uint256(24 hours)}));

        address[] memory guardians = _guardians();

        vm.startBroadcast(deployerKey);

        // The RecoveryManager constructs (and owns) its GuardianRegistry, so
        // the storage/policy pairing can never be misconfigured.
        recovery = new RecoveryManager();
        registry = GuardianRegistry(address(recovery.guardianRegistry()));
        policy = new PolicyManager(recovery);
        wallet = new KeymeshWallet(manager, initialDevice, address(recovery), address(policy));

        recovery.bootstrapRecoveryGovernance({
            wallet: address(wallet),
            initialGuardians: guardians,
            quorum: quorum,
            timelockSeconds: timelockSeconds
        });

        console2.log("manager (bootstrap-only):", manager);
        console2.log("initial device:          ", initialDevice);
        console2.log("KeymeshWallet:           ", address(wallet));
        console2.log("GuardianRegistry:        ", address(registry));
        console2.log("RecoveryManager:         ", address(recovery));
        console2.log("guardian count / quorum: ", guardians.length, quorum);

        vm.stopBroadcast();
    }

    function _guardians() internal view returns (address[] memory) {
        string memory raw = vm.envOr({name: "GUARDIAN_ADDRESSES", defaultValue: string("")});
        if (bytes(raw).length > 0) {
            return _parseAddresses(raw);
        }

        // Deterministic local-test guardians (Anvil fixture accounts #4..#6).
        // PUBLIC test keys only — never valid on a network holding value.
        address[] memory defaults = new address[](3);
        defaults[0] = 0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f;
        defaults[1] = 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720;
        defaults[2] = 0xBcd4042DE499D14e55001CcbB24a551F3b954096;
        return defaults;
    }

    function _parseAddresses(string memory csv) internal pure returns (address[] memory parsed) {
        uint256 count = 1;
        bytes memory b = bytes(csv);
        for (uint256 i = 0; i < b.length; ++i) {
            if (b[i] == ",") count += 1;
        }
        parsed = new address[](count);
        uint256 index = 0;
        uint256 start = 0;
        for (uint256 i = 0; i <= b.length; ++i) {
            if (i == b.length || b[i] == ",") {
                parsed[index++] = vm.parseAddress(_slice(csv, start, i));
                start = i + 1;
            }
        }
    }

    function _slice(string memory s, uint256 start, uint256 end)
        internal
        pure
        returns (string memory)
    {
        bytes memory b = bytes(s);
        bytes memory out = new bytes(end - start);
        for (uint256 i = start; i < end; ++i) {
            out[i - start] = b[i];
        }
        return string(out);
    }
}
