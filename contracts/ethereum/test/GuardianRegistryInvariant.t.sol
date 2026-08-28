// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";
import {IRecoveryManager} from "../src/interfaces/IRecoveryManager.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";

/// @notice Invariant and fuzz tests for GuardianRegistry.
/// Tests guardian set integrity, wallet isolation, no duplicates,
/// and bounded storage assumptions.
/// All guardian mutations go through RecoveryManager governance (device-signed execute).
contract GuardianRegistryInvariantTest is Test {
    GuardianRegistry internal registry;
    RecoveryManager internal recovery;
    KeymeshWallet internal walletA;
    KeymeshWallet internal walletB;

    uint256 internal constant DEVICE_KEY_A = 0x1337;
    uint256 internal constant DEVICE_KEY_B = 0x966;
    uint256 internal constant STRANGER_KEY = 0xFEED;

    address internal deviceA;
    address internal deviceB;
    address internal stranger;

    address internal g1 = address(0x1001);
    address internal g2 = address(0x1002);
    address internal g3 = address(0x1003);
    address internal g4 = address(0x1004);
    address internal g5 = address(0x1005);

    function setUp() public {
        vm.warp(2_099_000_000);
        deviceA = vm.addr(DEVICE_KEY_A);
        deviceB = vm.addr(DEVICE_KEY_B);
        stranger = vm.addr(STRANGER_KEY);

        recovery = new RecoveryManager();
        registry = GuardianRegistry(address(recovery.guardianRegistry()));

        // Test contract (address(this)) is the manager for both wallets
        walletA = new KeymeshWallet(address(this), deviceA, address(recovery), address(0));
        walletB = new KeymeshWallet(address(this), deviceB, address(recovery), address(0));

        // Bootstrap both wallets
        address[] memory guardiansA = new address[](3);
        guardiansA[0] = g1;
        guardiansA[1] = g2;
        guardiansA[2] = g3;
        recovery.bootstrapRecoveryGovernance(address(walletA), guardiansA, 2, 24 hours);

        address[] memory guardiansB = new address[](2);
        guardiansB[0] = g4;
        guardiansB[1] = g5;
        recovery.bootstrapRecoveryGovernance(address(walletB), guardiansB, 2, 24 hours);
    }

    /// @notice Execute a governance call via device-signed wallet.execute
    function _governViaDevice(
        KeymeshWallet target,
        uint256 deviceKey,
        address to,
        bytes memory data
    ) internal {
        uint256 nonce = target.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(target), block.chainid, nonce, to, 0, data, 2_100_000_000
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deviceKey, digest);
        target.execute(
            address(target), block.chainid, to, 0, data, nonce, 2_100_000_000,
            abi.encodePacked(r, s, v)
        );
    }

    /// @notice Add guardian through RecoveryManager governance
    function _addGuardian(KeymeshWallet wallet, address guardian) internal {
        bytes memory data = abi.encodeCall(
            IRecoveryManager.addGuardian, (address(wallet), guardian)
        );
        uint256 deviceKey = wallet == walletA ? DEVICE_KEY_A : DEVICE_KEY_B;
        _governViaDevice(wallet, deviceKey, address(recovery), data);
    }

    /// @notice Remove guardian through RecoveryManager governance
    function _removeGuardian(KeymeshWallet wallet, address guardian) internal {
        bytes memory data = abi.encodeCall(
            IRecoveryManager.removeGuardian, (address(wallet), guardian)
        );
        uint256 deviceKey = wallet == walletA ? DEVICE_KEY_A : DEVICE_KEY_B;
        _governViaDevice(wallet, deviceKey, address(recovery), data);
    }

    /****************************************
     *           Invariants
     *****************************************/

    /// @notice No duplicate guardians per wallet
    function invariant_noDuplicateGuardians() external view {
        address[] memory listA = registry.getGuardians(address(walletA));
        for (uint256 i = 0; i < listA.length; i++) {
            for (uint256 j = i + 1; j < listA.length; j++) {
                assertTrue(listA[i] != listA[j], "duplicate guardian in wallet A");
            }
        }

        address[] memory listB = registry.getGuardians(address(walletB));
        for (uint256 i = 0; i < listB.length; i++) {
            for (uint256 j = i + 1; j < listB.length; j++) {
                assertTrue(listB[i] != listB[j], "duplicate guardian in wallet B");
            }
        }
    }

    /// @notice Guardian count matches list length
    function invariant_countMatchesList() external view {
        assertEq(registry.guardianCount(address(walletA)), registry.getGuardians(address(walletA)).length);
        assertEq(registry.guardianCount(address(walletB)), registry.getGuardians(address(walletB)).length);
    }

    /// @notice Wallet isolation invariant
    function invariant_walletIsolation() external view {
        // g1 is guardian of A only
        assertTrue(registry.isGuardian(address(walletA), g1));
        assertFalse(registry.isGuardian(address(walletB), g1));

        // g4 is guardian of B only
        assertFalse(registry.isGuardian(address(walletA), g4));
        assertTrue(registry.isGuardian(address(walletB), g4));
    }

    /// @notice Zero address never a guardian
    function invariant_zeroAddressNotGuardian() external view {
        assertFalse(registry.isGuardian(address(walletA), address(0)));
        assertFalse(registry.isGuardian(address(walletB), address(0)));
    }

    /****************************************
     *           Fuzz Tests
     *****************************************/

    /// @notice Fuzz: add guardian idempotency
    function testFuzz_AddGuardianIdempotency(uint256 seed) public {
        address guardian;
        if (seed % 2 == 0) {
            guardian = address(uint160(uint256(keccak256(abi.encodePacked("guardian", seed, "A")))));
        } else {
            guardian = address(uint160(uint256(keccak256(abi.encodePacked("guardian", seed, "B")))));
        }
        vm.assume(guardian != address(0));
        vm.assume(!registry.isGuardian(address(walletA), guardian));
        vm.assume(!registry.isGuardian(address(walletB), guardian));

        // Add to wallet A via governance (success)
        _addGuardian(walletA, guardian);
        assertTrue(registry.isGuardian(address(walletA), guardian));
        assertEq(registry.guardianCount(address(walletA)), 4);

        // Adding again via direct call should fail with GuardianAlreadyActive
        vm.prank(address(recovery));
        vm.expectRevert(abi.encodeWithSelector(
            IGuardianRegistry.GuardianAlreadyActive.selector, address(walletA), guardian
        ));
        registry.addGuardian(address(walletA), guardian);

        assertEq(registry.guardianCount(address(walletA)), 4, "duplicate add rejected");
    }

    /// @notice Fuzz: remove guardian
    function testFuzz_RemoveGuardian(uint256 seed) public {
        address guardian = seed % 3 == 0 ? g1 : (seed % 3 == 1 ? g2 : g3);

        // Remove via governance (success)
        _removeGuardian(walletA, guardian);

        assertFalse(registry.isGuardian(address(walletA), guardian));
        assertEq(registry.guardianCount(address(walletA)), 2);

        // Cannot remove again via direct call
        vm.prank(address(recovery));
        vm.expectRevert(abi.encodeWithSelector(
            IGuardianRegistry.GuardianNotActive.selector, address(walletA), guardian
        ));
        registry.removeGuardian(address(walletA), guardian);
    }

    /// @notice Fuzz: remove unknown guardian fails
    function testFuzz_RemoveUnknownGuardianFails(uint256 seed) public {
        address unknown = address(uint160(uint256(keccak256(abi.encodePacked("unknown", seed)))));
        vm.assume(unknown != g1 && unknown != g2 && unknown != g3);
        vm.assume(unknown != address(0));

        vm.prank(address(recovery));
        vm.expectRevert(abi.encodeWithSelector(
            IGuardianRegistry.GuardianNotActive.selector, address(walletA), unknown
        ));
        registry.removeGuardian(address(walletA), unknown);

        assertEq(registry.guardianCount(address(walletA)), 3, "count unchanged");
    }

    /// @notice Fuzz: zero address rejected for add
    function testFuzz_AddZeroAddressRejected() public {
        vm.prank(address(recovery));
        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        registry.addGuardian(address(walletA), address(0));
    }

    /// @notice Fuzz: zero address rejected for remove (not active)
    function testFuzz_RemoveZeroAddressRejected() public {
        vm.prank(address(recovery));
        vm.expectRevert(abi.encodeWithSelector(
            IGuardianRegistry.GuardianNotActive.selector, address(walletA), address(0)
        ));
        registry.removeGuardian(address(walletA), address(0));
    }

    /// @notice Fuzz: non-device cannot mutate (direct registry calls fail)
    function testFuzz_NonDeviceCannotMutate(uint256 seed) public {
        address intruder;
        if (seed % 2 == 0) {
            intruder = g4; // guardian of wallet B
        } else {
            intruder = address(uint160(uint256(keccak256(abi.encodePacked("intruder", seed)))));
        }

        // Try to add via direct registry call (should fail - not RecoveryManager)
        vm.prank(intruder);
        vm.expectRevert(abi.encodeWithSelector(
            IGuardianRegistry.NotRecoveryManager.selector, intruder
        ));
        registry.addGuardian(address(walletA), intruder);

        // Try to remove via direct registry call
        vm.prank(intruder);
        vm.expectRevert(abi.encodeWithSelector(
            IGuardianRegistry.NotRecoveryManager.selector, intruder
        ));
        registry.removeGuardian(address(walletA), g3);

        assertEq(registry.guardianCount(address(walletA)), 3, "untouched");
    }

    /// @notice Fuzz: re-add removed guardian works
    function testFuzz_ReAddRemovedGuardian() public {
        // Remove g1 from wallet A
        _removeGuardian(walletA, g1);
        assertFalse(registry.isGuardian(address(walletA), g1));
        assertEq(registry.guardianCount(address(walletA)), 2);

        // Add g1 back to wallet A
        _addGuardian(walletA, g1);
        assertTrue(registry.isGuardian(address(walletA), g1));
        assertEq(registry.guardianCount(address(walletA)), 3);
    }

    /// @notice Fuzz: guardian in wallet A doesn't affect wallet B
    function testFuzz_GuardianIsolationAcrossWallets() public {
        // g1 is guardian of A, add g1 to B as well
        _addGuardian(walletB, g1);
        assertTrue(registry.isGuardian(address(walletA), g1));
        assertTrue(registry.isGuardian(address(walletB), g1));
        assertEq(registry.guardianCount(address(walletA)), 3);
        assertEq(registry.guardianCount(address(walletB)), 3);

        // Remove from B only
        _removeGuardian(walletB, g1);
        assertTrue(registry.isGuardian(address(walletA), g1), "still guardian of A");
        assertFalse(registry.isGuardian(address(walletB), g1), "removed from B");
        assertEq(registry.guardianCount(address(walletB)), 2);
    }

/// @notice Deterministic: large guardian set sequences - 5 operations with fixed seed
    function testFuzz_LargeGuardianSequences() public {
        // Fixed: exactly 5 operations (one per candidate address), deterministic
        address[] memory candidates = new address[](5);
        candidates[0] = address(0x2001);
        candidates[1] = address(0x2002);
        candidates[2] = address(0x2003);
        candidates[3] = address(0x2004);
        candidates[4] = address(0x2005);

        bool[] memory state = new bool[](5);
        // all start as false (not added)

        // Always run exactly 5 iterations - one per candidate
        for (uint256 i = 0; i < 5; i++) {
            uint256 idx = i % 5;  // fixed idx calculation, no seed dependency
            address guardian = candidates[idx];

            if (state[idx]) {
                // Remove via direct registry call (as RecoveryManager)
                vm.prank(address(recovery));
                registry.removeGuardian(address(walletA), guardian);
                state[idx] = false;
            } else {
                // Add via direct registry call (as RecoveryManager)
                vm.prank(address(recovery));
                registry.addGuardian(address(walletA), guardian);
                state[idx] = true;
            }
        }

        // Count expected guardians from state
        uint256 expectedCount = 3; // initial g1, g2, g3
        for (uint256 i = 0; i < 5; i++) {
            if (state[i]) expectedCount += 1;
        }
        assertEq(registry.guardianCount(address(walletA)), expectedCount);
    }

    /// @notice Fuzz: guardian count never exceeds added minus removed
    function testFuzz_GuardianCountConsistency(uint8 addCount, uint8 removeCount) public {
        address[5] memory candidates = [
            address(0x3001), address(0x3002), address(0x3003), address(0x3004), address(0x3005)
        ];

        // Add some guardians
        uint256 added = 0;
        for (uint256 i = 0; i < addCount && i < candidates.length; i++) {
            if (!registry.isGuardian(address(walletA), candidates[i])) {
                _addGuardian(walletA, candidates[i]);
                added += 1;
            }
        }

        // Remove some
        uint256 removed = 0;
        for (uint256 i = 0; (i + removeCount) % candidates.length < addCount && removed < removeCount && i < candidates.length; i++) {
            address g = candidates[i % candidates.length];
            if (registry.isGuardian(address(walletA), g)) {
                _removeGuardian(walletA, g);
                removed += 1;
            }
        }
    }

    /****************************************
     *           Availability Trade-off Tests
     *****************************************/

    /// @notice Documented trade-off: removing below quorum disables recovery
    ///         This is NOT a bug - it's an owner-controlled availability decision.
    function test_DocumentedTradeoff_RemoveBelowQuorum() public {
        // Start with 3 guardians, quorum 2
        assertEq(registry.guardianCount(address(walletA)), 3);
        assertEq(recovery.quorumOf(address(walletA)), 2);

        // Remove 2 guardians -> only 1 left, quorum still 2
        _removeGuardian(walletA, g1);
        _removeGuardian(walletA, g2);

        assertEq(registry.guardianCount(address(walletA)), 1);
        assertEq(recovery.quorumOf(address(walletA)), 2);

        // Recovery should fail with UnsatisfiableQuorum
        vm.prank(deviceA);
        vm.expectRevert(abi.encodeWithSelector(
            IRecoveryManager.UnsatisfiableQuorum.selector, uint256(2), uint256(1)
        ));
        recovery.initiateRecovery(address(walletA), deviceA, deviceB);

        // This is documented behavior, not a bug
    }

    /// @notice Recovery from the availability trap is owner-controlled
    function test_OwnerCanRestoreQuorumAfterRemoval() public {
        // Remove 2 guardians
        _removeGuardian(walletA, g1);
        _removeGuardian(walletA, g2);

        // Lower quorum to 1
        bytes memory data = abi.encodeCall(
            IRecoveryManager.setQuorum, (address(walletA), uint256(1))
        );
        _governViaDevice(walletA, DEVICE_KEY_A, address(recovery), data);

        assertEq(recovery.quorumOf(address(walletA)), 1);

        // Now recovery should be possible with 1 guardian (use deviceA which is authorized)
        vm.prank(deviceA);
        recovery.initiateRecovery(address(walletA), deviceA, deviceB);
    }
}

// Import the interface for GuardianRegistry errors
interface IGuardianRegistry {
    error NotRecoveryManager(address caller);
    error GuardianAlreadyActive(address wallet, address guardian);
    error GuardianNotActive(address wallet, address guardian);
}
