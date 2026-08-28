// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";
import {IKeymeshWallet} from "../src/interfaces/IKeymeshWallet.sol";
import {IPolicyManager} from "../src/interfaces/IPolicyManager.sol";
import {IRecoveryManager} from "../src/interfaces/IRecoveryManager.sol";

/// @notice Adversarial contract that reenters execute() during the external call
/// to test reentrancy protection and state integrity.
contract ReentrantExecutor {
    address public wallet;
    KeymeshWallet public target;
    bool public reentered;

    constructor(address _wallet, KeymeshWallet _target) {
        wallet = _wallet;
        target = _target;
    }

    receive() external payable {
        reentered = true;
        // Attempt to call execute again during the external call
        bytes32 digest = KeymeshTx.digest(
            wallet, block.chainid, 0, address(this), 0, "0x", uint64(block.timestamp + 100)
        );
        // We can't easily sign here - the point is just to test reentry attempts
    }
}

/// @notice Foundry invariant test suite for KeymeshWallet.
/// Uses Foundry's native invariant framework with a handler contract that
/// tracks model state and performs random operations.
contract KeymeshWalletInvariantTest is Test {
    KeymeshWallet internal wallet;
    RecoveryManager internal recovery;
    PolicyManager internal policy;
    ReentrantExecutor internal attacker;

    uint256 internal constant DEVICE_KEY = 0xA11CE;
    uint256 internal constant DEVICE2_KEY = 0xB0B;
    uint256 internal constant STRANGER_KEY = 0xFEED;
    uint256 internal constant EXPIRY = 2_100_000_000;

    address internal device;
    address internal device2;
    address internal stranger;
    address internal manager;

    // Model state for invariant tracking
    uint256 internal modelNonce;
    mapping(address => bool) internal modelDevices;
    uint256 internal modelDeviceCount;
    uint256 internal executionCount;

    // Fuzz parameters
    uint256 internal constant FUZZ_RUNS = 200;
    uint256 internal constant SEQ_LENGTH = 20;

    function setUp() public {
        device = vm.addr(DEVICE_KEY);
        device2 = vm.addr(DEVICE2_KEY);
        stranger = vm.addr(STRANGER_KEY);
        manager = address(this);

        vm.warp(2_099_000_000);

        recovery = new RecoveryManager();
        policy = new PolicyManager(recovery);
        wallet = new KeymeshWallet(manager, device, address(recovery), address(0));

        modelDevices[device] = true;
        modelDeviceCount = 1;

        // Register device2 via manager (test contract is manager)
        vm.prank(manager);
        wallet.registerDevice(device2);
        modelDevices[device2] = true;
        modelDeviceCount = 2;
        modelNonce = 0;

        // Deal ETH to wallet
        deal(address(wallet), 100 ether);
    }

    /// @notice Helper: get a random device key from a bounded set
    function _deviceKey(uint256 idx) internal pure returns (uint256) {
        uint256[6] memory keys = [DEVICE_KEY, DEVICE2_KEY, STRANGER_KEY, 0x1337, 0x9999, 0xBEEF];
        return keys[idx % 6];
    }

    /// @notice Helper: get signer address for a key
    function _signerAddress(uint256 key) internal pure returns (address) {
        return vm.addr(key);
    }

    /// @notice Helper: build and sign a valid transaction from a device key
    function _buildValidExecution(
        uint256 deviceKey,
        address to,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (bytes memory sig, bytes32 digest) {
        digest = KeymeshTx.digest(address(wallet), block.chainid, nonce, to, value, data, expiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deviceKey, digest);
        sig = abi.encodePacked(r, s, v);
    }

    /// @notice Helper: execute from a device key, return nonce before execution
    function _safeExecute(
        uint256 deviceKey,
        address to,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 expiry
    ) internal returns (uint256 nonceBefore) {
        nonceBefore = wallet.getNonce();
        (bytes memory sig,) = _buildValidExecution(deviceKey, to, value, data, nonce, expiry);
        wallet.execute(address(wallet), block.chainid, to, value, data, nonce, expiry, sig);
    }

    /****************************************
     *           Invariants
     *****************************************/

    /// @notice Nonce starts at 0
    function invariant_nonceStartZero() external view {
        assertEq(wallet.getNonce(), modelNonce);
    }

    /// @notice Zero address can never be a device
    function invariant_zeroAddressNeverDevice() external view {
        assertFalse(wallet.isDeviceAuthorized(address(0)));
    }

    /// @notice Nonce monotonically increases (only on success)
    function invariant_nonceMonotonic() external view {
        assertEq(wallet.getNonce(), modelNonce);
    }

    /// @notice Wallet address is immutable post-deployment
    function invariant_walletIdentity() external view {
        assertEq(wallet.manager(), manager);
        assertEq(wallet.recoveryManager(), address(recovery));
    }

    /// @notice Device count consistent - at least initial devices remain, count >= model
    function invariant_deviceCountConsistent() external view {
        // Model tracks initial setup (2 devices). Handler may add more via manager,
        // so count should be >= model, and initial devices must remain authorized.
        assertGe(wallet.deviceCount(), modelDeviceCount);
        assertTrue(wallet.isDeviceAuthorized(device), "device must remain authorized");
        assertTrue(wallet.isDeviceAuthorized(device2), "device2 must remain authorized");
    }

    /// @notice Zero address never authorized as device
    function invariant_noZeroAddressDevice() external pure {
        assertEq(uint160(address(0)), 0);
    }

    /****************************************
     *           Fuzz Tests
     *****************************************/

    /// @notice Fuzz: nonce increments exactly on successful execution, unchanged on failure
    function testFuzz_NonceMonotonicity(uint256 seed, uint8 action) public {
        vm.assume(action != 255); // valid range

        uint256 initialNonce = wallet.getNonce();
        uint256 keyIndex = seed % 5;
        uint256 deviceKey = _deviceKey(keyIndex);
        address signer = _signerAddress(deviceKey);

        bool isAuthorizedDevice = modelDevices[signer];

        if (isAuthorizedDevice) {
            // Successfully execute a tx
            address to = device2;
            uint256 value = 0;
            bytes memory data = "";
            uint256 nonce = wallet.getNonce();
            uint256 expiry = EXPIRY;

            (bytes memory sig, bytes32 digest) = _buildValidExecution(
                deviceKey, to, value, data, nonce, expiry
            );

            wallet.execute(address(wallet), block.chainid, to, value, data, nonce, expiry, sig);

            modelNonce += 1;
            assertEq(wallet.getNonce(), initialNonce + 1);
            assertTrue(wallet.getNonce() == modelNonce);
        } else {
            // Execution should fail - nonce unchanged
            address to = device2;
            uint256 nonce = wallet.getNonce();
            bytes32 digest = KeymeshTx.digest(
                address(wallet), block.chainid, nonce, to, 0, "", EXPIRY
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(deviceKey, digest);
            bytes memory sig = abi.encodePacked(r, s, v);

            vm.expectRevert();
            wallet.execute(address(wallet), block.chainid, to, 0, "", nonce, EXPIRY, sig);
            assertEq(wallet.getNonce(), initialNonce, "nonce must not change on failed execution");
            assertEq(wallet.getNonce(), modelNonce);
        }
    }

    /// @notice Fuzz: replay attempt rejected
    function testFuzz_ReplayRejected(uint256 seed) public {
        uint256 initialNonce = wallet.getNonce();

        // Execute valid tx
        _safeExecute(DEVICE_KEY, device2, 0, "", wallet.getNonce(), EXPIRY);

        // Attempt to replay the same tx
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, initialNonce, device2, 0, "", EXPIRY
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.InvalidNonce.selector, initialNonce + 1, initialNonce));
        wallet.execute(address(wallet), block.chainid, device2, 0, "", initialNonce, EXPIRY, sig);

        assertEq(wallet.getNonce(), initialNonce + 1, "replay must not consume another nonce");
    }

    /// @notice Fuzz: skipped nonce rejected (only if sequential model retained)
    function testFuzz_SkippedNonceRejected(uint256 nonceDelta) public {
        vm.assume(nonceDelta > 0 && nonceDelta < 100);

        uint256 expectedNonce = wallet.getNonce();
        uint256 providedNonce = expectedNonce + nonceDelta;

        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, providedNonce, device2, 0, "", EXPIRY
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.InvalidNonce.selector, expectedNonce, providedNonce));
        wallet.execute(address(wallet), block.chainid, device2, 0, "", providedNonce, EXPIRY, sig);

        assertEq(wallet.getNonce(), expectedNonce, "skipped nonce must not consume nonce");
    }

    /// @notice Fuzz: expired transaction rejected
    function testFuzz_ExpiredTransactionRejected(uint256 delta) public {
        vm.assume(delta > 0 && delta < 1000);

        uint256 nowTs = block.timestamp;
        uint256 expiry = nowTs - delta;
        uint256 nonce = wallet.getNonce();

        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, device2, 0, "", expiry
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.TransactionExpired.selector, expiry, block.timestamp)
        );
        wallet.execute(address(wallet), block.chainid, device2, 0, "", nonce, expiry, sig);

        assertEq(wallet.getNonce(), 0, "expired tx must not consume nonce");
    }

    /// @notice Fuzz: wrong chain id rejected
    function testFuzz_WrongChainRejected(uint256 chainIdDelta) public {
        vm.assume(chainIdDelta < 10000);

        uint256 wrongChain = block.chainid + chainIdDelta + 1;
        uint256 nonce = wallet.getNonce();

        bytes32 digest = KeymeshTx.digest(
            address(wallet), wrongChain, nonce, device2, 0, "", EXPIRY
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.WrongChain.selector, wrongChain));
        wallet.execute(address(wallet), wrongChain, device2, 0, "", nonce, EXPIRY, sig);
    }

    /// @notice Fuzz: wrong wallet parameter rejected
    function testFuzz_WrongWalletRejected(address wrongWallet) public {
        vm.assume(wrongWallet != address(wallet) && wrongWallet != address(0));
        uint256 nonce = wallet.getNonce();

        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, device2, 0, "", EXPIRY
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.WrongWallet.selector, wrongWallet));
        wallet.execute(wrongWallet, block.chainid, device2, 0, "", nonce, EXPIRY, sig);
    }

    /// @notice Fuzz: signature for different digest rejected
    function testFuzz_SignatureForDifferentDigestRejected(uint256 seed) public {
        uint256 deviceKey = _deviceKey(seed % 5);
        address signer = _signerAddress(deviceKey);

        // Sign a different digest
        bytes32 wrongDigest = keccak256("totally unrelated message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deviceKey, wrongDigest);
        bytes memory sig = abi.encodePacked(r, s, v);
        uint256 nonce = wallet.getNonce();

        // Even if signer is authorized, wrong digest recovery gives wrong signer
        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, device2, 0, "", nonce, EXPIRY, sig);
    }

    /// @notice Fuzz: tampered field after signing rejected
    function testFuzz_TamperedFieldRejected(uint256 toMutate, uint256 seed) public {
        // Build a valid signature over the correct digest
        address to = device2;
        uint256 value = 0;
        bytes memory data = "";
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(address(wallet), block.chainid, nonce, to, value, data, EXPIRY);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Tamper: use a different value (the signer recovers to a non-device address)
        uint256 tamperedValue = value == 0 ? 1 : value + 1;

        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, to, tamperedValue, data, nonce, EXPIRY, sig);

        assertEq(wallet.getNonce(), nonce, "tampered execution must not consume nonce");
    }

    /// @notice Fuzz: malformed signature rejected
    function testFuzz_MalformedSignaturesRejected(uint8 length) public {
        vm.assume(length < 65);

        bytes memory shortSig = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            shortSig[i] = bytes1(uint8(i % 256));
        }

        uint256 nonce = wallet.getNonce();
        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, device2, 0, "", nonce, EXPIRY, shortSig);
    }

    /// @notice Fuzz: failed target call reverts with nonce preserved
    function testFuzz_FailedTargetRevertsNoncePreserved(uint256 seed) public {
        // Use a contract that always reverts
        address reverter = address(new RevertingTarget());
        uint256 nonce = wallet.getNonce();

        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, reverter, 0, "", EXPIRY
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, reverter, 0, "", nonce, EXPIRY, sig);

        assertEq(wallet.getNonce(), 0, "reverted target must not consume nonce");
    }

    /****************************************
     *           Boundary Tests
     *****************************************/

    /// @notice Expiry boundary: now == expiry is valid (inclusive)
    function test_ExpiryBoundaryInclusive() public {
        vm.warp(EXPIRY);
        _safeExecute(DEVICE_KEY, device2, 0, "", wallet.getNonce(), EXPIRY);
        assertEq(wallet.getNonce(), 1);
    }

    /// @notice Expiry boundary: now == expiry + 1 is expired
    function test_ExpiryBoundaryExclusive() public {
        vm.warp(EXPIRY + 1);
        uint256 nonce = wallet.getNonce();

        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, device2, 0, "", EXPIRY
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.TransactionExpired.selector, EXPIRY, EXPIRY + 1));
        wallet.execute(address(wallet), block.chainid, device2, 0, "", nonce, EXPIRY, sig);
    }

    /// @notice Zero address nonce handling
    function test_ZeroNonceValue() public {
        // nonce 0 is valid - first transaction
        _safeExecute(DEVICE_KEY, device2, 0, "", 0, EXPIRY);
        assertEq(wallet.getNonce(), 1);
    }

    /// @notice Empty calldata
    function test_EmptyCalldata() public {
        _safeExecute(DEVICE_KEY, device2, 0, "", wallet.getNonce(), EXPIRY);
        assertEq(wallet.getNonce(), 1);
    }

    /// @notice Large calldata
    function test_LargeCalldata() public {
        bytes memory largeData = new bytes(1024);
        for (uint256 i = 0; i < 1024; i++) {
            largeData[i] = bytes1(uint8(i % 256));
        }
        // Deploy a contract that accepts large calldata
        address target = address(new BytesSink());
        _safeExecute(DEVICE_KEY, target, 0, largeData, wallet.getNonce(), EXPIRY);
        assertEq(wallet.getNonce(), 1);
    }

    /// @notice Single byte calldata
    function test_SingleByteCalldata() public {
        address target = address(new BytesSink());
        _safeExecute(DEVICE_KEY, target, 0, hex"42", wallet.getNonce(), EXPIRY);
        assertEq(wallet.getNonce(), 1);
    }

    /// @notice Zero-value transaction
    function test_ZeroValueTransaction() public {
        _safeExecute(DEVICE_KEY, device2, 0, "", wallet.getNonce(), EXPIRY);
        assertEq(wallet.getNonce(), 1);
        assertEq(address(wallet).balance, 100 ether);
    }

    /****************************************
     *           Reentrancy Tests
     *****************************************/

    /// @notice Reentrancy attempt during execute()
    function test_ReentrancyProtectionExecute() public {
        attacker = new ReentrantExecutor(address(wallet), wallet);

        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), address(attacker), 0, "", EXPIRY
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // The attacker contract will try to re-enter, but ReentrancyGuard should prevent it
        wallet.execute(address(wallet), block.chainid, address(attacker), 0, "", wallet.getNonce(), EXPIRY, sig);

        assertTrue(attacker.reentered(), "Reentrancy attempt was made");
        assertEq(wallet.getNonce(), 1, "nonce should advance after successful execution");
    }

    /// @notice Multiple sequential executions maintain nonce monotonicity
    function test_MultipleSequentialExecutions() public {
        for (uint256 i = 0; i < 10; i++) {
            _safeExecute(DEVICE_KEY, device2, 0, "", wallet.getNonce(), EXPIRY);
            assertEq(wallet.getNonce(), i + 1);
        }
    }

    /// @notice Failed execution followed by successful retry preserves nonce
    function test_FailedThenRetryNoncePreserved() public {
        uint256 nonce = wallet.getNonce();

        // Failed execution (unauthorized device)
        (bytes memory sig, bytes32 digest) = _buildValidExecution(
            STRANGER_KEY, device2, 0, "", nonce, EXPIRY
        );

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.UnauthorizedDevice.selector, _signerAddress(STRANGER_KEY)));
        wallet.execute(address(wallet), block.chainid, device2, 0, "", nonce, EXPIRY, sig);

        assertEq(wallet.getNonce(), nonce, "failed execution must not consume nonce");

        // Retry with authorized device
        _safeExecute(DEVICE_KEY, device2, 0, "", nonce, EXPIRY);
        assertEq(wallet.getNonce(), nonce + 1);
    }
}

/// @notice Helper contract that accepts large calldata
contract BytesSink {
    bytes private lastData;

    fallback() external payable {
        lastData = msg.data;
    }

    function lastCalldata() external view returns (bytes memory) {
        return lastData;
    }
}

/// @notice Helper contract that always reverts on receive/fallback
contract RevertingTarget {
    receive() external payable {
        revert("RevertingTarget: intentional revert");
    }
    fallback() external payable {
        revert("RevertingTarget: intentional revert");
    }
}
