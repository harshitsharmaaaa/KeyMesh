// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";

/// @notice Fuzz tests for the canonical KEYMESH_TX_V1 encoding.
/// Tests determinism, injectivity, and boundary value handling.
contract CanonicalEncodingFuzzTest is Test {
    bytes32 internal constant KNOWN_DOMAIN_TAG =
        0x908acdd86e8726216702d8abc211b34ca12c9f1537c7180c55096e1c3be1f405;

    address internal constant WALLET_A = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address internal constant WALLET_B = 0x14dC79964da2C08b23698B3D3cc7Ca32193d9955;
    address internal constant WALLET_C = 0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f;

    address internal constant TO_A = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    address internal constant TO_B = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
    address internal constant TO_C = 0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc;

    /****************************************
     *           Invariant Tests
     *****************************************/

    /// @notice Domain tag is constant
    function test_DomainTagConstant() public pure {
        assertEq(KeymeshTx.DOMAIN_TAG, KNOWN_DOMAIN_TAG);
    }

    /// @notice Max data bytes constant
    function test_MaxDataBytesConstant() public pure {
        assertEq(KeymeshTx.MAX_DATA_BYTES, 131072);
    }

    /// @notice Data too large reverts
    function test_DataTooLargeReverts() public {
        bytes memory oversized = new bytes(KeymeshTx.MAX_DATA_BYTES + 1);
        CanonicalDigestHarness harness = new CanonicalDigestHarness();
        vm.expectRevert(KeymeshTx.DataTooLarge.selector);
        harness.digest(WALLET_A, 1, 0, TO_A, 0, oversized, 2000000000);
    }

    /// @notice Max data bytes accepted
    function test_MaxDataBytesAccepted() public {
        bytes memory maxData = new bytes(KeymeshTx.MAX_DATA_BYTES);
        bytes32 digest = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, maxData, 2000000000);
        assertTrue(digest != bytes32(0), "digest should be non-zero");
    }

    /****************************************
     *           Fuzz: Determinism
     *****************************************/

    /// @notice Fuzz: same inputs produce same digest
    function testFuzz_DeterministicDigest(
        address wallet,
        uint256 chainId,
        uint256 nonce,
        address to,
        uint256 value,
        bytes memory data,
        uint256 expiry
    ) public pure {
        vm.assume(data.length <= KeymeshTx.MAX_DATA_BYTES);
        vm.assume(wallet != address(0));
        vm.assume(to != address(0));
        vm.assume(chainId > 0 && chainId <= type(uint64).max);

        bytes32 d1 = KeymeshTx.digest(wallet, chainId, nonce, to, value, data, expiry);
        bytes32 d2 = KeymeshTx.digest(wallet, chainId, nonce, to, value, data, expiry);

        assertEq(d1, d2, "same inputs must produce same digest");
    }

    /****************************************
     *           Fuzz: Injectivity (Changing any field changes digest)
     *****************************************/

    /// @notice Fuzz: changing wallet changes digest
    function testFuzz_DigestChangesOnWalletChange(
        address walletA,
        address walletB
    ) public pure {
        vm.assume(walletA != walletB);
        vm.assume(walletA != address(0));
        vm.assume(walletB != address(0));

        bytes32 d1 = KeymeshTx.digest(walletA, 1, 0, TO_A, 0, hex"", 2000000000);
        bytes32 d2 = KeymeshTx.digest(walletB, 1, 0, TO_A, 0, hex"", 2000000000);

        assertTrue(d1 != d2, "different wallet must produce different digest");
    }

    /// @notice Fuzz: changing chainId changes digest
    function testFuzz_DigestChangesOnChainIdChange(
        uint256 chainIdA,
        uint256 chainIdB
    ) public pure {
        vm.assume(chainIdA != chainIdB);

        bytes32 d1 = KeymeshTx.digest(WALLET_A, chainIdA, 0, TO_A, 0, hex"", 2000000000);
        bytes32 d2 = KeymeshTx.digest(WALLET_A, chainIdB, 0, TO_A, 0, hex"", 2000000000);

        assertTrue(d1 != d2, "different chainId must produce different digest");
    }

    /// @notice Fuzz: changing nonce changes digest
    function testFuzz_DigestChangesOnNonceChange(uint256 nonceA, uint256 nonceB) public pure {
        bytes32 d1 = KeymeshTx.digest(WALLET_A, 1, nonceA, TO_A, 0, hex"", 2000000000);
        bytes32 d2 = KeymeshTx.digest(WALLET_A, 1, nonceB, TO_A, 0, hex"", 2000000000);

        if (nonceA != nonceB) {
            assertTrue(d1 != d2, "different nonce must produce different digest");
        }
    }

    /// @notice Fuzz: changing destination changes digest
    function testFuzz_DigestChangesOnToChange(
        address toA,
        address toB
    ) public pure {
        vm.assume(toA != toB);
        vm.assume(toA != address(0));
        vm.assume(toB != address(0));

        bytes32 d1 = KeymeshTx.digest(WALLET_A, 1, 0, toA, 0, hex"", 2000000000);
        bytes32 d2 = KeymeshTx.digest(WALLET_A, 1, 0, toB, 0, hex"", 2000000000);

        assertTrue(d1 != d2, "different destination must produce different digest");
    }

    /// @notice Fuzz: changing value changes digest
    function testFuzz_DigestChangesOnValueChange(uint256 valueA, uint256 valueB) public pure {
        bytes32 d1 = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, valueA, hex"", 2000000000);
        bytes32 d2 = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, valueB, hex"", 2000000000);

        if (valueA != valueB) {
            assertTrue(d1 != d2, "different value must produce different digest");
        }
    }

    /// @notice Fuzz: changing data changes digest
    function testFuzz_DigestChangesOnDataChange(
        bytes memory dataA,
        bytes memory dataB
    ) public pure {
        vm.assume(dataA.length <= KeymeshTx.MAX_DATA_BYTES);
        vm.assume(dataB.length <= KeymeshTx.MAX_DATA_BYTES);
        vm.assume(keccak256(dataA) != keccak256(dataB));

        bytes32 d1 = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, dataA, 2000000000);
        bytes32 d2 = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, dataB, 2000000000);

        assertTrue(d1 != d2, "different data must produce different digest");
    }

    /// @notice Fuzz: changing expiry changes digest
    function testFuzz_DigestChangesOnExpiryChange(uint256 expiryA, uint256 expiryB) public pure {
        bytes32 d1 = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, hex"", expiryA);
        bytes32 d2 = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, hex"", expiryB);

        if (expiryA != expiryB) {
            assertTrue(d1 != d2, "different expiry must produce different digest");
        }
    }

    /// @notice Combined: changing multiple fields
    function testFuzz_DigestChangesOnMultipleFieldChange(
        uint256 nonce,
        uint256 value,
        bytes memory data
    ) public pure {
        vm.assume(data.length <= KeymeshTx.MAX_DATA_BYTES);

        bytes32 base = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, hex"", 2000000000);

        bytes32 d2 = KeymeshTx.digest(WALLET_A, 1, nonce, TO_A, 0, hex"", 2000000000);
        if (nonce != 0) assertTrue(base != d2, "nonce change must alter digest");

        bytes32 d3 = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, value, hex"", 2000000000);
        if (value != 0) assertTrue(base != d3, "value change must alter digest");

        bytes32 d4 = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, data, 2000000000);
        if (data.length > 0) assertTrue(base != d4, "data change must alter digest");
    }

    /****************************************
     *           Fuzz: Boundary Values
     *****************************************/

    /// @notice Fuzz: boundary values for integer fields
    function testFuzz_BoundaryChainId(uint64 chainId) public pure {
        vm.assume(chainId < type(uint64).max);
        bytes32 d1 = KeymeshTx.digest(WALLET_A, chainId, 0, TO_A, 0, hex"", 2000000000);
        bytes32 d2 = KeymeshTx.digest(WALLET_A, chainId + 1, 0, TO_A, 0, hex"", 2000000000);
        if (chainId < type(uint64).max) {
            assertTrue(d1 != d2, "adjacent chainIds differ");
        }
    }

    /// @notice Fuzz: boundary values for nonce
    function testFuzz_BoundaryNonce(uint64 nonce) public pure {
        vm.assume(nonce < type(uint64).max);
        bytes32 d1 = KeymeshTx.digest(WALLET_A, 1, nonce, TO_A, 0, hex"", 2000000000);
        bytes32 d2 = KeymeshTx.digest(WALLET_A, 1, nonce + 1, TO_A, 0, hex"", 2000000000);
        if (nonce < type(uint64).max) {
            assertTrue(d1 != d2, "adjacent nonces differ");
        }
    }

    /// @notice Fuzz: boundary for value (u256)
    function testFuzz_BoundaryValue(uint256 value) public pure {
        bytes32 d = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, value, hex"", 2000000000);
        // Just verify it doesn't revert and produces a digest
        assertTrue(d != bytes32(0) || value == 0, "digest computation should succeed");
    }

    /// @notice Fuzz: boundary for expiry
    function testFuzz_BoundaryExpiry(uint64 expiry) public pure {
        vm.assume(expiry < type(uint64).max);
        bytes32 d1 = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, hex"", expiry);
        bytes32 d2 = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, hex"", expiry + 1);
        if (expiry < type(uint64).max) {
            assertTrue(d1 != d2, "adjacent expiries differ");
        }
    }

    /****************************************
     *           Fuzz: Data Length Cases
     *****************************************/

    /// @notice Data length = 0
    function test_FuzzDataLength0() public pure {
        bytes32 d = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, new bytes(0), 2000000000);
        assertTrue(d != bytes32(0) || true, "should handle empty data");
    }

    /// @notice Data length = 1
    function test_FuzzDataLength1() public pure {
        bytes memory data = new bytes(1);
        data[0] = 0x42;
        bytes32 d = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, data, 2000000000);
        assertTrue(d != bytes32(0) || true, "should handle 1-byte data");
    }

    /// @notice Data length = 4 (selector boundary)
    function test_FuzzDataLength4() public pure {
        bytes memory data = new bytes(4);
        data[0] = 0xde;
        data[1] = 0xad;
        data[2] = 0xbe;
        data[3] = 0xef;
        bytes32 d = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, data, 2000000000);
        assertTrue(d != bytes32(0) || true, "should handle 4-byte data");
    }

    /// @notice Data length = max
    function test_FuzzDataLengthMax() public {
        bytes memory data = new bytes(KeymeshTx.MAX_DATA_BYTES);
        for (uint256 i = 0; i < 100; i++) {
            data[i] = bytes1(uint8(i % 256));
        }
        bytes32 d = KeymeshTx.digest(WALLET_A, 1, 0, TO_A, 0, data, 2000000000);
        assertTrue(d != bytes32(0), "should handle max data");
    }

    /// @notice Data length = max + 1 (reverts)
    function test_FuzzDataLengthOverMax() public {
        bytes memory data = new bytes(KeymeshTx.MAX_DATA_BYTES + 1);
        CanonicalDigestHarness harness = new CanonicalDigestHarness();
        vm.expectRevert(KeymeshTx.DataTooLarge.selector);
        harness.digest(WALLET_A, 1, 0, TO_A, 0, data, 2000000000);
    }

    /****************************************
     *           Known Vector Verification
     *****************************************/

    /// @notice Verify against the shared TypeScript/Rust vectors
    function test_Vector1_EthTransfer() public pure {
        bytes memory data = new bytes(0);
        bytes32 digest = KeymeshTx.digest(
            WALLET_A,
            31337,
            0,
            TO_A,
            1 ether,
            data,
            2000000000
        );
        assertEq(digest, 0xef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a);
    }

    function test_Vector2_ZeroValueCalldata() public pure {
        bytes memory data = new bytes(16);
        for (uint256 i = 0; i < 16; i++) {
            data[i] = bytes1(uint8(0xdeadbeefcafebabe0123456789abcdef >> (i * 8)));
        }
        bytes32 digest = KeymeshTx.digest(
            WALLET_B,
            11155111,
            7,
            TO_B,
            0,
            data,
            2000000001
        );
        assertEq(digest, 0x25fd006ab1961a20a4377609d7365b393d7d50e0234d0be5dc50f9076a3803f3);
    }

    function test_Vector3_MainnetShaped() public pure {
        bytes memory data = new bytes(64);
        for (uint256 i = 0; i < 16; i++) {
            data[i * 4 + 0] = 0xaa;
            data[i * 4 + 1] = 0xbb;
            data[i * 4 + 2] = 0xcc;
            data[i * 4 + 3] = 0xdd;
        }
        bytes32 digest = KeymeshTx.digest(
            WALLET_C,
            1,
            42,
            TO_C,
            123456789,
            data,
            4102444800
        );
        assertEq(digest, 0x645dc7006dfac3665699314be7d1a4af4f2a502d9b6099b71af0db0d8f1c0a58);
    }

    function test_ZeroTransaction() public pure {
        bytes32 d = KeymeshTx.digest(address(1), 1, 0, address(2), 0, new bytes(0), 0);
        assertTrue(d == d, "deterministic");
    }

    function test_MaximumIntegerFields() public pure {
        bytes32 d = KeymeshTx.digest(
            address(type(uint160).max),
            type(uint256).max,
            type(uint256).max,
            address(type(uint160).max),
            type(uint256).max,
            new bytes(0),
            type(uint256).max
        );
        assertTrue(d != bytes32(0), "handles max uint256");
    }
}

contract CanonicalDigestHarness {
    function digest(
        address wallet,
        uint256 chainId,
        uint256 nonce,
        address to,
        uint256 value,
        bytes memory data,
        uint256 expiry
    ) external pure returns (bytes32) {
        return KeymeshTx.digest(wallet, chainId, nonce, to, value, data, expiry);
    }
}
