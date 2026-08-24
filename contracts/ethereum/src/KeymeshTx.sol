// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title KeymeshTx
/// @notice Canonical KEYMESH_TX_V1 transaction encoding and digesting.
/// @dev Byte-for-byte equivalent to packages/protocol/src/canonical.ts and
///      crates/keymesh-core/src/transaction/mod.rs. Cross-language test
///      vectors (test/TransactionDigest.t.sol) pin this implementation; any
///      format change must bump DOMAIN and update all three consumers.
///
/// Encoding:
///   domain_tag = keccak256("KEYMESH_TX_V1")                    (32 bytes)
///   payload    = domain_tag(32)
///              | wallet(20) | chainId(32 BE) | nonce(32 BE)
///              | to(20)     | value(32 BE)    | dataLen(4 BE) | data
///              | expiry(32 BE, unix seconds)
///   digest     = keccak256(payload)
library KeymeshTx {
    string public constant DOMAIN = "KEYMESH_TX_V1";
    bytes32 public constant DOMAIN_TAG = keccak256(bytes(DOMAIN));

    /// @dev Mirrors MAX_DATA_BYTES in the TypeScript/Rust implementations.
    uint32 public constant MAX_DATA_BYTES = 131072;

    error DataTooLarge();

    /// @notice Deterministic KEYMESH_TX_V1 digest for a device-signed call.
    function digest(
        address wallet,
        uint256 chainId,
        uint256 nonce,
        address to,
        uint256 value,
        bytes memory data,
        uint256 expiry
    ) internal pure returns (bytes32) {
        if (data.length > MAX_DATA_BYTES) revert DataTooLarge();
        return keccak256(
            abi.encodePacked(
                DOMAIN_TAG,
                wallet, // packed: 20 raw bytes
                chainId, // uint256 big-endian
                nonce, // uint256 big-endian
                to, // packed: 20 raw bytes
                value, // uint256 big-endian
                uint32(data.length),
                data,
                expiry // uint256 big-endian
            )
        );
    }
}
