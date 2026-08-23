// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IKeymeshWallet} from "./interfaces/IKeymeshWallet.sol";
import {KeymeshErrors} from "./KeymeshErrors.sol";
import {KeymeshTx} from "./KeymeshTx.sol";

/// @title KeymeshWallet
/// @notice Device-authorized wallet: executes calls whose ECDSA signature
///         recovers to a registered device over the canonical KEYMESH_TX_V1
///         digest.
/// @dev Phase 1.1 status: IMPLEMENTED for single-device ECDSA authorization.
///
///      Authorization model:
///       - Execution authority = a signature from ANY registered device.
///         `msg.sender` is irrelevant to execution, so any relayer may submit.
///       - Device management is gated on `manager` (the deployer) as an
///         explicitly TRANSITIONAL Phase 1 control; devices may additionally
///         revoke themselves. Phase 2 replaces this with guardian/recovery
///         governance — no permanent admin exists and none should be added.
///
///      Replay protection: strictly sequential per-wallet nonce (must equal
///      the next expected value), expiry (valid while block.timestamp <=
///      expiry), plus wallet/chainId binding inside the signed digest.
///
///      Failure semantics: validation failures leave zero state changes. A
///      failing target bubbles as `ExecutionFailed`, also reverting the
///      nonce bump — so a reverted execution leaves the wallet untouched and
///      its signature remains retryable until expiry (mirroring how a
///      dropped Ethereum transaction keeps its nonce).
contract KeymeshWallet is IKeymeshWallet, ReentrancyGuard {
    /// @notice Transitional device-set manager; see contract dev docs.
    address public immutable manager;

    mapping(address device => bool) private _devices;
    uint256 private _deviceCount;
    uint256 private _nonce;

    constructor(address manager_, address initialDevice) {
        if (manager_ == address(0) || initialDevice == address(0)) {
            revert KeymeshErrors.ZeroAddress();
        }
        if (manager_ != initialDevice && msg.sender != manager_) {
            // Deployment must be requested by (or on behalf of) the manager.
            revert KeymeshErrors.Unauthorized();
        }
        manager = manager_;
        _devices[initialDevice] = true;
        _deviceCount = 1;
        emit DeviceRegistered(initialDevice, uint64(block.timestamp));
    }

    modifier onlyManager() {
        if (msg.sender != manager) revert NotDeviceManager(msg.sender);
        _;
    }

    // ---------------------------------------------------------------
    // Device management
    // ---------------------------------------------------------------

    function registerDevice(address device) external onlyManager {
        if (device == address(0)) revert KeymeshErrors.ZeroAddress();
        if (_devices[device]) revert AlreadyRegistered(device);

        _devices[device] = true;
        _deviceCount += 1;
        emit DeviceRegistered(device, uint64(block.timestamp));
    }

    function revokeDevice(address device) external {
        bool isSelf = msg.sender == device && _devices[device];
        if (msg.sender != manager && !isSelf) revert NotDeviceManager(msg.sender);
        if (!_devices[device]) revert NotRegistered(device);
        if (_deviceCount == 1) revert LastDeviceRemoval();

        delete _devices[device];
        _deviceCount -= 1;
        emit DeviceRevoked(device, uint64(block.timestamp));
    }

    function isDeviceAuthorized(address device) external view returns (bool) {
        return _devices[device];
    }

    function deviceCount() external view returns (uint256) {
        return _deviceCount;
    }

    // ---------------------------------------------------------------
    // Transaction execution
    // ---------------------------------------------------------------

    function getNonce() external view returns (uint256) {
        return _nonce;
    }

    /// @inheritdoc IKeymeshWallet
    function transactionDigest(
        address wallet,
        uint256 chainId,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint256 expiry
    ) external view returns (bytes32) {
        return KeymeshTx.digest(wallet, chainId, nonce, to, value, data, expiry);
    }

    /// @inheritdoc IKeymeshWallet
    function execute(
        address wallet,
        uint256 chainId,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint256 expiry,
        bytes calldata signature
    ) external nonReentrant {
        // Domain binding: explicit params are validated against live context
        // before use, so cross-wallet/cross-chain signatures fail loudly.
        if (wallet != address(this)) revert WrongWallet(wallet);
        if (chainId != block.chainid) revert WrongChain(chainId);

        // Temporal + sequence validity.
        if (block.timestamp > expiry) revert TransactionExpired(expiry, block.timestamp);
        if (nonce != _nonce) revert InvalidNonce({expected: _nonce, provided: nonce});

        if (to == address(0)) revert KeymeshErrors.ZeroAddress();

        // Signature -> signer -> device authorization.
        bytes32 digest = KeymeshTx.digest(wallet, chainId, nonce, to, value, data, expiry);
        address signer = ECDSA.recover(digest, signature); // reverts when malformed
        if (!_devices[signer]) revert UnauthorizedDevice(signer);

        // Effects before interaction: the nonce bump invalidates this exact
        // digest before control leaves the contract.
        _nonce += 1;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        if (!success) revert ExecutionFailed(returnData); // reverts nonce too

        emit TransactionExecuted(nonce, signer, to, value, data);
    }

    receive() external payable {}
}
