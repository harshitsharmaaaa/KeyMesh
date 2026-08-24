// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IKeymeshWallet} from "./interfaces/IKeymeshWallet.sol";
import {IPolicyManager} from "./interfaces/IPolicyManager.sol";
import {KeymeshErrors} from "./KeymeshErrors.sol";
import {KeymeshTx} from "./KeymeshTx.sol";

/// @title KeymeshWallet
/// @notice Device-authorized wallet: executes calls whose ECDSA signature
///         recovers to a registered device over the canonical KEYMESH_TX_V1
///         digest.
/// @dev Phase 1.2 status: IMPLEMENTED for single-device ECDSA authorization
///      plus guardian-governed device replacement.
///
///      Authorization model:
///       - Execution authority = a signature from ANY registered device.
///         `msg.sender` is irrelevant to execution, so any relayer may submit.
///       - Device-set changes are governed by the `recoveryManager` contract
///         (guardian quorum + timelock). The deployer-chosen `manager`
///         account is BOOTSTRAP-ONLY: it may add devices until recovery
///         governance is initialized, after which `ManagerAuthorityRetired`
///         makes every manager path revert — permanently, by construction.
///       - Devices may always revoke themselves.
///
///      Recovery application is atomic: {applyRecoveredDevice} authorizes the
///      new device BEFORE revoking the replaced one, so the wallet never dips
///      below one authorized device inside the transaction.
///
///      Replay protection: strictly sequential per-wallet nonce (must equal
///      the next expected value), expiry (valid while block.timestamp <=
///      expiry), plus wallet/chainId binding inside the signed digest.
///
///      Failure semantics: validation failures leave zero state changes. A
///      failing target bubbles as `ExecutionFailed`, also reverting the
///      nonce bump — so a reverted execution leaves the wallet untouched and
///      its signature remains retryable until expiry.
contract KeymeshWallet is IKeymeshWallet, ReentrancyGuard {
    /// @notice Bootstrap-only device-set manager; inert after initialization.
    address public immutable manager;

    /// @notice RecoveryManager contract allowed to apply finalized recoveries.
    address public immutable recoveryManager;

    /// @notice Transaction authorization policy layer. May be address(0) to
    ///         run with Phase 1.1 semantics (device signature suffices);
    ///         production wiring always sets it.
    address public immutable policyManager;

    bool private _recoveryInitialized;

    mapping(address device => bool) private _devices;
    uint256 private _deviceCount;
    uint256 private _nonce;

    constructor(
        address manager_,
        address initialDevice,
        address recoveryManager_,
        address policyManager_
    ) {
        if (manager_ == address(0) || initialDevice == address(0) || recoveryManager_ == address(0))
        {
            revert KeymeshErrors.ZeroAddress();
        }
        if (manager_ != initialDevice && msg.sender != manager_) {
            // Deployment must be requested by (or on behalf of) the manager.
            revert KeymeshErrors.Unauthorized();
        }
        manager = manager_;
        recoveryManager = recoveryManager_;
        policyManager = policyManager_;
        _devices[initialDevice] = true;
        _deviceCount = 1;
        emit DeviceRegistered(initialDevice, uint64(block.timestamp));
    }

    modifier onlyBootstrapManager() {
        if (_recoveryInitialized) revert ManagerAuthorityRetired(manager);
        if (msg.sender != manager) revert NotDeviceManager(msg.sender);
        _;
    }

    modifier onlyRecoveryManager() {
        if (msg.sender != recoveryManager) revert NotRecoveryManager(msg.sender);
        _;
    }

    // ---------------------------------------------------------------
    // Bootstrap / governance wiring
    // ---------------------------------------------------------------

    function recoveryInitialized() external view returns (bool) {
        return _recoveryInitialized;
    }

    /// @inheritdoc IKeymeshWallet
    function initializeRecoveryGovernance() external onlyRecoveryManager {
        if (_recoveryInitialized) revert KeymeshErrors.AlreadyInitialized();
        _recoveryInitialized = true;
        emit RecoveryGovernanceInitialized(uint64(block.timestamp));
    }

    // ---------------------------------------------------------------
    // Device management
    // ---------------------------------------------------------------

    function registerDevice(address device) external onlyBootstrapManager {
        if (device == address(0)) revert KeymeshErrors.ZeroAddress();
        if (_devices[device]) revert AlreadyRegistered(device);

        _devices[device] = true;
        _deviceCount += 1;
        emit DeviceRegistered(device, uint64(block.timestamp));
    }

    function revokeDevice(address device) external {
        bool preInitManager = !_recoveryInitialized && msg.sender == manager;
        bool isSelf = msg.sender == device && _devices[device];
        if (!preInitManager && !isSelf) revert NotDeviceManager(msg.sender);
        if (!_devices[device]) revert NotRegistered(device);
        if (_deviceCount == 1) revert LastDeviceRemoval();

        delete _devices[device];
        _deviceCount -= 1;
        emit DeviceRevoked(device, uint64(block.timestamp));
    }

    /// @inheritdoc IKeymeshWallet
    function applyRecoveredDevice(address replacedDevice, address newDevice)
        external
        onlyRecoveryManager
    {
        if (newDevice == address(0)) revert KeymeshErrors.ZeroAddress();
        if (_devices[newDevice]) revert AlreadyRegistered(newDevice);
        // The RecoveryManager validated this at initiation; re-check against
        // live state so finalization can never desync from reality.
        if (replacedDevice != address(0) && !_devices[replacedDevice]) {
            revert NotRegistered(replacedDevice);
        }

        // Authorize first: keeps device count >= 1 at every intermediate step.
        _devices[newDevice] = true;
        _deviceCount += 1;
        emit DeviceRegistered(newDevice, uint64(block.timestamp));

        if (replacedDevice != address(0)) {
            delete _devices[replacedDevice];
            _deviceCount -= 1;
            emit DeviceRevoked(replacedDevice, uint64(block.timestamp));
        }
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

        // Policy layer (Phase 1.3): a valid device signature is necessary but
        // not automatically sufficient. Classification is deterministic; when
        // guardians are required, an authorization bound to THIS exact digest
        // must exist and is consumed here — before any external call — so a
        // single approval can never execute twice.
        if (policyManager != address(0)) {
            if (
                IPolicyManager(policyManager).evaluateAuthorization(address(this), to, value, data)
                    == IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS
            ) {
                IPolicyManager(policyManager).consumeAuthorization(address(this), digest);
            }
        }

        // Effects before interaction: the nonce bump invalidates this exact
        // digest before control leaves the contract.
        _nonce += 1;

        (bool success, bytes memory returnData) = to.call{value: value}(data);
        if (!success) revert ExecutionFailed(returnData); // reverts nonce too

        emit TransactionExecuted(nonce, signer, to, value, data);
    }

    receive() external payable {}
}
