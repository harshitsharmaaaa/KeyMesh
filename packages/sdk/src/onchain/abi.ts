/**
 * Minimal human-readable ABIs for the Phase 1.2 contract set.
 * Kept in sync manually with:
 *   contracts/ethereum/src/interfaces/IKeymeshWallet.sol
 *   contracts/ethereum/src/interfaces/IGuardianRegistry.sol
 *   contracts/ethereum/src/interfaces/IRecoveryManager.sol
 *
 * Custom errors are INCLUDED so viem can decode revert data into readable
 * domain errors (see ./errors.ts). The Foundry digest-vector tests plus the
 * Anvil integration script guard against drift.
 *
 * Parsed via viem's parseAbi at module load: runtime decoders
 * (decodeEventLog/simulateContract) require object ABIs.
 */
import { parseAbi } from 'viem';

const keymeshWalletAbiItems = [
  // device management
  'function registerDevice(address device)',
  'function revokeDevice(address device)',
  'function isDeviceAuthorized(address device) view returns (bool)',
  'function deviceCount() view returns (uint256)',
  'function getNonce() view returns (uint256)',
  // bootstrap / recovery wiring
  'function manager() view returns (address)',
  'function recoveryManager() view returns (address)',
  'function recoveryInitialized() view returns (bool)',
  'function initializeRecoveryGovernance()',
  'function applyRecoveredDevice(address replacedDevice, address newDevice)',
  // canonical execution surface
  'function transactionDigest(address wallet, uint256 chainId, address to, uint256 value, bytes data, uint256 nonce, uint256 expiry) view returns (bytes32)',
  'function execute(address wallet, uint256 chainId, address to, uint256 value, bytes data, uint256 nonce, uint256 expiry, bytes signature)',
  // events
  'event DeviceRegistered(address indexed device, uint64 registeredAt)',
  'event DeviceRevoked(address indexed device, uint64 revokedAt)',
  'event RecoveryGovernanceInitialized(uint64 initializedAt)',
  'event TransactionExecuted(uint256 indexed nonce, address indexed device, address indexed to, uint256 value, bytes data)',
  // custom errors
  'error ZeroAddress()',
  'error NotDeviceManager(address caller)',
  'error AlreadyRegistered(address device)',
  'error NotRegistered(address device)',
  'error LastDeviceRemoval()',
  'error ManagerAuthorityRetired(address manager)',
  'error NotRecoveryManager(address caller)',
  'error WrongWallet(address provided)',
  'error WrongChain(uint256 provided)',
  'error InvalidNonce(uint256 expected, uint256 provided)',
  'error TransactionExpired(uint256 expiry, uint256 nowTs)',
  'error UnauthorizedDevice(address signer)',
  'error ExecutionFailed(bytes returnData)',
] as const;

const guardianRegistryAbiItems = [
  'function recoveryManager() view returns (address)',
  'function addGuardian(address wallet, address guardian)',
  'function removeGuardian(address wallet, address guardian)',
  'function isGuardian(address wallet, address guardian) view returns (bool)',
  'function guardianCount(address wallet) view returns (uint256)',
  'function getGuardians(address wallet) view returns (address[])',
  'event GuardianAdded(address indexed wallet, address indexed guardian)',
  'event GuardianRemoved(address indexed wallet, address indexed guardian)',
  'error GuardianNotActive(address wallet, address guardian)',
  'error GuardianAlreadyActive(address wallet, address guardian)',
  'error NotRecoveryManager(address caller)',
] as const;

const recoveryManagerAbiItems = [
  // configuration views
  'function MIN_TIMELOCK() view returns (uint64)',
  'function guardianRegistry() view returns (address)',
  'function statusOf(address wallet) view returns (uint8)',
  'function latestRecoveryIdOf(address wallet) view returns (uint256)',
  'function quorumOf(address wallet) view returns (uint256)',
  'function recoveryTimelockSeconds(address wallet) view returns (uint64)',
  'function requestById(uint256 recoveryId) view returns (address wallet, address initiator, address replacedDevice, address newDevice, uint64 initiatedAt, uint64 executeAfter, uint256 approvals, uint256 quorumSnapshot, uint8 status)',
  'function hasApproved(uint256 recoveryId, address guardian) view returns (bool)',
  // bootstrap (manager-only, once)
  'function bootstrapRecoveryGovernance(address wallet, address[] initialGuardians, uint256 quorum, uint64 timelockSeconds)',
  // device-signed governance (through wallet.execute)
  'function addGuardian(address wallet, address guardian)',
  'function removeGuardian(address wallet, address guardian)',
  'function setQuorum(address wallet, uint256 quorum)',
  'function setRecoveryTimelock(address wallet, uint64 timelockSeconds)',
  // lifecycle
  'function initiateRecovery(address wallet, address replacedDevice, address newDevice)',
  'function approveRecovery(address wallet)',
  'function cancelRecovery(address wallet)',
  'function finalizeRecovery(address wallet)',
  // events
  'event GuardianSetAdded(address indexed wallet, address[] guardians, uint256 quorum)',
  'event RecoveryGovernanceBootstrapped(address indexed wallet, address indexed bootstrappedBy, uint256 quorum, uint64 timelockSeconds)',
  'event RecoveryInitiated(uint256 indexed recoveryId, address indexed wallet, address indexed initiator, address replacedDevice, address newDevice, uint256 quorum, uint64 initiatedAt)',
  'event RecoveryApproved(uint256 indexed recoveryId, address indexed wallet, address indexed guardian, uint256 approvalCount)',
  'event RecoveryTimelockStarted(uint256 indexed recoveryId, address indexed wallet, uint64 executeAfter)',
  'event RecoveryCancelled(uint256 indexed recoveryId, address indexed wallet, address indexed by)',
  'event RecoveryFinalized(uint256 indexed recoveryId, address indexed wallet, address newDevice, address replacedDevice)',
  // custom errors
  'error RecoveryAlreadyActive(uint256 activeRecoveryId)',
  'error NoActiveRecovery(address wallet)',
  'error InvalidReplacementDevice(address newDevice)',
  'error InvalidReplacedDevice(address replacedDevice)',
  'error UnsatisfiableQuorum(uint256 quorum, uint256 guardianCount)',
  'error NotGuardianOrDevice(address caller)',
  'error NotRegisteredGuardian(address guardian)',
  'error DuplicateApproval(address guardian)',
  'error InvalidStateTransition(uint8 from, string attempted)',
  'error TimelockNotElapsed(uint64 executeAfter, uint64 nowTs)',
  'error AlreadyInitialized()',
  'error NotInitialized()',
  'error InvalidQuorum(uint256 quorum, uint256 guardianCount)',
  'error TimelockTooShort(uint64 provided, uint64 minimum)',
  'error InvalidGuardianSet()',
  'error Unauthorized()',
] as const;

const policyManagerAbiItems = [
  // configuration views
  'function recoveryManager() view returns (address)',
  'function MAX_RESTRICTED_DESTINATIONS() view returns (uint256)',
  'function MAX_RESTRICTED_SELECTORS() view returns (uint256)',
  'function policyOf(address wallet) view returns (uint8 defaultMode, uint256 valueThreshold, uint32 guardianApprovalsRequired, uint64 version)',
  'function policyVersion(address wallet) view returns (uint64)',
  'function isRestrictedDestination(address wallet, address destination) view returns (bool)',
  'function isRestrictedSelector(address wallet, bytes4 selector) view returns (bool)',
  'function evaluateAuthorization(address wallet, address to, uint256 value, bytes data) view returns (uint8)',
  'function authorizationOf(bytes32 digest) view returns (address wallet, address requester, uint64 requestedAt, uint64 policyVersion, uint32 approvals, uint32 approvalsRequired, uint8 status)',
  'function hasTransactionApproval(bytes32 digest, address guardian) view returns (bool)',
  'function isAdminSelector(bytes4 selector) pure returns (bool)',
  // configuration (wallet-governed; executed through KeymeshWallet.execute)
  'function configurePolicy(address wallet, uint8 defaultMode, uint256 valueThreshold, uint32 guardianApprovalsRequired)',
  'function setDefaultMode(address wallet, uint8 mode)',
  'function setValueThreshold(address wallet, uint256 threshold)',
  'function setTransactionQuorum(address wallet, uint32 guardianApprovalsRequired)',
  'function setDestinationRestriction(address wallet, address destination, bool restricted)',
  'function setSelectorRestriction(address wallet, bytes4 selector, bool restricted)',
  // transaction authorization lifecycle
  'function requestAuthorization(address wallet, bytes32 digest)',
  'function approveTransaction(address wallet, bytes32 digest)',
  'function cancelAuthorization(address wallet, bytes32 digest)',
  'function consumeAuthorization(address wallet, bytes32 digest)',
  // events
  'event PolicyConfigured(address indexed wallet, uint8 defaultMode, uint256 valueThreshold, uint32 guardianApprovalsRequired, uint64 version)',
  'event PolicyUpdated(address indexed wallet, uint64 indexed oldVersion, uint64 indexed newVersion)',
  'event DestinationPolicyUpdated(address indexed wallet, address indexed destination, bool restricted, uint64 version)',
  'event SelectorPolicyUpdated(address indexed wallet, bytes4 indexed selector, bool restricted, uint64 version)',
  'event TransactionAuthorizationRequested(bytes32 indexed digest, address indexed wallet, address indexed requester, uint32 approvalsRequired, uint64 policyVersion)',
  'event TransactionAuthorizationApproved(bytes32 indexed digest, address indexed wallet, address indexed guardian, uint32 approvalCount)',
  'event TransactionAuthorizationQuorumReached(bytes32 indexed digest, address indexed wallet)',
  'event TransactionAuthorizationCancelled(bytes32 indexed digest, address indexed wallet, address indexed by)',
  'event TransactionAuthorizationExecuted(bytes32 indexed digest, address indexed wallet)',
  // custom errors
  'error UnauthorizedPolicyUpdate(address caller)',
  'error AlreadyConfigured(address wallet)',
  'error NotConfigured(address wallet)',
  'error InvalidMode(uint8 mode)',
  'error InvalidThreshold()',
  'error InvalidGuardianApprovals(uint32 requested, uint32 guardianCount)',
  'error RestrictedSetLimit(string kind, uint256 limit)',
  'error RequesterNotDevice(address caller)',
  'error NotRegisteredGuardian(address guardian)',
  'error TransactionAuthorizationExists(bytes32 digest, uint8 status)',
  'error TransactionAuthorizationNotFound(bytes32 digest)',
  'error AuthorizationRequired(bytes32 digest)',
  'error InsufficientGuardianApprovals(bytes32 digest, uint32 approvals, uint32 required)',
  'error TransactionAuthorizationAlreadyApproved(address guardian)',
  'error PolicyChanged(bytes32 digest, uint64 authorizedUnder, uint64 currentVersion)',
  'error AuthorizationNotConsumable(bytes32 digest, uint8 status)',
] as const;

export const keymeshWalletAbi = parseAbi(keymeshWalletAbiItems);
export const guardianRegistryAbi = parseAbi(guardianRegistryAbiItems);
export const recoveryManagerAbi = parseAbi(recoveryManagerAbiItems);
export const policyManagerAbi = parseAbi(policyManagerAbiItems);

export type KeymeshWalletAbi = typeof keymeshWalletAbi;
export type GuardianRegistryAbi = typeof guardianRegistryAbi;
export type RecoveryManagerAbi = typeof recoveryManagerAbi;
export type PolicyManagerAbi = typeof policyManagerAbi;
