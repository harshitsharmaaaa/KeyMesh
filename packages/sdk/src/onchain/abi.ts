/**
 * Minimal human-readable ABI for KeymeshWallet (Phase 1.1 surface).
 * Kept in sync manually with contracts/ethereum/src/interfaces/IKeymeshWallet.sol;
 * the Foundry digest-vector tests plus the Anvil integration script guard
 * against drift.
 *
 * Parsed via viem's parseAbi at module load: runtime decoders
 * (decodeEventLog/parseEventLogs) require object ABIs.
 */
import { parseAbi } from 'viem';

const keymeshWalletAbiItems = [
  'function registerDevice(address device)',
  'function revokeDevice(address device)',
  'function isDeviceAuthorized(address device) view returns (bool)',
  'function deviceCount() view returns (uint256)',
  'function getNonce() view returns (uint256)',
  'function manager() view returns (address)',
  'function transactionDigest(address wallet, uint256 chainId, address to, uint256 value, bytes data, uint256 nonce, uint256 expiry) view returns (bytes32)',
  'function execute(address wallet, uint256 chainId, address to, uint256 value, bytes data, uint256 nonce, uint256 expiry, bytes signature)',
  'event DeviceRegistered(address indexed device, uint64 registeredAt)',
  'event DeviceRevoked(address indexed device, uint64 revokedAt)',
  'event TransactionExecuted(uint256 indexed nonce, address indexed device, address indexed to, uint256 value, bytes data)',
] as const;

export const keymeshWalletAbi = parseAbi(keymeshWalletAbiItems);

export type KeymeshWalletAbi = typeof keymeshWalletAbi;
