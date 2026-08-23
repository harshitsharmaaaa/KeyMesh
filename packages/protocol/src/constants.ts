export const PROTOCOL_VERSION = '0.1.0';

export const SUPPORTED_CHAINS = {
  ethereum: {
    mainnet: 1,
    sepolia: 11155111,
    holesky: 17000,
  },
} as const;

export type SupportedChain = keyof typeof SUPPORTED_CHAINS;

export const GUARDIAN_TYPES = {
  EOA: 'eoa',
  CONTRACT: 'contract',
  HARDWARE: 'hardware',
  SOCIAL: 'social',
} as const;

export type GuardianType = (typeof GUARDIAN_TYPES)[keyof typeof GUARDIAN_TYPES];

export const RECOVERY_STATES = {
  PENDING: 'pending',
  APPROVED: 'approved',
  TIMELOCK_ACTIVE: 'timelock_active',
  COMPLETED: 'completed',
  CANCELLED: 'cancelled',
  EXPIRED: 'expired',
} as const;

export type RecoveryState = (typeof RECOVERY_STATES)[keyof typeof RECOVERY_STATES];

export const TRANSACTION_TYPES = {
  NORMAL: 'normal',
  HIGH_VALUE: 'high_value',
  RECOVERY: 'recovery',
  GUARDIAN_MANAGEMENT: 'guardian_management',
  POLICY_UPDATE: 'policy_update',
} as const;

export type TransactionType = (typeof TRANSACTION_TYPES)[keyof typeof TRANSACTION_TYPES];

export const APPROVAL_THRESHOLDS = {
  DEFAULT: 1,
  HIGH_VALUE_DEFAULT: 2,
  RECOVERY_DEFAULT: 3,
} as const;

export const TIMELOCK_DEFAULTS = {
  RECOVERY_HOURS: 168,
  GUARDIAN_ADDITION_HOURS: 24,
  POLICY_CHANGE_HOURS: 48,
} as const;

export const STORAGE_KEYS = {
  WALLET_PREFIX: 'keymesh:wallet:',
  GUARDIAN_PREFIX: 'keymesh:guardian:',
  RECOVERY_PREFIX: 'keymesh:recovery:',
  POLICY_PREFIX: 'keymesh:policy:',
  DEVICE_PREFIX: 'keymesh:device:',
} as const;

export const EVENT_NAMES = {
  WALLET_CREATED: 'WalletCreated',
  GUARDIAN_ADDED: 'GuardianAdded',
  GUARDIAN_REMOVED: 'GuardianRemoved',
  RECOVERY_INITIATED: 'RecoveryInitiated',
  RECOVERY_APPROVED: 'RecoveryApproved',
  RECOVERY_COMPLETED: 'RecoveryCompleted',
  RECOVERY_CANCELLED: 'RecoveryCancelled',
  TRANSACTION_REQUESTED: 'TransactionRequested',
  TRANSACTION_AUTHORIZED: 'TransactionAuthorized',
  TRANSACTION_EXECUTED: 'TransactionExecuted',
  DEVICE_AUTHORIZED: 'DeviceAuthorized',
  DEVICE_REVOKED: 'DeviceRevoked',
  POLICY_UPDATED: 'PolicyUpdated',
} as const;

export type EventName = (typeof EVENT_NAMES)[keyof typeof EVENT_NAMES];
