import type { Device, GuardianType, Recovery, TransactionRequest } from '@keymesh/sdk';

/**
 * MOCK DATA — PROTOTYPE ONLY.
 *
 * The dashboard renders state produced through the @keymesh/sdk client so the
 * UI never touches protocol internals. The seed below stands in for on-chain
 * state that will arrive with the KeyMesh contracts in Phase 1.
 */

export interface SecurityEvent {
  id: string;
  kind:
    | 'WALLET_CREATED'
    | 'GUARDIAN_ADDED'
    | 'RECOVERY_INITIATED'
    | 'TRANSACTION_REQUESTED'
    | 'DEVICE_REVOKED';
  message: string;
  at: number;
}

const HOUR = 60 * 60 * 1000;
const now = Date.now();

export const MOCK_WALLET = {
  id: '8f2c1b3a-4d5e-4f60-9a1b-2c3d4e5f6a7b',
  address: '0x0000000000000000000000000000000000000000' as const,
  chainId: 11155111,
  label: 'Primary wallet (Sepolia)',
  createdAt: now - 72 * HOUR,
};

export const MOCK_DEVICES: Array<Device & { label: string }> = [
  {
    id: 'a1b2c3d4-0000-4000-8000-000000000001',
    name: 'MacBook Pro — daily driver',
    publicKey: `0x${'a1'.repeat(33)}`,
    curve: 'secp256k1',
    authorizedAt: now - 72 * HOUR,
    revokedAt: null,
    metadata: {},
    label: 'active',
  },
  {
    id: 'a1b2c3d4-0000-4000-8000-000000000002',
    name: 'Old phone (lost)',
    publicKey: `0x${'b2'.repeat(33)}`,
    curve: 'secp256k1',
    authorizedAt: now - 70 * HOUR,
    revokedAt: now - 24 * HOUR,
    metadata: {},
    label: 'revoked',
  },
];

export const MOCK_GUARDIANS: Array<{
  id: string;
  name: string;
  type: GuardianType;
  weight: number;
  status: 'active' | 'invited';
}> = [
  { id: 'g-1', name: 'Alice (hardware key)', type: 'hardware', weight: 2, status: 'active' },
  { id: 'g-2', name: 'Bob (EOA)', type: 'eoa', weight: 1, status: 'active' },
  {
    id: 'g-3',
    name: 'Carla (social recovery contact)',
    type: 'social',
    weight: 1,
    status: 'active',
  },
  {
    id: 'g-4',
    name: 'Dave (invited, pending acceptance)',
    type: 'eoa',
    weight: 1,
    status: 'invited',
  },
];

export function mockRecovery(): Recovery {
  return {
    id: 'r-9e8d7c6b-0000-4000-8000-000000000009',
    walletId: MOCK_WALLET.id,
    initiatorId: MOCK_DEVICES[1]!.id,
    newDeviceId: `0x${'c3'.repeat(33)}`,
    state: 'timelock_active',
    approvals: ['g-1', 'g-2', 'g-3'],
    requiredApprovals: 3,
    timelockEndsAt: now + 96 * HOUR,
    initiatedAt: now - 48 * HOUR,
    completedAt: null,
    cancelledAt: null,
    metadata: { note: 'Lost device recovery (mock)' },
  };
}

export function mockTransactions(): TransactionRequest[] {
  return [
    {
      id: 't-10000000-0000-4000-8000-000000000001',
      walletId: MOCK_WALLET.id,
      type: 'normal',
      from: MOCK_WALLET.address,
      to: '0x1234567890abcdef1234567890abcdef12345678',
      value: '50000000000000000',
      data: '0x',
      chainId: 11155111,
      requestedBy: MOCK_DEVICES[0]!.id,
      requestedAt: now - 2 * HOUR,
      approvals: [MOCK_DEVICES[0]!.id],
      requiredApprovals: 1,
      executedAt: now - HOUR,
      executionTxHash: null,
      status: 'executed',
      metadata: {},
    },
    {
      id: 't-20000000-0000-4000-8000-000000000002',
      walletId: MOCK_WALLET.id,
      type: 'high_value',
      from: MOCK_WALLET.address,
      to: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      value: '2500000000000000000',
      data: '0x',
      chainId: 11155111,
      requestedBy: MOCK_DEVICES[0]!.id,
      requestedAt: now - 30 * 60 * 1000,
      approvals: [MOCK_DEVICES[0]!.id],
      requiredApprovals: 2,
      executedAt: null,
      executionTxHash: null,
      status: 'pending',
      metadata: {},
    },
  ];
}

export const MOCK_SECURITY_EVENTS: SecurityEvent[] = [
  {
    id: 'e-1',
    kind: 'WALLET_CREATED',
    message: 'Wallet created with initial device "MacBook Pro"',
    at: now - 72 * HOUR,
  },
  {
    id: 'e-2',
    kind: 'GUARDIAN_ADDED',
    message: 'Guardian "Alice (hardware key)" added with weight 2',
    at: now - 71 * HOUR,
  },
  {
    id: 'e-3',
    kind: 'DEVICE_REVOKED',
    message: 'Device "Old phone (lost)" revoked after loss report',
    at: now - 24 * HOUR,
  },
  {
    id: 'e-4',
    kind: 'RECOVERY_INITIATED',
    message: 'Recovery initiated for replacement device; awaiting guardian quorum',
    at: now - 48 * HOUR,
  },
  {
    id: 'e-5',
    kind: 'RECOVERY_INITIATED',
    message: 'Recovery threshold reached (3/3); timelock active until T-96h',
    at: now - 40 * HOUR,
  },
  {
    id: 'e-6',
    kind: 'TRANSACTION_REQUESTED',
    message: 'High-value transfer of 2.5 ETH pending guardian approval (1/2)',
    at: now - 30 * 60 * 1000,
  },
];

/** Deterministic display formatting shared by all pages. */
export function formatTimeAgo(at: number): string {
  const diff = Date.now() - at;
  const minutes = Math.round(diff / 60000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function formatCountdown(until: number): string {
  const remaining = until - Date.now();
  if (remaining <= 0) return 'elapsed';
  const hours = Math.floor(remaining / HOUR);
  const minutes = Math.floor((remaining % HOUR) / 60000);
  return `${hours}h ${minutes}m remaining`;
}
