import { z } from 'zod';

/**
 * Shared recovery domain types for Phase 1.2 guardian recovery.
 *
 * These types describe ON-CHAIN state as exposed by the RecoveryManager,
 * GuardianRegistry, and KeymeshWallet contracts. They are deliberately
 * separate from the prototype local state machine in `./recovery`:
 *
 *  - `RecoveryStatus` here mirrors `IRecoveryManager.RecoveryStatus`
 *    one-for-one (same names, same discriminant order).
 *  - Guardians are plain addresses with an active flag — no weights, no
 *    off-chain identity metadata (that arrives in a later phase).
 */

/** Mirrors IRecoveryManager.RecoveryStatus discriminants 0..5. */
export const RECOVERY_STATUS = {
  NONE: 'none',
  PENDING: 'pending',
  QUORUM_REACHED: 'quorum_reached',
  EXECUTABLE: 'executable',
  EXECUTED: 'executed',
  CANCELLED: 'cancelled',
} as const;

export type OnchainRecoveryStatus = (typeof RECOVERY_STATUS)[keyof typeof RECOVERY_STATUS];

export const ONCHAIN_RECOVERY_STATUS_DISCRIMINANTS = {
  none: 0,
  pending: 1,
  quorum_reached: 2,
  executable: 3,
  executed: 4,
  cancelled: 5,
} as const satisfies Record<OnchainRecoveryStatus, number>;

const hexAddress = z.string().regex(/^0x[0-9a-fA-F]{40}$/);

export const GuardianRecordSchema = z.object({
  /** Guardian account address. */
  address: hexAddress,
  /** Active guardians can approve recoveries; removed ones cannot. */
  active: z.boolean(),
});

export type GuardianRecord = z.infer<typeof GuardianRecordSchema>;

/**
 * A recovery request as stored by the RecoveryManager contract.
 * Numeric fields arrive from viem as bigint; ids/counters are bigint too.
 */
export const OnchainRecoveryRequestSchema = z.object({
  recoveryId: z.bigint(),
  wallet: hexAddress,
  initiator: hexAddress,
  /** Device revoked at finalization; null models total device loss. */
  replacedDevice: hexAddress.nullable(),
  newDevice: hexAddress,
  initiatedAt: z.bigint(),
  /** Set when quorum was reached; null while pending. */
  executeAfter: z.bigint().nullable(),
  approvals: z.number(),
  quorumSnapshot: z.number(),
  status: z.enum([
    RECOVERY_STATUS.NONE,
    RECOVERY_STATUS.PENDING,
    RECOVERY_STATUS.QUORUM_REACHED,
    RECOVERY_STATUS.EXECUTABLE,
    RECOVERY_STATUS.EXECUTED,
    RECOVERY_STATUS.CANCELLED,
  ]),
});

export type OnchainRecoveryRequest = z.infer<typeof OnchainRecoveryRequestSchema>;

/** True when the status permits further lifecycle movement. */
export function isLiveOnchainStatus(status: OnchainRecoveryStatus): boolean {
  return (
    status === RECOVERY_STATUS.PENDING ||
    status === RECOVERY_STATUS.QUORUM_REACHED ||
    status === RECOVERY_STATUS.EXECUTABLE
  );
}

/** Terminal states keep their record on-chain but reject every action. */
export function isTerminalOnchainStatus(status: OnchainRecoveryStatus): boolean {
  return status === RECOVERY_STATUS.EXECUTED || status === RECOVERY_STATUS.CANCELLED;
}

/** Example fixtures for tests and docs; not real addresses in use anywhere. */
export const GUARDIAN_RECORD_EXAMPLE: GuardianRecord = {
  address: `0x${'ab'.repeat(20)}` as GuardianRecord['address'],
  active: true,
};

export const ONCHAIN_RECOVERY_REQUEST_EXAMPLE: OnchainRecoveryRequest = {
  recoveryId: 1n,
  wallet: `0x${'11'.repeat(20)}` as OnchainRecoveryRequest['wallet'],
  initiator: `0x${'ab'.repeat(20)}` as OnchainRecoveryRequest['initiator'],
  replacedDevice: `0x${'cd'.repeat(20)}` as OnchainRecoveryRequest['replacedDevice'],
  newDevice: `0x${'ef'.repeat(20)}` as OnchainRecoveryRequest['newDevice'],
  initiatedAt: 1_900_000_000n,
  executeAfter: null,
  approvals: 1,
  quorumSnapshot: 2,
  status: RECOVERY_STATUS.PENDING,
};
