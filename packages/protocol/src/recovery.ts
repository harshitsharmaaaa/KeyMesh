import { z } from 'zod';

export const RecoverySchema = z.object({
  id: z.string().uuid(),
  walletId: z.string().uuid(),
  initiatorId: z.string().uuid(),
  newDeviceId: z.string(),
  state: z.enum(['pending', 'approved', 'timelock_active', 'completed', 'cancelled', 'expired']),
  approvals: z.array(z.string().uuid()),
  requiredApprovals: z.number().int().positive(),
  timelockEndsAt: z.number().int().positive().nullable(),
  initiatedAt: z.number().int().positive(),
  completedAt: z.number().int().positive().nullable(),
  cancelledAt: z.number().int().positive().nullable(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type Recovery = z.infer<typeof RecoverySchema>;

/**
 * Recovery state machine:
 *
 *   pending --(threshold guardian approvals)--> approved
 *   approved --(timelock starts)--------------> timelock_active
 *   timelock_active --(timelock elapsed)------> completed
 *   any active state --(owner/guardian cancel)-> cancelled
 *   any active state --(timeout)--------------> expired
 *
 * Transitions that do not apply are no-ops (return the input unchanged) so the
 * functions are safe to replay. On-chain enforcement lives in the
 * RecoveryManager contract; keep both in sync (see docs/protocol/recovery.md).
 */
export interface CreateRecoveryParams {
  id: string;
  walletId: string;
  initiatorId: string;
  newDeviceId: string;
  requiredApprovals: number;
  /** Recovery timelock in hours. Default matches protocol default (168h = 7 days). */
  timelockHours?: number;
  metadata?: Record<string, unknown>;
}

const DEFAULT_TIMELOCK_HOURS = 168;

export function createRecovery(params: CreateRecoveryParams): Recovery {
  const now = Date.now();
  const timelockHours = params.timelockHours ?? DEFAULT_TIMELOCK_HOURS;
  return {
    id: params.id,
    walletId: params.walletId,
    initiatorId: params.initiatorId,
    newDeviceId: params.newDeviceId,
    state: 'pending',
    approvals: [],
    requiredApprovals: params.requiredApprovals,
    // Timelock duration is recorded at creation; the clock only matters once
    // the threshold is reached (see `approve`).
    timelockEndsAt: now + timelockHours * 60 * 60 * 1000,
    initiatedAt: now,
    completedAt: null,
    cancelledAt: null,
    metadata: params.metadata ?? {},
  };
}

function isTerminal(state: Recovery['state']): boolean {
  return state === 'completed' || state === 'cancelled' || state === 'expired';
}

export function approveRecovery(recovery: Recovery, guardianId: string): Recovery {
  if (recovery.state !== 'pending') return recovery;
  if (recovery.approvals.includes(guardianId)) return recovery;

  const approvals = [...recovery.approvals, guardianId];
  const reachedThreshold = approvals.length >= recovery.requiredApprovals;

  return {
    ...recovery,
    approvals,
    // Reaching the threshold immediately starts the timelock window; the
    // intermediate `approved` state remains reserved for future flows that
    // require an explicit activation step.
    state: reachedThreshold ? 'timelock_active' : 'pending',
    // Start the timelock clock at the moment the threshold is reached.
    timelockEndsAt: reachedThreshold
      ? Date.now() + remainingTimelock(recovery)
      : recovery.timelockEndsAt,
  };
}

/** Kept for explicitness: moving from `approved` into the timelock phase. */
export function startTimelock(recovery: Recovery): Recovery {
  if (recovery.state !== 'approved') return recovery;
  return { ...recovery, state: 'timelock_active' };
}

export function completeRecovery(recovery: Recovery): Recovery {
  if (recovery.state !== 'timelock_active') return recovery;
  if (!isTimelockElapsed(recovery)) return recovery;
  return { ...recovery, state: 'completed', completedAt: Date.now() };
}

export function cancelRecovery(recovery: Recovery): Recovery {
  if (isTerminal(recovery.state)) return recovery;
  return { ...recovery, state: 'cancelled', cancelledAt: Date.now() };
}

export function expireRecovery(recovery: Recovery): Recovery {
  if (isTerminal(recovery.state)) return recovery;
  return { ...recovery, state: 'expired' };
}

export function canApproveRecovery(recovery: Recovery, guardianId: string): boolean {
  return recovery.state === 'pending' && !recovery.approvals.includes(guardianId);
}

export function getRemainingRecoveryApprovals(recovery: Recovery): number {
  return Math.max(0, recovery.requiredApprovals - recovery.approvals.length);
}

function remainingTimelock(recovery: Recovery): number {
  if (!recovery.timelockEndsAt) return 0;
  // The stored value encodes the configured duration relative to creation.
  return Math.max(0, recovery.timelockEndsAt - recovery.initiatedAt);
}

export function isTimelockActive(recovery: Recovery): boolean {
  return recovery.state === 'timelock_active';
}

export function isTimelockElapsed(recovery: Recovery): boolean {
  if (!recovery.timelockEndsAt) return false;
  return Date.now() >= recovery.timelockEndsAt;
}
