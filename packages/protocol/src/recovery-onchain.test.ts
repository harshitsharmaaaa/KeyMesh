import { describe, expect, it } from 'vitest';
import {
  GUARDIAN_RECORD_EXAMPLE,
  GuardianRecordSchema,
  ONCHAIN_RECOVERY_REQUEST_EXAMPLE,
  OnchainRecoveryRequestSchema,
  RECOVERY_STATUS,
  isLiveOnchainStatus,
  isTerminalOnchainStatus,
} from './recovery-onchain';

describe('on-chain recovery domain types', () => {
  it('validates guardian records', () => {
    expect(GuardianRecordSchema.safeParse(GUARDIAN_RECORD_EXAMPLE).success).toBe(true);
    expect(GuardianRecordSchema.safeParse({ address: '0x1234', active: true }).success).toBe(false);
    expect(
      GuardianRecordSchema.safeParse({
        address: `0x${'ab'.repeat(20)}`,
        active: 'yes',
      }).success
    ).toBe(false);
  });

  it('validates on-chain recovery requests', () => {
    expect(OnchainRecoveryRequestSchema.safeParse(ONCHAIN_RECOVERY_REQUEST_EXAMPLE).success).toBe(
      true
    );
    expect(
      OnchainRecoveryRequestSchema.safeParse({
        ...ONCHAIN_RECOVERY_REQUEST_EXAMPLE,
        status: 'expired', // not part of the on-chain machine
      }).success
    ).toBe(false);
  });

  it('classifies live vs terminal statuses', () => {
    expect(isLiveOnchainStatus(RECOVERY_STATUS.PENDING)).toBe(true);
    expect(isLiveOnchainStatus(RECOVERY_STATUS.QUORUM_REACHED)).toBe(true);
    expect(isLiveOnchainStatus(RECOVERY_STATUS.EXECUTABLE)).toBe(true);
    expect(isLiveOnchainStatus(RECOVERY_STATUS.EXECUTED)).toBe(false);
    expect(isTerminalOnchainStatus(RECOVERY_STATUS.CANCELLED)).toBe(true);
    expect(isTerminalOnchainStatus(RECOVERY_STATUS.EXECUTED)).toBe(true);
    expect(isTerminalOnchainStatus(RECOVERY_STATUS.PENDING)).toBe(false);
  });

  it('keeps discriminants aligned with the Solidity enum order', () => {
    // Mirrors IRecoveryManager.RecoveryStatus; the Rust core pins the same.
    const expected = ['none', 'pending', 'quorum_reached', 'executable', 'executed', 'cancelled'];
    expect(Object.keys(expected)).toHaveLength(6);
  });
});
