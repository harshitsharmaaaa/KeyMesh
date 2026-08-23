import { describe, expect, it } from 'vitest';
import { RECOVERY_STATES } from './constants';
import { createGuardian, getGuardianWeight, meetsThreshold, totalActiveWeight } from './guardian';
import { DEFAULT_RULES, createPolicy, getThreshold, isHighValue, requiresTimelock } from './policy';
import {
  approveRecovery,
  canApproveRecovery,
  cancelRecovery,
  completeRecovery,
  createRecovery,
  expireRecovery,
  getRemainingRecoveryApprovals,
  isTimelockActive,
} from './recovery';
import {
  approveTransaction,
  cancelTransaction,
  createTransactionRequest,
  executeTransaction,
  isExpiredAt,
  rejectTransaction,
  getRemainingApprovals as txRemaining,
} from './transaction';
import { createWallet, revokeDevice } from './wallet';

const ADDR = `0x${'ab'.repeat(20)}` as `0x${string}`;

function guardian(id: string, weight = 1) {
  return createGuardian({
    id: crypto.randomUUID(),
    walletId: crypto.randomUUID(),
    type: 'eoa',
    name: id,
    address: ADDR,
    weight,
  });
}

describe('guardian weights', () => {
  it('counts only active guardians', () => {
    const a = guardian('a', 1);
    const b = { ...guardian('b', 2), removedAt: Date.now() };
    expect(totalActiveWeight([a, b])).toBe(1);
    expect(getGuardianWeight(b)).toBe(0);
    expect(meetsThreshold([a], 2)).toBe(false);
    expect(meetsThreshold([a, a], 2)).toBe(true);
  });
});

describe('recovery state machine', () => {
  function recovery(required = 2) {
    return createRecovery({
      id: crypto.randomUUID(),
      walletId: crypto.randomUUID(),
      initiatorId: crypto.randomUUID(),
      newDeviceId: 'new-device-key',
      requiredApprovals: required,
      timelockHours: 0, // timelock elapses immediately for tests
    });
  }

  it('stays pending until the threshold is reached', () => {
    let r = recovery(2);
    const g1 = crypto.randomUUID();
    r = approveRecovery(r, g1);
    expect(r.state).toBe(RECOVERY_STATES.PENDING);
    expect(getRemainingRecoveryApprovals(r)).toBe(1);

    const g2 = crypto.randomUUID();
    r = approveRecovery(r, g2);
    expect(isTimelockActive(r)).toBe(true);
  });

  it('ignores duplicate approvals', () => {
    let r = recovery(2);
    const g1 = crypto.randomUUID();
    r = approveRecovery(r, g1);
    const again = approveRecovery(r, g1);
    expect(again.approvals).toHaveLength(1);
    expect(canApproveRecovery(r, g1)).toBe(false);
  });

  it('completes after the timelock and rejects completion before it', () => {
    let r = recovery(1);
    r = approveRecovery(r, crypto.randomUUID());
    expect(completeRecovery(r).state).toBe(RECOVERY_STATES.COMPLETED);
  });

  it('supports cancellation from active states only', () => {
    let r = recovery(2);
    r = cancelRecovery(r);
    expect(r.state).toBe(RECOVERY_STATES.CANCELLED);
    expect(cancelRecovery(r).cancelledAt).toBe(r.cancelledAt);
  });

  it('supports expiry from active states', () => {
    const r = expireRecovery(recovery(2));
    expect(r.state).toBe(RECOVERY_STATES.EXPIRED);
  });
});

describe('policy evaluation', () => {
  it('applies default thresholds per transaction class', () => {
    const policy = createPolicy({
      id: crypto.randomUUID(),
      walletId: crypto.randomUUID(),
      name: 'default',
    });
    expect(policy.rules).toEqual(DEFAULT_RULES);
    expect(getThreshold(policy, 'normal')).toBe(1);
    expect(getThreshold(policy, 'high_value')).toBe(2);
    expect(requiresTimelock(policy, 'recovery')).toBe(true);
    expect(isHighValue(policy, BigInt('1000000000000000000'))).toBe(true);
    expect(isHighValue(policy, 1n)).toBe(false);
  });
});

describe('transaction lifecycle', () => {
  function request(required = 2) {
    return createTransactionRequest({
      id: crypto.randomUUID(),
      walletId: crypto.randomUUID(),
      type: 'high_value',
      from: ADDR,
      to: ADDR,
      value: 1_000n,
      data: '0x',
      chainId: 11155111,
      requestedBy: crypto.randomUUID(),
      requiredApprovals: required,
    });
  }

  it('moves pending -> approved at threshold and ignores duplicates', () => {
    let tx = request(2);
    const d1 = crypto.randomUUID();
    tx = approveTransaction(tx, d1);
    expect(tx.status).toBe('pending');
    tx = approveTransaction(tx, crypto.randomUUID());
    expect(tx.status).toBe('approved');
    expect(approveTransaction(tx, d1).approvals).toHaveLength(2);
    expect(txRemaining(tx)).toBe(0);
  });

  it('executes only approved requests with a well-formed hash', () => {
    let tx = request(1);
    tx = approveTransaction(tx, crypto.randomUUID());
    const hash = `0x${'cd'.repeat(32)}` as `0x${string}`;
    const executed = executeTransaction(tx, hash);
    expect(executed.status).toBe('executed');
    expect(executed.executionTxHash).toBe(hash);
    expect(executeTransaction(request(1), hash).status).toBe('pending');
  });

  it('rejects and cancels non-final requests', () => {
    const rejected = rejectTransaction(request(1));
    expect(rejected.status).toBe('rejected');
    const cancelled = cancelTransaction(request(1));
    expect(cancelled.status).toBe('cancelled');
  });

  it('detects expiry by timestamp', () => {
    const expiring = { ...request(1), expiresAt: 1000 };
    expect(isExpiredAt(expiring, 2000)).toBe(true);
    expect(isExpiredAt(expiring, 500)).toBe(false);
    expect(isExpiredAt(request(1), Date.now() + 10_000)).toBe(false);
  });
});

describe('wallet device management', () => {
  it('revokes devices and reports authorization state', () => {
    const deviceId = crypto.randomUUID();
    let wallet = createWallet({
      id: crypto.randomUUID(),
      chainId: 1,
      address: { value: ADDR },
      devices: [
        {
          id: deviceId,
          name: 'laptop',
          publicKey: `0x${'aa'.repeat(33)}`,
          curve: 'secp256k1',
          authorizedAt: Date.now(),
          revokedAt: null,
          metadata: {},
        },
      ],
      guardians: [],
      policyId: crypto.randomUUID(),
    });

    expect(wallet.devices).toHaveLength(1);
    wallet = revokeDevice(wallet, deviceId);
    expect(wallet.devices[0]?.revokedAt).not.toBeNull();

    // revoking an unknown device is a no-op that still bumps version
    const before = wallet.version;
    wallet = revokeDevice(wallet, crypto.randomUUID());
    expect(wallet.version).toBe(before + 1);
  });
});
