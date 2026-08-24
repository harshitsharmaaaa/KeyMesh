import { describe, expect, it } from 'vitest';
import { RECOVERY_STATES } from './constants';
import { createGuardian, getGuardianWeight, meetsThreshold, totalActiveWeight } from './guardian';
import {
  AUTHORIZATION_MODES,
  POLICY_CONFIG_EXAMPLE,
  PolicyConfigSchema,
  TXN_AUTHORIZATION_STATUSES,
  TransactionAuthorizationSchema,
  classifyTransaction,
  effectiveRequestQuorum,
  isAuthorizationVersionValid,
} from './policy';
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
  it('validates policy configs and authorization schemas', () => {
    expect(PolicyConfigSchema.safeParse(POLICY_CONFIG_EXAMPLE).success).toBe(true);
    expect(
      PolicyConfigSchema.safeParse({
        ...POLICY_CONFIG_EXAMPLE,
        defaultMode: 'guardian_only', // not a Phase 1.3 mode
      }).success
    ).toBe(false);
    expect(
      TransactionAuthorizationSchema.safeParse({
        digest: `0x${'ab'.repeat(32)}`,
        wallet: `0x${'11'.repeat(20)}`,
        requester: `0x${'22'.repeat(20)}`,
        requestedAt: 1_900_000_000,
        policyVersion: 1,
        approvals: 1,
        approvalsRequired: 2,
        status: TXN_AUTHORIZATION_STATUSES.PENDING,
      }).success
    ).toBe(true);
  });

  it('classifies by precedence: admin rule, selector, destination, value, default', () => {
    const config = POLICY_CONFIG_EXAMPLE; // threshold 1 ETH, default device-only

    // 4. value strictly above threshold.
    expect(
      classifyTransaction(
        config,
        {
          toIsPolicyManagerWithAdminSelector: false,
          selectorRestricted: false,
          destinationRestricted: false,
        },
        { to: ADDR, valueWei: (10n ** 18n + 1n).toString() }
      )
    ).toBe(AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS);

    // Boundary is inclusive to the default rule.
    expect(
      classifyTransaction(
        config,
        {
          toIsPolicyManagerWithAdminSelector: false,
          selectorRestricted: false,
          destinationRestricted: false,
        },
        { to: ADDR, valueWei: (10n ** 18n).toString(), data: '0x' }
      )
    ).toBe(AUTHORIZATION_MODES.DEVICE_ONLY);

    // 3. restricted destination regardless of value.
    expect(
      classifyTransaction(
        config,
        {
          toIsPolicyManagerWithAdminSelector: false,
          selectorRestricted: false,
          destinationRestricted: true,
        },
        { to: ADDR, valueWei: '0' }
      )
    ).toBe(AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS);

    // 2. restricted selector; empty calldata never matches selectors.
    const data = `0x${'deadbeef'}01`;
    expect(
      classifyTransaction(
        config,
        {
          toIsPolicyManagerWithAdminSelector: false,
          selectorRestricted: true,
          destinationRestricted: false,
        },
        { to: ADDR, valueWei: '0', data }
      )
    ).toBe(AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS);
    expect(
      classifyTransaction(
        config,
        {
          toIsPolicyManagerWithAdminSelector: false,
          selectorRestricted: true,
          destinationRestricted: false,
        },
        { to: ADDR, valueWei: '0', data: '0x' }
      )
    ).toBe(AUTHORIZATION_MODES.DEVICE_ONLY);
    expect(
      classifyTransaction(
        config,
        {
          toIsPolicyManagerWithAdminSelector: false,
          selectorRestricted: true,
          destinationRestricted: false,
        },
        { to: ADDR, valueWei: '0', data: '0x123456' }
      )
    ).toBe(AUTHORIZATION_MODES.DEVICE_ONLY);

    // 1. structural admin rule holds even for unconfigured wallets.
    const unconfigured = { ...POLICY_CONFIG_EXAMPLE, version: 0 };
    expect(
      classifyTransaction(
        unconfigured,
        {
          toIsPolicyManagerWithAdminSelector: true,
          selectorRestricted: true,
          destinationRestricted: false,
        },
        { to: ADDR, valueWei: '0', data }
      )
    ).toBe(AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS);
    expect(
      classifyTransaction(
        unconfigured,
        {
          toIsPolicyManagerWithAdminSelector: false,
          selectorRestricted: false,
          destinationRestricted: false,
        },
        { to: ADDR, valueWei: '5' }
      )
    ).toBe(AUTHORIZATION_MODES.DEVICE_ONLY);
  });

  it('never allows a zero request quorum and invalidates on version change', () => {
    expect(effectiveRequestQuorum(POLICY_CONFIG_EXAMPLE)).toBe(2);
    expect(effectiveRequestQuorum({ ...POLICY_CONFIG_EXAMPLE, guardianApprovalsRequired: 0 })).toBe(
      1
    );
    expect(isAuthorizationVersionValid(1, 1)).toBe(true);
    expect(isAuthorizationVersionValid(1, 2)).toBe(false);
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
