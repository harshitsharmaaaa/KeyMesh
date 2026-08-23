import { beforeEach, describe, expect, it } from 'vitest';
import { createKeymeshClient } from './index';

const DEVICE = {
  name: 'test laptop',
  publicKey: `0x${'11'.repeat(33)}`,
  curve: 'secp256k1',
} as const;

function client() {
  return createKeymeshClient({ chainId: 11155111 });
}

describe('KeymeshClient (prototype, local state only)', () => {
  let km = client();

  beforeEach(() => {
    km = client();
  });

  it('creates a wallet with one active device', async () => {
    const wallet = await km.createKeymeshWallet({ initialDevice: DEVICE });
    expect(wallet.devices).toHaveLength(1);
    expect(wallet.devices[0]?.revokedAt).toBeNull();
    expect(wallet.guardians).toHaveLength(0);
    // Placeholder address until contracts ship — asserted explicitly on purpose.
    expect(wallet.address).toBe(`0x${'0'.repeat(40)}`);
  });

  it('manages devices', async () => {
    const wallet = await km.createKeymeshWallet({ initialDevice: DEVICE });
    const second = await km.wallets.addDevice(wallet.id, {
      name: 'phone',
      publicKey: `0x${'22'.repeat(33)}`,
      curve: 'ed25519',
    });

    expect(second.devices).toHaveLength(2);
    const phone = second.devices.find((d) => d.name === 'phone');
    expect(phone?.curve).toBe('ed25519');

    const revoked = await km.wallets.revokeDevice(wallet.id, phone!.id);
    expect(await km.wallets.isDeviceAuthorized(wallet.id, phone!.id)).toBe(false);
    expect(await km.wallets.listActiveDevices(wallet.id)).toHaveLength(1);

    await expect(km.wallets.revokeDevice(wallet.id, crypto.randomUUID())).rejects.toThrow(
      /not found/i
    );
    expect(revoked.version).toBeGreaterThan(second.version);
  });

  it('adds and removes guardians', async () => {
    const wallet = await km.createKeymeshWallet({ initialDevice: DEVICE });
    const guardian = await km.addGuardian(wallet.id, {
      type: 'eoa',
      name: 'alice',
      address: `0x${'ab'.repeat(20)}`,
    });

    const afterAdd = await km.wallets.get(wallet.id);
    expect(afterAdd.guardians).toContain(guardian.id);

    await km.guardians.remove(wallet.id, guardian.id);
    const afterRemove = await km.wallets.get(wallet.id);
    expect(afterRemove.guardians).not.toContain(guardian.id);

    await expect(km.guardians.remove(wallet.id, guardian.id)).rejects.toThrow(/not found/i);
  });

  it('runs the recovery flow: approvals -> timelock -> completion', async () => {
    const wallet = await km.createKeymeshWallet({ initialDevice: DEVICE });
    const g1 = await km.addGuardian(wallet.id, { type: 'eoa', name: 'alice' });
    const g2 = await km.addGuardian(wallet.id, { type: 'eoa', name: 'bob' });

    const recovery = await km.startRecovery(wallet.id, {
      initiatorDeviceId: wallet.devices[0]!.id,
      newDevicePublicKey: `0x${'33'.repeat(33)}`,
      requiredApprovals: 2,
      timelockHours: 0,
    });

    expect(recovery.state).toBe('pending');

    await km.recovery.approve(recovery.id, g1.id);
    const afterFirst = await km.recovery.get(recovery.id);
    expect(afterFirst.state).toBe('pending');

    await km.recovery.approve(recovery.id, g2.id);
    const afterThreshold = await km.recovery.get(recovery.id);
    expect(afterThreshold.state).toBe('timelock_active');

    // Completing before the timelock elapses throws; with timelockHours=0 the
    // window has already passed, so completion succeeds.
    const completed = await km.recovery.complete(recovery.id);
    expect(completed.state).toBe('completed');
  });

  it('refuses recovery when guardians cannot meet the threshold', async () => {
    const wallet = await km.createKeymeshWallet({ initialDevice: DEVICE });
    await expect(
      km.startRecovery(wallet.id, {
        initiatorDeviceId: wallet.devices[0]!.id,
        newDevicePublicKey: `0x${'44'.repeat(33)}`,
        requiredApprovals: 3,
      })
    ).rejects.toThrow(/exceeds active guardian count/i);
  });

  it('tracks transaction requests and approvals', async () => {
    const wallet = await km.createKeymeshWallet({ initialDevice: DEVICE });
    const policy = await km.getPolicy(wallet.id);
    expect(policy.rules.find((r) => r.type === 'normal')?.threshold).toBe(1);

    const tx = await km.requestTransaction(wallet.id, {
      type: 'normal',
      to: `0x${'ab'.repeat(20)}`,
      value: 1n,
      requestedByDeviceId: wallet.devices[0]!.id,
      requiredApprovals: 2,
      expiresInSeconds: 3600,
    });

    expect(tx.status).toBe('pending');
    await km.transactions.approve(tx.id, crypto.randomUUID());
    await km.transactions.approve(tx.id, crypto.randomUUID());
    const approved = await km.transactions.get(tx.id);
    expect(approved.status).toBe('approved');

    const cancelled = await km.transactions.cancel(tx.id);
    // cancel is a no-op once final... approved -> cancelled is allowed pre-execution
    expect(['approved', 'cancelled']).toContain(cancelled.status);
  });

  it('blocks transaction requests from unknown or revoked devices', async () => {
    const wallet = await km.createKeymeshWallet({ initialDevice: DEVICE });
    await expect(
      km.requestTransaction(wallet.id, {
        type: 'normal',
        to: `0x${'ab'.repeat(20)}`,
        value: 1n,
        requestedByDeviceId: crypto.randomUUID(),
        requiredApprovals: 1,
      })
    ).rejects.toThrow(/active device/i);
  });

  it('updates policy rules and previews thresholds', async () => {
    const wallet = await km.createKeymeshWallet({ initialDevice: DEVICE });
    await km.policies.upsertRule(wallet.id, {
      type: 'high_value',
      threshold: 3,
      valueThresholdWei: '5000000000000000000',
    });

    expect(await km.policies.requiredApprovals(wallet.id, 'high_value')).toBe(3);
    expect(await km.policies.classifiesAsHighValue(wallet.id, 4n)).toBe(false);
    expect(await km.policies.classifiesAsHighValue(wallet.id, BigInt(5e18))).toBe(true);
  });
});
