import { hashKeymeshTransaction } from '@keymesh/protocol';
import type { KeymeshTransaction } from '@keymesh/protocol';
import { recoverAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { describe, expect, it } from 'vitest';
import { guardianRegistryAbi, keymeshWalletAbi, recoveryManagerAbi } from './onchain/abi';
import { signDigestWithDeviceKey } from './onchain/client';
import { type ContractCallError, registerDecoderAbis, wrapContractError } from './onchain/errors';

/**
 * Anvil well-known PUBLIC fixture key (test networks only).
 */
const DEVICE_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as const;
const DEVICE = privateKeyToAccount(DEVICE_KEY);

const TX: KeymeshTransaction = {
  wallet: `0x${'11'.repeat(20)}` as `0x${string}`,
  chainId: 31337n,
  nonce: 0n,
  to: `0x${'22'.repeat(20)}` as `0x${string}`,
  value: 0n,
  data: '0x',
  expiry: 2_000_000_000n,
};

describe('device digest signing helper', () => {
  it('produces signatures that recover to the device over the raw digest', async () => {
    const digest = hashKeymeshTransaction(TX);
    const signature = signDigestWithDeviceKey(DEVICE_KEY, digest);
    expect(signature.length).toBe(132); // '0x' + r||s||v (65 bytes hex)

    // Raw digest recovery (EIP-191 prefix must NOT be applied anywhere).
    expect((await recoverAddress({ hash: digest, signature })).toLowerCase()).toBe(
      DEVICE.address.toLowerCase()
    );
  });

  it('is deterministic for the same key and digest', () => {
    const digest = hashKeymeshTransaction(TX);
    expect(signDigestWithDeviceKey(DEVICE_KEY, digest)).toBe(
      signDigestWithDeviceKey(DEVICE_KEY, digest)
    );
  });
});

describe('contract error translation', () => {
  registerDecoderAbis(keymeshWalletAbi, recoveryManagerAbi, guardianRegistryAbi);

  function selectorData(abi: unknown, name: string, args: unknown[]): `0x${string}` {
    // Encode a revert payload the way Solidity would: selector + ABI args.
    const { encodeErrorResult } = require('viem') as typeof import('viem');
    return encodeErrorResult({ abi, errorName: name, args } as never) as `0x${string}`;
  }

  it('maps TimelockNotElapsed to TIMELOCK_NOT_EXPIRED with decoded args', () => {
    const data = selectorData(recoveryManagerAbi, 'TimelockNotElapsed', [100n, 50n]);
    const err = wrapContractError({ data }, 'finalizeRecovery') as ContractCallError;

    expect(err.name).toBe('ContractCallError');
    expect(err.code).toBe('TIMELOCK_NOT_EXPIRED');
    expect(err.decoded?.errorName).toBe('TimelockNotElapsed');
    expect(err.decoded?.args.executeAfter).toBe(100n);
    expect(err.message).toContain('finalizeRecovery');
  });

  it('maps DuplicateApproval to RECOVERY_ALREADY_APPROVED', () => {
    const data = selectorData(recoveryManagerAbi, 'DuplicateApproval', [DEVICE.address]);
    const err = wrapContractError({ cause: { data } }, 'approveRecovery') as ContractCallError;
    expect(err.code).toBe('RECOVERY_ALREADY_APPROVED');
    expect(err.decoded?.args.guardian).toBe(DEVICE.address);
  });

  it('wraps wallet ExecutionFailed carrying an inner RecoveryManager error', () => {
    const inner = selectorData(recoveryManagerAbi, 'InvalidStateTransition', [5, 'cancel']);
    const wrapped = selectorData(keymeshWalletAbi, 'ExecutionFailed', [inner]);
    const err = wrapContractError({ data: wrapped }, 'cancelRecovery') as ContractCallError;

    // The outer wallet wrapper decodes first; both layers are custom errors.
    expect(err.decoded?.errorName).toBe('ExecutionFailed');
    expect(err.code).toBe('EXECUTION_FAILED');
  });

  it('falls back to CONTRACT_CALL_FAILED for undecodable reverts', () => {
    const err = wrapContractError(new Error('boom'), 'something') as ContractCallError;
    expect(err.code).toBe('CONTRACT_CALL_FAILED');
    expect(err.message).toContain('boom');
  });
});
