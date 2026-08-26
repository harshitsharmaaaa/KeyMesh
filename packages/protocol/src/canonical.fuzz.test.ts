import { describe, expect, it } from 'vitest';
import {
  type KeymeshTransaction,
  MAX_CHAIN_ID,
  MAX_DATA_BYTES,
  MAX_EXPIRY,
  MAX_NONCE,
  MAX_VALUE,
  encodeCanonicalTransaction,
  hashKeymeshTransaction,
  validateKeymeshTransaction,
} from './canonical';

const BASE: KeymeshTransaction = {
  wallet: `0x${'11'.repeat(20)}`,
  chainId: 1n,
  nonce: 0n,
  to: `0x${'22'.repeat(20)}`,
  value: 0n,
  data: '0x',
  expiry: 2_000_000_000n,
};

const ADDRESS_MUTATIONS = [`0x${'aa'.repeat(20)}`, `0x${'ff'.repeat(20)}`] as const;
const DATA_MUTATIONS = ['0x00', '0xdeadbeef', `0x${'42'.repeat(32)}`] as const;

function mutate<T extends KeymeshTransaction>(patch: Partial<T>): KeymeshTransaction {
  return { ...BASE, ...patch };
}

describe('KEYMESH_TX_V1 boundary fuzzing', () => {
  it('same object always encodes and hashes identically', () => {
    const a = encodeCanonicalTransaction(BASE);
    const b = encodeCanonicalTransaction({ ...BASE });
    expect(a).toEqual(b);
    expect(hashKeymeshTransaction(BASE)).toBe(hashKeymeshTransaction({ ...BASE }));
  });

  it('changing any signed field changes the digest', () => {
    const baseDigest = hashKeymeshTransaction(BASE);

    for (const wallet of ADDRESS_MUTATIONS) {
      expect(hashKeymeshTransaction(mutate({ wallet }))).not.toBe(baseDigest);
    }
    for (const to of ADDRESS_MUTATIONS) {
      expect(hashKeymeshTransaction(mutate({ to }))).not.toBe(baseDigest);
    }
    for (const chainId of [1n, 2n, MAX_CHAIN_ID]) {
      const tx = mutate({ chainId });
      if (chainId !== BASE.chainId) expect(hashKeymeshTransaction(tx)).not.toBe(baseDigest);
    }
    for (const nonce of [0n, 1n, MAX_NONCE]) {
      const tx = mutate({ nonce });
      if (nonce !== BASE.nonce) expect(hashKeymeshTransaction(tx)).not.toBe(baseDigest);
    }
    for (const value of [0n, 1n, MAX_VALUE]) {
      const tx = mutate({ value });
      if (value !== BASE.value) expect(hashKeymeshTransaction(tx)).not.toBe(baseDigest);
    }
    for (const expiry of [0n, 1n, MAX_EXPIRY]) {
      const tx = mutate({ expiry });
      if (expiry !== BASE.expiry) expect(hashKeymeshTransaction(tx)).not.toBe(baseDigest);
    }
    for (const data of DATA_MUTATIONS) {
      expect(hashKeymeshTransaction(mutate({ data }))).not.toBe(baseDigest);
    }
  });

  it('accepts empty, single-byte, four-byte, and larger calldata', () => {
    const samples = ['0x', '0x42', '0xdeadbeef', `0x${'ab'.repeat(256)}`];
    for (const data of samples) {
      const tx = mutate({ data: data as `0x${string}` });
      expect(() => encodeCanonicalTransaction(tx)).not.toThrow();
      expect(hashKeymeshTransaction(tx)).toMatch(/^0x[0-9a-f]{64}$/);
    }
  });

  it('rejects data longer than the configured maximum', () => {
    const tooLong = mutate({ data: `0x${'ab'.repeat(MAX_DATA_BYTES + 1)}` as `0x${string}` });
    expect(() => validateKeymeshTransaction(tooLong)).toThrow();
  });

  it('covers integer boundary values', () => {
    const fields: Array<keyof Pick<KeymeshTransaction, 'chainId' | 'nonce' | 'value' | 'expiry'>> =
      ['chainId', 'nonce', 'value', 'expiry'];

    for (const field of fields) {
      const minTx = { ...BASE };
      const maxTx = { ...BASE };
      if (field === 'chainId') {
        minTx.chainId = 1n;
        maxTx.chainId = MAX_CHAIN_ID;
      } else if (field === 'nonce') {
        minTx.nonce = 0n;
        maxTx.nonce = MAX_NONCE;
      } else if (field === 'value') {
        minTx.value = 0n;
        maxTx.value = MAX_VALUE;
      } else {
        minTx.expiry = 0n;
        maxTx.expiry = MAX_EXPIRY;
      }
      expect(hashKeymeshTransaction(minTx)).toMatch(/^0x[0-9a-f]{64}$/);
      expect(hashKeymeshTransaction(maxTx)).toMatch(/^0x[0-9a-f]{64}$/);
    }
  });

  it('treats expiry boundary as inclusive', () => {
    expect(() =>
      validateKeymeshTransaction({ ...BASE, expiry: BASE.expiry }, { nowSeconds: BASE.expiry })
    ).not.toThrow();
    expect(() =>
      validateKeymeshTransaction({ ...BASE, expiry: BASE.expiry - 1n }, { nowSeconds: BASE.expiry })
    ).toThrow();
  });
});
