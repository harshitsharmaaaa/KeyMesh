import { ValidationError } from '@keymesh/types';
import { describe, expect, it } from 'vitest';
import {
  KEYMESH_TX_DOMAIN_TAG,
  type KeymeshTransaction,
  canonicalTransactionHex,
  encodeCanonicalTransaction,
  hashKeymeshTransaction,
  validateKeymeshTransaction,
} from './canonical';
import { KEYMESH_TRANSACTION_VECTORS } from './vectors';

const VALID: KeymeshTransaction = {
  wallet: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
  chainId: 31337n,
  nonce: 0n,
  to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  value: 1n,
  data: '0x',
  expiry: 2000000000n,
};

describe('KEYMESH_TX_V1 cross-language vectors', () => {
  it('exposes the frozen domain tag', () => {
    expect(KEYMESH_TX_DOMAIN_TAG).toBe(
      '0x908acdd86e8726216702d8abc211b34ca12c9f1537c7180c55096e1c3be1f405'
    );
  });

  for (const vector of KEYMESH_TRANSACTION_VECTORS) {
    it(`matches vector '${vector.name}' byte-for-byte`, () => {
      expect(canonicalTransactionHex(vector.tx)).toBe(vector.canonicalHex);
      expect(hashKeymeshTransaction(vector.tx)).toBe(vector.digest);
    });

    it(`encodes vector '${vector.name}' deterministically`, () => {
      const a = encodeCanonicalTransaction(vector.tx);
      const b = encodeCanonicalTransaction({ ...vector.tx });
      expect(a).toEqual(b);
    });
  }
});

describe('canonical encoding structure', () => {
  it('produces fixed header + length-prefixed data + trailing expiry', () => {
    // 32 domain + 20 wallet + 32 chainId + 32 nonce + 20 to + 32 value
    // + 4 len + data + 32 expiry
    const emptyData = encodeCanonicalTransaction(VALID);
    expect(emptyData.length).toBe(204);

    const withData = encodeCanonicalTransaction({ ...VALID, data: '0xdeadbeef' });
    expect(withData.length).toBe(208);
    // uint32 big-endian length prefix sits right before the data bytes
    expect(Array.from(withData.slice(168, 172))).toEqual([0, 0, 0, 4]);
    expect(Array.from(withData.slice(172, 176))).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it('changes digest when any signed field changes', () => {
    const base = hashKeymeshTransaction(VALID);
    const mutations: Array<Partial<KeymeshTransaction>> = [
      { chainId: 31338n },
      { nonce: 1n },
      { to: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC' },
      { value: 2n },
      { data: '0x01' },
      { expiry: 2000000001n },
      { wallet: '0x14dC79964da2C08b23698B3D3cc7Ca32193d9955' },
    ];
    for (const mutation of mutations) {
      expect(hashKeymeshTransaction({ ...VALID, ...mutation })).not.toBe(base);
    }
  });

  it('is case-insensitive over hex inputs (raw bytes are what matter)', () => {
    const lower = hashKeymeshTransaction({
      ...VALID,
      wallet: VALID.wallet.toLowerCase() as `0x${string}`,
    });
    expect(lower).toBe(hashKeymeshTransaction(VALID));
  });
});

describe('validation', () => {
  it('accepts a valid transaction', () => {
    expect(() => validateKeymeshTransaction(VALID)).not.toThrow();
  });

  it('rejects malformed addresses and data', () => {
    expect(() =>
      validateKeymeshTransaction({ ...VALID, wallet: '0x1234' as `0x${string}` })
    ).toThrow(ValidationError);
    expect(() => validateKeymeshTransaction({ ...VALID, to: 'nope' as `0x${string}` })).toThrow(
      ValidationError
    );
    expect(() => validateKeymeshTransaction({ ...VALID, data: '0xabc' as `0x${string}` })).toThrow(
      ValidationError
    ); // odd nibble count
  });

  it('rejects out-of-range integers per cross-language bounds', () => {
    expect(() => validateKeymeshTransaction({ ...VALID, chainId: 0n })).toThrow(ValidationError);
    expect(() => validateKeymeshTransaction({ ...VALID, nonce: -1n })).toThrow(ValidationError);
    expect(() => validateKeymeshTransaction({ ...VALID, value: 2n ** 128n })).toThrow(
      ValidationError
    );
    expect(() => validateKeymeshTransaction({ ...VALID, nonce: 2n ** 64n })).toThrow(
      ValidationError
    );
  });

  describe('expiry boundary semantics (now <= expiry is valid)', () => {
    const now = 1000n;

    it('accepts expiry == now', () => {
      expect(() =>
        validateKeymeshTransaction({ ...VALID, expiry: now }, { nowSeconds: now })
      ).not.toThrow();
    });

    it('accepts expiry > now', () => {
      expect(() =>
        validateKeymeshTransaction({ ...VALID, expiry: now + 1n }, { nowSeconds: now })
      ).not.toThrow();
    });

    it('rejects expiry < now', () => {
      expect(() =>
        validateKeymeshTransaction({ ...VALID, expiry: now - 1n }, { nowSeconds: now })
      ).toThrow(/expired/);
    });
  });
});
