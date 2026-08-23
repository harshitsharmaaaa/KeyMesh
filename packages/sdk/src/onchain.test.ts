import {
  KEYMESH_TRANSACTION_VECTORS,
  type KeymeshTransaction,
  hashKeymeshTransaction,
} from '@keymesh/protocol';
import { keccak_256 } from '@noble/hashes/sha3';
import { parseEventLogs, recoverAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { describe, expect, it } from 'vitest';
import {
  buildKeymeshTransaction,
  createKeymeshSession,
  keymeshWalletAbi,
  normalizeVTo2728,
} from './index';

/**
 * Anvil well-known development keys. These are PUBLIC deterministic test
 * fixtures (documented by Foundry/Anvil) — never used against real chains.
 */
const DEVICE_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const STRANGER_KEY = '0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e';

const WALLET = `0x${'11'.repeat(20)}` as const;
const TO = `0x${'22'.repeat(20)}` as const;

const TX: KeymeshTransaction = {
  wallet: WALLET,
  chainId: 31337n,
  nonce: 0n,
  to: TO,
  value: 1_000_000_000_000_000_000n,
  data: '0x',
  expiry: 2000000000n,
};

function sessionFor(key: `0x${string}`, walletAddress: `0x${string}` = WALLET) {
  return createKeymeshSession({
    walletAddress,
    chain: { id: Number(TX.chainId) } as never,
    rpcUrl: 'http://127.0.0.1',
    devicePrivateKey: key,
  });
}

describe('transaction building (pure builder)', () => {
  it('fills all canonical fields deterministically', () => {
    const tx = buildKeymeshTransaction({
      wallet: WALLET,
      chainId: 31337n,
      nonce: 41n,
      to: TO,
      value: 5n,
      nowSeconds: 1999999000n,
    });
    expect(tx.expiry).toBe(2000002600n); // now + default 3600
    expect(tx.data).toBe('0x');
    expect(tx.nonce).toBe(41n);
  });

  it('rejects an already-expired window', () => {
    expect(() =>
      buildKeymeshTransaction({
        wallet: WALLET,
        chainId: 31337n,
        nonce: 0n,
        to: TO,
        value: 1n,
        expiresInSeconds: -10,
      })
    ).toThrow(/expired/i);
  });

  it('propagates protocol validation errors', () => {
    expect(() =>
      buildKeymeshTransaction({
        wallet: '0x1234' as `0x${string}`,
        chainId: 31337n,
        nonce: 0n,
        to: TO,
        value: 1n,
      })
    ).toThrow(/wallet/i);

    expect(() =>
      buildKeymeshTransaction({
        wallet: WALLET,
        chainId: 0n,
        nonce: 0n,
        to: TO,
        value: 1n,
      })
    ).toThrow(/chainId/i);
  });
});

describe('signing', () => {
  it('reproduces the shared-vector digest', () => {
    const vector = KEYMESH_TRANSACTION_VECTORS[0]!;
    expect(hashKeymeshTransaction(vector.tx)).toBe(vector.digest);
  });

  it('signs with the device key; signature recovers to the device address', async () => {
    const signed = sessionFor(DEVICE_KEY).signTransaction(TX);

    expect(signed.digest).toBe(hashKeymeshTransaction(TX));
    expect(signed.signature).toMatch(/^0x[0-9a-f]{130}$/); // exactly 65 bytes
    // v byte normalized for OpenZeppelin ECDSA.recover
    expect(Number.parseInt(signed.signature.slice(-2), 16)).toBeGreaterThanOrEqual(27);

    expect(await recoverAddress({ hash: signed.digest, signature: signed.signature })).toBe(
      privateKeyToAccount(DEVICE_KEY).address
    );
  });

  it('is deterministic (RFC-6979 nonces)', () => {
    const a = sessionFor(DEVICE_KEY).signTransaction(TX);
    const b = sessionFor(DEVICE_KEY).signTransaction(TX);
    expect(a.signature).toBe(b.signature);
  });

  it('binds the signature to every signed field', () => {
    const base = sessionFor(DEVICE_KEY).signTransaction(TX);
    const mutations: Array<Partial<KeymeshTransaction>> = [
      { chainId: 31338n },
      { nonce: 1n },
      { value: 2n },
      { data: '0x01' },
      { expiry: TX.expiry + 1n },
      { wallet: `0x${'33'.repeat(20)}` as const },
    ];
    for (const mutation of mutations) {
      const other = sessionFor(DEVICE_KEY).signTransaction({ ...TX, ...mutation });
      const fieldName = Object.keys(mutation)[0]!;
      expect(other.digest !== base.digest).toBe(true); // field must be bound
      void fieldName;
    }
  });

  it('different devices produce different signatures over one digest', () => {
    const a = sessionFor(DEVICE_KEY).signTransaction(TX);
    const b = sessionFor(STRANGER_KEY).signTransaction(TX);
    expect(a.digest).toBe(b.digest);
    expect(a.signature).not.toBe(b.signature);
  });

  it('refuses invalid transactions before any signing happens', () => {
    expect(() => sessionFor(DEVICE_KEY).signTransaction({ ...TX, nonce: -1n })).toThrow(/nonce/i);
  });
});

describe('v-byte normalization', () => {
  const base = `0x${'ab'.repeat(64)}` as `0x${string}`;
  const variant = (suffix: string) => `${base}${suffix}` as `0x${string}`;

  it('maps yPar {0,1} -> {27,28}', () => {
    expect(normalizeVTo2728(variant('00')).slice(-2)).toBe('1b');
    expect(normalizeVTo2728(variant('01')).slice(-2)).toBe('1c');
  });

  it('passes {27,28} through unchanged', () => {
    expect(normalizeVTo2728(variant('1b'))).toBe(variant('1b'));
    expect(normalizeVTo2728(variant('1c'))).toBe(variant('1c'));
  });

  it('rejects garbage v bytes and wrong lengths', () => {
    expect(() => normalizeVTo2728(variant('02'))).toThrow(/v byte/);
    expect(() => normalizeVTo2728('0x00')).toThrow(/65-byte/);
  });
});

describe('contract response decoding', () => {
  it('decodes TransactionExecuted logs from receipts', () => {
    const eventTopic = `0x${Buffer.from(
      keccak_256(
        new TextEncoder().encode('TransactionExecuted(uint256,address,address,uint256,bytes)')
      )
    ).toString('hex')}` as `0x${string}`;
    const padUint = (v: bigint) => `0x${v.toString(16).padStart(64, '0')}` as const;
    const padAddr = (a: string) =>
      `0x${'0'.repeat(24)}${a.toLowerCase().replace(/^0x/, '')}` as const;

    const topics = [
      eventTopic,
      padUint(0n),
      padAddr(privateKeyToAccount(DEVICE_KEY).address),
      padAddr(TO),
    ];
    // ABI head order for (uint256 value, bytes data):
    // [value(123), offset(0x40)] then tail [len(4), padded "deadbeef"]
    const data =
      `0x${padUint(123n).slice(2)}${padUint(0x40n).slice(2)}${padUint(4n).slice(2)}deadbeef${'0'.repeat(56)}` as `0x${string}`;

    const log = { topics, data } as unknown as Parameters<typeof parseEventLogs>[0]['logs'][number];

    const parsed = parseEventLogs({
      abi: keymeshWalletAbi,
      logs: [log],
    });
    const decoded = parsed[0];
    if (!decoded) throw new Error('expected TransactionExecuted log to decode');

    expect(decoded.eventName).toBe('TransactionExecuted');
    const args = decoded.args as Record<string, unknown>;
    expect(args.nonce).toBe(0n);
    expect(String(args.to).toLowerCase()).toBe(TO.toLowerCase());
    expect(args.value).toBe(123n);
    expect(args.data).toBe('0xdeadbeef');
  });
});
