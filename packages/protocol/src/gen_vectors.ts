import { bytesToHex } from '@keymesh/types';
import {
  type KeymeshTransaction,
  encodeCanonicalTransaction,
  hashKeymeshTransaction,
} from './canonical';

const vectors = [
  // Zero transaction
  {
    name: 'zero-transaction',
    tx: {
      wallet: '0x0000000000000000000000000000000000000001',
      chainId: 1n,
      nonce: 0n,
      to: '0x0000000000000000000000000000000000000002',
      value: 0n,
      data: '0x',
      expiry: 0n,
    } as KeymeshTransaction,
  },
  // One-byte data
  {
    name: 'one-byte-data',
    tx: {
      wallet: '0x1111111111111111111111111111111111111111',
      chainId: 1n,
      nonce: 1n,
      to: '0x2222222222222222222222222222222222222222',
      value: 1n,
      data: '0x42',
      expiry: 2000000001n,
    } as KeymeshTransaction,
  },
  // Four-byte calldata
  {
    name: 'four-byte-calldata',
    tx: {
      wallet: '0xabababababababababababababababababababab',
      chainId: 1n,
      nonce: 0n,
      to: '0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
      value: 0n,
      data: '0xdeadbeef',
      expiry: 2000000000n,
    } as KeymeshTransaction,
  },
  // Large calldata (256 bytes)
  {
    name: 'large-calldata-256b',
    tx: {
      wallet: '0x3333333333333333333333333333333333333333',
      chainId: 137n,
      nonce: 5n,
      to: '0x4444444444444444444444444444444444444444',
      value: 5000000000000000000n,
      data: `0x${'aa'.repeat(256)}`,
      expiry: 2100000000n,
    } as KeymeshTransaction,
  },
];

console.log('Cross-language test vectors:');
for (const v of vectors) {
  const canonicalHex = bytesToHex(encodeCanonicalTransaction(v.tx));
  const digest = hashKeymeshTransaction(v.tx);
  console.log(`  ${v.name}:`);
  console.log(`    canonicalHex: "${canonicalHex}"`);
  console.log(`    digest: "${digest}"`);
}

// Verify injectivity
const baseVector = vectors[0];
if (baseVector === undefined) {
  throw new Error('expected at least one canonical vector');
}
const baseTx = baseVector.tx;
const baseDigest = hashKeymeshTransaction(baseTx);
console.log('\nInjectivity check:');
const mutations: Array<[string, KeymeshTransaction]> = [
  ['wallet', { ...baseTx, wallet: `0x${'ff'.repeat(20)}` }],
  ['to', { ...baseTx, to: `0x${'ff'.repeat(20)}` }],
  ['value', { ...baseTx, value: baseTx.value + 1n }],
  ['expiry', { ...baseTx, expiry: baseTx.expiry + 1n }],
  ['nonce', { ...baseTx, nonce: baseTx.nonce + 1n }],
  ['chainId', { ...baseTx, chainId: baseTx.chainId + 1n }],
  ['data', { ...baseTx, data: '0x42' }],
];
for (const [field, mutated] of mutations) {
  const digest = hashKeymeshTransaction(mutated);
  console.log(`  ${field}: changed=${baseDigest !== digest}`);
}
