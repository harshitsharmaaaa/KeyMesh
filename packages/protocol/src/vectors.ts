import type { KeymeshTransaction } from './canonical';

/**
 * Cross-language test vectors for the KEYMESH_TX_V1 canonical format.
 *
 * GENERATED ONCE by packages/protocol (see docs/protocol/canonical-transaction.md)
 * and treated as immutable fixtures: Rust (keymesh-core/src/transaction) and
 * Solidity (contracts/ethereum test/TransactionDigest.t.sol) must reproduce
 * `canonical` and `digest` byte-for-byte. If you ever need to change the
 * format, bump the domain string and regenerate every consumer.
 */
export interface KeymeshTransactionVector {
  name: string;
  tx: KeymeshTransaction;
  canonicalHex: `0x${string}`;
  digest: `0x${string}`;
}

export const KEYMESH_TRANSACTION_VECTORS: readonly KeymeshTransactionVector[] = [
  {
    name: 'eth-transfer',
    tx: {
      wallet: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      chainId: 31337n,
      nonce: 0n,
      to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      value: 1000000000000000000n,
      data: '0x',
      expiry: 2000000000n,
    },
    canonicalHex:
      '0x908acdd86e8726216702d8abc211b34ca12c9f1537c7180c55096e1c3be1f405f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000000000000007a69000000000000000000000000000000000000000000000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c80000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000000077359400',
    digest: '0xef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a',
  },
  {
    name: 'zero-value-calldata',
    tx: {
      wallet: '0x14dC79964da2C08b23698B3D3cc7Ca32193d9955',
      chainId: 11155111n,
      nonce: 7n,
      to: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
      value: 0n,
      data: '0xdeadbeefcafebabe0123456789abcdef',
      expiry: 2000000001n,
    },
    canonicalHex:
      '0x908acdd86e8726216702d8abc211b34ca12c9f1537c7180c55096e1c3be1f40514dc79964da2c08b23698b3d3cc7ca32193d99550000000000000000000000000000000000000000000000000000000000aa36a700000000000000000000000000000000000000000000000000000000000000073c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000000000000010deadbeefcafebabe0123456789abcdef0000000000000000000000000000000000000000000000000000000077359401',
    digest: '0x58f52cacdeacc22a70f0e855c44e50b34348984261d9c6954c48d6f895870b58',
  },
  {
    name: 'mainnet-shaped',
    tx: {
      wallet: '0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f',
      chainId: 1n,
      nonce: 42n,
      to: '0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc',
      value: 123456789n,
      data: `0x${'aabbccdd'.repeat(16)}`,
      expiry: 4102444800n,
    },
    canonicalHex:
      '0x908acdd86e8726216702d8abc211b34ca12c9f1537c7180c55096e1c3be1f40523618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002a9965507d1a55bcc2695c58ba16fb37d819b0a4dc00000000000000000000000000000000000000000000000000000000075bcd1500000040aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd00000000000000000000000000000000000000000000000000000000f4865700',
    digest: '0x645dc7006dfac3665699314be7d1a4af4f2a502d9b6099b71af0db0d8f1c0a58',
  },
] as const;
