import { bytesToHex, hexToBytes } from '@keymesh/types';
import { ValidationError } from '@keymesh/types';
import { keccak_256 } from '@noble/hashes/sha3';

/**
 * Canonical signed-transaction format for KeyMesh on-chain authorization.
 *
 * This is THE definition of the wire format. Rust (crates/keymesh-core
 * src/transaction) and Solidity (contracts/ethereum/src/KeymeshTx.sol)
 * implement byte-for-byte equivalents; shared test vectors in ./vectors.ts
 * pin all three implementations together. Change this file only together
 * with those two and a new domain version string.
 *
 * ## Encoding: KEYMESH_TX_V1
 *
 *   domain_tag = keccak256("KEYMESH_TX_V1")            (32 bytes)
 *
 *   payload =
 *     domain_tag                                       (32)
 *   | wallet         raw 20-byte address               (20)
 *   | chain_id       uint256 big-endian                (32)
 *   | nonce          uint256 big-endian                (32)
 *   | to             raw 20-byte address               (20)
 *   | value          uint256 big-endian                (32)
 *   | data_len       uint32 big-endian == len(data)    ( 4)
 *   | data           raw bytes                         (len(data))
 *   | expiry         uint256 big-endian unix seconds   (32)
 *
 *   digest = keccak256(payload)
 *
 * Every field is fixed-width except `data`, which is length-prefixed, so
 * the encoding is unambiguous under concatenation. `wallet`, `chain_id`
 * and `nonce` provide replay separation across wallets, chains and time.
 */

export const KEYMESH_TX_DOMAIN = 'KEYMESH_TX_V1';

const DOMAIN_TAG = keccak_256(new TextEncoder().encode(KEYMESH_TX_DOMAIN));

/** Domain tag as hex, exposed for cross-language debugging/tests. */
export const KEYMESH_TX_DOMAIN_TAG = bytesToHex(DOMAIN_TAG);

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const BYTES_RE = /^0x(?:[0-9a-fA-F]{2})*$/;

/**
 * Cross-language numeric bounds. Solidity uses uint256 everywhere; TypeScript
 * has native bigint; Rust avoids a bignum dependency by validating into u64 /
 * u128 ranges. These bounds keep the three implementations exactly equivalent
 * for every representable transaction.
 */
export const MAX_CHAIN_ID = 2n ** 64n - 1n;
export const MAX_NONCE = 2n ** 64n - 1n;
export const MAX_VALUE = 2n ** 128n - 1n;
export const MAX_EXPIRY = 2n ** 64n - 1n;
export const MAX_DATA_BYTES = 128 * 1024;

export interface KeymeshTransaction {
  /** Deployed KeymeshWallet that is the only valid executor of this payload. */
  wallet: `0x${string}`;
  chainId: bigint;
  /** Wallet-scoped, strictly increasing counter enforced by the contract. */
  nonce: bigint;
  to: `0x${string}`;
  value: bigint;
  data: `0x${string}`;
  /** Unix seconds; the transaction is valid while now <= expiry (inclusive). */
  expiry: bigint;
}

export interface ValidateTransactionOptions {
  /** When set, requires expiry >= nowSeconds (client-side pre-flight check). */
  nowSeconds?: bigint;
}

function assertUintBE(name: string, v: bigint, max: bigint): void {
  if (typeof v !== 'bigint' || v < 0n || v > max) {
    throw new ValidationError(`${name} out of range [0, ${max}]`, name);
  }
}

export function validateKeymeshTransaction(
  tx: KeymeshTransaction,
  options: ValidateTransactionOptions = {}
): void {
  if (!ADDRESS_RE.test(tx.wallet)) throw new ValidationError('invalid wallet address', 'wallet');
  if (!ADDRESS_RE.test(tx.to)) throw new ValidationError('invalid to address', 'to');
  assertUintBE('chainId', tx.chainId, MAX_CHAIN_ID);
  assertUintBE('nonce', tx.nonce, MAX_NONCE);
  assertUintBE('value', tx.value, MAX_VALUE);
  assertUintBE('expiry', tx.expiry, MAX_EXPIRY);
  if (tx.chainId === 0n) throw new ValidationError('chainId must be positive', 'chainId');
  if (!BYTES_RE.test(tx.data)) throw new ValidationError('data must be hex bytes', 'data');
  if (tx.data.length / 2 - 1 > MAX_DATA_BYTES) {
    throw new ValidationError(`data exceeds ${MAX_DATA_BYTES} bytes`, 'data');
  }
  if (options.nowSeconds !== undefined && tx.expiry < options.nowSeconds) {
    throw new ValidationError('transaction expired', 'expiry');
  }
}

function writeUint256BE(target: Uint8Array, offset: number, value: bigint): void {
  for (let i = 0; i < 32; i++) {
    target[offset + 31 - i] = Number((value >> BigInt(8 * i)) & 0xffn);
  }
}

function writeUint32BE(target: Uint8Array, offset: number, value: number): void {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

/** Deterministic KEYMESH_TX_V1 canonical encoding. Validates first. */
export function encodeCanonicalTransaction(tx: KeymeshTransaction): Uint8Array {
  validateKeymeshTransaction(tx);

  const data = hexToBytes(tx.data);
  const out = new Uint8Array(32 + 20 + 32 + 32 + 20 + 32 + 4 + data.length + 32);
  let o = 0;

  out.set(DOMAIN_TAG, o);
  o += 32;
  out.set(hexToBytes(tx.wallet), o);
  o += 20;
  writeUint256BE(out, o, tx.chainId);
  o += 32;
  writeUint256BE(out, o, tx.nonce);
  o += 32;
  out.set(hexToBytes(tx.to), o);
  o += 20;
  writeUint256BE(out, o, tx.value);
  o += 32;
  writeUint32BE(out, o, data.length);
  o += 4;
  out.set(data, o);
  o += data.length;
  writeUint256BE(out, o, tx.expiry);

  return out;
}

/** Canonical encoding as 0x-hex (matches Rust/Solidity byte-for-byte). */
export function canonicalTransactionHex(tx: KeymeshTransaction): `0x${string}` {
  return bytesToHex(encodeCanonicalTransaction(tx));
}

/** digest = keccak256(canonical_bytes); the message signed by devices. */
export function hashKeymeshTransaction(tx: KeymeshTransaction): `0x${string}` {
  return bytesToHex(keccak_256(encodeCanonicalTransaction(tx)));
}
