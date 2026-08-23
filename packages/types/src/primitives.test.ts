import { describe, expect, it } from 'vitest';
import { isAddress, toAddress } from './address';
import { bytesToHex, concatBytes, equalsBytes, hexToBytes, randomBytes } from './bytes';
import { CryptographyError, KeymeshError, ValidationError, isKeymeshError } from './errors';
import { err, isErr, isOk, mapErr, ok, tryCatch, unwrap } from './result';

describe('bytes', () => {
  it('round-trips hex encoding', () => {
    const bytes = new Uint8Array([0x00, 0xff, 0x10]);
    const hex = bytesToHex(bytes);
    expect(hex).toBe('0x00ff10');
    expect(equalsBytes(hexToBytes(hex), bytes)).toBe(true);
  });

  it('rejects odd-length hex', () => {
    expect(() => hexToBytes('0xabc')).toThrow(/odd length/i);
  });

  it('concats and generates random bytes of the requested length', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3]);
    expect(equalsBytes(concatBytes(a, b), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(randomBytes(32)).toHaveLength(32);
  });
});

describe('address', () => {
  it('accepts a valid 20-byte hex address', () => {
    const addr = '0x1234567890abcdef1234567890abcdef12345678';
    expect(isAddress(addr)).toBe(true);
    expect(toAddress(addr).value).toBe(addr);
  });

  it('rejects malformed addresses', () => {
    expect(isAddress('0x1234')).toBe(false);
    expect(isAddress('not-an-address')).toBe(false);
    expect(() => toAddress('0x1234')).toThrow(/invalid ethereum address/i);
  });
});

describe('errors', () => {
  it('preserves code and cause through the hierarchy', () => {
    const cause = new Error('root cause');
    const error = new CryptographyError('signing failed', 'sign', cause);
    expect(error).toBeInstanceOf(KeymeshError);
    expect(error.code).toBe('CRYPTOGRAPHY_ERROR');
    expect(error.cause).toBe(cause);
    expect(isKeymeshError(error)).toBe(true);
    expect(isKeymeshError(new Error('plain'))).toBe(false);
  });

  it('exposes validation context', () => {
    const error = new ValidationError('bad field', 'address');
    expect(error.code).toBe('VALIDATION_ERROR');
    expect(error.field).toBe('address');
  });
});

describe('result', () => {
  it('wraps successes and failures', () => {
    expect(isOk(ok(42))).toBe(true);
    expect(unwrap(ok(42))).toBe(42);
    expect(isErr(err(new Error('boom')))).toBe(true);
  });

  it('captures thrown errors with tryCatch', () => {
    const result = tryCatch(() => {
      throw new ValidationError('nope');
    });
    expect(isErr(result)).toBe(true);
    if (!result.ok && result.error instanceof ValidationError) {
      expect(result.error.field).toBeUndefined();
    }
  });

  it('maps the error channel only', () => {
    const failure = mapErr(err(new Error('a')), (e: Error) => new Error(`${e.message}!`));
    expect(isErr(failure)).toBe(true);
  });
});
