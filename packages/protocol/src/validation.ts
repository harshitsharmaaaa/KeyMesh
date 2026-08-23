import type { ZodError } from 'zod';
import { GuardianSchema } from './guardian';
import { PolicySchema } from './policy';
import { RecoverySchema } from './recovery';
import { TransactionRequestSchema } from './transaction';
import { DeviceSchema, WalletSchema } from './wallet';

/**
 * Single source of truth: validation delegates to the canonical domain
 * schemas so serialization formats cannot drift between packages.
 */
export {
  DeviceSchema,
  WalletSchema,
  GuardianSchema,
  RecoverySchema,
  PolicySchema,
  TransactionRequestSchema,
};

export type ValidationResult<T> = { success: true; data: T } | { success: false; error: ZodError };

function parse<T>(
  schema: {
    safeParse(input: unknown): { success: true; data: T } | { success: false; error: ZodError };
  },
  input: unknown
): ValidationResult<T> {
  return schema.safeParse(input);
}

export function validateWallet(input: unknown) {
  return parse<import('./wallet').Wallet>(WalletSchema, input);
}

export function validateGuardian(input: unknown) {
  return parse<import('./guardian').Guardian>(GuardianSchema, input);
}

export function validateRecovery(input: unknown) {
  return parse<import('./recovery').Recovery>(RecoverySchema, input);
}

export function validatePolicy(input: unknown) {
  return parse<import('./policy').Policy>(PolicySchema, input);
}

export function validateTransactionRequest(input: unknown) {
  return parse<import('./transaction').TransactionRequest>(TransactionRequestSchema, input);
}
