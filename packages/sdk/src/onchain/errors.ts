import { KeymeshError } from '@keymesh/types';
import type { Abi, DecodeErrorResultReturnType } from 'viem';
import { decodeErrorResult } from 'viem';

/**
 * Translates raw contract revert data into meaningful domain errors.
 *
 * The on-chain contracts use custom errors exclusively; this layer maps the
 * decoded selector back to a stable `code` so callers (dashboard, tests,
 * integrations) can branch deterministically without parsing strings.
 */

export class ContractCallError extends KeymeshError {
  readonly contractFunction: string;
  readonly decoded: DecodedContractError | null;
  /** Original error (with viem cause chain) for debugging undecoded reverts. */
  readonly raw: unknown;

  constructor(
    message: string,
    code: string,
    contractFunction: string,
    decoded?: DecodedContractError | null,
    raw?: unknown
  ) {
    super(message, code);
    this.name = 'ContractCallError';
    this.contractFunction = contractFunction;
    this.decoded = decoded ?? null;
    this.raw = raw;
  }
}

export interface DecodedContractError {
  errorName: string;
  code: string;
  args: Record<string, unknown>;
}

/** Selector-name -> stable domain code + human message template. */
const ERROR_CODES: Record<string, string> = {
  // wallet
  NotDeviceManager: 'NOT_DEVICE_MANAGER',
  ManagerAuthorityRetired: 'MANAGER_AUTHORITY_RETIRED',
  NotRecoveryManager: 'NOT_RECOVERY_MANAGER',
  AlreadyRegistered: 'DEVICE_ALREADY_REGISTERED',
  NotRegistered: 'DEVICE_NOT_REGISTERED',
  LastDeviceRemoval: 'LAST_DEVICE_REMOVAL',
  UnauthorizedDevice: 'UNAUTHORIZED_DEVICE',
  WrongWallet: 'WRONG_WALLET',
  WrongChain: 'WRONG_CHAIN',
  InvalidNonce: 'INVALID_NONCE',
  TransactionExpired: 'TRANSACTION_EXPIRED',
  ExecutionFailed: 'EXECUTION_FAILED',
  ZeroAddress: 'ZERO_ADDRESS',
  Unauthorized: 'UNAUTHORIZED',
  // guardian registry
  GuardianNotActive: 'GUARDIAN_NOT_ACTIVE',
  GuardianAlreadyActive: 'GUARDIAN_ALREADY_ACTIVE',
  // recovery manager
  RecoveryAlreadyActive: 'RECOVERY_ALREADY_ACTIVE',
  NoActiveRecovery: 'NO_ACTIVE_RECOVERY',
  InvalidReplacementDevice: 'INVALID_REPLACEMENT_DEVICE',
  InvalidReplacedDevice: 'INVALID_REPLACED_DEVICE',
  UnsatisfiableQuorum: 'UNSATISFIABLE_QUORUM',
  NotGuardianOrDevice: 'NOT_GUARDIAN_OR_DEVICE',
  NotRegisteredGuardian: 'GUARDIAN_NOT_REGISTERED',
  DuplicateApproval: 'RECOVERY_ALREADY_APPROVED',
  InvalidStateTransition: 'INVALID_STATE_TRANSITION',
  TimelockNotElapsed: 'TIMELOCK_NOT_EXPIRED',
  AlreadyInitialized: 'RECOVERY_ALREADY_INITIALIZED',
  NotInitialized: 'RECOVERY_NOT_INITIALIZED',
  InvalidQuorum: 'INVALID_THRESHOLD',
  TimelockTooShort: 'TIMELOCK_TOO_SHORT',
  InvalidGuardianSet: 'INVALID_GUARDIAN_SET',
};

/** ABIs that may be involved in a reverted call chain (wallet wraps recovery). */
let decoderAbis: Abi[] = [];

/** Registers ABIs used to decode revert data (wired once by index.ts). */
export function registerDecoderAbis(...abis: Abi[]): void {
  decoderAbis = abis;
}

export function decodeContractError(data: `0x${string}` | undefined): DecodedContractError | null {
  if (!data || data === '0x' || data.length < 10) return null;
  for (const abi of decoderAbis) {
    try {
      const decoded: DecodeErrorResultReturnType = decodeErrorResult({ abi, data });
      if (!decoded.errorName) continue;
      const args: Record<string, unknown> = {};
      if (decoded.args) {
        const inputs = abi.find(
          (item): item is Extract<typeof item, { type: 'error' }> =>
            item.type === 'error' && item.name === decoded.errorName
        )?.inputs;
        inputs?.forEach((input, i) => {
          if (input.name) args[input.name] = decoded.args?.[i];
        });
      }
      return {
        errorName: decoded.errorName,
        code: ERROR_CODES[decoded.errorName] ?? decoded.errorName.toUpperCase(),
        args,
      };
    } catch {
      // not from this ABI; try next
    }
  }
  return null;
}

/** JSON-safe stringify of decoded error args (bigints -> strings). */
function stringifyArgs(args: Record<string, unknown>): string {
  return JSON.stringify(args, (_key, value) =>
    typeof value === 'bigint' ? value.toString() : value
  );
}

/** Builds a ContractCallError from revert data when decodable. */
export function wrapContractError(err: unknown, context: string): Error {
  const candidates: unknown[] = [err, (err as { cause?: unknown })?.cause];
  const message =
    (err as { shortMessage?: string })?.shortMessage ??
    (err as { message?: string })?.message ??
    String(err);

  for (const candidate of candidates) {
    // viem nests revert data at either `.data` or `.data.data` depending on
    // the error class; probe both shapes defensively.
    const data =
      (candidate as { data?: { data?: `0x${string}` } })?.data?.data ??
      (candidate as { data?: `0x${string}` })?.data;
    if (typeof data === 'string') {
      const decoded = decodeContractError(data as `0x${string}`);
      if (decoded) {
        const argCount = Object.keys(decoded.args).length;
        return new ContractCallError(
          `${context}: ${decoded.errorName}${argCount ? ` (${stringifyArgs(decoded.args)})` : ''}`,
          decoded.code,
          context,
          decoded
        );
      }
      // Undecodable revert data still carries the raw selector; surface it.
      return new ContractCallError(
        `${context}: unknown revert data ${data}`,
        'CONTRACT_CALL_FAILED',
        context
      );
    }
  }
  return new ContractCallError(message, 'CONTRACT_CALL_FAILED', context, null, err);
}
