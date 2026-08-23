import { z } from 'zod';
import type { TransactionType } from './constants';

export const TransactionRequestSchema = z.object({
  id: z.string().uuid(),
  walletId: z.string().uuid(),
  type: z.enum(['normal', 'high_value', 'recovery', 'guardian_management', 'policy_update']),
  from: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  to: z
    .string()
    .regex(/^0x[0-9a-fA-F]{40}$/)
    .optional(),
  value: z.string().regex(/^\d+$/),
  data: z.string().regex(/^0x[0-9a-fA-F]*$/),
  chainId: z.number().int().positive(),
  requestedBy: z.string().uuid(),
  requestedAt: z.number().int().positive(),
  expiresAt: z.number().int().positive().optional(),
  approvals: z.array(z.string().uuid()),
  requiredApprovals: z.number().int().positive(),
  executedAt: z.number().int().positive().nullable(),
  executionTxHash: z
    .string()
    .regex(/^0x[0-9a-fA-F]{64}$/)
    .nullable(),
  status: z.enum(['pending', 'approved', 'rejected', 'executed', 'expired', 'cancelled']),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type TransactionRequest = z.infer<typeof TransactionRequestSchema>;

/**
 * PROTOTYPE BOUNDARY: a TransactionRequest is an authorization record only.
 * It carries no signature. Signing and broadcasting are explicit future
 * integration points (Signer + ChainAdapter in the SDK, KeymeshWallet
 * contract on-chain).
 */
export interface CreateTransactionRequestParams {
  id: string;
  walletId: string;
  type: TransactionType;
  from: `0x${string}`;
  to?: `0x${string}`;
  value: bigint;
  data: `0x${string}`;
  chainId: number;
  requestedBy: string;
  requiredApprovals: number;
  expiresAt?: number;
  metadata?: Record<string, unknown>;
}

export function createTransactionRequest(
  params: CreateTransactionRequestParams
): TransactionRequest {
  return {
    id: params.id,
    walletId: params.walletId,
    type: params.type,
    from: params.from,
    to: params.to,
    value: params.value.toString(),
    data: params.data,
    chainId: params.chainId,
    requestedBy: params.requestedBy,
    requestedAt: Date.now(),
    expiresAt: params.expiresAt,
    approvals: [],
    requiredApprovals: params.requiredApprovals,
    executedAt: null,
    executionTxHash: null,
    status: 'pending',
    metadata: params.metadata ?? {},
  };
}

function isFinal(status: TransactionRequest['status']): boolean {
  return status === 'executed' || status === 'rejected' || status === 'expired';
}

export function approveTransaction(
  request: TransactionRequest,
  approverId: string
): TransactionRequest {
  if (request.status !== 'pending') return request;
  if (request.approvals.includes(approverId)) return request;

  const approvals = [...request.approvals, approverId];
  return {
    ...request,
    approvals,
    status: approvals.length >= request.requiredApprovals ? 'approved' : 'pending',
  };
}

export function rejectTransaction(request: TransactionRequest): TransactionRequest {
  if (isFinal(request.status)) return request;
  return { ...request, status: 'rejected' };
}

export function cancelTransaction(request: TransactionRequest): TransactionRequest {
  if (isFinal(request.status)) return request;
  return { ...request, status: 'cancelled' };
}

export function executeTransaction(
  request: TransactionRequest,
  txHash: `0x${string}`
): TransactionRequest {
  if (request.status !== 'approved') return request;
  return { ...request, status: 'executed', executedAt: Date.now(), executionTxHash: txHash };
}

export function expireTransaction(request: TransactionRequest): TransactionRequest {
  if (isFinal(request.status)) return request;
  return { ...request, status: 'expired' };
}

export function isExpiredAt(request: TransactionRequest, now: number): boolean {
  if (request.status === 'expired') return true;
  return request.expiresAt !== undefined && now > request.expiresAt && !isFinal(request.status);
}

export function canApprove(request: TransactionRequest, approverId: string): boolean {
  return request.status === 'pending' && !request.approvals.includes(approverId);
}

export function getRemainingApprovals(request: TransactionRequest): number {
  return Math.max(0, request.requiredApprovals - request.approvals.length);
}
