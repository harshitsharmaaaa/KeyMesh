'use client';

import { useCallback, useEffect, useState } from 'react';

/**
 * Phase 1.3 policy console. All state and actions flow through the server
 * API route (/api/keymesh-policies), which drives the real on-chain
 * PolicyManager via @keymesh/sdk. The browser never sees key material.
 */

interface PolicyState {
  ok: boolean;
  walletAddress: string;
  currentDevice: string;
  policyVersion: number;
  defaultMode: string;
  valueThresholdWei: string;
  guardianApprovalsRequired: number;
  restrictedDestinations: Array<{ address: string; restricted: boolean }>;
  authorization: {
    digest: string;
    status: string;
    approvals: number;
    approvalsRequired: number;
    policyVersion: number;
  } | null;
  lastAction?: { action: string; detail: string };
  error?: string;
}

const ACTIONS = [
  { id: 'configure', label: 'Configure policy (v1)' },
  { id: 'set-threshold', label: 'Lower threshold to 0.1 ETH' },
  { id: 'add-restricted', label: 'Restrict device B' },
  { id: 'remove-restricted', label: 'Unrestrict device B' },
  { id: 'request-high-value', label: 'Request high-value transfer' },
  { id: 'approve-high-value', label: 'Guardian approves' },
  { id: 'execute-high-value', label: 'Execute transfer' },
] as const;

function short(address: string): string {
  return `${address.slice(0, 8)}…${address.slice(-4)}`;
}

function formatEth(wei: string): string {
  try {
    return `${Number(BigInt(wei)) / 1e18} ETH`;
  } catch {
    return wei;
  }
}

export default function PoliciesPage() {
  const [state, setState] = useState<PolicyState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch('/api/keymesh-policies', { cache: 'no-store' });
      const body = (await res.json()) as PolicyState;
      if (!res.ok || !body.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      setState(body);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function act(action: string) {
    setBusy(true);
    try {
      const res = await fetch('/api/keymesh-policies', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ action }),
      });
      const body = (await res.json()) as PolicyState;
      if (!res.ok || !body.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      setState(body);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h1>Policies</h1>
      <p className="muted">
        Live transaction-authorization policies against a local Anvil wallet, driven by
        @keymesh/sdk. Policy changes are executed THROUGH the wallet with a device signature AND a
        guardian-approved authorization for that exact change — a single device can never weaken
        policy on its own.
      </p>

      {error && (
        <section className="card">
          <p className="status-warn">{error}</p>
        </section>
      )}

      <section className="card">
        <h2>Current policy</h2>
        <p>
          Wallet contract: <code>{state ? state.walletAddress : '…'}</code>
        </p>
        <p>
          Policy version: <strong>{state?.policyVersion ?? '…'}</strong> · Default mode:{' '}
          <strong>{state?.defaultMode.replace('_', ' ') ?? '…'}</strong>
        </p>
        <p>
          Value threshold: <strong>{state ? formatEth(state.valueThresholdWei) : '…'}</strong>{' '}
          (strictly above requires guardians) · Guardian approvals required:{' '}
          <strong>{state?.guardianApprovalsRequired ?? '…'}</strong>
        </p>
        <ul>
          {(state?.restrictedDestinations ?? []).map((r) => (
            <li key={r.address}>
              <code>{short(r.address)}</code>{' '}
              <span className={r.restricted ? 'status-warn' : 'muted'}>
                {r.restricted ? 'restricted' : 'unrestricted'}
              </span>
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <h2>Pending transaction authorization</h2>
        {!state?.authorization ? (
          <p className="muted">
            None. Use “Request high-value transfer” to open one bound to the exact canonical digest.
          </p>
        ) : (
          <>
            <p>
              Digest <code>{short(state.authorization.digest)}</code> ·{' '}
              <span
                className={
                  state.authorization.status === 'authorized' ||
                  state.authorization.status === 'executed'
                    ? 'status-ok'
                    : 'status-warn'
                }
              >
                {state.authorization.status}
              </span>
            </p>
            <p>
              Approvals: <strong>{state.authorization.approvals}</strong> of{' '}
              {state.authorization.approvalsRequired} · created under policy v
              {state.authorization.policyVersion}
            </p>
          </>
        )}
      </section>

      <section className="card">
        <h2>Actions (local development)</h2>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {ACTIONS.map((a) => (
            <button key={a.id} type="button" disabled={busy} onClick={() => void act(a.id)}>
              {busy ? '…' : a.label}
            </button>
          ))}
          <button type="button" disabled={busy} onClick={() => void refresh()}>
            Refresh
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void act('reset')}
            title="deploy a fresh wallet"
          >
            Reset demo
          </button>
        </div>
        {state?.lastAction && (
          <p className="muted">
            Last action “{state.lastAction.action}”: {state.lastAction.detail}
          </p>
        )}
        <p className="muted">Requires Anvil on port 8545.</p>
      </section>
    </>
  );
}
