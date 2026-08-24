'use client';

import { useCallback, useEffect, useState } from 'react';

/**
 * Phase 1.2 recovery demo. All state and actions flow through the server API
 * route (/api/keymesh-recovery), which drives the real on-chain recovery via
 * @keymesh/sdk. The browser never sees key material or contract ABIs.
 */

interface RecoveryState {
  ok: boolean;
  walletAddress: string;
  devices: {
    current: string;
    secondary: string;
    replacement: string;
    currentAuthorized: boolean;
    replacementAuthorized: boolean;
  };
  guardians: string[];
  quorum: number;
  timelockSeconds: number;
  status: string;
  activeRequest: {
    recoveryId: string;
    initiator: string;
    replacedDevice: string | null;
    newDevice: string;
    approvals: number;
    quorumSnapshot: number;
    executeAfter: string | null;
    status: string;
  } | null;
  chainNow: string;
  lastAction?: { action: string; detail: string };
  error?: string;
}

const ACTIONS = [
  {
    id: 'initiate',
    label: 'Initiate recovery',
    hint: 'healthy device proposes replacing the stolen one',
  },
  { id: 'approve', label: 'Approve recovery', hint: 'guardian 1 records one approval' },
  {
    id: 'cancel',
    label: 'Cancel recovery',
    hint: 'authorized devices can stop a hostile recovery',
  },
] as const;

function short(address: string): string {
  return `${address.slice(0, 8)}…${address.slice(-4)}`;
}

function statusClass(status: string): string {
  if (status === 'executed') return 'status-ok';
  if (status === 'cancelled' || status === 'none') return 'muted';
  return 'status-warn';
}

export default function RecoveryPage() {
  const [state, setState] = useState<RecoveryState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch('/api/keymesh-recovery', { cache: 'no-store' });
      const body = (await res.json()) as RecoveryState;
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
      const res = await fetch('/api/keymesh-recovery', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ action }),
      });
      const body = (await res.json()) as RecoveryState;
      if (!res.ok || !body.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      setState(body);
      setError(body.error ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const request = state?.activeRequest ?? null;
  const chainNowBig = state ? BigInt(state.chainNow) : null;
  const timelockElapsed =
    request?.executeAfter != null && chainNowBig !== null
      ? BigInt(request.executeAfter) <= chainNowBig
      : false;

  return (
    <>
      <h1>Recovery</h1>
      <p className="muted">
        Live guardian-governed recovery against a local Anvil wallet, driven end-to-end by
        @keymesh/sdk. Bootstrap installs guardians once; afterwards only guardian quorum plus the
        timelock can change devices. Keys stay in the server-side local test fixture — never in this
        page.
      </p>

      {error && (
        <section className="card">
          <p className="status-warn">{error}</p>
          <p className="muted">
            Start Anvil (<code>anvil</code>) and build contracts (
            <code>forge build --root contracts/ethereum</code>), then refresh.
          </p>
        </section>
      )}

      <section className="card">
        <h2>Wallet &amp; devices</h2>
        <p>
          Wallet contract: <code>{state ? state.walletAddress : '…'}</code>
        </p>
        <p>
          Current device <code>{state ? short(state.devices.current) : '…'}</code>{' '}
          <span className={state?.devices.currentAuthorized ? 'status-ok' : 'status-warn'}>
            {state?.devices.currentAuthorized ? 'authorized' : 'revoked'}
          </span>
        </p>
        <p>
          Replacement device <code>{state ? short(state.devices.replacement) : '…'}</code>{' '}
          <span className={state?.devices.replacementAuthorized ? 'status-ok' : 'muted'}>
            {state?.devices.replacementAuthorized ? 'authorized' : 'not authorized'}
          </span>
        </p>
        <p className="muted">
          Multi-device wallets are supported; recovery replaces exactly one device slot.
        </p>
      </section>

      <section className="card">
        <h2>Guardians</h2>
        <p>
          Guardian count: <strong>{state?.guardians.length ?? '…'}</strong> · Required quorum:{' '}
          <strong>{state?.quorum ?? '…'}</strong> · Timelock:{' '}
          <strong>{state ? `${state.timelockSeconds}s` : '…'}</strong>
        </p>
        <ul>
          {(state?.guardians ?? []).map((g) => (
            <li key={g}>
              <code>{short(g)}</code>
            </li>
          ))}
        </ul>
        <p className="muted">
          Guardians approve recoveries only. They cannot sign transactions, move funds, or cancel.
        </p>
      </section>

      <section className="card">
        <h2>Active recovery</h2>
        {!request ? (
          <p>
            Status:{' '}
            <span className={statusClass(state?.status ?? 'none')}>{state?.status ?? '…'}</span>
            {state?.status === 'executed' && ' — the last recovery replaced the device'}
            {state?.status === 'cancelled' && ' — the last recovery was cancelled'}
          </p>
        ) : (
          <>
            <p>
              Recovery #{request.recoveryId} ·{' '}
              <span className={statusClass(request.status)}>
                {request.status.replace('_', ' ')}
              </span>
            </p>
            <p>
              Approvals: <strong>{request.approvals}</strong> of {request.quorumSnapshot}
            </p>
            <p>
              Replaces <code>{short(request.replacedDevice ?? '0x0')}</code> with{' '}
              <code>{short(request.newDevice)}</code>
            </p>
            <p>
              Timelock:{' '}
              {request.executeAfter === null
                ? 'starts when quorum is reached'
                : timelockElapsed
                  ? 'elapsed — finalization now possible'
                  : `running until ${new Date(Number(request.executeAfter) * 1000).toLocaleTimeString()}`}
            </p>
          </>
        )}
      </section>

      <section className="card">
        <h2>Actions (local development)</h2>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {ACTIONS.map((a) => (
            <button
              key={a.id}
              type="button"
              disabled={busy}
              onClick={() => void act(a.id)}
              title={a.hint}
            >
              {busy ? '…' : a.label}
            </button>
          ))}
          <button
            type="button"
            disabled={busy}
            onClick={() => void act('finalize')}
            title="permissionless execution after quorum + timelock"
          >
            {busy ? '…' : 'Finalize recovery'}
          </button>
          <button type="button" disabled={busy} onClick={() => void refresh()}>
            Refresh state
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
        <p className="muted">Requires a running local node: anvil on port 8545.</p>
      </section>
    </>
  );
}
