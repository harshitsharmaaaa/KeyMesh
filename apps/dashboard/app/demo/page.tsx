'use client';

import { useState } from 'react';

interface DemoStep {
  name: string;
  detail: string;
}

type DemoResponse = { ok: true; wallet: string; steps: DemoStep[] } | { ok: false; error: string };

export default function TxDemoPage() {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<DemoResponse | null>(null);

  async function runDemo(): Promise<void> {
    setRunning(true);
    setResult(null);
    try {
      const res = await fetch('/api/keymesh-demo', { method: 'POST' });
      setResult((await res.json()) as DemoResponse);
    } catch (err) {
      setResult({ ok: false, error: err instanceof Error ? err.message : String(err) });
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <h1>Device-signed transaction demo</h1>
      <section className="card">
        <h2>Phase 1.1 — local Anvil flow</h2>
        <p>
          Runs the real KEYMESH authorization path through <code>@keymesh/sdk</code>: deploy wallet
          → create transaction → canonical encoding + keccak digest → device ECDSA signature →
          on-chain recovery, device/nonce/expiry/domain validation → execution.
        </p>
        <p className="status-warn">
          LOCAL DEVELOPMENT ONLY. Requires a running local node (<code>anvil</code>) and a built
          contract artifact (<code>forge build</code>). The server uses PUBLIC Anvil fixture keys;
          no key material is sent to or stored in the browser.
        </p>
        <p>
          <button type="button" onClick={runDemo} disabled={running}>
            {running ? 'Running…' : 'Run demo transaction'}
          </button>
        </p>
        {result && !result.ok && <p className="status-danger">Failed: {result.error}</p>}
        {result?.ok && (
          <>
            <p className="status-ok">Transaction executed successfully.</p>
            <ul>
              {result.steps.map((step) => (
                <li key={step.name}>
                  <strong>{step.name}</strong> — <span className="muted">{step.detail}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>
    </>
  );
}
