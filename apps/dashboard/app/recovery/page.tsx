import { formatCountdown, mockRecovery } from '@/lib/mock-data';

export default function RecoveryPage() {
  const recovery = mockRecovery();
  return (
    <>
      <h1>Recovery</h1>
      <p className="muted">
        Recovery requires a guardian quorum followed by a mandatory timelock before the new device
        is authorized. State shown here is mock; enforcement will live in the RecoveryManager
        contract.
      </p>
      <section className="card">
        <h2>Active recovery request</h2>
        <p>
          State: <span className="status-warn">{recovery.state.replace('_', ' ')}</span>
        </p>
        <p>
          Approvals: {recovery.approvals.length} of {recovery.requiredApprovals}
        </p>
        <p>
          Timelock: {formatCountdown(recovery.timelockEndsAt ?? 0)}{' '}
          <span className="muted">(any active guardian may cancel until it elapses)</span>
        </p>
        <p className="muted">Replacement device: 0xc3…c3 (mock)</p>
      </section>
      <section className="card">
        <h2>Recovery rules</h2>
        <ul>
          <li>Threshold guardian approval is required to start a recovery.</li>
          <li>A timelock window must elapse before completion.</li>
          <li>Cancelling a recovery resets all approvals.</li>
          <li>Guardians are never able to move funds directly.</li>
        </ul>
      </section>
    </>
  );
}
