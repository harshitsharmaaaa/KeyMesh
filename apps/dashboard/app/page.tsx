import {
  MOCK_GUARDIANS,
  MOCK_SECURITY_EVENTS,
  formatCountdown,
  formatTimeAgo,
  mockRecovery,
  mockTransactions,
} from '@/lib/mock-data';
import Link from 'next/link';

export default function DashboardPage() {
  const recovery = mockRecovery();
  const transactions = mockTransactions();
  const activeGuardians = MOCK_GUARDIANS.filter((g) => g.status === 'active');
  const pendingTx = transactions.filter((t) => t.status === 'pending');

  return (
    <>
      <h1>Wallet overview</h1>
      <div className="grid">
        <section className="card">
          <h2>Wallet status</h2>
          <p className="muted">Primary wallet (Sepolia)</p>
          <p>
            Address: <code>0x0000…0000</code>{' '}
            <span className="status-warn">(placeholder until contracts ship)</span>
          </p>
          <p>Devices: 1 active, 1 revoked</p>
          <p>
            Policy: default — normal transfers need device approval; high-value transfers need
            device + guardian quorum.
          </p>
        </section>

        <section className="card">
          <h2>Guardians</h2>
          <p>
            <span className="status-ok">{activeGuardians.length} active</span> /{' '}
            {MOCK_GUARDIANS.length} total
          </p>
          <p>Recovery threshold: 3 of {activeGuardians.length} weighted guardians</p>
          <Link href="/guardians">Manage guardians →</Link>
        </section>

        <section className="card">
          <h2>Recovery</h2>
          <p>
            State: <span className="status-warn">{recovery.state.replace('_', ' ')}</span>
          </p>
          <p>
            Approvals: {recovery.approvals.length}/{recovery.requiredApprovals}
          </p>
          <p>
            Timelock:{' '}
            <span className="status-warn">{formatCountdown(recovery.timelockEndsAt ?? 0)}</span>
          </p>
          <Link href="/recovery">Recovery details →</Link>
        </section>

        <section className="card">
          <h2>Pending authorizations</h2>
          {pendingTx.length === 0 ? (
            <p className="muted">No pending transactions.</p>
          ) : (
            pendingTx.map((tx) => (
              <p key={tx.id}>
                {tx.type} — {(Number(BigInt(tx.value)) / 1e18).toFixed(2)} ETH ·{' '}
                <span className="status-warn">
                  {tx.approvals.length}/{tx.requiredApprovals} approvals
                </span>
              </p>
            ))
          )}
        </section>
      </div>

      <section className="card">
        <h2>Recent security activity</h2>
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Event</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_SECURITY_EVENTS.map((event) => (
              <tr key={event.id}>
                <td className="muted">{formatTimeAgo(event.at)}</td>
                <td>{event.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted" style={{ marginTop: '0.75rem' }}>
          Mock data. The event feed will be backed by on-chain events once Phase 1 lands.
        </p>
      </section>
    </>
  );
}
