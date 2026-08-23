import { MOCK_DEVICES, MOCK_SECURITY_EVENTS, formatTimeAgo } from '@/lib/mock-data';

export default function SecurityPage() {
  return (
    <>
      <h1>Security</h1>
      <section className="card">
        <h2>Devices</h2>
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>Status</th>
              <th>Authorized</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_DEVICES.map((d) => (
              <tr key={d.id}>
                <td>{d.name}</td>
                <td className={d.revokedAt === null ? 'status-ok' : 'status-danger'}>
                  {d.revokedAt === null ? 'active' : 'revoked'}
                </td>
                <td className="muted">{formatTimeAgo(d.authorizedAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="card">
        <h2>Activity log</h2>
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Event</th>
            </tr>
          </thead>
          <tbody>
            {[...MOCK_SECURITY_EVENTS].reverse().map((event) => (
              <tr key={event.id}>
                <td className="muted">{formatTimeAgo(event.at)}</td>
                <td>{event.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
