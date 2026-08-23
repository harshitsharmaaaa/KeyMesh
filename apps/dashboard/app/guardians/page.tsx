import { MOCK_GUARDIANS } from '@/lib/mock-data';

export default function GuardiansPage() {
  return (
    <>
      <h1>Guardians</h1>
      <p className="muted">
        Guardians approve high-value actions and recoveries. Registration and on-chain weight
        accounting arrive with the GuardianRegistry contract; this page shows the intended UX over
        mock data.
      </p>
      <section className="card">
        <table>
          <thead>
            <tr>
              <th>Guardian</th>
              <th>Type</th>
              <th>Weight</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_GUARDIANS.map((g) => (
              <tr key={g.id}>
                <td>{g.name}</td>
                <td className="muted">{g.type}</td>
                <td>{g.weight}</td>
                <td className={g.status === 'active' ? 'status-ok' : 'status-warn'}>{g.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
