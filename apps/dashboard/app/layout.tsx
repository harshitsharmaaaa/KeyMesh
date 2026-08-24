import type { Metadata } from 'next';
import Link from 'next/link';
import './globals.css';

export const metadata: Metadata = {
  title: 'KeyMesh Dashboard',
  description: 'Non-custodial key management dashboard (prototype)',
};

const NAV_ITEMS = [
  { href: '/', label: 'Dashboard' },
  { href: '/guardians', label: 'Guardians' },
  { href: '/recovery', label: 'Recovery' },
  { href: '/policies', label: 'Policies' },
  { href: '/security', label: 'Security' },
  { href: '/demo', label: 'Tx demo (local)' },
] as const;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="topbar">
            <Link href="/" className="brand">
              KEYMESH
            </Link>
            <nav className="nav">
              {NAV_ITEMS.map((item) => (
                <Link key={item.href} href={item.href}>
                  {item.label}
                </Link>
              ))}
            </nav>
            <span className="prototype-badge">PROTOTYPE — mock data</span>
          </header>
          <main className="content">{children}</main>
          <footer className="footer">
            KeyMesh is under active development. This UI displays local/mock state only and must
            never be trusted with real funds.
          </footer>
        </div>
      </body>
    </html>
  );
}
