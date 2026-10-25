'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { api, getAccessToken, setAccessToken, type PublicUser } from '@/lib/client-api';

const NAV = [
  { href: '/overview', label: 'Overview' },
  { href: '/incidents', label: 'Incidents' },
  { href: '/ips', label: 'Addresses' },
  { href: '/reports', label: 'Reports' },
  { href: '/blocking', label: 'Blocking' },
  { href: '/allowlist', label: 'Allowlist' },
  { href: '/admin/users', label: 'Users' },
  { href: '/admin/api-keys', label: 'API keys' },
  { href: '/admin/audit', label: 'Audit' },
  { href: '/admin/rules', label: 'Rules' },
  { href: '/admin/settings', label: 'Settings' },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const path = usePathname();
  const [user, setUser] = useState<PublicUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api<{ user: PublicUser }>('/auth/me')
      .then((r) => setUser(r.user))
      .catch(() => {
        setAccessToken(null);
        
        router.replace('/sign-in');
      })
      .finally(() => setLoading(false));
  }, [router]);

  if (loading) {
    return (
      <main className="p-8 text-neutral-500">Loading…</main>
    );
  }
  if (!user) return null;

  return (
    <div className="min-h-screen bg-neutral-50 text-neutral-900">
      <header className="border-b bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3">
          <nav className="flex flex-wrap gap-3 text-sm">
            {NAV.map((n) => (
              <Link
                key={n.href}
                href={n.href}
                className={path.startsWith(n.href) ? 'font-semibold text-blue-700' : 'text-neutral-600 hover:text-neutral-900'}
              >
                {n.label}
              </Link>
            ))}
          </nav>
          <div className="flex flex-wrap items-center gap-3 text-sm text-neutral-600">
            <span>{user.email}</span>
            <Link href="/account/password" className="text-blue-700 underline">Password</Link>
            <Link href="/account/sessions" className="text-blue-700 underline">Sessions</Link>
            <Link href="/account/security" className="text-blue-700 underline">Security</Link>
            <button
              type="button"
              className="text-blue-700 underline"
              onClick={async () => {
                try { await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'include' }); } catch { /* */ }
                setAccessToken(null);
                
                router.replace('/sign-in');
              }}
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <div className="mx-auto max-w-6xl px-4 py-6">{children}</div>
    </div>
  );
}
