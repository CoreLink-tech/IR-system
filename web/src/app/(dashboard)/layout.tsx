'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { api, setAccessToken, type PublicUser } from '@/lib/client-api';

const NAV_GROUPS = [
  {
    label: 'Monitor',
    items: [
      { href: '/overview', label: 'Overview', icon: '◎' },
      { href: '/incidents', label: 'Incidents', icon: '⚠' },
      { href: '/ips', label: 'IP Intelligence', icon: '◈' },
    ],
  },
  {
    label: 'Enforcement',
    items: [
      { href: '/blocking', label: 'Blocklist', icon: '⊘' },
      { href: '/allowlist', label: 'Allowlist', icon: '✓' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { href: '/reports', label: 'Reports', icon: '▦' },
    ],
  },
  {
    label: 'Administration',
    items: [
      { href: '/admin/users', label: 'Users', icon: '◎' },
      { href: '/admin/api-keys', label: 'API Keys', icon: '⚿' },
      { href: '/admin/audit', label: 'Audit Log', icon: '☰' },
      { href: '/admin/rules', label: 'Detection Rules', icon: '⚡' },
      { href: '/admin/settings', label: 'Settings', icon: '⚙' },
    ],
  },
];

function NavIcon({ name }: { name: string }) {
  // Simple geometric icons using CSS/Unicode for zero dependency
  return <span className="w-5 text-center text-sm opacity-70">{name}</span>;
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const path = usePathname();
  const [user, setUser] = useState<PublicUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    api<{ user: PublicUser }>('/auth/me')
      .then((r) => setUser(r.user))
      .catch(() => {
        setAccessToken(null);
        router.replace('/sign-in');
      })
      .finally(() => setLoading(false));
  }, [router]);

  // Close mobile sidebar on route change
  useEffect(() => {
    setSidebarOpen(false);
  }, [path]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[var(--bg-base)]">
        <div className="text-[var(--text-secondary)]">Loading…</div>
      </div>
    );
  }
  if (!user) return null;

  const isActive = (href: string) => path === href || path.startsWith(href + '/');

  return (
    <div className="flex min-h-screen bg-[var(--bg-base)] text-[var(--text-primary)]">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed inset-y-0 left-0 z-50 flex w-60 flex-col border-r border-[var(--border)] bg-[var(--bg-sidebar)]
          transition-transform duration-200 ease-out
          lg:static lg:translate-x-0
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
        `}
      >
        {/* Brand */}
        <div className="flex h-14 items-center gap-2.5 border-b border-[var(--border)] px-4">
          <div className="flex h-7 w-7 items-center justify-center rounded bg-[var(--accent)] text-xs font-bold text-[var(--text-inverse)]">
            W
          </div>
          <div>
            <div className="text-sm font-semibold tracking-tight">Watcher, by ZenLink</div>
            <div className="text-[10px] text-[var(--text-muted)]">Security Operations</div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto px-2 py-3">
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="mb-4">
              <div className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                {group.label}
              </div>
              <ul className="space-y-0.5">
                {group.items.map((item) => (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      className={`
                        flex items-center gap-2.5 rounded-[var(--radius)] px-2.5 py-1.5 text-[13px] transition-colors
                        ${isActive(item.href)
                          ? 'bg-[var(--bg-active)] text-[var(--text-primary)] font-medium'
                          : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'}
                      `}
                    >
                      <NavIcon name={item.icon} />
                      {item.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>

        {/* User footer */}
        <div className="border-t border-[var(--border)] p-3">
          <div className="mb-2 truncate px-1 text-xs text-[var(--text-secondary)]">
            {user.email}
          </div>
          <div className="flex flex-wrap gap-1">
            <Link href="/account/security" className="btn btn-ghost text-xs px-2 py-1">
              Account
            </Link>
            <button
              type="button"
              className="btn btn-ghost text-xs px-2 py-1"
              onClick={async () => {
                try {
                  await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'include' });
                } catch { /* */ }
                setAccessToken(null);
                router.replace('/sign-in');
              }}
            >
              Sign out
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top bar */}
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-[var(--border)] bg-[var(--bg-sidebar)]/95 px-4 backdrop-blur">
          <button
            type="button"
            className="btn btn-ghost p-2 lg:hidden"
            onClick={() => setSidebarOpen(true)}
            aria-label="Open navigation"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <div className="flex-1" />
          <div className="text-xs text-[var(--text-muted)]">
            {user.role.replace('_', ' ')}
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto p-4 md:p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
