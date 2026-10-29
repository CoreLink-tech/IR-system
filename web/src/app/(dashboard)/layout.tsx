'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { api, setAccessToken, type PublicUser } from '@/lib/client-api';

type NavItem = { href: string; label: string; icon: string; roles: string[] };
type NavGroup = { label: string; items: NavItem[] };

/** Role-scoped navigation. Only items whose roles include the current user role are shown. */
const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Monitor',
    items: [
      { href: '/overview', label: 'Overview', icon: 'grid', roles: ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST', 'VIEWER'] },
      { href: '/incidents', label: 'Incidents', icon: 'alert', roles: ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST', 'VIEWER'] },
      { href: '/ips', label: 'IP Intelligence', icon: 'globe', roles: ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST', 'VIEWER'] },
    ],
  },
  {
    label: 'Enforcement',
    items: [
      { href: '/blocking', label: 'Blocklist', icon: 'block', roles: ['SUPER_ADMIN', 'SECURITY_ADMIN'] },
      { href: '/allowlist', label: 'Allowlist', icon: 'check', roles: ['SUPER_ADMIN', 'SECURITY_ADMIN'] },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { href: '/reports', label: 'Reports', icon: 'file', roles: ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST'] },
    ],
  },
  {
    label: 'Administration',
    items: [
      // Super admin only
      { href: '/admin/users', label: 'Users', icon: 'users', roles: ['SUPER_ADMIN'] },
      { href: '/admin/api-keys', label: 'API Keys', icon: 'key', roles: ['SUPER_ADMIN'] },
      { href: '/admin/settings', label: 'Settings', icon: 'settings', roles: ['SUPER_ADMIN'] },
      // Super admin + Security admin
      { href: '/admin/audit', label: 'Audit Log', icon: 'list', roles: ['SUPER_ADMIN', 'SECURITY_ADMIN'] },
      { href: '/admin/rules', label: 'Detection Rules', icon: 'sliders', roles: ['SUPER_ADMIN', 'SECURITY_ADMIN'] },
    ],
  },
];

function navForRole(role: string): NavGroup[] {
  return NAV_GROUPS
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => item.roles.includes(role)),
    }))
    .filter((group) => group.items.length > 0);
}

function Icon({ name }: { name: string }) {
  const props = { width: 17, height: 17, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.7 };
  switch (name) {
    case 'grid':
      return <svg {...props}><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>;
    case 'alert':
      return <svg {...props}><path d="M12 3L21 20H3Z"/><path d="M12 9V14M12 17V17.1"/></svg>;
    case 'globe':
      return <svg {...props}><circle cx="12" cy="12" r="9"/><path d="M3 12H21M12 3A15 15 0 0 1 12 21M12 3A15 15 0 0 0 12 21"/></svg>;
    case 'block':
      return <svg {...props}><circle cx="12" cy="12" r="9"/><path d="M6 6L18 18"/></svg>;
    case 'check':
      return <svg {...props}><path d="M5 12L10 17L20 6"/></svg>;
    case 'file':
      return <svg {...props}><path d="M5 3H15L19 7V21H5Z"/><path d="M14 3V8H19M8 13H16M8 17H16"/></svg>;
    case 'users':
      return <svg {...props}><circle cx="9" cy="8" r="4"/><path d="M2 21V19A7 7 0 0 1 16 19V21"/></svg>;
    case 'key':
      return <svg {...props}><circle cx="8" cy="15" r="5"/><path d="M12 11L21 2M17 6L20 9"/></svg>;
    case 'list':
      return <svg {...props}><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8H16M8 12H16M8 16H13"/></svg>;
    case 'sliders':
      return <svg {...props}><path d="M4 7H20M4 12H20M4 17H20"/><circle cx="8" cy="7" r="2"/><circle cx="16" cy="12" r="2"/></svg>;
    case 'settings':
      return <svg {...props}><circle cx="12" cy="12" r="3"/><path d="M19 14L21 16L19 20L16 19L14 21H10L9 18L5 19L3 15L5 12L3 9L6 6L9 7L10 4H14L16 7L19 6L21 10L19 12Z"/></svg>;
    default:
      return <span className="w-[17px]" />;
  }
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

  useEffect(() => {
    setSidebarOpen(false);
  }, [path]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#f3f5f4]">
        <div className="text-sm text-[#718079]">Loading…</div>
      </div>
    );
  }
  if (!user) return null;

  const isActive = (href: string) => path === href || path.startsWith(href + '/');
  const initials = (user.name || user.email || 'WA')
    .split(/[\s@]/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase() || '')
    .join('') || 'WA';

  return (
    <div className="flex min-h-screen bg-[#f3f5f4] text-[#172923]">
      {/* Mobile backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-[rgba(20,35,28,0.35)] lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed inset-y-0 left-0 z-50 flex w-[244px] flex-col border-r border-[#e0e7e3] bg-[#fcfdfc]
          px-[15px] pb-[15px] pt-[23px] transition-transform duration-200
          lg:static lg:translate-x-0
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
        `}
      >
        {/* Brand */}
        <div className="mb-[26px] flex items-center gap-[11px] px-[10px]">
          <svg className="h-[38px] w-[36px] text-[#176b52]" viewBox="0 0 40 44" fill="none">
            <path d="M20 2L36 8V21C36 31 29 37 20 42C11 37 4 31 4 21V8L20 2Z" stroke="currentColor" strokeWidth="2.4"/>
            <text x="20" y="28" textAnchor="middle" fill="currentColor" fontSize="16" fontWeight="700" fontFamily="system-ui,sans-serif">W</text>
          </svg>
          <div>
            <div className="text-[20px] font-[760] tracking-[-0.8px] leading-tight">Watcher</div>
            <div className="text-[10px] text-[#718079]">by ZenLink Technologies</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto">
          {navForRole(user.role).map((group) => (
            <div key={group.label}>
              <div className="mb-[7px] mt-[12px] px-[10px] text-[10px] font-[750] uppercase tracking-[1.2px] text-[#8a9690]">
                {group.label}
              </div>
              <div className="grid gap-[3px]">
                {group.items.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`
                      flex items-center gap-3 rounded-[5px] px-[11px] py-[10px] text-[13px] transition-colors
                      ${isActive(item.href)
                        ? 'bg-[#e9f2ed] font-bold text-[#123e32] shadow-[inset_3px_0_#176b52]'
                        : 'text-[#5f6f67] hover:bg-[#f1f5f2] hover:text-[#123e32]'}
                    `}
                  >
                    <Icon name={item.icon} />
                    {item.label}
                  </Link>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer */}
        <div className="mt-auto">
          <div className="rounded-[6px] border border-[#e0e7e3] bg-white p-[13px_11px]">
            <div className="flex items-center gap-2 text-[11px] font-bold">
              <span className="inline-block h-[7px] w-[7px] rounded-full bg-[#2d9368]" />
              All systems operational
            </div>
            <small className="mt-[5px] ml-[15px] block text-[10px] text-[#718079]">
              API and database status
            </small>
          </div>
          <div className="mt-[14px] flex items-center gap-[9px] border-t border-[#e0e7e3] px-[6px] pt-[14px]">
            <div className="grid h-[31px] w-[31px] place-items-center rounded-[4px] bg-[#e5ede8] text-[11px] font-[750] text-[#123e32]">
              {initials}
            </div>
            <div className="min-w-0 flex-1">
              <strong className="block truncate text-[11px]">{user.email}</strong>
              <small className="text-[10px] text-[#718079]">{user.role.replace(/_/g, ' ')}</small>
            </div>
          </div>
          <div className="mt-2 flex gap-1 px-1">
            <Link href="/account/security" className="btn btn-ghost text-[10px] px-2 py-1">
              Account
            </Link>
            <button
              type="button"
              className="btn btn-ghost text-[10px] px-2 py-1"
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

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-[62px] items-center justify-between gap-4 border-b border-[#e0e7e3] bg-white px-[30px]">
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="flex h-[34px] w-[34px] items-center justify-center rounded-[5px] border border-[#e0e7e3] bg-white text-[#123e32] lg:hidden"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open navigation"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                <path d="M4 6H20M4 12H20M4 18H20" />
              </svg>
            </button>
            <div className="hidden text-[12px] text-[#718079] sm:block">
              <strong className="font-[650] text-[#33463c]">Watcher</strong>
              &nbsp;/&nbsp; Security operations
            </div>
          </div>
          <div className="flex items-center gap-[14px]">
            <span className="hidden text-[11px] text-[#718079] md:inline">
              {user.role.replace(/_/g, ' ')}
            </span>
            <div className="grid h-[31px] w-[31px] place-items-center rounded-[4px] bg-[#e5ede8] text-[11px] font-[750] text-[#123e32]">
              {initials}
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-auto p-[30px]">
          <div className="mx-auto max-w-[1600px]">{children}</div>
        </main>
      </div>
    </div>
  );
}
