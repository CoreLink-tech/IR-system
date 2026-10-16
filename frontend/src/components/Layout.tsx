import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '@/auth/useSession';
import { signOut, noteActivity } from '@/api/session';
import { useExecutiveSummary, useHealth } from '@/api/hooks';
import { PostureChip } from './badges';
import { Announcer } from './announce';
import { Button } from './ui';
import { IconShield, IconUser } from './icons';
import { useTimeMode } from '@/lib/time';
import { ROLE_LABEL, type Capability } from '@/lib/permissions';

interface NavItem { to: string; label: string; cap: Capability; end?: boolean }
const NAV: NavItem[] = [
  { to: '/', label: 'Overview', cap: 'reports.executive', end: true },
  { to: '/incidents', label: 'Incidents', cap: 'incidents.read' },
  { to: '/ips', label: 'Addresses', cap: 'ips.read' },
  { to: '/blocking', label: 'Blocking', cap: 'blocks.read' },
  { to: '/reports', label: 'Reports', cap: 'reports.executive' },
  { to: '/admin/users', label: 'Users', cap: 'users.manage' },
  { to: '/admin/api-keys', label: 'API keys', cap: 'apikeys.manage' },
  { to: '/admin/rules', label: 'Detection rules', cap: 'rules.manage' },
  { to: '/admin/audit', label: 'Audit log', cap: 'audit.read' },
  { to: '/admin/settings', label: 'Settings', cap: 'settings.read' },
];

function UserMenu() {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const nav = useNavigate();
  const wrap = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    const onClick = (e: MouseEvent) => { if (!wrap.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener('keydown', onKey); document.addEventListener('mousedown', onClick);
    return () => { document.removeEventListener('keydown', onKey); document.removeEventListener('mousedown', onClick); };
  }, [open]);
  if (!user) return null;
  return (
    <div className="menu-wrap" ref={wrap}>
      <Button aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <IconUser /> <span>{user.name || user.email}</span>
      </Button>
      {open && (
        <div className="menu" role="menu" aria-label="Account">
          <p className="small muted" style={{ padding: '.4rem .6rem', margin: 0 }}>{user.email}<br /><span className="badge role-badge">{ROLE_LABEL[user.role]}</span></p>
          <Button role="menuitem" onClick={() => { setOpen(false); nav('/account/password'); }}>Change password</Button>
          <Button role="menuitem" onClick={async () => { setOpen(false); await signOut('signedOut'); nav('/sign-in', { replace: true }); }}>Sign out</Button>
        </div>
      )}
    </div>
  );
}

function TimeToggle() {
  const { mode, toggle } = useTimeMode();
  return <Button onClick={toggle} aria-pressed={mode === 'utc'} title="Switch between your local time and UTC. UTC is always shown when you hover over a time.">Times: {mode === 'utc' ? 'UTC' : 'my time'}</Button>;
}

function ApiStatus() {
  const h = useHealth();
  if (!h.isError) return null;
  return <div className="banner" role="alert">Cannot reach the Security API. What you see may be out of date. Retrying automatically.</div>;
}

export function Layout({ children }: { children?: ReactNode }) {
  const { user, can } = useAuth();
  const posture = useExecutiveSummary({ days: 7 }, 120_000);
  useEffect(() => {
    const on = () => noteActivity();
    const events: Array<keyof WindowEventMap> = ['pointerdown', 'keydown', 'scroll', 'touchstart'];
    events.forEach((e) => window.addEventListener(e, on, { passive: true }));
    return () => events.forEach((e) => window.removeEventListener(e, on));
  }, []);
  const items = NAV.filter((n) => can(n.cap));
  return (
    <>
      <a className="skip-link" href="#main">Skip to content</a>
      <Announcer />
      <header className="topbar">
        <Link to="/" className="brand"><span style={{ width: 24, display: 'inline-flex' }}><IconShield /></span> Security Dashboard</Link>
        <PostureChip posture={posture.data?.posture} />
        <span className="spacer" />
        <TimeToggle />
        {user && <span className="chip role-badge" aria-label={`Your role: ${ROLE_LABEL[user.role]}`}>{ROLE_LABEL[user.role]}</span>}
        <UserMenu />
      </header>
      <nav className="nav" aria-label="Main">
        {items.map((n) => <NavLink key={n.to} to={n.to} end={n.end}>{n.label}</NavLink>)}
      </nav>
      <ApiStatus />
      <main id="main" tabIndex={-1}>{children ?? <Outlet />}</main>
    </>
  );
}
