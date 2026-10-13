import { Component, useEffect, type ErrorInfo, type ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/auth/useSession';
import { rememberPlace } from '@/api/session';
import type { Capability } from '@/lib/permissions';
import { LinkButton, Skeleton } from './ui';

export function NoAccess() {
  return (
    <div className="card stack" role="alert">
      <h1>You do not have access to this page</h1>
      <p>Your role does not include this part of the dashboard. If you think you should have it, ask a super admin to change your role.</p>
      <LinkButton to="/" variant="primary">Back to the overview</LinkButton>
    </div>
  );
}

export function NotFoundPage() {
  return (
    <div className="card stack">
      <h1>Page not found</h1>
      <p>There is nothing at this address. It may have moved, or the link may be wrong.</p>
      <LinkButton to="/" variant="primary">Back to the overview</LinkButton>
    </div>
  );
}

/** Signed in, or sent to sign in. Remembers where the person was so they come back to it. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { status, user } = useAuth();
  const loc = useLocation();
  useEffect(() => { if (status === 'signedOut') rememberPlace(loc.pathname + loc.search); }, [status, loc.pathname, loc.search]);
  if (status === 'loading') return <main><p className="muted">Checking your sign-in...</p><Skeleton lines={4} /></main>;
  if (status === 'signedOut') return <Navigate to="/sign-in" replace />;
  if (user?.mustChangePassword && loc.pathname !== '/account/password') return <Navigate to="/account/password" replace />;
  return <>{children}</>;
}

/** A page the person's role may not use shows a clear message, never a blank screen. */
export function RequireCap({ cap, children }: { cap: Capability; children: ReactNode }) {
  const { can } = useAuth();
  return can(cap) ? <>{children}</> : <NoAccess />;
}

/** If a page crashes, say so in plain words. No stack trace, no raw error. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(_e: Error, _i: ErrorInfo) { /* deliberately not logged: it could contain data from the page */ }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="card stack" role="alert">
        <h1>Something went wrong on this page</h1>
        <p>The page could not be shown. Reload it. If it keeps happening, tell your administrator.</p>
        <button type="button" className="btn primary" onClick={() => window.location.reload()}>Reload</button>
      </div>
    );
  }
}
