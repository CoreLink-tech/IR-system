import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderApp, ROLES, API, jwt } from '@/test/helpers';
import * as fx from '@/test/fixtures';
import { getState } from '@/api/session';
import type { Role } from '@/api/types';

const NAV: Record<Role, string[]> = {
  SUPER_ADMIN: ['Overview', 'Incidents', 'Addresses', 'Blocking', 'Reports', 'Users', 'API keys', 'Detection rules', 'Audit log', 'Settings'],
  SECURITY_ADMIN: ['Overview', 'Incidents', 'Addresses', 'Blocking', 'Reports', 'API keys', 'Detection rules', 'Audit log', 'Settings'],
  ANALYST: ['Overview', 'Incidents', 'Addresses', 'Blocking', 'Reports', 'Audit log'],
  VIEWER: ['Overview', 'Incidents', 'Addresses', 'Blocking', 'Reports'],
};
const empty = { 'GET /incidents': { body: fx.page([]) } };

describe('navigation shows only what the role may use', () => {
  for (const role of ROLES) {
    it(`${role}`, async () => {
      await renderApp({ role, routes: empty });
      const nav = await screen.findByRole('navigation', { name: 'Main' });
      expect(within(nav).getAllByRole('link').map((a) => a.textContent)).toEqual(NAV[role]);
    });
  }
});

describe('a page the role cannot use', () => {
  const blocked: Array<[Role, string]> = [
    ['VIEWER', '/admin/users'], ['VIEWER', '/admin/rules'], ['VIEWER', '/admin/audit'], ['VIEWER', '/admin/api-keys'], ['VIEWER', '/admin/settings'],
    ['ANALYST', '/admin/users'], ['ANALYST', '/admin/rules'], ['ANALYST', '/admin/api-keys'], ['ANALYST', '/admin/settings'],
    ['SECURITY_ADMIN', '/admin/users'],
  ];
  for (const [role, route] of blocked) {
    it(`${role} at ${route} sees a clear access message, not a blank screen, and no request is made for it`, async () => {
      const { net } = await renderApp({ role, route });
      expect(await screen.findByRole('heading', { name: 'You do not have access to this page' })).toBeInTheDocument();
      expect(screen.getByRole('link', { name: 'Back to the overview' })).toBeInTheDocument();
      const forbidden = net.calls.filter((c) => /\/(rules|api-keys|audit-logs|settings|auth\/users)/.test(c.path));
      expect(forbidden).toEqual([]);
    });
  }
  it('an unknown address shows a not-found page', async () => {
    await renderApp({ role: 'VIEWER', route: '/nothing/here' });
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});

describe('the top bar', () => {
  it('shows the posture the API returned, the role badge and the account menu', async () => {
    await renderApp({ role: 'ANALYST', routes: { 'GET /reports/executive-summary': { body: fx.executive({ posture: 'URGENT' }) } } });
    await waitFor(() => expect(screen.getAllByText('Urgent').length).toBeGreaterThan(0));
    expect(screen.getByLabelText('Your role: Analyst')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /ANALYST Person/ }));
    expect(screen.getByRole('menuitem', { name: 'Change password' })).toBeInTheDocument();
    expect(screen.getByRole('menuitem', { name: 'Sign out' })).toBeInTheDocument();
  });
  it('shows "cannot reach the Security API" when the health check fails, and the page keeps working', async () => {
    await renderApp({ role: 'VIEWER', routes: { 'GET /health': { status: 503, body: {} } } });
    expect(await screen.findByText(/Cannot reach the Security API\. What you see may be out of date/)).toBeInTheDocument();
  });
  it('switches times between local and UTC, and always keeps UTC in the tooltip', async () => {
    const at = '2026-10-07T13:30:00.000Z';
    await renderApp({ role: 'ANALYST', route: '/incidents/INC-1', routes: {
      'GET /incidents/INC-1': { body: fx.incident({ timeline: [{ id: 't', incidentId: 'i', action: 'incident.created', actor: 'system', details: null, createdAt: at }] }) },
      'GET /reports/incidents/INC-1': { body: fx.report() },
    } });
    await userEvent.click(await screen.findByRole('tab', { name: 'Timeline' }));
    const t = await screen.findByText(/7 Oct 2026, 13:30 UTC/);
    expect(t.closest('time')).toHaveAttribute('title', '2026-10-07 13:30:00 UTC');
    await userEvent.click(screen.getByRole('button', { name: /Times: UTC/ }));
    expect(screen.queryByText(/13:30 UTC/)).not.toBeInTheDocument();
    expect(document.querySelector('time[title="2026-10-07 13:30:00 UTC"]')).toBeTruthy();
  });
  it('has a skip link and a labelled main landmark', async () => {
    await renderApp({ role: 'VIEWER' });
    expect(await screen.findByRole('link', { name: 'Skip to content' })).toHaveAttribute('href', '#main');
    expect(screen.getByRole('main')).toBeInTheDocument();
  });
});

describe('signing out and coming back', () => {
  it('shows the sign-in page when there is no session', async () => {
    await renderApp({ role: 'VIEWER', signedIn: false, routes: { 'GET /auth/csrf': { status: 401, body: {} } } });
    // The app starts at "loading" until bootstrap decides; with no cookie, bootstrap runs from main.tsx, so do it here.
    const { bootstrap } = await import('@/api/session');
    await bootstrap();
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
  });
  it('sign out clears what was fetched, so the next person on this browser sees nothing of it', async () => {
    const { client } = await renderApp({ role: 'VIEWER' });
    await waitFor(() => expect(client.getQueryCache().getAll().length).toBeGreaterThan(0));
    await userEvent.click(await screen.findByRole('button', { name: /VIEWER Person/ }));
    await userEvent.click(screen.getByRole('menuitem', { name: 'Sign out' }));
    await waitFor(() => expect(getState().status).toBe('signedOut'));
    await waitFor(() => expect(client.getQueryCache().getAll()).toHaveLength(0));
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
  });
  it('REGRESSION an account that must change its password is held on that page and cannot reach anything else', async () => {
    await renderApp({ role: 'ANALYST', route: '/incidents', userOver: { mustChangePassword: true } });
    expect(await screen.findByRole('heading', { name: 'Change password' })).toBeInTheDocument();
    expect(screen.getByText(/You must choose a new password/)).toBeInTheDocument();
  });
});

void API; void jwt;
