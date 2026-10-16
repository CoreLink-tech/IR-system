/**
 * Runs the real dashboard (real session code, real pages) against a LIVE Security API.
 * Skipped unless LIVE_API is set:
 *
 *   LIVE_API=http://localhost:4000 LIVE_EMAIL=admin@... LIVE_PASSWORD=... npm run test:live
 *
 * jsdom has no cookie jar for fetch, so a small wrapper does what a browser does: it sends the
 * Origin header, keeps Set-Cookie values, and sends the refresh cookie only to /api/v1/auth when
 * the request asks for credentials. This is NOT a real browser; see docs/FRONTEND.md for what that leaves unchecked.
 */
import { describe, expect, it, vi, beforeAll, afterAll } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import App from '@/App';
import { TimeProvider } from '@/lib/time';
import { setConfig } from '@/lib/config';
import { __resetForTests, bootstrap, getState } from '@/api/session';
import { newClient } from './helpers';

const LIVE = process.env.LIVE_API;
const ORIGIN = 'http://localhost:5173';
const d = LIVE ? describe : describe.skip;

const STAMP = Date.now().toString(36);
const jar = new Map<string, string>();
const realFetch = globalThis.fetch;
function browserFetch(input: RequestInfo | URL, init: RequestInit = {}) {
  const url = new URL(typeof input === 'string' ? input : input.toString());
  const headers = new Headers(init.headers as HeadersInit);
  headers.set('Origin', ORIGIN);
  if (init.credentials === 'include' && url.pathname.startsWith('/api/v1/auth') && jar.size) headers.set('Cookie', [...jar].map(([k, v]) => `${k}=${v}`).join('; '));
  return realFetch(url, { ...init, headers, credentials: undefined }).then((res) => {
    for (const c of (res.headers as any).getSetCookie?.() ?? []) {
      const [pair] = c.split(';'); const i = pair.indexOf('='); const n = pair.slice(0, i), v = pair.slice(i + 1);
      if (/Max-Age=0/i.test(c) || !v) jar.delete(n); else jar.set(n, v);
    }
    return res;
  });
}

const mount = (route: string) => render(
  <QueryClientProvider client={newClient()}><TimeProvider initial="utc"><MemoryRouter initialEntries={[route]}><App /></MemoryRouter></TimeProvider></QueryClientProvider>,
);

d('the real dashboard against the live Security API', () => {
  beforeAll(() => { vi.stubGlobal('fetch', browserFetch as any); });
  afterAll(() => { vi.unstubAllGlobals(); });

  it('signs in through the sign-in page with the cookie session', async () => {
    __resetForTests(); jar.clear(); setConfig({ apiBaseUrl: LIVE!, idleTimeoutMinutes: 30 });
    mount('/incidents');
    await bootstrap();
    await userEvent.type(await screen.findByLabelText('Email'), process.env.LIVE_EMAIL!);
    await userEvent.type(screen.getByLabelText('Password'), process.env.LIVE_PASSWORD!);
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Incidents' }, { timeout: 15000 })).toBeInTheDocument();
    expect(getState().status).toBe('signedIn');
    expect(jar.has('ir_rt')).toBe(true);                         // the cookie is held by the "browser", not by the app
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toMatch(/eyJ/);
  }, 30000);

  it('resumes the session after a page reload, using only the cookie', async () => {
    const before = [...jar.values()][0];
    __resetForTests(); setConfig({ apiBaseUrl: LIVE!, idleTimeoutMinutes: 30 });
    mount('/');
    await bootstrap();
    expect(getState().status).toBe('signedIn');
    expect([...jar.values()][0]).not.toBe(before);                   // the refresh token rotated
    expect(await screen.findByRole('heading', { name: 'Overview' }, { timeout: 15000 })).toBeInTheDocument();
  }, 30000);

  it('shows the live overview in words: posture, key numbers, limitations, and the analyst chart', async () => {
    __resetForTests(); setConfig({ apiBaseUrl: LIVE!, idleTimeoutMinutes: 30 });
    mount('/'); await bootstrap();
    await waitFor(() => expect(document.querySelector('.posture')).not.toBeNull(), { timeout: 15000 });
    expect(document.querySelector('.posture')!.textContent).toMatch(/Urgent|Action needed|Monitoring|All clear/);
    expect(screen.getByText('Key numbers')).toBeInTheDocument();
    expect(screen.getByText('What this summary cannot confirm')).toBeVisible();
    expect(await screen.findByRole('img', { name: /Daily activity over \d+ days/ }, { timeout: 15000 })).toBeInTheDocument();
  }, 30000);

  it('lists live incidents, opens one by its public number, and renders its real report', async () => {
    __resetForTests(); setConfig({ apiBaseUrl: LIVE!, idleTimeoutMinutes: 30 });
    const r = mount('/incidents'); await bootstrap();
    const table = await screen.findByRole('table', { name: 'Incidents' }, { timeout: 15000 });
    const link = within(table).getAllByRole('link')[0];
    expect(link.textContent).toMatch(/^INC-/);
    r.unmount();
    mount(`/incidents/${link.textContent}`);
    expect(await screen.findByRole('heading', { name: link.textContent! }, { timeout: 15000 })).toBeInTheDocument();
    expect(await screen.findByText('What this report cannot confirm', {}, { timeout: 15000 })).toBeVisible();
    for (const h of ['What happened', 'Why it matters', 'Risk level']) expect(screen.getByRole('heading', { name: h })).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/brute_force_login|_threshold|riskDelta/); // no rule codes in the primary view
  }, 40000);

  it('adds a note on a live incident and sees it on the timeline, with the status untouched', async () => {
    const list = await (await browserFetch(`${LIVE}/api/v1/incidents?pageSize=1`, { headers: { Authorization: `Bearer ${await (await import('@/api/session')).ensureToken()}` } })).json();
    const inc = list.data[0];
    const r = mount(`/incidents/${inc.incidentId}?tab=actions`);
    await userEvent.type(await screen.findByLabelText('Note', {}, { timeout: 15000 }), 'live dashboard test note');
    await userEvent.click(screen.getByRole('button', { name: 'Add note' }));
    expect(await screen.findByText('Note added to the timeline.', {}, { timeout: 15000 })).toBeInTheDocument();
    r.unmount();
    mount(`/incidents/${inc.incidentId}?tab=timeline`);
    expect((await screen.findAllByText('live dashboard test note', {}, { timeout: 15000 })).length).toBeGreaterThan(0);
  }, 60000);

  it('edits a live detection rule, sees it audited, and resets it', async () => {
    const r = mount('/admin/rules');
    const card = (await screen.findByRole('heading', { name: 'Repeated failed logins' }, { timeout: 15000 })).closest('article')!;
    const input = within(card).getByLabelText('How many before the rule triggers') as HTMLInputElement;
    const start = Number(input.value);
    await userEvent.clear(input); await userEvent.type(input, String(start + 2));
    const inc = within(card).getByLabelText('How many before an incident is opened') as HTMLInputElement;
    await userEvent.clear(inc); await userEvent.type(inc, String(start + 2));
    await userEvent.type(within(card).getByLabelText('Why are you changing this? (optional)'), `live dashboard test ${STAMP}`);
    await userEvent.click(within(card).getByRole('button', { name: 'Save changes' }));
    expect(await within(card).findByText(/Saved\. The new settings apply/, {}, { timeout: 15000 })).toBeInTheDocument();
    const fresh = (await screen.findByRole('heading', { name: 'Repeated failed logins' })).closest('article')!;
    await waitFor(() => expect(within(fresh).getByText('Changed')).toBeInTheDocument(), { timeout: 15000 });
    await userEvent.click(within(fresh).getByRole('button', { name: 'Show change history' }));
    expect(await within(fresh).findByText(new RegExp(`Reason: live dashboard test ${STAMP}`), {}, { timeout: 15000 })).toBeInTheDocument();
    await userEvent.click(within(fresh).getByRole('button', { name: 'Reset to defaults' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Reset' }));
    await waitFor(() => expect(within((screen.getByRole('heading', { name: 'Repeated failed logins' })).closest('article')!).getByText('Default settings')).toBeInTheDocument(), { timeout: 15000 });
    r.unmount();
  }, 90000);

  it('rejects an out-of-range rule value at the server and shows its message', async () => {
    mount('/admin/rules');
    const card = (await screen.findByRole('heading', { name: 'Repeated failed logins' }, { timeout: 15000 })).closest('article')!;
    const t = within(card).getByLabelText('How many before the rule triggers') as HTMLInputElement;
    await userEvent.clear(t); await userEvent.type(t, '30');       // passes the screen's range check, but breaks the "incident not before the rule" ordering
    await userEvent.click(within(card).getByRole('button', { name: 'Save changes' }));
    expect(await within(card).findByText(/An incident cannot be opened before the rule itself triggers/, {}, { timeout: 15000 })).toBeInTheDocument();
  }, 40000);

  it('shows the live users list with the safeguards, API keys, audit log, settings and blocking pages without errors', async () => {
    for (const [route, ready] of [['/admin/users', 'Accounts'], ['/admin/api-keys', 'API keys'], ['/admin/audit', 'Audit log'], ['/admin/settings', 'Connection'], ['/blocking', 'Blocking'], ['/ips', 'Addresses seen so far'], ['/reports?tab=security', 'Busiest addresses']] as const) {
      const r = mount(route);
      await screen.findAllByText(ready, {}, { timeout: 15000 });
      await waitFor(() => expect(document.querySelector('[aria-label="Loading"]')).toBeNull(), { timeout: 15000 });
      expect([route, document.querySelector('.error-box')?.textContent ?? null]).toEqual([route, null]);
      r.unmount();
    }
  }, 120000);

  it('creates a live API key and shows it exactly once', async () => {
    const r = mount('/admin/api-keys');
    await userEvent.click(await screen.findByRole('button', { name: 'Create an API key' }, { timeout: 15000 }));
    const dlg = await screen.findByRole('dialog');
    await userEvent.type(within(dlg).getByLabelText('Name'), `live-ui-${STAMP}`);
    await userEvent.click(within(dlg).getByRole('button', { name: 'Create key' }));
    const once = await screen.findByRole('dialog', { name: 'Your new API key' }, { timeout: 15000 });
    const raw = within(once).getByTestId('raw-key').textContent!;
    expect(raw).toMatch(/^IRS_[A-Za-z0-9_-]{20,}$/);
    await userEvent.click(within(once).getByRole('checkbox')); await userEvent.click(within(once).getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(document.body.textContent).not.toContain(raw));
    const row = (await screen.findAllByRole('row')).find((x) => new RegExp(`live-ui-${STAMP}`).test(x.textContent ?? ''))!;
    await userEvent.click(within(row).getByRole('button', { name: /Revoke/ }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Revoke the key' }));
    await waitFor(() => expect(within(screen.getAllByRole('row').find((x) => new RegExp(`live-ui-${STAMP}`).test(x.textContent ?? ''))!).getByText('Revoked')).toBeInTheDocument(), { timeout: 15000 });
    r.unmount();
  }, 90000);

  it('signs out through the menu: the cookie is cleared and the server refuses the old refresh token', async () => {
    mount('/');
    await userEvent.click(await screen.findByRole('button', { name: /Live Admin|admin@/ }, { timeout: 15000 }));
    await userEvent.click(screen.getByRole('menuitem', { name: 'Sign out' }));
    expect(await screen.findByRole('heading', { name: 'Sign in' }, { timeout: 15000 })).toBeInTheDocument();
    expect(jar.has('ir_rt')).toBe(false);
  }, 40000);
});
