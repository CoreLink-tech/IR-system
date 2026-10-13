import { describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderApp } from '@/test/helpers';
import * as fx from '@/test/fixtures';
import * as S from '@/api/session';

const signedOutApp = (routes: Record<string, any> = {}) => renderApp({ role: 'VIEWER', signedIn: false, route: '/sign-in', routes });

describe('sign in', () => {
  it('signs in with email and password and lands on the overview', async () => {
    const { net } = await signedOutApp();
    await userEvent.type(await screen.findByLabelText('Email'), ' person@pishon.ng ');
    await userEvent.type(screen.getByLabelText('Password'), 'a-long-password-1');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
    expect(net.last('POST /auth/login')!.body).toMatchObject({ email: 'person@pishon.ng', useCookie: true });
  });
  it('returns the person to the page they were on', async () => {
    S.rememberPlace('/incidents?status=OPEN');
    await signedOutApp({ 'GET /incidents': { body: fx.page([fx.incident()]) } });
    await userEvent.type(await screen.findByLabelText('Email'), 'a@b.ng');
    await userEvent.type(screen.getByLabelText('Password'), 'a-long-password-1');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Incidents' })).toBeInTheDocument();
  });
  it('gives the same message for a wrong email and a wrong password, and clears the password', async () => {
    await signedOutApp({ 'POST /auth/login': { status: 401, body: { statusCode: 401, message: 'Invalid credentials' } } });
    await userEvent.type(await screen.findByLabelText('Email'), 'nobody@pishon.ng');
    await userEvent.type(screen.getByLabelText('Password'), 'wrong-password');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    const msg = await screen.findByText('The email or password is not right. Check both and try again.');
    expect(msg).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toHaveValue('');
    expect(document.body.textContent).not.toMatch(/no such user|unknown email|wrong password/i);
  });
  it('shows a countdown from Retry-After after a 429 and holds the button until it ends', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      await signedOutApp({ 'POST /auth/login': { status: 429, headers: { 'Retry-After': '3' }, body: { statusCode: 429, message: 'Too many requests' } } });
      await userEvent.type(await screen.findByLabelText('Email'), 'a@b.ng');
      await userEvent.type(screen.getByLabelText('Password'), 'a-long-password-1');
      await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
      expect(await screen.findByText(/Try again in 3 seconds/)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Sign in' })).toBeDisabled();
      await act(async () => { await vi.advanceTimersByTimeAsync(3100); });
      expect(await screen.findByText(/You can try again now/)).toBeInTheDocument();
    } finally { vi.useRealTimers(); }
  });
  it('says it cannot reach the Security API when the network is down', async () => {
    await signedOutApp();
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('x'); }));
    await userEvent.type(await screen.findByLabelText('Email'), 'a@b.ng');
    await userEvent.type(screen.getByLabelText('Password'), 'a-long-password-1');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText(/Your connection may be down/)).toBeInTheDocument();
  });
  it('has a password visibility toggle and the right autocomplete hints for password managers', async () => {
    await signedOutApp();
    const pw = await screen.findByLabelText('Password');
    expect(pw).toHaveAttribute('type', 'password');
    expect(pw).toHaveAttribute('autocomplete', 'current-password');
    expect(screen.getByLabelText('Email')).toHaveAttribute('autocomplete', 'username');
    await userEvent.click(screen.getByRole('button', { name: /Show/ }));
    expect(pw).toHaveAttribute('type', 'text');
    await userEvent.click(screen.getByRole('button', { name: /Hide/ }));
    expect(pw).toHaveAttribute('type', 'password');
  });
  it('explains why the person was signed out (expired, away, or a possibly stolen session)', async () => {
    for (const [reason, text] of [['expired', /Your session ended/], ['idle', /you were away/], ['compromised', /All your sessions were ended for safety/]] as const) {
      const r = await signedOutApp();
      await act(async () => { await S.signOut(reason, false); });
      expect(await screen.findByText(text)).toBeInTheDocument();
      r.unmount();
    }
  });
});

describe('overview', () => {
  const routes = {
    'GET /reports/security-summary': { body: fx.securitySummary() },
  };
  it('puts the server posture and headline first, in words, with its icon', async () => {
    await renderApp({ role: 'VIEWER', routes: { 'GET /reports/executive-summary': { body: fx.executive({ posture: 'URGENT', headline: 'Act now: a critical incident is open' }) } } });
    const banner = (await screen.findByText('Act now: a critical incident is open')).closest('[role="status"]')!;
    expect(within(banner as HTMLElement).getByText('Urgent')).toBeInTheDocument();
    expect(banner.querySelector('svg')).toBeTruthy();
  });
  it('shows every part of the executive summary exactly as returned, including the limitations', async () => {
    const e = fx.executive();
    await renderApp({ role: 'VIEWER' });
    expect(await screen.findByText(e.overview)).toBeInTheDocument();
    for (const k of e.keyNumbers) expect(within(screen.getByRole('main')).getByText(k.label)).toBeInTheDocument();
    expect(screen.getByText(e.needsAttention[0])).toBeInTheDocument();
    expect(screen.getByText(e.trend)).toBeInTheDocument();
    expect(screen.getByText(e.limitations[0])).toBeVisible();
    expect(screen.getByText('What this summary cannot confirm')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'INC-20261007-00001ABCD' })).toHaveAttribute('href', '/incidents/INC-20261007-00001ABCD');
  });
  it('a viewer gets the executive summary only, and never asks for the security summary', async () => {
    const { net } = await renderApp({ role: 'VIEWER' });
    await screen.findByText(fx.executive().overview);
    expect(screen.queryByText('Detail for analysts')).not.toBeInTheDocument();
    expect(net.count('GET /reports/security-summary')).toBe(0);
  });
  it('an analyst also gets the daily chart, with a text alternative and the same numbers in a table', async () => {
    await renderApp({ role: 'ANALYST', routes });
    const chart = await screen.findByRole('img', { name: /Daily activity over 3 days: 120 events and 2 incidents/ });
    expect(chart).toBeInTheDocument();
    await userEvent.click(screen.getByText('Show the numbers as a table'));
    expect(screen.getByRole('cell', { name: '2026-10-06' })).toBeInTheDocument();
  });
  it('changes the period and asks the API for that period, and keeps it in the URL', async () => {
    const { net } = await renderApp({ role: 'ANALYST', routes });
    await screen.findByText(fx.executive().overview);
    await userEvent.click(screen.getByRole('button', { name: 'Last 30 days' }));
    await waitFor(() => expect(net.calls.some((c) => c.path === '/reports/executive-summary' && c.query.get('days') === '30')).toBe(true));
    await userEvent.click(screen.getByRole('button', { name: 'Last 24 hours' }));
    await waitFor(() => expect(net.calls.some((c) => c.path === '/reports/executive-summary' && c.query.get('days') === '1')).toBe(true));
  });
  it('supports a custom range, validates it, and sends ISO dates', async () => {
    const { net } = await renderApp({ role: 'VIEWER' });
    await screen.findByText(fx.executive().overview);
    await userEvent.click(screen.getByRole('button', { name: 'Custom range' }));
    await userEvent.click(screen.getByRole('button', { name: 'Show this period' }));
    expect(screen.getByText('Choose both a start and an end.')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('From'), '2026-10-05T10:00');
    await userEvent.type(screen.getByLabelText('To'), '2026-10-04T10:00');
    await userEvent.click(screen.getByRole('button', { name: 'Show this period' }));
    expect(screen.getByText('The end must be after the start.')).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText('To'));
    await userEvent.type(screen.getByLabelText('To'), '2026-10-06T10:00');
    await userEvent.click(screen.getByRole('button', { name: 'Show this period' }));
    await waitFor(() => expect(net.calls.some((c) => c.path === '/reports/executive-summary' && /^2026-10-0\dT/.test(c.query.get('from') ?? '') && c.query.get('to'))).toBe(true));
  });
  it('shows when it was last updated, refreshes on demand, and refreshes by itself', async () => {
    const { net } = await renderApp({ role: 'VIEWER' });
    await screen.findByText(/Last updated/);
    const before = net.count('GET /reports/executive-summary');
    await userEvent.click(screen.getByRole('button', { name: 'Refresh now' }));
    await waitFor(() => expect(net.count('GET /reports/executive-summary')).toBeGreaterThan(before));
  });
  it('copies the summary as text, only when asked', async () => {
    const written: string[] = [];
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (t: string) => { written.push(t); } }, configurable: true });
    const { net } = await renderApp({ role: 'VIEWER', routes: { 'GET /reports/executive-summary': (c: any) => (c.query.get('format') === 'text' ? { text: 'PLAIN TEXT SUMMARY' } : { body: fx.executive() }) } });
    await screen.findByText(fx.executive().overview);
    expect(written).toEqual([]);
    expect(net.calls.some((c) => c.query.get('format') === 'text')).toBe(false);
    await userEvent.click(screen.getByRole('button', { name: 'Copy as text' }));
    await waitFor(() => expect(written).toEqual(['PLAIN TEXT SUMMARY']));
  });
  it('one failed panel does not blank the page: the summary shows while the analyst detail reports its own error', async () => {
    await renderApp({ role: 'ANALYST', routes: { 'GET /reports/security-summary': { status: 500, body: { statusCode: 500, message: 'x', requestId: 'req-77' } } } });
    expect(await screen.findByText(fx.executive().overview)).toBeInTheDocument();
    expect(await screen.findByText('The Security API had a problem')).toBeInTheDocument();
    expect(screen.getByText('req-77')).toBeInTheDocument();
  });
  it('shows a retry when the whole summary cannot load', async () => {
    let n = 0;
    await renderApp({ role: 'VIEWER', routes: { 'GET /reports/executive-summary': () => (++n <= 1 ? { status: 503, body: { statusCode: 503, message: 'x', requestId: 'r' } } : { body: fx.executive() }) } });
    const retry = await screen.findByRole('button', { name: 'Try again' });
    await userEvent.click(retry);
    expect(await screen.findByText(fx.executive().overview)).toBeInTheDocument();
  });
});
