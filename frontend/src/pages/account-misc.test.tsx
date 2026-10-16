import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { renderApp } from '@/test/helpers';
import * as fx from '@/test/fixtures';
import { getState } from '@/api/session';
import { loadConfig, config, setConfig } from '@/lib/config';
import { makeQueryClient, shouldRetry } from '@/api/hooks';
import { ApiError } from '@/api/errors';
import { downloadText } from '@/components/actions';

describe('change password', () => {
  const open = (routes: Record<string, any> = {}) => renderApp({ role: 'VIEWER', route: '/account/password', routes });
  it('checks length and matching before sending anything', async () => {
    const { net } = await open();
    await userEvent.type(await screen.findByLabelText('Current password'), 'old-password-1');
    await userEvent.type(screen.getByLabelText('New password'), 'short');
    await userEvent.type(screen.getByLabelText('New password again'), 'short');
    await userEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(screen.getByText('Use at least 12 characters.')).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText('New password')); await userEvent.type(screen.getByLabelText('New password'), 'a-much-longer-password');
    await userEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(screen.getByText('The two new passwords are not the same.')).toBeInTheDocument();
    expect(net.count('POST /auth/change-password')).toBe(0);
  });
  it('changes the password, ends this session (the server ends them all) and asks for a fresh sign-in', async () => {
    const { net } = await open({ 'POST /auth/change-password': { status: 201, body: { ok: true } } });
    await userEvent.type(await screen.findByLabelText('Current password'), 'old-password-1');
    await userEvent.type(screen.getByLabelText('New password'), 'a-much-longer-password');
    await userEvent.type(screen.getByLabelText('New password again'), 'a-much-longer-password');
    await userEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.getByText('Password changed')).toBeInTheDocument();
    expect(net.last('POST /auth/change-password')!.body).toEqual({ currentPassword: 'old-password-1', newPassword: 'a-much-longer-password' });
    expect(getState().status).toBe('signedOut');
  });
  it('shows the server refusal (for example a wrong current password) and keeps the form', async () => {
    await open({ 'POST /auth/change-password': { status: 401, body: { statusCode: 401, message: 'Current password is incorrect' } } });
    await userEvent.type(await screen.findByLabelText('Current password'), 'wrong-password');
    await userEvent.type(screen.getByLabelText('New password'), 'a-much-longer-password');
    await userEvent.type(screen.getByLabelText('New password again'), 'a-much-longer-password');
    await userEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText('The current password is not right.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change password' })).toBeEnabled();
    expect(getState().status).toBe('signedIn');     // REGRESSION: a wrong current password used to sign the person out
  });
  it('is reachable while a password change is required, and says why', async () => {
    await renderApp({ role: 'ANALYST', route: '/account/password', userOver: { mustChangePassword: true } });
    expect(await screen.findByText('You must choose a new password')).toBeInTheDocument();
  });
});

describe('runtime configuration', () => {
  it('reads /config.json and ignores bad values, trimming a trailing slash from the API address', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ apiBaseUrl: 'https://api.example.com/', idleTimeoutMinutes: 10 }))));
    await loadConfig();
    expect(config()).toMatchObject({ apiBaseUrl: 'https://api.example.com', idleTimeoutMinutes: 10 });
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ apiBaseUrl: 5, idleTimeoutMinutes: -3 }))));
    await loadConfig();
    expect(config()).toMatchObject({ apiBaseUrl: 'https://api.example.com', idleTimeoutMinutes: 10 });
  });
  it('keeps its defaults when the file is missing or the request fails', async () => {
    setConfig({ apiBaseUrl: 'http://keep.me', idleTimeoutMinutes: 7 });
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 404 })));
    await loadConfig();
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('x'); }));
    await loadConfig();
    expect(config()).toMatchObject({ apiBaseUrl: 'http://keep.me', idleTimeoutMinutes: 7 });
  });
});

describe('request retry policy', () => {
  it('retries connection trouble and server errors twice, never a refusal, a missing page or a rate limit', () => {
    const net = new ApiError({ kind: 'network' });
    expect([shouldRetry(0, net), shouldRetry(1, net), shouldRetry(2, net)]).toEqual([true, true, false]);
    expect(shouldRetry(0, new ApiError({ kind: 'http', status: 503 }))).toBe(true);
    for (const status of [400, 401, 403, 404, 409, 429]) expect(shouldRetry(0, new ApiError({ kind: 'http', status }))).toBe(false);
    expect(makeQueryClient().getDefaultOptions().queries!.refetchOnWindowFocus).toBe(true);
  });
});

describe('saving text', () => {
  it('downloads a text file on request, as a Blob with a safe name', () => {
    const urls: string[] = [];
    (URL as any).createObjectURL = (b: Blob) => { urls.push(b.type); return 'blob:x'; };
    (URL as any).revokeObjectURL = () => undefined;
    const clicks: string[] = [];
    const orig = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () { clicks.push(`${this.download}|${this.rel}`); };
    downloadText('report.txt', 'hello');
    HTMLAnchorElement.prototype.click = orig;
    expect(urls).toEqual(['text/plain;charset=utf-8']);
    expect(clicks).toEqual(['report.txt|noopener']);
    expect(document.querySelector('a[download]')).toBeNull();
  });
  it('says so when copying is not possible', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async () => { throw new Error('denied'); } }, configurable: true });
    await renderApp({ role: 'VIEWER', routes: { 'GET /reports/executive-summary': (c: any) => (c.query.get('format') === 'text' ? { text: 't' } : { body: fx.executive() }) } });
    await userEvent.click(await screen.findByRole('button', { name: 'Copy as text' }));
    expect(await screen.findByRole('button', { name: 'Copy failed' })).toBeInTheDocument();
  });
  it('says so when a download fails', async () => {
    await renderApp({ role: 'VIEWER', routes: { 'GET /reports/executive-summary': (c: any) => (c.query.get('format') === 'text' ? { status: 500, body: {} } : { body: fx.executive() }) } });
    await userEvent.click(await screen.findByRole('button', { name: 'Download text' }));
    expect(await screen.findByText('Download failed. Try again.')).toBeInTheDocument();
  });
});

describe('print and small screens (the style rules that make them work)', () => {
  const css = readFileSync(join(process.cwd(), 'src/styles/global.css'), 'utf8');
  it('has a print stylesheet that hides navigation and controls and shows the report', () => {
    const print = css.slice(css.indexOf('@media print'));
    for (const hidden of ['.topbar', '.nav', '.no-print', '.tabs', 'button']) expect(print).toContain(hidden);
    expect(print).toMatch(/\.report section[^{]*\{[^}]*break-inside: avoid/);
  });
  it('turns tables into stacked, labelled cards under 720px', () => {
    const small = css.slice(css.indexOf('@media (max-width: 720px)'), css.indexOf('/* Tabs'));
    expect(small).toMatch(/\.rtable tr\s*\{\s*display: block/);
    expect(small).toContain('content: attr(data-label)');
  });
  it('keeps touch targets at 44px and respects reduced motion', () => {
    expect(css).toMatch(/\.btn[^{]*\{[^}]*min-height: 44px; min-width: 44px/);
    expect(css).toMatch(/input\[type="text"\][^{]*\{[^}]*min-height: 44px/);
    expect(css).toContain('prefers-reduced-motion: reduce');
  });
});
