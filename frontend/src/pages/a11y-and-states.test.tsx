import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import { renderApp } from '@/test/helpers';
import * as fx from '@/test/fixtures';
import type { Role } from '@/api/types';

const ID = 'INC-20261007-00001ABCD', IP = '198.51.100.7';
const everything: Record<string, any> = {
  'GET /incidents': { body: fx.page([fx.incident(), fx.incident({ id: 'x', incidentId: 'INC-X', sourceIp: null, userId: 'u9', status: 'RESOLVED' })]) },
  [`GET /incidents/${ID}`]: { body: fx.incident() },
  [`GET /reports/incidents/${ID}`]: { body: fx.report() },
  [`GET /reports/technical/${ID}`]: { body: fx.technical() },
  'GET /reports/security-summary': { body: fx.securitySummary() },
  'GET /auth/assignees': { body: { data: [{ id: 'u2', email: 'ana@example.com', name: 'Ana', role: 'ANALYST' }] } },
  'GET /ips': { body: fx.page([{ ...fx.ipRecord(), blocked: true }]) },
  [`GET /ips/${IP}`]: { body: fx.ipDetail() },
  'GET /security/blocked-ips': { body: { data: [fx.activeBlock()] } },
  'GET /security/allowlist': { body: [{ id: 'al1', ipAddress: '41.58.1.1', reason: 'Office', addedBy: 'u', createdAt: new Date().toISOString(), expiresAt: null }] },
  'GET /security/blocks/history': { body: [{ id: 'h1', ipAddress: IP, action: 'BLOCK', reason: 'Attack', administratorId: null, relatedIncidentId: null, isPermanent: false, expiresAt: null, active: true, automatic: true, createdAt: new Date().toISOString() }] },
  'GET /auth/users': { body: { data: [fx.userRow('SUPER_ADMIN', { id: 'u-SUPER_ADMIN' }), fx.userRow('ANALYST', { id: 'u2' })] } },
  'GET /api-keys': { body: [fx.apiKey()] },
  'GET /rules': { body: { data: [fx.rule()] } },
  'GET /audit-logs': { body: fx.page([fx.audit()]) },
  'GET /settings/operational': { body: fx.settings() },
};
// Colour contrast cannot be computed without a layout engine; it is covered by contrast.test.ts instead.
const check = async (container: HTMLElement) => expect(await axe(container, { rules: { 'color-contrast': { enabled: false } } })).toHaveNoViolations();

const pages: Array<[string, Role, string, RegExp | string]> = [
  ['overview', 'ANALYST', '/', 'Detail for analysts'],
  ['incidents list', 'ANALYST', '/incidents', 'Incidents'],
  ['incident report', 'VIEWER', `/incidents/${ID}`, fx.report().headline],
  ['incident timeline', 'VIEWER', `/incidents/${ID}?tab=timeline`, 'Incident opened'],
  ['incident technical', 'ANALYST', `/incidents/${ID}?tab=technical`, 'Related events'],
  ['incident actions (security admin)', 'SECURITY_ADMIN', `/incidents/${ID}?tab=actions`, 'Change status'],
  ['addresses (analyst)', 'ANALYST', '/ips', 'Addresses seen so far'],
  ['addresses (viewer)', 'VIEWER', '/ips', 'Look up any address'],
  ['address page', 'SECURITY_ADMIN', `/ips/${IP}`, 'What has been seen'],
  ['blocking: blocked now', 'SECURITY_ADMIN', '/blocking', 'Addresses blocked now'],
  ['blocking: allowlist', 'SECURITY_ADMIN', '/blocking?tab=allowlist', 'Allowlist'],
  ['blocking: history', 'ANALYST', '/blocking?tab=history', 'Block history'],
  ['reports: executive', 'VIEWER', '/reports', 'Key numbers'],
  ['reports: security', 'ANALYST', '/reports?tab=security', 'Busiest addresses'],
  ['users', 'SUPER_ADMIN', '/admin/users', 'Accounts'],
  ['api keys', 'SECURITY_ADMIN', '/admin/api-keys', 'API keys'],
  ['detection rules', 'SECURITY_ADMIN', '/admin/rules', 'Password guessing'],
  ['audit log', 'ANALYST', '/admin/audit', 'Audit log'],
  ['settings', 'SECURITY_ADMIN', '/admin/settings', 'Connection'],
  ['change password', 'VIEWER', '/account/password', 'Change password'],
  ['no access', 'VIEWER', '/admin/users', 'You do not have access to this page'],
  ['not found', 'VIEWER', '/nope', 'Page not found'],
];

describe('accessibility (axe) on every page', () => {
  for (const [name, role, route, ready] of pages) {
    it(`${name}`, async () => {
      const { container } = await renderApp({ role, route, routes: everything });
      await screen.findAllByText(ready);
      await waitFor(() => expect(container.querySelector('[aria-label="Loading"]')).toBeNull());
      await check(container);
    });
  }
  it('sign in', async () => {
    const { container } = await renderApp({ role: 'VIEWER', route: '/sign-in', signedIn: false });
    await screen.findByRole('heading', { name: 'Sign in' });
    await check(container);
  });
  it('open dialogs: block, create key, unblock', async () => {
    const a = await renderApp({ role: 'SECURITY_ADMIN', route: '/blocking', routes: everything });
    await userEvent.click(await screen.findByRole('button', { name: 'Block an address' }));
    await check(await screen.findByRole('dialog').then((d) => d.parentElement!));
    a.unmount();
    const b = await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/api-keys', routes: everything });
    await userEvent.click(await screen.findByRole('button', { name: 'Create an API key' }));
    await check(await screen.findByRole('dialog').then((d) => d.parentElement!));
    b.unmount();
  });
  it('a dialog traps keyboard focus inside itself', async () => {
    await renderApp({ role: 'SECURITY_ADMIN', route: '/blocking', routes: everything });
    await userEvent.click(await screen.findByRole('button', { name: 'Block an address' }));
    const dlg = await screen.findByRole('dialog');
    for (let i = 0; i < 12; i++) { await userEvent.tab(); expect(dlg.contains(document.activeElement)).toBe(true); }
    for (let i = 0; i < 12; i++) { await userEvent.tab({ shift: true }); expect(dlg.contains(document.activeElement)).toBe(true); }
  });
  it('status changes are announced to screen readers', async () => {
    await renderApp({ role: 'ANALYST', route: `/incidents/${ID}?tab=actions`, routes: { ...everything, [`POST /incidents/${fx.incident().id}/notes`]: { status: 201, body: {} } } });
    await userEvent.type(await screen.findByLabelText('Note'), 'hello');
    await userEvent.click(screen.getByRole('button', { name: 'Add note' }));
    await waitFor(() => expect(screen.getAllByRole('status').some((n) => /Note added/.test(n.textContent ?? ''))).toBe(true));
  });
  it('every form control has a label and every button has a name, on the busiest pages', async () => {
    for (const [role, route] of [['SECURITY_ADMIN', '/admin/rules'], ['SUPER_ADMIN', '/admin/users'], ['ANALYST', '/incidents'], ['ANALYST', '/ips']] as const) {
      const r = await renderApp({ role, route, routes: everything });
      await screen.findByRole('main'); await waitFor(() => expect(r.container.querySelector('[aria-label="Loading"]')).toBeNull());
      for (const el of r.container.querySelectorAll('input:not([type=hidden]), select, textarea')) {
        const named = (el as HTMLElement).getAttribute('aria-label') || (el.id && r.container.querySelector(`label[for="${el.id}"]`));
        expect([route, el.outerHTML.slice(0, 80), !!named]).toEqual([route, el.outerHTML.slice(0, 80), true]);
      }
      for (const b of r.container.querySelectorAll('button')) expect([route, (b.textContent || b.getAttribute('aria-label') || '').trim().length > 0]).toEqual([route, true]);
      r.unmount();
    }
  });
  it('tables carry a caption, column headers, and a data-label on every cell, which is what turns them into cards on a phone', async () => {
    const { container } = await renderApp({ role: 'ANALYST', route: '/incidents', routes: everything });
    await screen.findByRole('table', { name: 'Incidents' });
    const cells = [...container.querySelectorAll('td')];
    expect(cells.length).toBeGreaterThan(0);
    for (const c of cells) expect(c.getAttribute('data-label')).toBeTruthy();
    expect(container.querySelectorAll('th[scope="col"]').length).toBe(8);
  });
});

describe('every error state, on a real page', () => {
  const page = (routes: Record<string, any>) => renderApp({ role: 'ANALYST', route: '/incidents', routes });
  it('403 shows an access message and the rest of the app keeps working', async () => {
    await page({ 'GET /incidents': { status: 403, body: { statusCode: 403, message: 'Forbidden', requestId: 'req-403' } } });
    expect(await screen.findByText('You do not have access to this')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument();
  });
  it('404 says not found', async () => {
    await page({ 'GET /incidents': { status: 404, body: { statusCode: 404, message: 'x' } } });
    expect(await screen.findByText('Not found')).toBeInTheDocument();
  });
  it('429 says when to retry, counts down, and holds the retry button', async () => {
    await page({ 'GET /incidents': { status: 429, headers: { 'Retry-After': '30' }, body: { statusCode: 429, message: 'Too many requests' } } });
    expect(await screen.findByText('Too many requests')).toBeInTheDocument();
    expect(screen.getByText(/Please wait 30 seconds/)).toBeInTheDocument();
    expect(screen.getByText(/You can try again in \d+ seconds/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeDisabled();
  });
  it('a network failure says it cannot reach the Security API, with a retry', async () => {
    const { net } = await page({ 'GET /incidents': { body: fx.page([]) } });
    const { vi } = await import('vitest');
    await screen.findByText(/Nothing has been flagged yet/);
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    await userEvent.selectOptions(screen.getByLabelText('Status'), 'OPEN');
    expect((await screen.findAllByText('Cannot reach the Security API'))[0]).toBeInTheDocument();
    void net;
  });
  it('a server error shows the request id and never a stack trace or raw JSON', async () => {
    await page({ 'GET /incidents': { status: 500, body: { statusCode: 500, message: 'Internal server error', path: '/api/v1/incidents', requestId: 'req-500-abc', stack: 'Error: boom\n at x' } } });
    expect(await screen.findByText('req-500-abc')).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/boom|Error:|stack|"statusCode"|\{/);
  });
  it('a 401 in the middle of a session refreshes silently and carries on', async () => {
    let n = 0;
    const { net } = await page({ 'GET /incidents': () => (++n === 1 ? { status: 401, body: {} } : { body: fx.page([fx.incident()]) }) });
    expect(await screen.findByRole('table', { name: 'Incidents' })).toBeInTheDocument();
    expect(net.count('POST /auth/refresh')).toBe(1);
  });
  it('when the refresh itself is refused, the person is sent to sign in with a message', async () => {
    await page({ 'GET /incidents': { status: 401, body: {} }, 'POST /auth/refresh': { status: 401, body: { statusCode: 401, message: 'x' } } });
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.getByText('Your session ended')).toBeInTheDocument();
  });
  it('theft detection ends everything and tells the person clearly', async () => {
    await page({ 'GET /incidents': { status: 401, body: {} }, 'POST /auth/refresh': { status: 401, body: { statusCode: 401, message: 'x', code: 'refresh_token_reuse' } } });
    expect(await screen.findByText('All your sessions were ended for safety')).toBeInTheDocument();
  });
  it('a crash in a page shows a plain message with no technical detail', async () => {
    const { net } = await page({ 'GET /incidents': { body: { data: 'not-a-list', meta: null } } });
    expect(await screen.findByText('Something went wrong on this page')).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/TypeError|undefined|at \w+/);
    void net;
  });
});

describe('the UI never derives severity or risk from a number', () => {
  it('shows the level the API returned even when the number says otherwise', async () => {
    const odd = fx.incident({ severity: 'LOW', riskScore: 99 });
    const ip = { ...fx.ipRecord({ riskLevel: 'NORMAL', riskScore: 99 }), blocked: false };
    const rep = fx.report({ severity: 'LOW', sections: { ...fx.report().sections, riskLevel: { level: 'NORMAL', score: 99, explanation: 'Quiet.' } } });
    const a = await renderApp({ role: 'ANALYST', route: '/incidents', routes: { ...everything, 'GET /incidents': { body: fx.page([odd]) } } });
    const row = (await screen.findByRole('table', { name: 'Incidents' })).querySelector('tbody tr')!;
    expect(within(row as HTMLElement).getByText('Low')).toBeInTheDocument();
    expect(within(row as HTMLElement).queryByText('Critical')).not.toBeInTheDocument();
    a.unmount();
    const b = await renderApp({ role: 'ANALYST', route: '/ips', routes: { ...everything, 'GET /ips': { body: fx.page([ip]) } } });
    const r2 = (await screen.findByRole('table', { name: 'Addresses' })).querySelector('tbody tr')!;
    expect(within(r2 as HTMLElement).getByText('Normal')).toBeInTheDocument();
    expect(within(r2 as HTMLElement).queryByText('Critical')).not.toBeInTheDocument();
    b.unmount();
    await renderApp({ role: 'VIEWER', route: `/incidents/${ID}`, routes: { ...everything, [`GET /reports/incidents/${ID}`]: { body: rep } } });
    const sec = (await screen.findByRole('heading', { name: 'Risk level' })).closest('section')!;
    expect(within(sec).getByText('Normal')).toBeInTheDocument();
    expect(within(sec).queryByText('Critical')).not.toBeInTheDocument();
  });
  it('shows the posture the API returned, whatever the key numbers look like', async () => {
    await renderApp({ role: 'VIEWER', routes: { 'GET /reports/executive-summary': { body: fx.executive({ posture: 'ALL_CLEAR', keyNumbers: [{ label: 'Critical incidents', value: '57' }] }) } } });
    await waitFor(() => expect(document.querySelector('.posture')).not.toBeNull());
    const banner = document.querySelector('.posture') as HTMLElement;
    expect(banner).toHaveTextContent('All clear');
    expect(banner).not.toHaveTextContent('Urgent');
  });
});

describe('severity and posture never rely on colour alone', () => {
  it('every severity, status and posture badge has an icon and a word', async () => {
    const { container } = await renderApp({ role: 'ANALYST', route: '/incidents', routes: { ...everything, 'GET /incidents': { body: fx.page(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s, i) => fx.incident({ id: `s${i}`, incidentId: `INC-${s}`, severity: s as any }))) } } });
    await screen.findByRole('table', { name: 'Incidents' });
    const badges = [...container.querySelectorAll('.badge')];
    expect(badges.length).toBeGreaterThan(10);
    for (const b of badges) { expect([b.textContent, !!b.querySelector('svg')]).toEqual([b.textContent, true]); expect((b.textContent ?? '').trim().length).toBeGreaterThan(0); }
    for (const chip of container.ownerDocument.querySelectorAll('.chip.posture-action, .chip.posture-urgent, .chip.posture-clear, .chip.posture-monitor')) expect(chip.querySelector('svg')).toBeTruthy();
  });
});
