import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderApp } from '@/test/helpers';
import * as fx from '@/test/fixtures';

const IP = '198.51.100.7';
const ipRoutes = (over: Record<string, any> = {}) => ({
  [`GET /ips/${IP}`]: { body: fx.ipDetail() },
  'GET /security/blocked-ips': { body: { data: [] } },
  'GET /security/allowlist': { body: [] },
  'GET /incidents': { body: fx.page([fx.incident()]) },
  ...over,
});

describe('address list', () => {
  const rows = [{ ...fx.ipRecord(), blocked: true }, { ...fx.ipRecord({ id: 'ip2', ipAddress: '203.0.113.9', riskLevel: 'NORMAL', riskScore: 3, country: null }), blocked: false }];
  it('is for analysts and above: a viewer gets only the lookup box and no list request', async () => {
    const { net } = await renderApp({ role: 'VIEWER', route: '/ips' });
    expect(await screen.findByRole('search', { name: 'Look up an address' })).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'Addresses' })).not.toBeInTheDocument();
    expect(net.count('GET /ips')).toBe(0);
  });
  it('shows risk as the level the API returned, blocked status, country and counts', async () => {
    await renderApp({ role: 'ANALYST', route: '/ips', routes: { 'GET /ips': { body: fx.page(rows) } } });
    const t = await screen.findByRole('table', { name: 'Addresses' });
    const r = within(t).getAllByRole('row').slice(1);
    expect(within(r[0]).getByRole('link', { name: IP })).toHaveAttribute('href', `/ips/${IP}`);
    expect(within(r[0]).getByText('High')).toBeInTheDocument();
    expect(within(r[0]).getByText('Blocked')).toBeInTheDocument();
    expect(within(r[1]).getByText('Normal')).toBeInTheDocument();
    expect(within(r[1]).getByText('Not blocked')).toBeInTheDocument();
    expect(within(r[1]).getByText('unknown')).toBeInTheDocument();
  });
  it('sends filters and sort to the API and keeps them in the URL', async () => {
    const { net } = await renderApp({ role: 'ANALYST', route: '/ips?q=198&risk=HIGH&blocked=true&country=NG&sort=risk', routes: { 'GET /ips': { body: fx.page(rows) } } });
    await screen.findByRole('table', { name: 'Addresses' });
    expect(Object.fromEntries(net.last('GET /ips')!.query)).toMatchObject({ search: '198', riskLevel: 'HIGH', blocked: 'true', country: 'NG', sortBy: 'riskScore', sortOrder: 'desc' });
  });
  it('opens an address from the lookup box', async () => {
    await renderApp({ role: 'VIEWER', route: '/ips', routes: ipRoutes() });
    await userEvent.type(await screen.findByLabelText('Look up any address'), IP);
    await userEvent.click(screen.getByRole('button', { name: 'Open address' }));
    expect(await screen.findByRole('heading', { name: IP })).toBeInTheDocument();
  });
  it('an empty result explains itself', async () => {
    await renderApp({ role: 'ANALYST', route: '/ips?risk=CRITICAL', routes: { 'GET /ips': { body: fx.page([]) } } });
    expect(await screen.findByText('No addresses match')).toBeInTheDocument();
  });
});

describe('address page', () => {
  it('shows the record as returned: first and last seen, counts, level and score', async () => {
    await renderApp({ role: 'VIEWER', route: `/ips/${IP}`, routes: ipRoutes() });
    expect(await screen.findByRole('heading', { name: IP })).toBeInTheDocument();
    const rec = screen.getByRole('heading', { name: 'What has been seen' }).closest('section')!;
    for (const t of ['First seen', 'Last seen', 'Requests', 'Events', 'Failed sign-ins']) expect(within(rec).getByText(t)).toBeInTheDocument();
    expect(within(rec).getByText('400')).toBeInTheDocument();
    expect(screen.getByText('score 72')).toBeInTheDocument();
  });
  it('shows location and network flags only when intelligence was checked', async () => {
    await renderApp({ role: 'VIEWER', route: `/ips/${IP}`, routes: ipRoutes({ [`GET /ips/${IP}`]: { body: fx.ipDetail({ ip: fx.ipRecord({ isVpn: true, country: 'NG', city: 'Lagos' }) }) } }) });
    const sec = (await screen.findByRole('heading', { name: 'Where it comes from' })).closest('section')!;
    expect(within(sec).getByText('Lagos, NG')).toBeInTheDocument();
    expect(within(sec).getByText('VPN').nextSibling).toHaveTextContent('Yes');
  });
  it('says no provider has checked the address, instead of showing flags, when intelligence was never run', async () => {
    await renderApp({ role: 'VIEWER', route: `/ips/${IP}`, routes: ipRoutes({ [`GET /ips/${IP}`]: { body: fx.ipDetail({ ip: fx.ipRecord({ lastIntelUpdate: null, isVpn: true }) }) } }) });
    const sec = (await screen.findByRole('heading', { name: 'Where it comes from' })).closest('section')!;
    expect(within(sec).getByText(/No provider has checked this address/)).toBeInTheDocument();
    expect(within(sec).queryByText('VPN')).not.toBeInTheDocument();
  });
  it('lists related incidents for the address', async () => {
    const { net } = await renderApp({ role: 'VIEWER', route: `/ips/${IP}`, routes: ipRoutes() });
    expect(await screen.findByRole('table', { name: 'Incidents for this address' })).toBeInTheDocument();
    expect(net.calls.some((c) => c.path === '/incidents' && c.query.get('sourceIp') === IP)).toBe(true);
  });
  it('a viewer sees no raw events and no controls; an analyst sees events and a refresh button but no block control', async () => {
    const v = await renderApp({ role: 'VIEWER', route: `/ips/${IP}`, routes: ipRoutes() });
    await screen.findByRole('heading', { name: IP });
    expect(screen.queryByRole('heading', { name: 'Recent events' })).not.toBeInTheDocument();
    for (const b of ['Block', 'Unblock', 'Refresh intelligence', 'Add to allowlist']) expect(screen.queryByRole('button', { name: b })).not.toBeInTheDocument();
    v.unmount();
    await renderApp({ role: 'ANALYST', route: `/ips/${IP}`, routes: ipRoutes() });
    expect(await screen.findByRole('heading', { name: 'Recent events' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Refresh intelligence' })).toBeInTheDocument();
    for (const b of ['Block', 'Unblock', 'Add to allowlist']) expect(screen.queryByRole('button', { name: b })).not.toBeInTheDocument();
  });
  it('refreshes intelligence on request and reloads the record', async () => {
    const { net } = await renderApp({ role: 'ANALYST', route: `/ips/${IP}`, routes: ipRoutes({ [`POST /ips/${IP}/refresh-intelligence`]: { status: 201, body: {} } }) });
    await userEvent.click(await screen.findByRole('button', { name: 'Refresh intelligence' }));
    await waitFor(() => expect(net.count(`POST /ips/${IP}/refresh-intelligence`)).toBe(1));
    await waitFor(() => expect(net.count(`GET /ips/${IP}`)).toBeGreaterThan(1));
  });
  it('shows a block as in force (from the API list), who set it and when it ends, with the enforcement caveat', async () => {
    await renderApp({ role: 'SECURITY_ADMIN', route: `/ips/${IP}`, routes: ipRoutes({ 'GET /security/blocked-ips': { body: { data: [fx.activeBlock()] } } }) });
    const note = await screen.findByText('Currently blocked');
    expect(note.closest('.notice')!).toHaveTextContent('Blocked automatically');
    expect(note.closest('.notice')!).toHaveTextContent(/Expires in \d+ min/);
    expect(note.closest('.notice')!).toHaveTextContent(/cannot confirm that the website actually rejected the traffic/);
    expect(screen.getByRole('button', { name: 'Unblock' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Block' })).not.toBeInTheDocument();
  });
  it('a security admin can block, and an allowlisted address cannot be blocked from the page', async () => {
    const a = await renderApp({ role: 'SECURITY_ADMIN', route: `/ips/${IP}`, routes: ipRoutes() });
    expect(await screen.findByRole('button', { name: 'Block' })).toBeEnabled();
    a.unmount();
    const allow = { id: 'al1', ipAddress: IP, reason: 'Office', addedBy: 'u1', createdAt: new Date().toISOString(), expiresAt: null };
    await renderApp({ role: 'SECURITY_ADMIN', route: `/ips/${IP}`, routes: ipRoutes({ 'GET /security/allowlist': { body: [allow] } }) });
    expect(await screen.findByRole('button', { name: 'Block' })).toBeDisabled();
    expect(screen.getByText(/so it cannot be blocked/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Remove from allowlist' })).toBeInTheDocument();
  });
  it('unblocks with a required reason', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: `/ips/${IP}`, routes: ipRoutes({ 'GET /security/blocked-ips': { body: { data: [fx.activeBlock()] } }, 'POST /security/unblock': { status: 201, body: {} } }) });
    await userEvent.click(await screen.findByRole('button', { name: 'Unblock' }));
    const dlg = await screen.findByRole('dialog', { name: 'Unblock this address?' });
    await userEvent.click(within(dlg).getByRole('button', { name: 'Unblock' }));
    expect(within(dlg).getByText(/A reason is required/)).toBeInTheDocument();
    await userEvent.type(within(dlg).getByLabelText('Reason'), 'It was our own tester');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Unblock' }));
    await waitFor(() => expect(net.last('POST /security/unblock')!.body).toEqual({ ipAddress: IP, reason: 'It was our own tester' }));
  });
  it('shows the block history', async () => {
    const b = { id: 'b1', ipAddress: IP, action: 'BLOCK', reason: 'Attack', administratorId: null, relatedIncidentId: null, isPermanent: false, expiresAt: new Date().toISOString(), active: false, automatic: true, createdAt: new Date().toISOString() };
    await renderApp({ role: 'VIEWER', route: `/ips/${IP}`, routes: ipRoutes({ [`GET /ips/${IP}`]: { body: fx.ipDetail({ blocks: [b as any] }) } }) });
    const t = await screen.findByRole('table', { name: 'Block history' });
    expect(within(t).getByText('Blocked')).toBeInTheDocument();
    expect(within(t).getByText('Automatic')).toBeInTheDocument();
  });
  it('shows not found for an unknown address and keeps the rest of the app usable', async () => {
    await renderApp({ role: 'VIEWER', route: '/ips/9.9.9.9', routes: ipRoutes({ 'GET /ips/9.9.9.9': { status: 404, body: { statusCode: 404, message: 'IP not found' } } }) });
    expect(await screen.findByText('Not found')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument();
  });
});

describe('blocking page', () => {
  const routes = (over: Record<string, any> = {}) => ({
    'GET /security/blocked-ips': { body: { data: [fx.activeBlock(), fx.activeBlock({ ipAddress: '203.0.113.50', permanent: true, expiresAt: null, automatic: false, reason: 'Known scanner' })] } },
    'GET /security/allowlist': { body: [{ id: 'al1', ipAddress: '41.58.1.1', reason: 'Head office', addedBy: 'u1', createdAt: new Date().toISOString(), expiresAt: null }] },
    'GET /security/blocks/history': { body: [{ id: 'h1', ipAddress: IP, action: 'BLOCK', reason: 'Attack', administratorId: null, relatedIncidentId: null, isPermanent: false, expiresAt: null, active: true, automatic: true, createdAt: new Date().toISOString() }] },
    ...over,
  });
  it('always reminds that blocks are applied by the website within about 30 seconds and cannot be confirmed', async () => {
    await renderApp({ role: 'VIEWER', route: '/blocking', routes: routes() });
    expect(await screen.findByText(/applies blocks within about 30 seconds/)).toBeVisible();
    expect(screen.getByText(/cannot confirm that the website actually rejected the traffic/)).toBeVisible();
  });
  it('lists active blocks with how, why, since, and a countdown or "never"', async () => {
    await renderApp({ role: 'ANALYST', route: '/blocking', routes: routes() });
    const t = await screen.findByRole('table', { name: 'Addresses blocked now' });
    const r = within(t).getAllByRole('row').slice(1);
    expect(within(r[0]).getByText('Automatic')).toBeInTheDocument();
    expect(within(r[0]).getByText(/in \d+ min/)).toBeInTheDocument();
    expect(within(r[1]).getByText('By an administrator')).toBeInTheDocument();
    expect(within(r[1]).getByText('Never (permanent)')).toBeInTheDocument();
  });
  it('a viewer and an analyst can read but have no block, unblock or allowlist controls', async () => {
    for (const role of ['VIEWER', 'ANALYST'] as const) {
      const r = await renderApp({ role, route: '/blocking', routes: routes() });
      await screen.findByRole('table', { name: 'Addresses blocked now' });
      for (const b of [/Block an address/, /Add to allowlist/, /^Unblock/]) expect(screen.queryByRole('button', { name: b })).not.toBeInTheDocument();
      r.unmount();
    }
  });
  it('the history tab is for analysts and above', async () => {
    const v = await renderApp({ role: 'VIEWER', route: '/blocking', routes: routes() });
    await screen.findByRole('table', { name: 'Addresses blocked now' });
    expect(screen.queryByRole('tab', { name: 'History' })).not.toBeInTheDocument();
    expect(v.net.count('GET /security/blocks/history')).toBe(0);
    v.unmount();
    await renderApp({ role: 'ANALYST', route: '/blocking?tab=history', routes: routes() });
    expect(await screen.findByRole('table', { name: 'Block history' })).toBeInTheDocument();
  });
  it('a security admin can block a new address from here, with the same dialog', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: '/blocking', routes: routes({ 'POST /security/block': { status: 201, body: {} } }) });
    await userEvent.click(await screen.findByRole('button', { name: 'Block an address' }));
    const dlg = await screen.findByRole('dialog', { name: 'Block an address' });
    await userEvent.type(within(dlg).getByLabelText('Address'), '192.0.2.77');
    await userEvent.type(within(dlg).getByLabelText('Reason'), 'Scanning');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Block address' }));
    await waitFor(() => expect(net.last('POST /security/block')!.body).toMatchObject({ ipAddress: '192.0.2.77', reason: 'Scanning', ttlMinutes: 60 }));
  });
  it('unblocking from the list asks for a reason', async () => {
    await renderApp({ role: 'SECURITY_ADMIN', route: '/blocking', routes: routes() });
    await userEvent.click((await screen.findAllByRole('button', { name: /^Unblock/ }))[0]);
    expect(await screen.findByRole('dialog', { name: 'Unblock this address?' })).toBeInTheDocument();
  });
  it('adds to and removes from the allowlist, confirming the removal in plain words', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: '/blocking?tab=allowlist', routes: routes({ 'POST /security/allow': { status: 201, body: {} }, 'DELETE /security/allow/41.58.1.1': { body: {} } }) });
    await userEvent.click(await screen.findByRole('button', { name: /^Remove/ }));
    const dlg = await screen.findByRole('dialog', { name: 'Remove from the allowlist?' });
    expect(within(dlg).getByText(/can be blocked again/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(net.count('DELETE /security/allow/41.58.1.1')).toBe(1));
    await userEvent.click(screen.getByRole('button', { name: 'Add to allowlist' }));
    const add = await screen.findByRole('dialog', { name: 'Add to the allowlist' });
    await userEvent.type(within(add).getByLabelText('Address'), '41.58.9.9');
    await userEvent.selectOptions(within(add).getByLabelText('For how long'), '1440');
    await userEvent.type(within(add).getByLabelText('Reason'), 'Partner');
    await userEvent.click(within(add).getByRole('button', { name: 'Add to allowlist' }));
    await waitFor(() => expect(net.last('POST /security/allow')!.body).toEqual({ ipAddress: '41.58.9.9', reason: 'Partner', ttlMinutes: 1440 }));
  });
  it('says so when nothing is blocked', async () => {
    await renderApp({ role: 'VIEWER', route: '/blocking', routes: routes({ 'GET /security/blocked-ips': { body: { data: [] } } }) });
    expect(await screen.findByText('Nothing is blocked right now')).toBeInTheDocument();
  });
});
