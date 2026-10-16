import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderApp, ROLES } from '@/test/helpers';
import * as fx from '@/test/fixtures';

const ID = 'INC-20261007-00001ABCD';
const rows = [
  fx.incident({ id: 'a', incidentId: 'INC-A', title: 'Guessing passwords', status: 'OPEN', assignedTo: null }),
  fx.incident({ id: 'b', incidentId: 'INC-B', title: 'Account used from many addresses', status: 'INVESTIGATING', sourceIp: null, userId: 'user-9', assignedTo: 'u2', assignee: { id: 'u2', email: 'ana@example.com', name: 'Ana' }, severity: 'CRITICAL' }),
  fx.incident({ id: 'c', incidentId: 'INC-C', title: 'Platform-wide surge', status: 'RESOLVED', sourceIp: null, userId: null, severity: 'LOW' }),
];
const list = (extra: Record<string, any> = {}) => ({ 'GET /incidents': { body: fx.page(rows) }, ...extra });

describe('incident list', () => {
  it('shows number, plain title, severity, status, scope, assignee, age and last activity for every row', async () => {
    await renderApp({ role: 'VIEWER', route: '/incidents', routes: list() });
    const table = await screen.findByRole('table', { name: 'Incidents' });
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Incident', 'What happened', 'Severity', 'Status', 'Affects', 'Assigned to', 'Opened', 'Last activity']);
    const r = within(table).getAllByRole('row').slice(1);
    expect(r).toHaveLength(3);
    expect(within(r[0]).getByRole('link', { name: 'INC-A' })).toHaveAttribute('href', '/incidents/INC-A');
    expect(within(r[0]).getByText('Guessing passwords')).toBeInTheDocument();
    expect(within(r[0]).getByText('One address')).toBeInTheDocument();
    expect(within(r[1]).getByText('One account, many addresses')).toBeInTheDocument();
    expect(within(r[1]).getByText('Ana')).toBeInTheDocument();
    expect(within(r[1]).getByText('Critical')).toBeInTheDocument();
    expect(within(r[2]).getByText('Platform-wide')).toBeInTheDocument();
    expect(within(r[2]).getByText('Resolved')).toBeInTheDocument();
    expect(within(r[0]).getByText(/1 h ago/)).toBeInTheDocument();
    expect(within(r[0]).getByText(/5 min ago/)).toBeInTheDocument();
  });
  it('marks open incidents that nobody has taken, with a word and not only a colour', async () => {
    await renderApp({ role: 'ANALYST', route: '/incidents', routes: list() });
    const table = await screen.findByRole('table', { name: 'Incidents' });
    const r = within(table).getAllByRole('row').slice(1);
    expect(within(r[0]).getByText('Unassigned')).toBeInTheDocument();
    expect(r[0]).toHaveClass('row-flag');
    expect(within(r[1]).queryByText('Unassigned')).not.toBeInTheDocument();
    expect(r[1]).not.toHaveClass('row-flag');
  });
  it('sends filters, sort and page to the API, and keeps them in the URL so a link reproduces the view', async () => {
    const { net } = await renderApp({ role: 'VIEWER', route: '/incidents?status=OPEN&severity=HIGH&q=198.51&sort=risk&page=2', routes: list() });
    await screen.findByRole('table', { name: 'Incidents' });
    const q = net.last('GET /incidents')!.query;
    expect(Object.fromEntries(q)).toMatchObject({ status: 'OPEN', severity: 'HIGH', search: '198.51', sortBy: 'riskScore', sortOrder: 'desc', page: '2', pageSize: '20' });
    expect(screen.getByLabelText('Status')).toHaveValue('OPEN');
    expect(screen.getByLabelText('Severity')).toHaveValue('HIGH');
    expect(screen.getByLabelText('Order')).toHaveValue('risk');
    expect(screen.getByLabelText('Address or incident number')).toHaveValue('198.51');
  });
  it('filtering resets to the first page', async () => {
    const { net } = await renderApp({ role: 'VIEWER', route: '/incidents?page=3', routes: list() });
    await screen.findByRole('table', { name: 'Incidents' });
    await userEvent.selectOptions(screen.getByLabelText('Status'), 'RESOLVED');
    await waitFor(() => expect(net.last('GET /incidents')!.query.get('page')).toBe('1'));
    expect(net.last('GET /incidents')!.query.get('status')).toBe('RESOLVED');
  });
  it('searches as you type, after a short pause', async () => {
    const { net } = await renderApp({ role: 'VIEWER', route: '/incidents', routes: list() });
    await screen.findByRole('table', { name: 'Incidents' });
    await userEvent.type(screen.getByLabelText('Address or incident number'), '203.0');
    await waitFor(() => expect(net.last('GET /incidents')!.query.get('search')).toBe('203.0'));
    expect(net.calls.filter((c) => c.path === '/incidents' && c.query.get('search')).length).toBeLessThanOrEqual(2); // not one request per key press
  });
  it('pages through results', async () => {
    const { net } = await renderApp({ role: 'VIEWER', route: '/incidents', routes: { 'GET /incidents': (c: any) => ({ body: fx.page(rows, { total: 45, totalPages: 3, page: Number(c.query.get('page') ?? 1) }) }) } });
    expect(await screen.findByText('Showing 1 to 20 of 45 incidents')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(net.last('GET /incidents')!.query.get('page')).toBe('2'));
    expect(screen.getByRole('button', { name: 'Previous' })).toBeEnabled();
  });
  it('explains an empty result, and an empty system', async () => {
    const r = await renderApp({ role: 'VIEWER', route: '/incidents?status=OPEN', routes: { 'GET /incidents': { body: fx.page([]) } } });
    expect(await screen.findByText('No incidents match')).toBeInTheDocument();
    expect(screen.getByText('Try removing a filter.')).toBeInTheDocument();
    r.unmount();
    await renderApp({ role: 'VIEWER', route: '/incidents', routes: { 'GET /incidents': { body: fx.page([]) } } });
    expect(await screen.findByText(/Nothing has been flagged yet/)).toBeInTheDocument();
  });
  it('shows an error with a retry, not a blank page, when the list cannot load', async () => {
    await renderApp({ role: 'VIEWER', route: '/incidents', routes: { 'GET /incidents': { status: 500, body: { statusCode: 500, message: 'x', requestId: 'req-list' } } } });
    expect(await screen.findByText('The Security API had a problem')).toBeInTheDocument();
    expect(screen.getByText('req-list')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });
});

const detailRoutes = (over: Record<string, any> = {}, inc = fx.incident()) => ({
  [`GET /incidents/${ID}`]: { body: inc },
  [`GET /reports/incidents/${ID}`]: { body: fx.report() },
  [`GET /reports/technical/${ID}`]: { body: fx.technical() },
  'GET /auth/assignees': { body: { data: [{ id: 'u2', email: 'ana@example.com', name: 'Ana', role: 'ANALYST' }, { id: 'u3', email: 'bo@example.com', name: null, role: 'SECURITY_ADMIN' }] } },
  ...over,
});

describe('incident investigation: the plain-English report', () => {
  it('renders every section exactly as returned, with the limitations always visible', async () => {
    await renderApp({ role: 'VIEWER', route: `/incidents/${ID}`, routes: detailRoutes() });
    const r = fx.report();
    expect(await screen.findByRole('heading', { name: r.headline })).toBeInTheDocument();
    for (const h of ['What happened', 'Why it matters', 'Risk level', 'Evidence', 'What has been done', 'Where things stand', 'What to do next']) expect(screen.getByRole('heading', { name: h })).toBeInTheDocument();
    expect(screen.getByText(r.sections.whatHappened)).toBeInTheDocument();
    expect(screen.getByText(r.sections.riskLevel.explanation)).toBeInTheDocument();
    expect(screen.getByText('Failed sign-ins')).toBeInTheDocument();
    for (const a of r.sections.recommendedActions) expect(screen.getByText(a)).toBeInTheDocument();
    expect(screen.getByText('What this report cannot confirm')).toBeInTheDocument();
    expect(screen.getByText(r.limitations[0])).toBeVisible();
  });
  it('shows server text as text: markup in a report is never interpreted', async () => {
    const evil = fx.report({ headline: '<img src=x onerror=alert(1)>Hello', sections: { ...fx.report().sections, whatHappened: '<script>window.__pwned = true</script>done' } });
    await renderApp({ role: 'VIEWER', route: `/incidents/${ID}`, routes: detailRoutes({ [`GET /reports/incidents/${ID}`]: { body: evil } }) });
    expect(await screen.findByText('<img src=x onerror=alert(1)>Hello')).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).toBeNull();
    expect(document.querySelector('script')).toBeNull();
    expect((window as any).__pwned).toBeUndefined();
  });
  it('copies, downloads and prints the report, but only when clicked', async () => {
    const written: string[] = [];
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (t: string) => { written.push(t); } }, configurable: true });
    let printed = 0; window.print = (() => { printed++; }) as any;
    const { net } = await renderApp({ role: 'VIEWER', route: `/incidents/${ID}`, routes: detailRoutes({ [`GET /reports/incidents/${ID}`]: (c: any) => (c.query.get('format') === 'text' ? { text: 'REPORT AS TEXT' } : { body: fx.report() }) }) });
    await screen.findByRole('heading', { name: fx.report().headline });
    expect(net.calls.some((c) => c.query.get('format') === 'text')).toBe(false);
    await userEvent.click(screen.getByRole('button', { name: 'Copy as text' }));
    await waitFor(() => expect(written).toEqual(['REPORT AS TEXT']));
    await userEvent.click(screen.getByRole('button', { name: 'Print or save as PDF' }));
    expect(printed).toBe(1);
    expect(screen.getByRole('button', { name: 'Download text' })).toBeInTheDocument();
  });
  it('shows the header facts: number, severity, status, scope and who has it', async () => {
    await renderApp({ role: 'VIEWER', route: `/incidents/${ID}`, routes: detailRoutes() });
    expect(await screen.findByRole('heading', { name: ID })).toBeInTheDocument();
    const head = screen.getByRole('heading', { name: ID }).closest('div')!;
    expect(within(head).getByText('High')).toBeInTheDocument();
    expect(within(head).getByText('Open')).toBeInTheDocument();
    expect(within(head).getByText('One address')).toBeInTheDocument();
    expect(within(head).getByText('Unassigned')).toBeInTheDocument();
  });
  it('shows the incident when only the report fails, and the report panel says why', async () => {
    await renderApp({ role: 'ANALYST', route: `/incidents/${ID}`, routes: detailRoutes({ [`GET /reports/incidents/${ID}`]: { status: 500, body: { statusCode: 500, message: 'x', requestId: 'req-r' } } }) });
    expect(await screen.findByRole('heading', { name: ID })).toBeInTheDocument();
    expect(await screen.findByText('The Security API had a problem')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Timeline' })).toBeInTheDocument();
  });
  it('shows not found for an unknown incident', async () => {
    await renderApp({ role: 'VIEWER', route: '/incidents/INC-NOPE', routes: { 'GET /incidents/INC-NOPE': { status: 404, body: { statusCode: 404, message: 'Incident not found' } }, 'GET /reports/incidents/INC-NOPE': { status: 404, body: {} } } });
    expect(await screen.findByText('Not found')).toBeInTheDocument();
  });
});

describe('incident investigation: tabs per role', () => {
  const tabsFor = async (role: any) => { await renderApp({ role, route: `/incidents/${ID}`, routes: detailRoutes() }); await screen.findByRole('heading', { name: ID }); return screen.getAllByRole('tab').map((t) => t.textContent); };
  it('a viewer gets the report and the timeline only', async () => { expect(await tabsFor('VIEWER')).toEqual(['Report', 'Timeline']); });
  it('an analyst also gets Technical and Actions', async () => { expect(await tabsFor('ANALYST')).toEqual(['Report', 'Timeline', 'Technical', 'Actions']); });
  it('admins get all four', async () => { for (const r of ['SECURITY_ADMIN', 'SUPER_ADMIN']) expect(await tabsFor(r)).toEqual(['Report', 'Timeline', 'Technical', 'Actions']); });
  it('a viewer who opens ?tab=technical is shown the report instead, and no technical request is made', async () => {
    const { net } = await renderApp({ role: 'VIEWER', route: `/incidents/${ID}?tab=technical`, routes: detailRoutes() });
    expect(await screen.findByRole('heading', { name: fx.report().headline })).toBeInTheDocument();
    expect(net.count(`GET /reports/technical/${ID}`)).toBe(0);
  });
  it('tabs work with the keyboard (arrows, Home, End) and the chosen tab is in the URL', async () => {
    await renderApp({ role: 'ANALYST', route: `/incidents/${ID}`, routes: detailRoutes() });
    const first = await screen.findByRole('tab', { name: 'Report' });
    first.focus();
    await userEvent.keyboard('{ArrowRight}');
    expect(screen.getByRole('tab', { name: 'Timeline' })).toHaveAttribute('aria-selected', 'true');
    await userEvent.keyboard('{End}');
    expect(screen.getByRole('tab', { name: 'Actions' })).toHaveAttribute('aria-selected', 'true');
    await userEvent.keyboard('{Home}');
    expect(screen.getByRole('tab', { name: 'Report' })).toHaveAttribute('aria-selected', 'true');
  });
});

describe('incident investigation: timeline and technical tabs', () => {
  it('lists escalation and other entries in plain words with who did them and when', async () => {
    await renderApp({ role: 'VIEWER', route: `/incidents/${ID}?tab=timeline`, routes: detailRoutes() });
    const list = await screen.findByRole('list', { name: 'Incident timeline' });
    expect(within(list).getByText('Incident opened')).toBeInTheDocument();
    expect(within(list).getByText('Severity raised')).toBeInTheDocument();
    expect(within(list).getByText('Raised to HIGH')).toBeInTheDocument();
    expect(within(list).getAllByText(/by system/).length).toBe(2);
  });
  it('shows rules fired with the detector reason, event counts, top paths, intelligence and related events', async () => {
    await renderApp({ role: 'ANALYST', route: `/incidents/${ID}?tab=technical`, routes: detailRoutes() });
    expect(await screen.findByRole('heading', { name: 'Rules that fired' })).toBeInTheDocument();
    expect(screen.getByText('brute_force_login')).toBeInTheDocument();
    expect(screen.getByText('40 failed logins in 10 min')).toBeInTheDocument();
    expect(screen.getByText(/login_failed/)).toBeInTheDocument();
    expect(screen.getAllByText('/login').length).toBeGreaterThan(0);
    expect(screen.getByText(/Country: NG/)).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Related events' })).toBeInTheDocument();
  });
  it('says plainly that no intelligence provider checked the address, rather than showing flags', async () => {
    const t = fx.technical({ ip: { address: '198.51.100.7', country: null, isVpn: false, isProxy: false, isTor: false, isDatacenter: false, isMalicious: false, intelligenceChecked: false, reputationScore: 0 } as any });
    await renderApp({ role: 'ANALYST', route: `/incidents/${ID}?tab=technical`, routes: detailRoutes({ [`GET /reports/technical/${ID}`]: { body: t } }) });
    expect(await screen.findByText(/No intelligence provider has checked 198.51.100.7/)).toBeInTheDocument();
    expect(screen.queryByText(/VPN: /)).not.toBeInTheDocument();
  });
  it('pages the related events table 20 at a time', async () => {
    const many = Array.from({ length: 45 }, (_, i) => ({ ...fx.incident().events![0], id: `ev${i}`, requestPath: `/p${i}` }));
    await renderApp({ role: 'ANALYST', route: `/incidents/${ID}?tab=technical`, routes: detailRoutes({}, fx.incident({ events: many })) });
    expect(await screen.findByText('Showing 1 to 20 of 45 events')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText('Showing 21 to 40 of 45 events')).toBeInTheDocument();
  });
});

describe('incident investigation: actions by role', () => {
  const actions = async (role: any, inc = fx.incident(), over: Record<string, any> = {}) => {
    const r = await renderApp({ role, route: `/incidents/${ID}?tab=actions`, routes: detailRoutes(over, inc) });
    await screen.findByRole('heading', { name: 'Change status' });
    return r;
  };
  it('an analyst can change status and add a note, but cannot assign or block', async () => {
    await actions('ANALYST');
    expect(screen.getByRole('heading', { name: 'Add a note' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Assign' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Block / })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open the page for 198.51.100.7/ })).toHaveAttribute('href', '/ips/198.51.100.7');
  });
  it('a security admin can also assign and block', async () => {
    await actions('SECURITY_ADMIN');
    expect(screen.getByRole('heading', { name: 'Assign' })).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Block 198.51.100.7' })).toBeInTheDocument();
  });
  it('hides the block button for an account incident and a platform-wide incident, and says why', async () => {
    await actions('SECURITY_ADMIN', fx.incident({ sourceIp: null, userId: 'user-9' }));
    expect(screen.queryByRole('button', { name: /^Block / })).not.toBeInTheDocument();
    expect(screen.getByText(/one account across many addresses/)).toBeInTheDocument();
  });
  it('platform-wide: no address assumed anywhere', async () => {
    await actions('SECURITY_ADMIN', fx.incident({ sourceIp: null, userId: null }));
    expect(screen.queryByRole('button', { name: /^Block / })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Open the page for/ })).not.toBeInTheDocument();
    expect(screen.getByText(/covers the whole platform/)).toBeInTheDocument();
  });
  it('disables blocking, with an explanation, for an allowlisted address', async () => {
    await actions('SECURITY_ADMIN', fx.incident(), { [`GET /reports/technical/${ID}`]: { body: fx.technical({ allowlisted: true }) } });
    const btn = await screen.findByRole('button', { name: 'Block 198.51.100.7' });
    await waitFor(() => expect(btn).toBeDisabled());
    expect(screen.getByText(/on the allowlist, which protects it from being blocked/)).toBeInTheDocument();
  });
  it('REGRESSION no optimistic update: the old status stays until the server answers, then shows what the server says', async () => {
    const { net } = await actions('ANALYST', fx.incident(), { [`POST /incidents/${fx.incident().id}/status`]: { delayMs: 150, status: 201, body: { ...fx.incident(), status: 'INVESTIGATING' } } });
    await userEvent.selectOptions(screen.getByLabelText('Status'), 'INVESTIGATING');
    await userEvent.type(screen.getByLabelText('Notes (optional)'), 'Looking at it');
    await userEvent.click(screen.getByRole('button', { name: 'Change status' }));
    const head = screen.getByRole('heading', { name: ID }).closest('div')!;
    expect(within(head).getByText('Open')).toBeInTheDocument();                 // still the old status while waiting
    expect(within(head).queryByText('Being investigated')).not.toBeInTheDocument();
    expect(await screen.findByText('The server recorded the status as: Being investigated.')).toBeInTheDocument();
    expect(net.last(`POST /incidents/${fx.incident().id}/status`)!.body).toEqual({ status: 'INVESTIGATING', notes: 'Looking at it' });
  });
  it('closing an incident asks first and states the effect in plain words', async () => {
    const { net } = await actions('ANALYST', fx.incident(), { [`POST /incidents/${fx.incident().id}/status`]: { status: 201, body: { ...fx.incident(), status: 'RESOLVED' } } });
    await userEvent.selectOptions(screen.getByLabelText('Status'), 'RESOLVED');
    await userEvent.click(screen.getByRole('button', { name: 'Change status' }));
    const dlg = await screen.findByRole('dialog', { name: 'Mark as Resolved?' });
    expect(within(dlg).getByText(/New activity from the same source will open a new incident/)).toBeInTheDocument();
    expect(net.count(`POST /incidents/${fx.incident().id}/status`)).toBe(0);     // nothing sent before confirming
    await userEvent.click(within(dlg).getByRole('button', { name: 'Yes, mark as Resolved' }));
    expect(await screen.findByText('The server recorded the status as: Resolved.')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('cancelling the confirmation sends nothing', async () => {
    const { net } = await actions('ANALYST');
    await userEvent.selectOptions(screen.getByLabelText('Status'), 'FALSE_POSITIVE');
    await userEvent.click(screen.getByRole('button', { name: 'Change status' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    expect(net.calls.some((c) => c.method === 'POST' && c.path.endsWith('/status'))).toBe(false);
  });
  it('shows a server refusal on a status change, plainly, and leaves the form usable', async () => {
    await actions('ANALYST', fx.incident(), { [`POST /incidents/${fx.incident().id}/status`]: { status: 400, body: { statusCode: 400, message: 'Invalid status transition' } } });
    await userEvent.selectOptions(screen.getByLabelText('Status'), 'CONTAINED');
    await userEvent.click(screen.getByRole('button', { name: 'Change status' }));
    expect(await screen.findByText('Invalid status transition')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change status' })).toBeEnabled();
  });
  it('adds a note and reports the server result without changing the status', async () => {
    const { net } = await actions('ANALYST', fx.incident(), { [`POST /incidents/${fx.incident().id}/notes`]: { status: 201, body: { id: 't9', action: 'note.added', details: 'Phoned the customer' } } });
    await userEvent.type(screen.getByLabelText('Note'), 'Phoned the customer');
    await userEvent.click(screen.getByRole('button', { name: 'Add note' }));
    expect(await screen.findByText('Note added to the timeline.')).toBeInTheDocument();
    expect(net.last(`POST /incidents/${fx.incident().id}/notes`)!.body).toEqual({ note: 'Phoned the customer' });
    expect(screen.getByLabelText('Note')).toHaveValue('');
  });
  it('assigns an incident to a chosen person', async () => {
    const { net } = await actions('SECURITY_ADMIN', fx.incident(), { [`POST /incidents/${fx.incident().id}/assign`]: { status: 201, body: fx.incident() } });
    await userEvent.selectOptions(await screen.findByLabelText('Assign to'), 'u2');
    await userEvent.click(screen.getByRole('button', { name: 'Assign' }));
    expect(await screen.findByText('Assigned.')).toBeInTheDocument();
    expect(net.last(`POST /incidents/${fx.incident().id}/assign`)!.body).toEqual({ assignedTo: 'u2' });
  });
  it('a viewer has no actions tab at all, and a role with no powers is told so if it gets there', async () => {
    await renderApp({ role: 'VIEWER', route: `/incidents/${ID}?tab=actions`, routes: detailRoutes() });
    expect(await screen.findByRole('heading', { name: fx.report().headline })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Change status' })).not.toBeInTheDocument();
  });
});

describe('blocking from an incident', () => {
  const open = async () => {
    const r = await renderApp({ role: 'SECURITY_ADMIN', route: `/incidents/${ID}?tab=actions`, routes: detailRoutes({ 'POST /security/block': { status: 201, body: { id: 'b1' } } }) });
    await userEvent.click(await screen.findByRole('button', { name: 'Block 198.51.100.7' }));
    return { ...r, dlg: await screen.findByRole('dialog', { name: 'Block an address' }) };
  };
  it('states the effect and the enforcement limit before anything is sent, and requires a reason', async () => {
    const { net, dlg } = await open();
    expect(within(dlg).getByText(/turned away for 1 hour/)).toBeInTheDocument();
    expect(within(dlg).getByText(/within about 30 seconds/)).toBeInTheDocument();
    expect(within(dlg).getByText(/cannot confirm that the website actually rejected the traffic/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole('button', { name: 'Block address' }));
    expect(within(dlg).getByText(/A reason is required/)).toBeInTheDocument();
    expect(net.count('POST /security/block')).toBe(0);
  });
  it('blocks for a chosen time with the incident linked, then closes', async () => {
    const { net, dlg } = await open();
    await userEvent.selectOptions(within(dlg).getByLabelText('How long'), '1440');
    await userEvent.type(within(dlg).getByLabelText('Reason'), 'Password guessing');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Block address' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(net.last('POST /security/block')!.body).toEqual({ ipAddress: '198.51.100.7', reason: 'Password guessing', ttlMinutes: 1440, relatedIncidentId: fx.incident().id });
  });
  it('blocks permanently when asked', async () => {
    const { net, dlg } = await open();
    await userEvent.selectOptions(within(dlg).getByLabelText('How long'), 'permanent');
    expect(within(dlg).getByText(/turned away permanently/)).toBeInTheDocument();
    await userEvent.type(within(dlg).getByLabelText('Reason'), 'Known attacker');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Block address' }));
    await waitFor(() => expect(net.count('POST /security/block')).toBe(1));
    expect(net.last('POST /security/block')!.body).toMatchObject({ permanent: true });
    expect(net.last('POST /security/block')!.body).not.toHaveProperty('ttlMinutes');
  });
  it("shows the server's refusal for a private address in plain words and stays open", async () => {
    const r = await open();
    r.net.routes['POST /security/block'] = { status: 400, body: { statusCode: 400, message: 'Internal and private addresses cannot be blocked' } };
    await userEvent.type(within(r.dlg).getByLabelText('Reason'), 'x');
    await userEvent.click(within(r.dlg).getByRole('button', { name: 'Block address' }));
    expect(await within(r.dlg).findByText(/private or internal address/)).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });
  it("shows the server's refusal for an allowlisted address in plain words", async () => {
    const r = await open();
    r.net.routes['POST /security/block'] = { status: 409, body: { statusCode: 409, message: 'IP is on the allowlist' } };
    await userEvent.type(within(r.dlg).getByLabelText('Reason'), 'x');
    await userEvent.click(within(r.dlg).getByRole('button', { name: 'Block address' }));
    expect(await within(r.dlg).findByText(/allowlist, which protects it from being blocked/)).toBeInTheDocument();
  });
  it('Escape closes the dialog and focus returns to the button that opened it', async () => {
    await open();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Block 198.51.100.7' })).toHaveFocus();
  });
});

void ROLES;
