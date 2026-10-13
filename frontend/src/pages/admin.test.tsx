import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderApp } from '@/test/helpers';
import * as fx from '@/test/fixtures';

describe('users (super admin)', () => {
  const rows = [fx.userRow('SUPER_ADMIN', { id: 'u-SUPER_ADMIN', email: 'super_admin@pishon.ng' }), fx.userRow('ANALYST', { id: 'u2', email: 'ana@pishon.ng', name: 'Ana' }), fx.userRow('VIEWER', { id: 'u3', email: 'vi@pishon.ng', isActive: false, mustChangePassword: true })];
  const base = (over: Record<string, any> = {}) => ({ 'GET /auth/users': { body: { data: rows } }, 'GET /auth/assignees': { body: { data: [] } }, ...over });
  const open = (over: Record<string, any> = {}) => renderApp({ role: 'SUPER_ADMIN', route: '/admin/users', routes: base(over) });

  it('lists accounts with role, status, last sign-in and whether a password change is pending', async () => {
    await open();
    const t = await screen.findByRole('table', { name: 'Accounts' });
    expect(within(t).getByText('Ana')).toBeInTheDocument();
    expect(within(t).getByText('Deactivated')).toBeInTheDocument();
    expect(within(t).getByText('Must be changed')).toBeInTheDocument();
    expect(within(t).getAllByText('Active').length).toBe(2);
  });
  it('shows the safeguards, and removes the controls that would break them on your own row', async () => {
    await open();
    await screen.findByRole('table', { name: 'Accounts' });
    expect(screen.getByText(/cannot change your own role or deactivate yourself/)).toBeInTheDocument();
    expect(screen.getByText(/last active super admin can never be demoted/)).toBeInTheDocument();
    const me = screen.getByText('You').closest('tr')!;
    expect(within(me).queryByRole('combobox')).not.toBeInTheDocument();
    expect(within(me).queryByRole('button', { name: /Deactivate/ })).not.toBeInTheDocument();
    expect(within(me).getByText(/cannot change your own role/)).toBeInTheDocument();
  });
  it('changes a role only after a plain-words confirmation, and shows the server result', async () => {
    const { net } = await open({ 'PATCH /auth/users/u2': { body: { ...rows[1], role: 'SECURITY_ADMIN' } } });
    await userEvent.selectOptions(await screen.findByLabelText('Role for ana@pishon.ng'), 'SECURITY_ADMIN');
    const dlg = await screen.findByRole('dialog', { name: 'Change ana@pishon.ng to Security admin?' });
    expect(within(dlg).getByText(/Block and unblock addresses/)).toBeInTheDocument();
    expect(net.count('PATCH /auth/users/u2')).toBe(0);
    await userEvent.click(within(dlg).getByRole('button', { name: 'Change role' }));
    await waitFor(() => expect(net.last('PATCH /auth/users/u2')!.body).toEqual({ role: 'SECURITY_ADMIN' }));
    expect(await screen.findByText('ana@pishon.ng is now Security admin.')).toBeInTheDocument();
  });
  it("shows the server's refusal when demoting the last super admin, and leaves the dialog open", async () => {
    await open({ 'PATCH /auth/users/u2': { status: 409, body: { statusCode: 409, message: 'This is the last active super admin. Make another account a super admin first.', code: 'last_super_admin' } } });
    await userEvent.click(await screen.findByRole('button', { name: /Deactivate ana@pishon.ng/ }));
    const dlg = await screen.findByRole('dialog', { name: 'Deactivate ana@pishon.ng?' });
    expect(within(dlg).getByText(/signed out everywhere now/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole('button', { name: 'Deactivate' }));
    expect(await within(dlg).findByText(/last active super admin/)).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });
  it('reactivates a deactivated account', async () => {
    const { net } = await open({ 'PATCH /auth/users/u3': { body: { ...rows[2], isActive: true } } });
    await userEvent.click(await screen.findByRole('button', { name: /Reactivate vi@pishon.ng/ }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Reactivate' }));
    await waitFor(() => expect(net.last('PATCH /auth/users/u3')!.body).toEqual({ isActive: true }));
  });
  it('forces a password reset: needs at least 12 characters, ends sessions, and never shows the password afterwards', async () => {
    const { net } = await open({ 'POST /auth/users/u2/reset-password': { status: 201, body: { ok: true } } });
    await userEvent.click(await screen.findByRole('button', { name: /Reset password for ana@pishon.ng/ }));
    const dlg = await screen.findByRole('dialog', { name: 'Reset password for ana@pishon.ng' });
    expect(within(dlg).getByText(/ends every session/)).toBeInTheDocument();
    await userEvent.type(within(dlg).getByLabelText('Temporary password'), 'short');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Reset password' }));
    expect(within(dlg).getByText(/at least 12 characters/)).toBeInTheDocument();
    expect(net.count('POST /auth/users/u2/reset-password')).toBe(0);
    await userEvent.clear(within(dlg).getByLabelText('Temporary password'));
    await userEvent.type(within(dlg).getByLabelText('Temporary password'), 'A-Temporary-Pass-1');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Reset password' }));
    await waitFor(() => expect(net.last('POST /auth/users/u2/reset-password')!.body).toEqual({ newPassword: 'A-Temporary-Pass-1' }));
    expect(await screen.findByText(/All of their sessions were ended/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('A-Temporary-Pass-1');
  });
  it('generates a strong temporary password on request', async () => {
    await open();
    await userEvent.click(await screen.findByRole('button', { name: /Reset password for ana@pishon.ng/ }));
    const dlg = await screen.findByRole('dialog');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Generate' }));
    expect((within(dlg).getByLabelText('Temporary password') as HTMLInputElement).value).toMatch(/^[A-Za-z0-9]{20}$/);
  });
  it('creates an account, asking for a password change at first sign-in by default', async () => {
    const { net } = await open({ 'POST /auth/users': { status: 201, body: fx.userRow('ANALYST') } });
    await userEvent.click(await screen.findByRole('button', { name: 'Create an account' }));
    const dlg = await screen.findByRole('dialog', { name: 'Create an account' });
    await userEvent.type(within(dlg).getByLabelText('Email'), 'new@pishon.ng');
    await userEvent.selectOptions(within(dlg).getByLabelText('Role'), 'ANALYST');
    expect(within(dlg).getByText(/Investigate: raw events/)).toBeInTheDocument();
    await userEvent.type(within(dlg).getByLabelText('Temporary password'), 'Another-Temp-Pass-9');
    expect(within(dlg).getByRole('checkbox')).toBeChecked();
    await userEvent.click(within(dlg).getByRole('button', { name: 'Create account' }));
    await waitFor(() => expect(net.last('POST /auth/users')!.body).toEqual({ email: 'new@pishon.ng', role: 'ANALYST', password: 'Another-Temp-Pass-9', requirePasswordChange: true }));
  });
  it('shows an error panel with a retry if the list cannot load', async () => {
    await renderApp({ role: 'SUPER_ADMIN', route: '/admin/users', routes: { 'GET /auth/users': { status: 500, body: { statusCode: 500, message: 'x', requestId: 'req-u' } } } });
    expect(await screen.findByText('req-u')).toBeInTheDocument();
  });
});

describe('API keys (security admin and above)', () => {
  const RAW = 'PMS_0123456789abcdef0123456789abcdef0123456789abcdef';
  const created = { id: 'k2', name: 'New key', scopes: ['events:write'], expiresAt: null, apiKey: RAW };
  const base = (over: Record<string, any> = {}) => ({ 'GET /api-keys': { body: [fx.apiKey(), fx.apiKey({ id: 'k3', name: 'Old key', keyPrefix: 'PMS_zz99yy88', isActive: false, revokedAt: new Date().toISOString() })] }, ...over });
  it('lists keys with prefix, plain-English permissions, status, last use and expiry, and never a full key', async () => {
    await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/api-keys', routes: base() });
    const t = await screen.findByRole('table', { name: 'API keys' });
    expect(within(t).getByText('PMS_ab12cd34...')).toBeInTheDocument();
    expect(within(t).getAllByText('Send security events, Read the blocked-address list').length).toBe(2);
    expect(within(t).getByText('Revoked')).toBeInTheDocument();
    expect(within(t).getByText('Active')).toBeInTheDocument();
  });
  it('is not for analysts or viewers', async () => {
    for (const role of ['ANALYST', 'VIEWER'] as const) {
      const { net, unmount } = await renderApp({ role, route: '/admin/api-keys' });
      expect(await screen.findByRole('heading', { name: 'You do not have access to this page' })).toBeInTheDocument();
      expect(net.count('GET /api-keys')).toBe(0);
      unmount();
    }
  });
  it('creates a key with plain checkboxes, shows the raw key once in a copy-once dialog, and discards it on close', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/api-keys', routes: base({ 'POST /api-keys': { status: 201, body: created } }) });
    await userEvent.click(await screen.findByRole('button', { name: 'Create an API key' }));
    const dlg = await screen.findByRole('dialog', { name: 'Create an API key' });
    expect(within(dlg).getByText(/Lets the website report what happens on it/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole('button', { name: 'Create key' }));
    expect(within(dlg).getByText(/Give the key a name/)).toBeInTheDocument();
    await userEvent.type(within(dlg).getByLabelText('Name'), 'New key');
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /Read the blocked-address list/ }));
    await userEvent.selectOptions(within(dlg).getByLabelText('Expires'), '90');
    await userEvent.click(within(dlg).getByRole('button', { name: 'Create key' }));
    const once = await screen.findByRole('dialog', { name: 'Your new API key' });
    expect(within(once).getByText(/only time you will see this key/)).toBeInTheDocument();
    expect(within(once).getByTestId('raw-key')).toHaveTextContent(RAW);
    expect(net.last('POST /api-keys')!.body).toEqual({ name: 'New key', scopes: ['events:write'], expiresInDays: 90 });
    const done = within(once).getByRole('button', { name: 'Done' });
    expect(done).toBeDisabled();                                   // cannot close until the person confirms they saved it
    await userEvent.click(within(once).getByRole('checkbox'));
    await userEvent.click(done);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(RAW);          // nothing keeps the key
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(RAW);
  });
  it('Escape does not dismiss the copy-once dialog before the key is saved', async () => {
    await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/api-keys', routes: base({ 'POST /api-keys': { status: 201, body: created } }) });
    await userEvent.click(await screen.findByRole('button', { name: 'Create an API key' }));
    await userEvent.type(within(await screen.findByRole('dialog')).getByLabelText('Name'), 'K');
    await userEvent.click(screen.getByRole('button', { name: 'Create key' }));
    await screen.findByTestId('raw-key');
    await userEvent.keyboard('{Escape}');
    expect(screen.getByTestId('raw-key')).toBeInTheDocument();
  });
  it('rotates a key after explaining the effect, and shows the new key once', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/api-keys', routes: base({ 'POST /api-keys/k1/rotate': { status: 201, body: { ...created, id: 'k1', name: 'PishonMarket website' } } }) });
    await userEvent.click(await screen.findByRole('button', { name: /Rotate PishonMarket website/ }));
    const dlg = await screen.findByRole('dialog', { name: 'Replace "PishonMarket website"?' });
    expect(within(dlg).getByText(/old one stops working immediately/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole('button', { name: 'Replace the key' }));
    expect(await screen.findByRole('dialog', { name: 'New key issued' })).toBeInTheDocument();
    expect(net.count('POST /api-keys/k1/rotate')).toBe(1);
  });
  it('revokes a key after warning that it cannot be turned back on', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/api-keys', routes: base({ 'DELETE /api-keys/k1': { body: { id: 'k1' } } }) });
    await userEvent.click(await screen.findByRole('button', { name: /Revoke PishonMarket website/ }));
    const dlg = await screen.findByRole('dialog', { name: 'Revoke "PishonMarket website"?' });
    expect(within(dlg).getByText(/cannot be turned back on/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole('button', { name: 'Revoke the key' }));
    await waitFor(() => expect(net.count('DELETE /api-keys/k1')).toBe(1));
  });
  it('a revoked key has no actions', async () => {
    await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/api-keys', routes: base() });
    const row = (await screen.findByText('Old key')).closest('tr')!;
    expect(within(row).queryByRole('button')).not.toBeInTheDocument();
  });
});

describe('detection rules (security admin and above)', () => {
  const routes = (over: Record<string, any> = {}) => ({
    'GET /rules': { body: { data: [fx.rule(), fx.rule({ code: 'high_request_rate', title: 'Request flooding', name: 'High request rate', description: 'Too many requests.', whyItMatters: null, isDefault: false, isEnabled: false, config: { windowMinutes: 5, threshold: 90, riskDelta: 25 }, defaultConfig: { windowMinutes: 5, threshold: 60, riskDelta: 25 }, limits: { windowMinutes: { min: 0, max: 0, editable: false }, threshold: { min: 1, max: 1000, editable: true }, riskDelta: { min: 1, max: 100, editable: true } } })] } },
    'GET /audit-logs': { body: fx.page([fx.audit({ action: 'rule.update', targetType: 'rule', targetId: 'brute_force_login', metadata: { old: { isEnabled: true, config: { threshold: 5 } }, new: { isEnabled: true, config: { threshold: 8 } }, reason: 'too noisy' } })]) },
    ...over,
  });
  it('lists rules by plain title with description, state, defaults and the fixed window shown as read-only', async () => {
    await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/rules', routes: routes() });
    const card = (await screen.findByRole('heading', { name: 'Password guessing' })).closest('article')!;
    expect(within(card).getByText('Many failed sign-ins from one address.')).toBeInTheDocument();
    expect(within(card).getByText('On')).toBeInTheDocument();
    expect(within(card).getByText('Default settings')).toBeInTheDocument();
    expect(within(card).getByLabelText('Time window (fixed)')).toBeDisabled();
    expect(within(card).getByText(/The detector always looks at the last 10 minutes/)).toBeInTheDocument();
    expect(within(card).getByLabelText('How many before the rule triggers')).toBeEnabled();
    const other = screen.getByRole('heading', { name: 'Request flooding' }).closest('article')!;
    expect(within(other).getByText('Off')).toBeInTheDocument();
    expect(within(other).getByText('Changed')).toBeInTheDocument();
    expect(within(other).getByText(/Default 60. Allowed 1 to 1000/)).toBeInTheDocument();
  });
  it('is not for analysts or viewers', async () => {
    const { net } = await renderApp({ role: 'ANALYST', route: '/admin/rules' });
    expect(await screen.findByRole('heading', { name: 'You do not have access to this page' })).toBeInTheDocument();
    expect(net.count('GET /rules')).toBe(0);
  });
  it('saves only the settings that changed, with the reason, and reports the result', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/rules', routes: routes({ 'PATCH /rules/brute_force_login': { body: fx.rule({ isDefault: false, config: { windowMinutes: 10, threshold: 8, riskPerAttempt: 8, maxRisk: 70, incidentAt: 8 } }) } }) });
    const card = (await screen.findByRole('heading', { name: 'Password guessing' })).closest('article')!;
    const save = within(card).getByRole('button', { name: 'Save changes' });
    expect(save).toBeDisabled();
    await userEvent.clear(within(card).getByLabelText('How many before the rule triggers'));
    await userEvent.type(within(card).getByLabelText('How many before the rule triggers'), '8');
    await userEvent.clear(within(card).getByLabelText('How many before an incident is opened'));
    await userEvent.type(within(card).getByLabelText('How many before an incident is opened'), '8');
    await userEvent.type(within(card).getByLabelText('Why are you changing this? (optional)'), 'too noisy');
    await userEvent.click(save);
    expect(await within(card).findByText('Saved. The new settings apply to the next event.')).toBeInTheDocument();
    expect(net.last('PATCH /rules/brute_force_login')!.body).toEqual({ config: { threshold: 8, incidentAt: 8 }, reason: 'too noisy' });
  });
  it('REGRESSION the "Saved" message survives the list reloading after a save (the card used to remount and lose it)', async () => {
    let saved = false;
    await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/rules', routes: routes({
      'GET /rules': () => ({ body: { data: [saved ? fx.rule({ isDefault: false, updatedAt: new Date().toISOString(), config: { windowMinutes: 10, threshold: 8, riskPerAttempt: 8, maxRisk: 70, incidentAt: 8 } }) : fx.rule()] } }),
      'PATCH /rules/brute_force_login': () => { saved = true; return { body: fx.rule({ isDefault: false }) }; },
    }) });
    const card = (await screen.findByRole('heading', { name: 'Password guessing' })).closest('article')!;
    await userEvent.clear(within(card).getByLabelText('How many before the rule triggers')); await userEvent.type(within(card).getByLabelText('How many before the rule triggers'), '8');
    await userEvent.clear(within(card).getByLabelText('How many before an incident is opened')); await userEvent.type(within(card).getByLabelText('How many before an incident is opened'), '8');
    await userEvent.click(within(card).getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByText('Saved. The new settings apply to the next event.')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('Changed')).toBeInTheDocument());          // the reloaded list arrived
    expect(screen.getByText('Saved. The new settings apply to the next event.')).toBeInTheDocument();   // and the message is still there
    expect(screen.getByLabelText('How many before the rule triggers')).toHaveValue(8);
  });
  it('catches an out-of-range or non-whole number before sending, and shows the allowed range', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/rules', routes: routes() });
    const card = (await screen.findByRole('heading', { name: 'Password guessing' })).closest('article')!;
    await userEvent.clear(within(card).getByLabelText('How many before the rule triggers'));
    await userEvent.type(within(card).getByLabelText('How many before the rule triggers'), '5000');
    await userEvent.click(within(card).getByRole('button', { name: 'Save changes' }));
    expect(await within(card).findByText('Must be between 1 and 1000.')).toBeInTheDocument();
    expect(net.count('PATCH /rules/brute_force_login')).toBe(0);
  });
  it("shows the server's validation message when it refuses a combination", async () => {
    await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/rules', routes: routes({ 'PATCH /rules/brute_force_login': { status: 400, body: { statusCode: 400, message: ['An incident cannot be opened before the rule itself triggers.'] } } }) });
    const card = (await screen.findByRole('heading', { name: 'Password guessing' })).closest('article')!;
    await userEvent.clear(within(card).getByLabelText('How many before the rule triggers'));
    await userEvent.type(within(card).getByLabelText('How many before the rule triggers'), '20');
    await userEvent.click(within(card).getByRole('button', { name: 'Save changes' }));
    expect(await within(card).findByText(/An incident cannot be opened before the rule itself triggers/)).toBeInTheDocument();
  });
  it('turning a rule off explains the consequence first; turning it on needs no confirmation', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/rules', routes: routes({ 'PATCH /rules/brute_force_login': { body: fx.rule({ isEnabled: false }) }, 'PATCH /rules/high_request_rate': { body: fx.rule({ code: 'high_request_rate' }) } }) });
    const card = (await screen.findByRole('heading', { name: 'Password guessing' })).closest('article')!;
    await userEvent.click(within(card).getByRole('button', { name: 'Turn off' }));
    const dlg = await screen.findByRole('dialog', { name: 'Turn off "Password guessing"?' });
    expect(within(dlg).getByText(/will stop looking for this kind of attack/)).toBeInTheDocument();
    expect(net.count('PATCH /rules/brute_force_login')).toBe(0);
    await userEvent.click(within(dlg).getByRole('button', { name: 'Turn off' }));
    await waitFor(() => expect(net.last('PATCH /rules/brute_force_login')!.body).toMatchObject({ isEnabled: false }));
    const off = screen.getByRole('heading', { name: 'Request flooding' }).closest('article')!;
    await userEvent.click(within(off).getByRole('button', { name: 'Turn on' }));
    await waitFor(() => expect(net.last('PATCH /rules/high_request_rate')!.body).toMatchObject({ isEnabled: true }));
  });
  it('resets to defaults after confirming, and the button is disabled when already at defaults', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/rules', routes: routes({ 'POST /rules/high_request_rate/reset': { status: 201, body: fx.rule({ code: 'high_request_rate', config: { windowMinutes: 5, threshold: 60, riskDelta: 25 }, defaultConfig: { windowMinutes: 5, threshold: 60, riskDelta: 25 }, limits: { windowMinutes: { min: 0, max: 0, editable: false }, threshold: { min: 1, max: 1000, editable: true }, riskDelta: { min: 1, max: 100, editable: true } } }) } }) });
    const first = (await screen.findByRole('heading', { name: 'Password guessing' })).closest('article')!;
    expect(within(first).getByRole('button', { name: 'Reset to defaults' })).toBeDisabled();
    const other = screen.getByRole('heading', { name: 'Request flooding' }).closest('article')!;
    await userEvent.click(within(other).getByRole('button', { name: 'Reset to defaults' }));
    const dlg = await screen.findByRole('dialog', { name: 'Reset "Request flooding" to its defaults?' });
    expect(within(dlg).getByText(/Whether the rule is on or off does not change/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole('button', { name: 'Reset' }));
    await waitFor(() => expect(net.count('POST /rules/high_request_rate/reset')).toBe(1));
  });
  it('shows the change history from the audit log, with old and new values and the reason', async () => {
    const { net } = await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/rules', routes: routes() });
    const card = (await screen.findByRole('heading', { name: 'Password guessing' })).closest('article')!;
    await userEvent.click(within(card).getByRole('button', { name: 'Show change history' }));
    expect(await within(card).findByText(/How many before the rule triggers: 5 to 8/)).toBeInTheDocument();
    expect(within(card).getByText('Reason: too noisy')).toBeInTheDocument();
    const q = net.last('GET /audit-logs')!.query;
    expect(q.get('targetType')).toBe('rule'); expect(q.get('targetId')).toBe('brute_force_login');
  });
});

describe('audit log (analysts and above)', () => {
  const entries = [fx.audit(), fx.audit({ id: 'a2', action: 'auth.login', actorLabel: 'ana@pishon.ng', targetId: null, targetType: null, result: 'FAILURE', metadata: null, ipAddress: null, requestId: null })];
  it('is closed to viewers, and open to analysts', async () => {
    const v = await renderApp({ role: 'VIEWER', route: '/admin/audit' });
    expect(await screen.findByRole('heading', { name: 'You do not have access to this page' })).toBeInTheDocument();
    expect(v.net.count('GET /audit-logs')).toBe(0);
    v.unmount();
    await renderApp({ role: 'ANALYST', route: '/admin/audit', routes: { 'GET /audit-logs': { body: fx.page(entries) } } });
    expect(await screen.findByRole('table', { name: 'Audit log' })).toBeInTheDocument();
  });
  it('shows readable sentences, with the result as words, and details one click deeper', async () => {
    await renderApp({ role: 'ANALYST', route: '/admin/audit', routes: { 'GET /audit-logs': { body: fx.page(entries) } } });
    expect(await screen.findByText('sec@pishon.ng blocked an address (198.51.100.7)')).toBeInTheDocument();
    expect(screen.getByText('ana@pishon.ng signed in and it did not succeed')).toBeInTheDocument();
    const table = screen.getByRole('table', { name: 'Audit log' });
    expect(within(table).getByText('Worked')).toBeInTheDocument();
    expect(within(table).getByText('Did not work')).toBeInTheDocument();
    await userEvent.click(screen.getByText('sec@pishon.ng blocked an address (198.51.100.7)'));
    expect(screen.getByText('ip.block')).toBeInTheDocument();
    expect(screen.getByText(/"reason": "attack"/)).toBeInTheDocument();
  });
  it('filters by action, who, result and dates, in the URL, and sends them to the API', async () => {
    const { net } = await renderApp({ role: 'ANALYST', route: '/admin/audit?action=block&actorType=USER&result=FAILURE&from=2026-10-01&to=2026-10-07&page=2', routes: { 'GET /audit-logs': { body: fx.page(entries) } } });
    await screen.findByRole('table', { name: 'Audit log' });
    const q = Object.fromEntries(net.last('GET /audit-logs')!.query);
    expect(q).toMatchObject({ action: 'block', actorType: 'USER', result: 'FAILURE', page: '2' });
    expect(new Date(q.from).getTime()).toBeLessThan(new Date(q.to).getTime());
  });
  it('shows server text that looks like markup as plain text', async () => {
    await renderApp({ role: 'ANALYST', route: '/admin/audit', routes: { 'GET /audit-logs': { body: fx.page([fx.audit({ actorLabel: '<b>x</b>', metadata: { note: '<img src=x onerror=alert(1)>' } })]) } } });
    expect(await screen.findByText(/<b>x<\/b> blocked an address/)).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).toBeNull();
    expect(document.querySelector('b')).toBeNull();
  });
  it('says so when nothing matches', async () => {
    await renderApp({ role: 'ANALYST', route: '/admin/audit?action=zzz', routes: { 'GET /audit-logs': { body: fx.page([]) } } });
    expect(await screen.findByText('Nothing matches')).toBeInTheDocument();
  });
});

describe('settings (security admin and above)', () => {
  it('shows operational facts read-only, with no secrets, and says when no provider is configured', async () => {
    await renderApp({ role: 'SECURITY_ADMIN', route: '/admin/settings', routes: { 'GET /settings/operational': { body: fx.settings() } } });
    expect(await screen.findByText(/No provider is set up/)).toBeInTheDocument();
    expect(screen.getByText('On')).toBeInTheDocument();
    expect(screen.getByText('85 or more')).toBeInTheDocument();
    expect(screen.getByText(/The Security API is reachable \(version 1.0.0\)/)).toBeInTheDocument();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /save|change|edit/i })).not.toBeInTheDocument();
  });
  it('lists configured providers', async () => {
    await renderApp({ role: 'SUPER_ADMIN', route: '/admin/settings', routes: { 'GET /settings/operational': { body: fx.settings({ intelligenceProviders: ['ipapi', 'tor'] }) } } });
    expect(await screen.findByText(/Providers in use: ipapi, tor/)).toBeInTheDocument();
  });
  it('is closed to analysts and viewers', async () => {
    const { net } = await renderApp({ role: 'ANALYST', route: '/admin/settings' });
    expect(await screen.findByRole('heading', { name: 'You do not have access to this page' })).toBeInTheDocument();
    expect(net.count('GET /settings/operational')).toBe(0);
  });
});
