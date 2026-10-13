import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api, buildUrl } from './client';
import { ApiError, describeError, isNetwork } from './errors';
import { __resetForTests, getState, signIn } from './session';
import { setConfig } from '@/lib/config';
import { API, baseRoutes, installFetch, jwt, type Net } from '@/test/helpers';

let net: Net;
beforeEach(async () => {
  __resetForTests();
  setConfig({ apiBaseUrl: API });
  net = installFetch(baseRoutes('ANALYST'));
  await signIn('a@b.ng', 'a-long-password-1');
  net.calls.length = 0;
});

describe('building requests', () => {
  it('builds a URL with only the filters that have values', () => {
    expect(buildUrl('/incidents', { page: 2, status: '', severity: undefined, search: 'a b', flag: false })).toBe(`${API}/api/v1/incidents?page=2&search=a+b&flag=false`);
    expect(buildUrl('/health')).toBe(`${API}/api/v1/health`);
  });
  it('sends the access token in a header, never in the URL, and sends no cookies on ordinary calls', async () => {
    net.routes['GET /incidents'] = { body: { data: [] } };
    await api('/incidents', { query: { page: 1 } });
    const [url, init] = (fetch as any).mock.calls.at(-1);
    expect(String(url)).not.toMatch(/token|bearer|eyJ|\.sig/i);
    expect(init.headers.Authorization).toMatch(/^Bearer .+\..+\./);
    expect(init.credentials).toBe('omit');
  });
  it('sends no token on public calls', async () => {
    net.routes['GET /health'] = { body: { status: 'ok' } };
    await api('/health', { anonymous: true });
    expect((fetch as any).mock.calls.at(-1)[1].headers.Authorization).toBeUndefined();
  });
  it('asks for plain text when told to', async () => {
    net.routes['GET /reports/x'] = { text: 'hello' };
    expect(await api('/reports/x', { text: true, query: { format: 'text' } })).toBe('hello');
  });
});

describe('a 401 triggers a silent refresh, once, then retries', () => {
  it('refreshes and retries the call with the new token', async () => {
    let n = 0;
    net.routes['GET /incidents'] = () => (++n === 1 ? { status: 401, body: { message: 'expired' } } : { body: { data: ['ok'] } });
    net.routes['POST /auth/refresh'] = { status: 201, body: { user: { id: 'u', email: 'a@b.ng', role: 'ANALYST', name: null, isActive: true, mustChangePassword: false }, accessToken: jwt(), csrfToken: 'csrf-9' } };
    expect(await api('/incidents')).toEqual({ data: ['ok'] });
    expect(net.count('POST /auth/refresh')).toBe(1);
    expect(net.count('GET /incidents')).toBe(2);
  });
  it('sends the CSRF token it fetched, with credentials, when refreshing', async () => {
    let n = 0;
    net.routes['GET /incidents'] = () => (++n === 1 ? { status: 401, body: {} } : { body: {} });
    await api('/incidents');
    const refresh = (fetch as any).mock.calls.find((c: any[]) => String(c[0]).endsWith('/auth/refresh'));
    expect(refresh[1].credentials).toBe('include');
    expect(refresh[1].headers['X-CSRF-Token']).toBe('csrf-1');
    expect(String(refresh[0])).not.toMatch(/csrf|token/);
  });
  it('shares one refresh between concurrent requests that all hit a 401', async () => {
    const seen = new Set<string>();
    const answer = (c: any) => (c.headers.Authorization === `Bearer ${[...seen][0]}` && seen.size ? { status: 401, body: {} } : { body: { ok: true } });
    let first = '';
    net.routes['GET /a'] = (c) => { first ||= c.headers.Authorization; return c.headers.Authorization === first ? { status: 401, body: {} } : { body: { a: 1 } }; };
    net.routes['GET /b'] = (c) => (c.headers.Authorization === first ? { status: 401, body: {} } : { body: { b: 1 } });
    net.routes['GET /c'] = (c) => (c.headers.Authorization === first ? { status: 401, body: {} } : { body: { c: 1 } });
    net.routes['POST /auth/refresh'] = { delayMs: 20, status: 201, body: { user: { id: 'u', email: 'a@b.ng', role: 'ANALYST', name: null, isActive: true, mustChangePassword: false }, accessToken: jwt(800), csrfToken: 'x' } };
    void answer; void seen;
    const r = await Promise.all([api('/a'), api('/b'), api('/c')]);
    expect(r).toEqual([{ a: 1 }, { b: 1 }, { c: 1 }]);
    expect(net.count('POST /auth/refresh')).toBe(1);
  });
  it('signs out, with the reason "expired", when the refresh is refused', async () => {
    net.routes['GET /incidents'] = { status: 401, body: {} };
    net.routes['POST /auth/refresh'] = { status: 401, body: { statusCode: 401, message: 'Refresh token expired or revoked' } };
    await expect(api('/incidents')).rejects.toMatchObject({ status: 401 });
    expect(getState()).toMatchObject({ status: 'signedOut', reason: 'expired', user: null });
  });
  it('signs out with the reason "compromised" when the server reports a reused token', async () => {
    net.routes['GET /incidents'] = { status: 401, body: {} };
    net.routes['POST /auth/refresh'] = { status: 401, body: { statusCode: 401, message: 'Refresh token expired or revoked', code: 'refresh_token_reuse' } };
    await expect(api('/incidents')).rejects.toBeInstanceOf(ApiError);
    expect(getState()).toMatchObject({ status: 'signedOut', reason: 'compromised' });
  });
  it('does not sign out when the server is merely unreachable during a refresh', async () => {
    net.routes['GET /incidents'] = { status: 401, body: {} };
    net.routes['POST /auth/refresh'] = { status: 503, body: {} };
    await expect(api('/incidents')).rejects.toBeInstanceOf(ApiError);
    expect(getState().status).toBe('signedIn');
  });
  it('gives up after one retry rather than looping, and reports the answer without ending a session that just refreshed', async () => {
    net.routes['GET /incidents'] = { status: 401, body: { statusCode: 401, message: 'Nope' } };
    await expect(api('/incidents')).rejects.toMatchObject({ status: 401, message: 'Nope' });
    expect(net.count('GET /incidents')).toBe(2);
    expect(getState().status).toBe('signedIn');
  });
  it('REGRESSION wrong current password: a 401 from change-password is an answer, not an ended session', async () => {
    net.routes['POST /auth/change-password'] = { status: 401, body: { statusCode: 401, message: 'Current password invalid' } };
    await expect(api('/auth/change-password', { method: 'POST', body: {}, refusal401: true })).rejects.toMatchObject({ status: 401, message: 'Current password invalid' });
    expect(net.count('POST /auth/refresh')).toBe(0);
    expect(net.count('POST /auth/change-password')).toBe(1);
    expect(getState().status).toBe('signedIn');
  });
});

describe('error handling', () => {
  it('403 is an access problem and does not sign out', async () => {
    net.routes['GET /rules'] = { status: 403, body: { statusCode: 403, message: 'Forbidden', requestId: 'r1' } };
    const e: any = await api('/rules').catch((x) => x);
    expect(e.status).toBe(403);
    expect(describeError(e).title).toMatch(/do not have access/);
    expect(getState().status).toBe('signedIn');
  });
  it('429 carries the wait time from Retry-After', async () => {
    net.routes['GET /incidents'] = { status: 429, headers: { 'Retry-After': '42' }, body: { message: 'Too many requests' } };
    const e: any = await api('/incidents').catch((x) => x);
    expect(e.retryAfterSeconds).toBe(42);
    expect(describeError(e).body).toMatch(/42 seconds/);
  });
  it('5xx shows the request id so support can find it', async () => {
    net.routes['GET /incidents'] = { status: 500, body: { statusCode: 500, message: 'Internal server error', requestId: 'req-abc-123' } };
    const e: any = await api('/incidents').catch((x) => x);
    expect(describeError(e).requestId).toBe('req-abc-123');
    expect(describeError(e).body).not.toMatch(/stack|Error:|at /);
  });
  it('a network failure says the API cannot be reached', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    const e: any = await api('/incidents').catch((x) => x);
    expect(e.kind).toBe('network');
    expect(isNetwork(e)).toBe(true);
    expect(describeError(e).title).toBe('Cannot reach the Security API');
  });
  it('404 and a validation list are described in plain words', async () => {
    net.routes['GET /incidents/nope'] = { status: 404, body: { statusCode: 404, message: 'Incident not found' } };
    expect(describeError(await api('/incidents/nope').catch((x) => x)).title).toBe('Not found');
    net.routes['POST /x'] = { status: 400, body: { statusCode: 400, message: ['reason must not be empty', 'ttlMinutes must be a number'] } };
    expect(describeError(await api('/x', { method: 'POST', body: {} }).catch((x) => x)).body).toContain('reason must not be empty');
  });
  it('turns the two known block refusals into plain words', () => {
    const priv = new ApiError({ kind: 'http', status: 400, message: 'Internal and private addresses cannot be blocked' });
    const allow = new ApiError({ kind: 'http', status: 409, message: 'IP is on the allowlist' });
    expect(describeError(priv).body).toMatch(/private or internal address/);
    expect(describeError(allow).body).toMatch(/allowlist, which protects it/);
  });
  it('never shows raw JSON or an unknown error object', () => {
    expect(describeError(new Error('secret stack'))).toMatchObject({ title: 'Something went wrong' });
    expect(JSON.stringify(describeError(new Error('secret stack')))).not.toContain('secret stack');
  });
  it('a password-change-required answer flags the session so the app can redirect', async () => {
    net.routes['GET /incidents'] = { status: 403, body: { statusCode: 403, message: 'You must change your password before continuing', code: 'password_change_required' } };
    await api('/incidents').catch(() => undefined);
    expect(getState().user?.mustChangePassword).toBe(true);
  });
  it('refuses to call the API when signed out', async () => {
    __resetForTests();
    await expect(api('/incidents')).rejects.toMatchObject({ status: 401 });
  });
});
