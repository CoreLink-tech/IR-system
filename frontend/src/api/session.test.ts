import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as S from './session';
import { setConfig } from '@/lib/config';
import { API, baseRoutes, installFetch, jwt, type Net } from '@/test/helpers';

const userBody = (role = 'ANALYST') => ({ id: 'u1', email: 'a@b.ng', name: 'A', role, isActive: true, mustChangePassword: false });
let net: Net;

beforeEach(() => { S.__resetForTests(); setConfig({ apiBaseUrl: API, idleTimeoutMinutes: 30 }); net = installFetch(baseRoutes('ANALYST')); sessionStorage.clear(); });
afterEach(() => { vi.useRealTimers(); });

describe('signing in', () => {
  it('asks for a cookie session, keeps the access token in memory, and never writes a token to storage', async () => {
    const u = await S.signIn('a@b.ng', 'a-long-password-1');
    expect(u.role).toBe('VIEWER' === u.role ? 'VIEWER' : 'ANALYST');
    expect(net.last('POST /auth/login')!.body).toEqual({ email: 'a@b.ng', password: 'a-long-password-1', useCookie: true });
    expect((fetch as any).mock.calls.find((c: any[]) => String(c[0]).endsWith('/auth/login'))[1].credentials).toBe('include');
    expect(S.getState()).toMatchObject({ status: 'signedIn', reason: null });
    expect(JSON.stringify({ ...localStorage })).not.toMatch(/ey|\.sig/);
    expect(JSON.stringify({ ...sessionStorage })).not.toMatch(/ey|\.sig/);
    expect(document.cookie).toBe('');
  });
  it('carries the server error, including a 429 wait time', async () => {
    net.routes['POST /auth/login'] = { status: 429, headers: { 'Retry-After': '30' }, body: { statusCode: 429, message: 'Too many requests' } };
    await expect(S.signIn('a@b.ng', 'x')).rejects.toMatchObject({ status: 429, retryAfterSeconds: 30 });
    expect(S.getState().status).toBe('loading');
  });
  it('reports an unreachable server as a network problem', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('x'); }));
    await expect(S.signIn('a@b.ng', 'x')).rejects.toMatchObject({ kind: 'network' });
  });
  it('parses Retry-After safely', () => {
    expect([S.parseRetryAfter('42'), S.parseRetryAfter('1.2'), S.parseRetryAfter('abc'), S.parseRetryAfter(null), S.parseRetryAfter('-5')]).toEqual([42, 2, undefined, undefined, undefined]);
  });
});

describe('resuming from the cookie when the page loads', () => {
  it('asks for a CSRF token first, then refreshes with it', async () => {
    await S.bootstrap();
    expect(net.calls.map((c) => `${c.method} ${c.path}`)).toEqual(['GET /auth/csrf', 'POST /auth/refresh']);
    expect(net.last('POST /auth/refresh')!.headers['X-CSRF-Token']).toBe('csrf-1');
    expect(S.getState().status).toBe('signedIn');
  });
  it('is quietly signed out, with no scary message, when there is no session', async () => {
    net.routes['GET /auth/csrf'] = { status: 401, body: { code: 'no_session' } };
    await S.bootstrap();
    expect(S.getState()).toMatchObject({ status: 'signedOut', reason: null });
    expect(net.count('POST /auth/refresh')).toBe(0);
  });
  it('shows the "all sessions ended" state when the cookie was a reused token', async () => {
    net.routes['POST /auth/refresh'] = { status: 401, body: { statusCode: 401, message: 'x', code: 'refresh_token_reuse' } };
    await S.bootstrap();
    expect(S.getState()).toMatchObject({ status: 'signedOut', reason: 'compromised' });
  });
  it('keeps going (does not sign out) if the server is down at start-up', async () => {
    vi.useFakeTimers();
    net.routes['GET /auth/csrf'] = { status: 503, body: {} };
    const out = await S.refresh();
    expect(out).toBe('offline');
    expect(S.getState().status).not.toBe('signedOut');
  });
});

describe('keeping the session alive', () => {
  it('refreshes quietly before the access token runs out', async () => {
    vi.useFakeTimers();
    net.routes['POST /auth/login'] = { status: 201, body: { user: userBody(), accessToken: jwt(300), csrfToken: 'c' } };
    await S.signIn('a@b.ng', 'a-long-password-1');
    net.calls.length = 0;
    await vi.advanceTimersByTimeAsync(5 * 60_000 - 55_000); // 300 s lifetime, refresh due 60 s before expiry
    expect(net.count('POST /auth/refresh')).toBe(1);
    expect(S.getState().status).toBe('signedIn');
  });
  it('hands out the current token and refreshes first when it is about to expire', async () => {
    net.routes['POST /auth/login'] = { status: 201, body: { user: userBody(), accessToken: jwt(5), csrfToken: 'c' } };
    await S.signIn('a@b.ng', 'a-long-password-1');
    net.calls.length = 0;
    const t = await S.ensureToken();
    expect(t).toBeTruthy();
    expect(net.count('POST /auth/refresh')).toBe(1);
  });
});

describe('signing out', () => {
  it('revokes the cookie session on the server using the CSRF token, then clears memory', async () => {
    await S.signIn('a@b.ng', 'a-long-password-1');
    net.calls.length = 0;
    await S.signOut('signedOut');
    expect(net.last('POST /auth/logout')!.headers['X-CSRF-Token']).toBe('csrf-1');
    expect(S.getState()).toMatchObject({ status: 'signedOut', user: null, reason: 'signedOut' });
    expect(await S.ensureToken()).toBeNull();
  });
  it('still signs this browser out when the server cannot be reached', async () => {
    await S.signIn('a@b.ng', 'a-long-password-1');
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('offline'); }));
    await S.signOut('signedOut');
    expect(S.getState().status).toBe('signedOut');
  });
  it('a forced sign-out (idle, expired) does not need the server', async () => {
    await S.signIn('a@b.ng', 'a-long-password-1');
    net.calls.length = 0;
    await S.signOut('idle', false);
    expect(net.calls).toHaveLength(0);
    expect(S.getState().reason).toBe('idle');
  });
});

describe('idle timeout', () => {
  it('signs out after the configured time with no activity, and activity keeps it alive', async () => {
    vi.useFakeTimers();
    setConfig({ idleTimeoutMinutes: 2 });
    await S.signIn('a@b.ng', 'a-long-password-1');
    await vi.advanceTimersByTimeAsync(90_000);
    S.noteActivity(Date.now());
    await vi.advanceTimersByTimeAsync(90_000);
    expect(S.getState().status).toBe('signedIn');
    await vi.advanceTimersByTimeAsync(60_000);
    expect(S.getState()).toMatchObject({ status: 'signedOut', reason: 'idle' });
  });
});

describe('remembering where the person was', () => {
  it('keeps a same-site path and returns it once', () => {
    S.rememberPlace('/incidents/INC-1?tab=timeline');
    expect(S.takePlace()).toBe('/incidents/INC-1?tab=timeline');
    expect(S.takePlace()).toBe('/');
  });
  it('REGRESSION open redirect: never accepts another site, a protocol-relative URL, a backslash trick or the sign-in page', () => {
    for (const bad of ['https://evil.test', '//evil.test', '/\\evil.test', 'javascript:alert(1)', '/sign-in', 'evil', '', undefined, null, 5, '/' + 'a'.repeat(3000)]) {
      expect([bad, S.safePath(bad)]).toEqual([bad, null]);
    }
    expect(S.safePath('/admin/rules?x=1#y')).toBe('/admin/rules?x=1#y');
  });
  it('ignores a tampered saved value', () => {
    sessionStorage.setItem('ir-return-to', '//evil.test/steal');
    expect(S.takePlace()).toBe('/');
  });
});

describe('several tabs, one session', () => {
  class Bus { static all = new Set<Bus>(); onmessage: ((e: MessageEvent) => void) | null = null; constructor(public name: string) { Bus.all.add(this); }
    postMessage(data: unknown) { for (const b of Bus.all) if (b !== this && b.name === this.name) b.onmessage?.({ data } as MessageEvent); }
    close() { Bus.all.delete(this); } }
  const tab = async () => { vi.resetModules(); const m = await import('./session'); (await import('@/lib/config')).setConfig({ apiBaseUrl: API, idleTimeoutMinutes: 30 }); m.startCrossTab(); return m; };

  it('signing out in one tab signs out the other, with the same reason', async () => {
    vi.stubGlobal('BroadcastChannel', Bus);
    const a = await tab(); const b = await tab();
    await a.signIn('a@b.ng', 'a-long-password-1');
    expect(b.getState().status).toBe('signedIn'); // the other tab was told, and shares the new token
    await a.signOut('signedOut');
    expect(b.getState()).toMatchObject({ status: 'signedOut', reason: 'signedOut' });
    a.__resetForTests(); b.__resetForTests();
  });
  it('a refresh in one tab gives the other tab the new token, so it does not refresh again', async () => {
    vi.stubGlobal('BroadcastChannel', Bus);
    const a = await tab(); const b = await tab();
    await a.signIn('a@b.ng', 'a-long-password-1');
    net.calls.length = 0;
    const out = await b.refresh();      // b already holds a fresh token from a
    expect(out).toBe('ok');
    expect(net.count('POST /auth/refresh')).toBe(0);
    a.__resetForTests(); b.__resetForTests();
  });
  it('a reuse detected in one tab ends the session in all tabs', async () => {
    vi.stubGlobal('BroadcastChannel', Bus);
    const a = await tab(); const b = await tab();
    await a.signIn('a@b.ng', 'a-long-password-1');
    net.routes['GET /auth/csrf'] = { body: { csrfToken: 'x' } };
    net.routes['POST /auth/refresh'] = { status: 401, body: { code: 'refresh_token_reuse' } };
    await a.refresh((await a.ensureToken())!); // the server refused the token we hold
    expect(b.getState()).toMatchObject({ status: 'signedOut', reason: 'compromised' });
    a.__resetForTests(); b.__resetForTests();
  });
  it('uses a Web Lock around refresh when the browser has one, so two tabs cannot refresh at once', async () => {
    const order: string[] = [];
    const locks = { request: vi.fn(async (name: string, fn: () => Promise<unknown>) => { order.push(`lock:${name}`); const r = await fn(); order.push('unlock'); return r; }) };
    vi.stubGlobal('navigator', { ...navigator, locks });
    await S.signIn('a@b.ng', 'a-long-password-1');
    await S.refresh('forced');
    expect(locks.request).toHaveBeenCalledWith('ir-refresh', expect.any(Function));
    expect(order).toEqual(['lock:ir-refresh', 'unlock']);
    vi.unstubAllGlobals();
  });
});
