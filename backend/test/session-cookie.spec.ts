import {
  buildRefreshCookie, checkCookieRequest, clearRefreshCookie, cookieSecure, csrfTokenFor, parseCookies, readRefreshCookie,
} from '../src/auth/session-cookie';
import { allowedOrigins, isAllowedOrigin } from '../src/common/utils/origins';

const env: any = { JWT_REFRESH_SECRET: 'refresh-secret-for-tests-fedcba9876543210fedcba9876543210', CORS_ORIGINS: 'https://dash.pishon.ng, http://localhost:3000' };

describe('origins', () => {
  it('lists the configured dashboard origins, trimmed, and defaults to local development', () => {
    expect(allowedOrigins(env)).toEqual(['https://dash.pishon.ng', 'http://localhost:3000']);
    expect(allowedOrigins({} as any)).toEqual(['http://localhost:3000']);
  });
  it('matches exactly: no prefix, suffix, case change, port change or missing origin', () => {
    expect(isAllowedOrigin('https://dash.pishon.ng', env)).toBe(true);
    for (const bad of ['https://dash.pishon.ng.evil.test', 'https://evil.test', 'http://dash.pishon.ng', 'https://DASH.pishon.ng', 'https://dash.pishon.ng:8443', 'null', '', undefined, 42]) {
      expect(isAllowedOrigin(bad as any, env)).toBe(false);
    }
  });
});

describe('refresh cookie', () => {
  it('is httpOnly, SameSite=Strict, scoped to the auth routes, with a lifetime', () => {
    const c = buildRefreshCookie('tok.en', 7 * 86400 * 1000, { NODE_ENV: 'production' } as any);
    expect(c).toContain('pishon_rt=tok.en');
    expect(c).toContain('HttpOnly');
    expect(c).toContain('SameSite=Strict');
    expect(c).toContain('Path=/api/v1/auth');
    expect(c).toContain('Max-Age=604800');
    expect(c).toContain('Secure');
  });
  it('is Secure in production by default, off in development, and the setting can override both', () => {
    expect(cookieSecure({ NODE_ENV: 'production' } as any)).toBe(true);
    expect(cookieSecure({ NODE_ENV: 'development' } as any)).toBe(false);
    expect(cookieSecure({ NODE_ENV: 'production', COOKIE_SECURE: 'false' } as any)).toBe(false);
    expect(cookieSecure({ NODE_ENV: 'development', COOKIE_SECURE: 'true' } as any)).toBe(true);
    expect(buildRefreshCookie('t', 1000, { NODE_ENV: 'development' } as any)).not.toContain('Secure');
  });
  it('is cleared with an immediate expiry and no value', () => {
    const c = clearRefreshCookie({ NODE_ENV: 'production' } as any);
    expect(c).toMatch(/^pishon_rt=;/);
    expect(c).toContain('Max-Age=0');
    expect(c).toContain('HttpOnly');
  });
  it('is encoded so a token can never break out of the header', () => {
    expect(buildRefreshCookie('a;b\r\nSet-Cookie: x=1', 1000, env)).not.toMatch(/[\r\n]/);
    const c = buildRefreshCookie('a;b', 1000, env);
    expect(readRefreshCookie({ headers: { cookie: c.split(';')[0] } })).toBe('a;b');
  });
});

describe('cookie parsing', () => {
  it('reads named cookies, ignores junk, and keeps the first of a repeated name', () => {
    expect(parseCookies('a=1; pishon_rt=abc; b=2')).toEqual({ a: '1', pishon_rt: 'abc', b: '2' });
    expect(parseCookies('pishon_rt=first; pishon_rt=second').pishon_rt).toBe('first');
    expect(parseCookies('=x; novalue; ;')).toEqual({});
    expect(parseCookies(undefined)).toEqual({});
    expect(parseCookies('a='.repeat(5000))).toEqual({});
  });
  it('returns nothing when the cookie is absent or cannot be decoded', () => {
    expect(readRefreshCookie({ headers: {} })).toBeUndefined();
    expect(readRefreshCookie({ headers: { cookie: 'pishon_rt=%E0%A4%A' } })).toBeUndefined();
  });
});

describe('cross-site request checks for refresh and logout', () => {
  const token = 'refresh.jwt.value';
  const good = () => ({ headers: { origin: 'https://dash.pishon.ng', 'x-csrf-token': csrfTokenFor(token, env) } });
  it('passes with an allowed origin and the matching token', () => {
    expect(checkCookieRequest(good(), token, env)).toBeNull();
  });
  it('fails with no origin, a foreign origin, or a lookalike', () => {
    for (const origin of [undefined, 'https://evil.test', 'https://dash.pishon.ng.evil.test']) {
      expect(checkCookieRequest({ headers: { ...good().headers, origin } }, token, env)).toBe('origin');
    }
  });
  it('fails with no token, a wrong token, or a token for a different session', () => {
    expect(checkCookieRequest({ headers: { origin: 'https://dash.pishon.ng' } }, token, env)).toBe('token');
    expect(checkCookieRequest({ headers: { origin: 'https://dash.pishon.ng', 'x-csrf-token': 'nope' } }, token, env)).toBe('token');
    expect(checkCookieRequest({ headers: { origin: 'https://dash.pishon.ng', 'x-csrf-token': csrfTokenFor('another.token', env) } }, token, env)).toBe('token');
  });
  it('changes when the refresh token rotates, and depends on the server secret', () => {
    expect(csrfTokenFor('a', env)).not.toBe(csrfTokenFor('b', env));
    expect(csrfTokenFor('a', env)).toBe(csrfTokenFor('a', env));
    expect(csrfTokenFor('a', env)).not.toBe(csrfTokenFor('a', { ...env, JWT_REFRESH_SECRET: 'another-secret-another-secret-another-secret!!' }));
  });
});
