import { createHash, createHmac, timingSafeEqual } from 'crypto';
import { isAllowedOrigin } from '../common/utils/origins';
import { loadRefreshKeyRing } from './jwt-keys';

/**
 * Browser sign-in keeps the refresh token in an httpOnly cookie, so a script injected
 * into the dashboard cannot read it. Because the browser attaches a cookie on its own,
 * the two calls that use it (refresh and logout) are protected against cross-site
 * requests in three independent ways:
 *
 *   1. SameSite=Strict, so the browser does not send the cookie from another site.
 *   2. The Origin header must exactly match a dashboard origin in CORS_ORIGINS.
 *   3. A token in the X-CSRF-Token header, derived from the refresh token itself. Another
 *      site cannot read it (CORS blocks that) and it changes whenever the token rotates.
 *
 * During a refresh-secret rotation, CSRF tokens computed with either the current or the
 * previous key are accepted so an in-flight page is not locked out.
 *
 * The cookie is scoped to the auth routes, so it is not sent with ordinary API calls.
 */
export const REFRESH_COOKIE = 'ir_rt';
export const CSRF_HEADER = 'x-csrf-token';
const COOKIE_PATH = '/api/v1/auth';

/** Secure is on in production unless explicitly turned off (plain-http local testing). */
export function cookieSecure(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.COOKIE_SECURE === 'true') return true;
  if (env.COOKIE_SECURE === 'false') return false;
  return env.NODE_ENV === 'production';
}

export function parseCookies(header: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (typeof header !== 'string' || header.length === 0 || header.length > 8192) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    const name = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    if (!(name in out)) out[name] = value;
  }
  return out;
}

export function readRefreshCookie(req: { headers: Record<string, any> }): string | undefined {
  const v = parseCookies(req.headers?.cookie)[REFRESH_COOKIE];
  if (!v) return undefined;
  try { return decodeURIComponent(v); } catch { return undefined; }
}

export function buildRefreshCookie(token: string, maxAgeMs: number, env: NodeJS.ProcessEnv = process.env): string {
  return [
    `${REFRESH_COOKIE}=${encodeURIComponent(token)}`,
    `Max-Age=${Math.max(0, Math.floor(maxAgeMs / 1000))}`,
    `Path=${COOKIE_PATH}`,
    'HttpOnly',
    'SameSite=Strict',
    ...(cookieSecure(env) ? ['Secure'] : []),
  ].join('; ');
}

export function clearRefreshCookie(env: NodeJS.ProcessEnv = process.env): string {
  return buildRefreshCookie('', 0, env);
}

function csrfWithSecret(refreshToken: string, secret: string): string {
  const bound = createHash('sha256').update(refreshToken).digest('hex');
  return createHmac('sha256', secret).update(`csrf:${bound}`).digest('base64url');
}

/** Bound to one refresh token. Always computed with the current refresh secret. */
export function csrfTokenFor(refreshToken: string, env: NodeJS.ProcessEnv = process.env): string {
  const ring = loadRefreshKeyRing(env);
  return csrfWithSecret(refreshToken, ring.current);
}

function csrfMatches(given: string, refreshToken: string, env: NodeJS.ProcessEnv = process.env): boolean {
  const ring = loadRefreshKeyRing(env);
  const a = Buffer.from(given);
  const candidates = [ring.current, ring.previous].filter(Boolean) as string[];
  for (const secret of candidates) {
    const b = Buffer.from(csrfWithSecret(refreshToken, secret));
    if (a.length === b.length && timingSafeEqual(a, b)) return true;
  }
  return false;
}

export type CsrfFailure = 'origin' | 'token';

/** Returns null when the request passes, otherwise which check failed. */
export function checkCookieRequest(
  req: { headers: Record<string, any> }, refreshToken: string, env: NodeJS.ProcessEnv = process.env,
): CsrfFailure | null {
  if (!isAllowedOrigin(req.headers?.origin, env)) return 'origin';
  const given = req.headers?.[CSRF_HEADER];
  if (typeof given !== 'string' || given.length === 0) return 'token';
  if (!csrfMatches(given, refreshToken, env)) return 'token';
  return null;
}
