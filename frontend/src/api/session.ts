import { config } from '@/lib/config';
import type { LoginResult, User } from './types';
import { ApiError } from './errors';

/**
 * Sign-in state for the whole dashboard.
 *
 * Where each secret lives, and why:
 *  - The access token (short lived) is held in a variable in this tab only. It is never written
 *    to storage, a cookie or a URL, so a stolen copy of the page's storage yields nothing.
 *  - The refresh token (7 days) never reaches JavaScript at all. The API keeps it in an
 *    httpOnly, Secure, SameSite=Strict cookie, so a script injected into the page cannot read it.
 *  - Because the browser sends that cookie by itself, refresh and sign-out also carry a CSRF
 *    token, which the API ties to the refresh token and checks against the allowed origin.
 *
 * Refresh tokens rotate, and reusing an old one ends every session. Two tabs refreshing at the
 * same moment would look exactly like theft, so refreshes are serialised across tabs with a Web
 * Lock, and whichever tab refreshes shares the new token with the others.
 */
export type SignOutReason = 'expired' | 'compromised' | 'idle' | 'signedOut';
export interface SessionState {
  status: 'loading' | 'signedOut' | 'signedIn';
  user: User | null;
  reason: SignOutReason | null;
}

type RefreshOutcome = 'ok' | 'expired' | 'compromised' | 'offline';

const RETURN_KEY = 'pishon-return-to';
const CHANNEL = 'pishon-session';
const LOCK = 'pishon-refresh';
const SAFETY_MS = 60_000; // refresh this long before the access token runs out

let state: SessionState = { status: 'loading', user: null, reason: null };
let accessToken: string | null = null;
let accessExpiresAt = 0;
let csrfToken: string | null = null;
let refreshing: Promise<RefreshOutcome> | null = null;
let timer: ReturnType<typeof setTimeout> | undefined;
let channel: BroadcastChannel | null = null;
let lastActivity = Date.now();
let idleTimer: ReturnType<typeof setInterval> | undefined;
const listeners = new Set<() => void>();

export const getState = () => state;
export function subscribe(fn: () => void) { listeners.add(fn); return () => { listeners.delete(fn); }; }
function set(next: SessionState) { state = next; listeners.forEach((l) => l()); }

function tokenExpiry(jwt: string): number {
  try {
    const payload = JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.exp === 'number' ? payload.exp * 1000 : Date.now() + 14 * 60_000;
  } catch { return Date.now() + 14 * 60_000; }
}

const url = (path: string) => `${config().apiBaseUrl}/api/v1${path}`;

function broadcast(msg: Record<string, unknown>) {
  try { channel?.postMessage(msg); } catch { /* the channel may be closed */ }
}

function apply(r: LoginResult, share = true) {
  accessToken = r.accessToken;
  accessExpiresAt = tokenExpiry(r.accessToken);
  if (r.csrfToken) csrfToken = r.csrfToken;
  set({ status: 'signedIn', user: r.user, reason: null });
  schedule();
  if (share) broadcast({ type: 'auth', result: { user: r.user, accessToken: r.accessToken, csrfToken: r.csrfToken } });
}

function clear(reason: SignOutReason | null) {
  accessToken = null; accessExpiresAt = 0; csrfToken = null;
  if (timer) clearTimeout(timer);
  set({ status: 'signedOut', user: null, reason });
}

function schedule() {
  if (timer) clearTimeout(timer);
  const wait = Math.max(5_000, accessExpiresAt - Date.now() - SAFETY_MS);
  timer = setTimeout(() => { void refresh().then((o) => { if (o === 'offline') retryLater(); }); }, wait);
}

function retryLater(delay = 20_000) {
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => { void refresh().then((o) => { if (o === 'offline') retryLater(Math.min(delay * 2, 120_000)); }); }, delay);
}

async function json(res: Response): Promise<any> { try { return await res.json(); } catch { return null; } }

async function networkRefresh(): Promise<RefreshOutcome> {
  try {
    const c = await fetch(url('/auth/csrf'), { credentials: 'include', cache: 'no-store' });
    if (c.status === 401) return 'expired';
    if (!c.ok) return 'offline';
    const token = (await json(c))?.csrfToken as string | undefined;
    if (!token) return 'expired';
    const r = await fetch(url('/auth/refresh'), {
      method: 'POST', credentials: 'include', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token }, body: '{}',
    });
    const body = await json(r);
    if (r.ok && body?.accessToken) { apply(body as LoginResult); return 'ok'; }
    if (body?.code === 'refresh_token_reuse') return 'compromised';
    if (r.status === 401 || r.status === 403) return 'expired';
    return 'offline';
  } catch { return 'offline'; }
}

/**
 * Refresh the access token. One at a time in this tab, and one at a time across tabs.
 * `rejected` is the token the server just refused. A token that is still within its lifetime
 * but was refused (revoked, account switched off, secrets rotated) must be replaced, so the
 * "someone else already refreshed" shortcut only applies when we now hold a different token.
 */
export function refresh(rejected?: string): Promise<RefreshOutcome> {
  if (refreshing) return refreshing;
  const run = async (): Promise<RefreshOutcome> => {
    // Another tab may have refreshed while this one waited for the lock.
    if (accessToken && accessToken !== rejected && accessExpiresAt - Date.now() > SAFETY_MS) return 'ok';
    return networkRefresh();
  };
  const withLock: Promise<RefreshOutcome> = (typeof navigator !== 'undefined' && (navigator as any).locks)
    ? (navigator as any).locks.request(LOCK, run)
    : run();
  refreshing = withLock.then((outcome) => {
    if (outcome === 'expired' || outcome === 'compromised') {
      clear(outcome);
      broadcast({ type: 'signout', reason: outcome });
    }
    return outcome;
  }).finally(() => { refreshing = null; });
  return refreshing;
}

/** A usable access token, refreshing first if it is about to run out. Null if signed out. */
export async function ensureToken(): Promise<string | null> {
  if (accessToken && accessExpiresAt - Date.now() > 15_000) return accessToken;
  if (state.status !== 'signedIn') return null;
  const outcome = await refresh();
  return outcome === 'ok' || (outcome === 'offline' && accessToken && accessExpiresAt > Date.now()) ? accessToken : null;
}

export async function signIn(email: string, password: string): Promise<User> {
  let res: Response;
  try {
    res = await fetch(url('/auth/login'), {
      method: 'POST', credentials: 'include', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, useCookie: true }),
    });
  } catch { throw new ApiError({ kind: 'network' }); }
  const body = await json(res);
  if (!res.ok) {
    throw new ApiError({
      kind: 'http', status: res.status, message: body?.message, code: body?.code, requestId: body?.requestId,
      retryAfterSeconds: parseRetryAfter(res.headers.get('Retry-After')),
    });
  }
  apply(body as LoginResult);
  startIdleWatch();
  return (body as LoginResult).user;
}

/** Ends the session. `server` asks the API to revoke the refresh token as well. */
export async function signOut(reason: SignOutReason = 'signedOut', server = reason === 'signedOut') {
  if (server) {
    try {
      const c = await fetch(url('/auth/csrf'), { credentials: 'include', cache: 'no-store' });
      const token = c.ok ? (await json(c))?.csrfToken : null;
      if (token) {
        await fetch(url('/auth/logout'), {
          method: 'POST', credentials: 'include', cache: 'no-store',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token }, body: '{}',
        });
      }
    } catch { /* signing out locally still protects this browser */ }
  }
  clear(reason);
  broadcast({ type: 'signout', reason });
}

/** Called when the API says this account must set a new password before anything else. */
export function requirePasswordChange() {
  if (state.user && !state.user.mustChangePassword) set({ ...state, user: { ...state.user, mustChangePassword: true } });
}

/** Try to resume from the cookie when the page loads. */
export async function bootstrap(): Promise<void> {
  const outcome = await refresh();
  if (outcome === 'ok') { startIdleWatch(); return; }
  clear(outcome === 'compromised' ? 'compromised' : null);
}

export function parseRetryAfter(v: string | null | undefined): number | undefined {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.ceil(n) : undefined;
}

// ---- where the user was, so they return to it after signing in ----------------------------

/** Only same-site paths are kept, so this can never become an open redirect. */
export function safePath(p: unknown): string | null {
  return typeof p === 'string' && /^\/(?![/\\])/.test(p) && !p.startsWith('/sign-in') && p.length < 2048 ? p : null;
}
export function rememberPlace(path: string) { const p = safePath(path); if (p) try { sessionStorage.setItem(RETURN_KEY, p); } catch { /* private mode */ } }
export function takePlace(): string {
  try { const p = safePath(sessionStorage.getItem(RETURN_KEY)); sessionStorage.removeItem(RETURN_KEY); return p ?? '/'; } catch { return '/'; }
}

// ---- several tabs, one session ------------------------------------------------------------

export function startCrossTab() {
  if (typeof BroadcastChannel === 'undefined' || channel) return;
  channel = new BroadcastChannel(CHANNEL);
  channel.onmessage = (e: MessageEvent) => {
    const m = e.data;
    if (m?.type === 'auth' && m.result?.accessToken) apply(m.result as LoginResult, false);
    else if (m?.type === 'signout') clear((m.reason as SignOutReason) ?? 'signedOut');
    else if (m?.type === 'activity' && typeof m.at === 'number') lastActivity = Math.max(lastActivity, m.at);
  };
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && state.status === 'signedIn' && accessExpiresAt - Date.now() < SAFETY_MS) void refresh();
  });
}

// ---- idle timeout -------------------------------------------------------------------------

export function noteActivity(now = Date.now()) {
  if (now - lastActivity > 15_000) broadcast({ type: 'activity', at: now });
  lastActivity = now;
}

export function startIdleWatch() {
  if (idleTimer) clearInterval(idleTimer);
  lastActivity = Date.now();
  idleTimer = setInterval(() => {
    if (state.status !== 'signedIn') return;
    if (Date.now() - lastActivity > config().idleTimeoutMinutes * 60_000) void signOut('idle', true);
  }, 15_000);
}

export function stopIdleWatch() { if (idleTimer) clearInterval(idleTimer); idleTimer = undefined; }

/** Test hook: forget everything, as if the page had just loaded. */
export function __resetForTests() {
  accessToken = null; accessExpiresAt = 0; csrfToken = null; refreshing = null;
  if (timer) clearTimeout(timer);
  stopIdleWatch();
  channel?.close(); channel = null;
  state = { status: 'loading', user: null, reason: null };
  listeners.clear();
}
export const __csrfForTests = () => csrfToken;
