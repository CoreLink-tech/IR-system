import { config } from '@/lib/config';
import { ApiError } from './errors';
import { ensureToken, getState, parseRetryAfter, refresh, requirePasswordChange, signOut } from './session';

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  query?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  /** Ask for plain text (the ?format=text reports). */
  text?: boolean;
  /** Public routes (health) send no token. */
  anonymous?: boolean;
  /**
   * A 401 on this call means "that answer was wrong" (for example the current password), not
   * "your session ended". It is returned as an ordinary error with no refresh and no sign-out.
   */
  refusal401?: boolean;
  signal?: AbortSignal;
  timeoutMs?: number;
}

const TIMEOUT_MS = 30_000;

export function buildUrl(path: string, query?: RequestOptions['query']): string {
  const u = `${config().apiBaseUrl}/api/v1${path}`;
  if (!query) return u;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
  const s = qs.toString();
  return s ? `${u}?${s}` : u;
}

async function once(path: string, opts: RequestOptions, token: string | null): Promise<Response> {
  const ctl = new AbortController();
  const timeout = setTimeout(() => ctl.abort('timeout'), opts.timeoutMs ?? TIMEOUT_MS);
  opts.signal?.addEventListener('abort', () => ctl.abort(opts.signal!.reason));
  try {
    return await fetch(buildUrl(path, opts.query), {
      method: opts.method ?? 'GET',
      headers: {
        Accept: opts.text ? 'text/plain' : 'application/json',
        ...(opts.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      credentials: 'omit', // the refresh cookie only travels on the auth routes, handled in session.ts
      cache: 'no-store',
      signal: ctl.signal,
    });
  } catch (e: any) {
    if (opts.signal?.aborted) throw e; // the page moved on; not an error to show
    throw new ApiError({ kind: ctl.signal.aborted ? 'timeout' : 'network' });
  } finally { clearTimeout(timeout); }
}

async function toError(res: Response): Promise<ApiError> {
  let body: any = null;
  try { body = await res.json(); } catch { /* not JSON, e.g. a proxy error page */ }
  return new ApiError({
    kind: 'http', status: res.status, message: body?.message, code: body?.code, requestId: body?.requestId,
    retryAfterSeconds: parseRetryAfter(res.headers.get('Retry-After')),
  });
}

/**
 * One call to the API. Adds the access token, and on a 401 refreshes it once and retries.
 * Concurrent calls that hit a 401 at the same time share one refresh (see session.ts).
 */
export async function api<T = unknown>(path: string, opts: RequestOptions = {}): Promise<T> {
  let token: string | null = null;
  if (!opts.anonymous) {
    token = await ensureToken();
    if (!token) throw new ApiError({ kind: 'http', status: 401, message: 'Not signed in' });
  }
  let res = await once(path, opts, token);
  if (res.status === 401 && !opts.anonymous && !opts.refusal401) {
    const outcome = await refresh(token ?? undefined);
    // The server could not be reached to refresh: that is a connection problem, not an ended session.
    if (outcome === 'offline') throw new ApiError({ kind: 'network' });
    token = outcome === 'ok' ? await ensureToken() : null;
    if (!token) {
      // refresh() has already recorded why (expired or compromised); do not overwrite it.
      if (getState().status === 'signedIn') await signOut('expired', false);
      throw new ApiError({ kind: 'http', status: 401, message: 'Session ended' });
    }
    // A fresh token was just issued, so a second 401 is the server's answer to this call, not an
    // expired session. Report it; a genuinely ended session shows up at the next refresh.
    res = await once(path, opts, token);
  }
  if (!res.ok) {
    const err = await toError(res);
    if (err.status === 403 && err.code === 'password_change_required') requirePasswordChange();
    throw err;
  }
  if (opts.text) return (await res.text()) as unknown as T;
  if (res.status === 204) return undefined as T;
  try { return (await res.json()) as T; } catch { return undefined as T; }
}
