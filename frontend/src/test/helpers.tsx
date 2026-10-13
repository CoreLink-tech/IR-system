import { type ReactElement } from 'react';
import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import App from '@/App';
import { TimeProvider } from '@/lib/time';
import { setConfig } from '@/lib/config';
import { __resetForTests, signIn } from '@/api/session';
import type { Role } from '@/api/types';
import * as fx from './fixtures';

export interface Call { method: string; path: string; query: URLSearchParams; body: any; headers: Record<string, string> }
export type Reply = { status?: number; body?: unknown; text?: string; headers?: Record<string, string>; delayMs?: number };
export type Handler = Reply | ((c: Call) => Reply | Promise<Reply>);
export const API = 'http://api.test';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
/** A real-looking access token whose expiry is the given number of seconds from now. */
export const jwt = (secondsFromNow = 900) => `${b64({ alg: 'none' })}.${b64({ exp: Math.floor(Date.now() / 1000) + secondsFromNow })}.sig`;

export interface Net { calls: Call[]; unmatched: string[]; routes: Record<string, Handler>; count(key: string): number; last(key: string): Call | undefined }

/** Replaces fetch with a table of answers keyed "METHOD /path" (the path after /api/v1). Anything not listed is recorded and answered 404. */
export function installFetch(initial: Record<string, Handler> = {}): Net {
  const net: Net = {
    calls: [], unmatched: [], routes: { ...initial },
    count: (k) => net.calls.filter((c) => `${c.method} ${c.path}` === k).length,
    last: (k) => [...net.calls].reverse().find((c) => `${c.method} ${c.path}` === k),
  };
  const impl = async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.toString());
    const method = (init.method ?? 'GET').toUpperCase();
    const path = url.pathname.replace('/api/v1', '');
    const headers = Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>));
    let body: any; try { body = init.body ? JSON.parse(String(init.body)) : undefined; } catch { body = init.body; }
    const call: Call = { method, path, query: url.searchParams, body, headers };
    net.calls.push(call);
    const key = `${method} ${path}`;
    const h = net.routes[key];
    if (h === undefined) { net.unmatched.push(key); return new Response(JSON.stringify({ statusCode: 404, message: `no test route for ${key}` }), { status: 404 }); }
    const r = typeof h === 'function' ? await h(call) : h;
    if (r.delayMs) await new Promise((res) => setTimeout(res, r.delayMs));
    if (init.signal?.aborted) throw new DOMException('Aborted', 'AbortError');
    const status = r.status ?? 200;
    const hdrs = new Headers({ 'Content-Type': r.text !== undefined ? 'text/plain' : 'application/json', ...(r.headers ?? {}) });
    return new Response(status === 204 ? null : r.text !== undefined ? r.text : JSON.stringify(r.body ?? {}), { status, headers: hdrs });
  };
  vi.stubGlobal('fetch', vi.fn(impl));
  return net;
}

/** What every signed-in page asks for in the background (posture chip and health check). */
export const baseRoutes = (role: Role): Record<string, Handler> => ({
  'GET /health': { body: { status: 'ok', service: 'x', version: '1.0.0', time: new Date().toISOString() } },
  'GET /reports/executive-summary': { body: fx.executive() },
  'POST /auth/login': { status: 201, body: { user: fx.user(role), accessToken: jwt(), csrfToken: 'csrf-1' } },
  'GET /auth/csrf': { body: { csrfToken: 'csrf-1' } },
  'POST /auth/refresh': { status: 201, body: { user: fx.user(role), accessToken: jwt(), csrfToken: 'csrf-2' } },
  'POST /auth/logout': { status: 201, body: { ok: true } },
});

export function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 }, mutations: { retry: false } } });
}

export interface Rendered { net: Net; client: QueryClient; container: HTMLElement; unmount: () => void }

/** Mounts the whole app as a signed-in person of the given role, at a route, with the given server answers. */
export async function renderApp(opts: { role: Role; route?: string; routes?: Record<string, Handler>; signedIn?: boolean; userOver?: Partial<ReturnType<typeof fx.user>> }): Promise<Rendered> {
  __resetForTests();
  setConfig({ apiBaseUrl: API, idleTimeoutMinutes: 30 });
  const net = installFetch({ ...baseRoutes(opts.role), ...(opts.userOver ? { 'POST /auth/login': { status: 201, body: { user: fx.user(opts.role, opts.userOver), accessToken: jwt(), csrfToken: 'csrf-1' } } } : {}), ...(opts.routes ?? {}) });
  if (opts.signedIn !== false) await signIn('person@pishon.ng', 'a-long-password-1');
  const client = newClient();
  const ui: ReactElement = (
    <QueryClientProvider client={client}><TimeProvider initial="utc"><MemoryRouter initialEntries={[opts.route ?? '/']}><App /></MemoryRouter></TimeProvider></QueryClientProvider>
  );
  const r = render(ui);
  return { net, client, container: r.container, unmount: r.unmount };
}

export const ROLES: Role[] = ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST', 'VIEWER'];
