/** Everything that can go wrong talking to the API, in one shape the pages can show. */
export type ErrorKind = 'network' | 'timeout' | 'http';

export class ApiError extends Error {
  readonly kind: ErrorKind;
  readonly status: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly retryAfterSeconds?: number;
  readonly details: string[];

  constructor(init: { kind: ErrorKind; status?: number; message?: string | string[]; code?: string; requestId?: string; retryAfterSeconds?: number }) {
    const list = Array.isArray(init.message) ? init.message : init.message ? [init.message] : [];
    super(list[0] ?? 'Request failed');
    this.name = 'ApiError';
    this.kind = init.kind;
    this.status = init.status ?? 0;
    this.code = init.code;
    this.requestId = init.requestId;
    this.retryAfterSeconds = init.retryAfterSeconds;
    this.details = list;
  }
}

export const isApiError = (e: unknown): e is ApiError => e instanceof ApiError;
export const isNetwork = (e: unknown) => isApiError(e) && (e.kind === 'network' || e.kind === 'timeout');

/** Server answers worth turning into plain words. Anything else shows the server's own message. */
const KNOWN: Array<[RegExp, string]> = [
  [/internal and private addresses cannot be blocked/i, 'That is a private or internal address. Blocking it could cut your own website off from this system, so it is not allowed.'],
  [/ip is on the allowlist/i, 'That address is on the allowlist, which protects it from being blocked. Remove it from the allowlist first if you really want to block it.'],
];

/** The words a person should see for an error. Never raw JSON and never a stack trace. */
export function describeError(e: unknown): { title: string; body: string; requestId?: string; retryAfterSeconds?: number } {
  if (!isApiError(e)) return { title: 'Something went wrong', body: 'An unexpected problem stopped this page from loading. Try again. If it keeps happening, tell your administrator.' };
  if (e.kind === 'network') return { title: 'Cannot reach the Security API', body: 'Your connection may be down, or the server may be offline. Check your connection and try again.' };
  if (e.kind === 'timeout') return { title: 'The Security API is taking too long', body: 'The server did not answer in time. Try again in a moment.' };
  switch (e.status) {
    case 400: case 409: case 422: {
      const known = KNOWN.find(([re]) => e.details.some((d) => re.test(d)));
      return { title: 'That could not be done', body: known ? known[1] : (e.details.join(' ') || 'The request was not accepted.'), requestId: e.requestId };
    }
    case 401: return { title: 'Please sign in again', body: 'Your session is no longer valid.' };
    case 403: return { title: 'You do not have access to this', body: 'Your role does not allow this action. If you need it, ask a super admin.', requestId: e.requestId };
    case 404: return { title: 'Not found', body: 'That item does not exist, or it was removed.', requestId: e.requestId };
    case 429: return {
      title: 'Too many requests',
      body: e.retryAfterSeconds ? `Please wait ${e.retryAfterSeconds} seconds and try again.` : 'Please wait a moment and try again.',
      retryAfterSeconds: e.retryAfterSeconds,
    };
    default:
      return { title: 'The Security API had a problem', body: 'The server hit an error. Try again. If it keeps happening, give the reference below to whoever runs the server.', requestId: e.requestId };
  }
}
