'use client';

/**
 * Browser client for the dashboard. Access token lives in memory only.
 */

let accessToken: string | null = null;

export function setAccessToken(t: string | null) {
  accessToken = t;
}

export function getAccessToken() {
  return accessToken;
}

export class ApiError extends Error {
  status: number;
  code?: string;
  retryAfterSeconds?: number;
  constructor(status: number, message: string, code?: string, retryAfterSeconds?: number) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export async function api<T = unknown>(
  path: string,
  init: RequestInit & { json?: unknown } = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  const res = await fetch(`/api/v1${path}`, {
    ...init,
    headers,
    credentials: 'include',
    body: init.json !== undefined ? JSON.stringify(init.json) : init.body,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(
      res.status,
      body.message || res.statusText,
      body.code,
      body.retryAfterSeconds ?? (res.headers.get('Retry-After') ? Number(res.headers.get('Retry-After')) : undefined),
    );
  }
  return body as T;
}

export type PublicUser = {
  id: string;
  email: string;
  name: string | null;
  role: string;
  isActive: boolean;
  mustChangePassword: boolean;
  twoFactorEnabled?: boolean;
};

export type LoginResult =
  | { user: PublicUser; accessToken: string; csrfToken?: string }
  | { twoFactorRequired: true; challengeToken: string; expiresInSeconds: number }
  | { twoFactorEnrollmentRequired: true; challengeToken: string; expiresInSeconds: number };

export async function signIn(email: string, password: string): Promise<LoginResult> {
  const result = await api<LoginResult>('/auth/login', {
    method: 'POST',
    json: { email, password, useCookie: true },
  });
  if ('accessToken' in result) setAccessToken(result.accessToken);
  return result;
}
