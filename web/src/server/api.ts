import { NextResponse } from 'next/server';
import { randomBytes } from 'crypto';

export function requestId(req: Request): string {
  const h = req.headers.get('x-request-id');
  if (h && /^[A-Za-z0-9._:-]{8,64}$/.test(h)) return h;
  return randomBytes(12).toString('hex');
}

export function json(
  body: unknown,
  init: { status?: number; requestId?: string; retryAfterSeconds?: number } = {},
) {
  const headers = new Headers({
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
  });
  if (init.requestId) headers.set('X-Request-Id', init.requestId);
  if (init.retryAfterSeconds) headers.set('Retry-After', String(init.retryAfterSeconds));
  return NextResponse.json(body, { status: init.status ?? 200, headers });
}

export function err(
  status: number,
  message: string,
  opts: { code?: string; requestId?: string; retryAfterSeconds?: number } = {},
) {
  return json(
    {
      statusCode: status,
      message,
      code: opts.code,
      requestId: opts.requestId,
      retryAfterSeconds: opts.retryAfterSeconds,
      timestamp: new Date().toISOString(),
    },
    { status, requestId: opts.requestId, retryAfterSeconds: opts.retryAfterSeconds },
  );
}

export function clientIp(req: Request): string {
  // Behind Vercel: x-forwarded-for is set by the platform.
  const xff = req.headers.get('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  const real = req.headers.get('x-real-ip');
  if (real) return real.trim();
  return '0.0.0.0';
}
