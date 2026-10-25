import { cookies } from 'next/headers';
import { clientIp, err, json, requestId } from '@/server/api';
import { csrfFor } from '@/server/auth/jwt';
import { refreshSession } from '@/server/auth/session';
import { createHash, createHmac, timingSafeEqual } from 'crypto';
import { getEnv } from '@/lib/env';

export const runtime = 'nodejs';

function checkCsrf(refreshToken: string, header: string | null): boolean {
  if (!header) return false;
  const bound = createHash('sha256').update(refreshToken).digest('hex');
  const expected = createHmac('sha256', getEnv().jwtRefreshSecret).update(`csrf:${bound}`).digest('base64url');
  try {
    const a = Buffer.from(expected);
    const b = Buffer.from(header);
    return a.length === b.length && timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

export async function POST(req: Request) {
  const rid = requestId(req);
  const jar = await cookies();
  const fromCookie = jar.get('ir_rt')?.value;
  let body: { refreshToken?: string } = {};
  try {
    body = await req.json().catch(() => ({}));
  } catch { /* empty */ }
  const presented = fromCookie || body.refreshToken;
  if (!presented) return err(401, 'No refresh token', { code: 'unauthorized', requestId: rid });

  // Cookie mode requires CSRF
  if (fromCookie) {
    const csrf = req.headers.get('x-csrf-token');
    if (!checkCsrf(fromCookie, csrf)) {
      return err(403, 'CSRF check failed', { code: 'csrf', requestId: rid });
    }
  }

  try {
    const out = await refreshSession(presented, {
      ip: clientIp(req),
      userAgent: req.headers.get('user-agent') || undefined,
    });
    if (fromCookie) {
      jar.set('ir_rt', out.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/v1/auth',
        maxAge: 7 * 24 * 60 * 60,
      });
      return json(
        { user: out.user, accessToken: out.accessToken, csrfToken: out.csrfToken },
        { requestId: rid },
      );
    }
    return json(
      { user: out.user, accessToken: out.accessToken, refreshToken: out.refreshToken },
      { requestId: rid },
    );
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string };
    if (fromCookie) jar.set('ir_rt', '', { httpOnly: true, path: '/api/v1/auth', maxAge: 0 });
    if (ex.status) return err(ex.status, ex.message || 'Error', { code: ex.code, requestId: rid });
    return err(500, 'Internal server error', { requestId: rid });
  }
}
