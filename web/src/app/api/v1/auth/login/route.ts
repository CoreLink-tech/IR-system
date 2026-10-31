import { cookies } from 'next/headers';
import { clientIp, err, json, requestId } from '@/server/api';
import { rateLimitAsync } from '@/server/services/rate-limit';
import { loginWithPassword } from '@/server/auth/session';

export const runtime = 'nodejs';

export async function POST(req: Request) {
  const rid = requestId(req);
  const rl = await rateLimitAsync(`auth:login:${clientIp(req)}`, 20, 60_000);
  if (!rl.ok) {
    return err(429, 'Too many login attempts', {
      code: 'rate_limited',
      requestId: rid,
      retryAfterSeconds: rl.retryAfterSeconds,
    });
  }

  let body: { email?: string; password?: string; useCookie?: boolean };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  if (!email || !password) {
    return err(400, 'Email and password required', { code: 'invalid_body', requestId: rid });
  }

  try {
    const outcome = await loginWithPassword(email, password, {
      ip: clientIp(req),
      userAgent: req.headers.get('user-agent') || undefined,
    });

    if (outcome.kind === 'mfa') {
      return json(
        { twoFactorRequired: true, challengeToken: outcome.challengeToken, expiresInSeconds: outcome.expiresInSeconds },
        { requestId: rid },
      );
    }
    if (outcome.kind === 'enroll') {
      return json(
        {
          twoFactorEnrollmentRequired: true,
          challengeToken: outcome.challengeToken,
          expiresInSeconds: outcome.expiresInSeconds,
        },
        { requestId: rid },
      );
    }

    if (body.useCookie !== false) {
      const jar = await cookies();
      jar.set('ir_rt', outcome.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/v1/auth',
        maxAge: 7 * 24 * 60 * 60,
      });
      return json(
        { user: outcome.user, accessToken: outcome.accessToken, csrfToken: outcome.csrfToken },
        { requestId: rid },
      );
    }

    return json(
      {
        user: outcome.user,
        accessToken: outcome.accessToken,
        refreshToken: outcome.refreshToken,
      },
      { requestId: rid },
    );
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string; retryAfterSeconds?: number };
    if (ex.status) {
      return err(ex.status, ex.message || 'Error', {
        code: ex.code,
        requestId: rid,
        retryAfterSeconds: ex.retryAfterSeconds,
      });
    }
    console.error(rid, e);
    return err(500, 'Internal server error', { requestId: rid });
  }
}
