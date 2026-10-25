import { cookies } from 'next/headers';
import { clientIp, err, json, requestId } from '@/server/api';
import { enrollConfirm } from '@/server/auth/two-factor';

export const runtime = 'nodejs';

export async function POST(req: Request) {
  const rid = requestId(req);
  let body: { challengeToken?: string; code?: string };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  try {
    const outcome = await enrollConfirm(body.challengeToken || '', body.code || '', {
      ip: clientIp(req),
      userAgent: req.headers.get('user-agent') || undefined,
    });
    const jar = await cookies();
    jar.set('ir_rt', outcome.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/v1/auth',
      maxAge: 7 * 24 * 60 * 60,
    });
    return json(
      {
        user: outcome.user,
        accessToken: outcome.accessToken,
        csrfToken: outcome.csrfToken,
        recoveryCodes: outcome.recoveryCodes,
      },
      { requestId: rid },
    );
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string };
    if (ex.status) return err(ex.status, ex.message || 'Error', { code: ex.code, requestId: rid });
    console.error(rid, e);
    return err(500, 'Internal server error', { requestId: rid });
  }
}
