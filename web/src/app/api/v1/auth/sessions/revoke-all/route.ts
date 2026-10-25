import { cookies } from 'next/headers';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { revokeAllSessions } from '@/server/auth/session';

export const runtime = 'nodejs';

export async function POST(req: Request) {
  const rid = requestId(req);
  const user = await requireUser(req);
  if (!user) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  await revokeAllSessions(user.id);
  const jar = await cookies();
  jar.set('ir_rt', '', { httpOnly: true, path: '/api/v1/auth', maxAge: 0 });
  return json({ ok: true }, { requestId: rid });
}
