import { cookies } from 'next/headers';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { hashRefreshToken } from '@/server/auth/crypto';
import { listSessions, revokeSession } from '@/server/auth/session';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const user = await requireUser(req);
  if (!user) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  const jar = await cookies();
  const current = jar.get('ir_rt')?.value;
  const data = await listSessions(user.id, current ? hashRefreshToken(current) : undefined);
  return json({ data }, { requestId: rid });
}

export async function DELETE(req: Request) {
  const rid = requestId(req);
  const user = await requireUser(req);
  if (!user) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  const url = new URL(req.url);
  const id = url.searchParams.get('id');
  if (!id) return err(400, 'id required', { code: 'invalid_body', requestId: rid });
  try {
    await revokeSession(user.id, id);
    return json({ ok: true }, { requestId: rid });
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string };
    if (ex.status) return err(ex.status, ex.message || 'Error', { code: ex.code, requestId: rid });
    return err(500, 'Internal server error', { requestId: rid });
  }
}
