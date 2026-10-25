import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { changePassword } from '@/server/auth/password';

export const runtime = 'nodejs';

export async function POST(req: Request) {
  const rid = requestId(req);
  const user = await requireUser(req);
  if (!user) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  let body: { currentPassword?: string; newPassword?: string };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  try {
    await changePassword(user.id, body.currentPassword || '', body.newPassword || '');
    return json({ ok: true }, { requestId: rid });
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string };
    if (ex.status) return err(ex.status, ex.message || 'Error', { code: ex.code, requestId: rid });
    return err(500, 'Internal server error', { requestId: rid });
  }
}
