import { eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { recoveryCodes, users } from '@/server/db/schema';
import { revokeAllSessions } from '@/server/auth/session';

export const runtime = 'nodejs';

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN') return err(403, 'Super admin only', { code: 'forbidden', requestId: rid });
  const { id } = await ctx.params;
  if (id === me.id) {
    return err(400, 'Cannot reset your own two-step verification', { code: 'self_reset_forbidden', requestId: rid });
  }
  const rows = await db.select().from(users).where(eq(users.id, id)).limit(1);
  if (!rows[0]) return err(404, 'User not found', { code: 'not_found', requestId: rid });
  await db.delete(recoveryCodes).where(eq(recoveryCodes.userId, id));
  await db
    .update(users)
    .set({
      totpSecret: null,
      totpEnabledAt: null,
      totpLastStep: null,
      tokenVersion: rows[0].tokenVersion + 1,
    })
    .where(eq(users.id, id));
  await revokeAllSessions(id);
  const mustEnrol = rows[0].role === 'SUPER_ADMIN' || rows[0].role === 'SECURITY_ADMIN';
  return json({ ok: true, email: rows[0].email, mustEnrolAtNextSignIn: mustEnrol }, { requestId: rid });
}
