import { eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { apiKeys } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN' && me.role !== 'SECURITY_ADMIN') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  const { id } = await ctx.params;
  const rows = await db.select().from(apiKeys).where(eq(apiKeys.id, id)).limit(1);
  if (!rows[0]) return err(404, 'API key not found', { code: 'not_found', requestId: rid });
  await db
    .update(apiKeys)
    .set({ isActive: false, revokedAt: new Date() })
    .where(eq(apiKeys.id, id));
  return json({ id, name: rows[0].name, isActive: false, revokedAt: new Date().toISOString() }, { requestId: rid });
}
