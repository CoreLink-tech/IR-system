import { eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { allowlist } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function DELETE(req: Request, ctx: { params: Promise<{ ip: string }> }) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER' || me.role === 'ANALYST') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  const { ip } = await ctx.params;
  const decoded = decodeURIComponent(ip);
  const rows = await db.select().from(allowlist).where(eq(allowlist.ipAddress, decoded)).limit(1);
  if (!rows[0]) return err(404, 'Not found', { code: 'not_found', requestId: rid });
  await db.delete(allowlist).where(eq(allowlist.id, rows[0].id));
  return json({ ok: true, ipAddress: decoded }, { requestId: rid });
}
