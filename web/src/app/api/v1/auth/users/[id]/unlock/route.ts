import { eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { loginThrottle, users } from '@/server/db/schema';
import { sha256 } from '@/server/auth/crypto';

export const runtime = 'nodejs';

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN') return err(403, 'Super admin only', { code: 'forbidden', requestId: rid });
  const { id } = await ctx.params;
  const rows = await db.select().from(users).where(eq(users.id, id)).limit(1);
  if (!rows[0]) return err(404, 'User not found', { code: 'not_found', requestId: rid });
  const key = sha256(rows[0].email.trim().toLowerCase());
  await db.delete(loginThrottle).where(eq(loginThrottle.keyHash, key));
  return json({ ok: true, email: rows[0].email }, { requestId: rid });
}
