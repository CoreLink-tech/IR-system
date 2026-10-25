import { and, eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { ipBlocks } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER' || me.role === 'ANALYST') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  let body: { ipAddress?: string; reason?: string };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  const ip = (body.ipAddress || '').trim();
  if (!ip) return err(400, 'ipAddress required', { code: 'invalid_body', requestId: rid });
  const activeKey = `block:${ip}`;
  const existing = await db
    .select()
    .from(ipBlocks)
    .where(and(eq(ipBlocks.activeKey, activeKey), eq(ipBlocks.active, true)))
    .limit(1);
  if (!existing[0]) return err(404, 'No active block for that address', { code: 'not_found', requestId: rid });
  await db
    .update(ipBlocks)
    .set({ active: false, activeKey: null })
    .where(eq(ipBlocks.id, existing[0].id));
  return json({ ok: true, ipAddress: ip, reason: body.reason || 'Unblocked' }, { requestId: rid });
}
