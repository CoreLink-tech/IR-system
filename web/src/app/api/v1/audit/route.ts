import { desc } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { auditLog } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER') return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });

  const url = new URL(req.url);
  const pageSize = Math.min(100, Math.max(1, Number(url.searchParams.get('pageSize') || 50)));
  const rows = await db.select().from(auditLog).orderBy(desc(auditLog.createdAt)).limit(pageSize);
  return json(
    {
      data: rows.map((r) => ({
        id: r.id,
        requestId: r.requestId,
        actorType: r.actorType,
        actorId: r.actorId,
        actorLabel: r.actorLabel,
        action: r.action,
        targetType: r.targetType,
        targetId: r.targetId,
        result: r.result,
        metadata: r.metadata ? JSON.parse(r.metadata) : null,
        ipAddress: r.ipAddress,
        createdAt: r.createdAt.toISOString(),
      })),
    },
    { requestId: rid },
  );
}
