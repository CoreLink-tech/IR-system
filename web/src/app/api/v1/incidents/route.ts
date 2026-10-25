import { desc } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { incidents } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const user = await requireUser(req);
  if (!user) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });

  const url = new URL(req.url);
  const page = Math.max(1, Number(url.searchParams.get('page') || 1));
  const pageSize = Math.min(100, Math.max(1, Number(url.searchParams.get('pageSize') || 20)));
  const offset = (page - 1) * pageSize;

  const rows = await db.select().from(incidents).orderBy(desc(incidents.createdAt)).limit(pageSize).offset(offset);

  return json(
    {
      data: rows.map((r) => ({
        id: r.id,
        publicNumber: r.publicNumber,
        title: r.title,
        status: r.status,
        severity: r.severity,
        sourceIp: r.sourceIp,
        riskScore: r.riskScore,
        eventCount: r.eventCount,
        assignedTo: r.assignedTo,
        createdAt: r.createdAt.toISOString(),
        updatedAt: r.updatedAt.toISOString(),
        resolvedAt: r.resolvedAt?.toISOString() ?? null,
      })),
      meta: { page, pageSize },
    },
    { requestId: rid },
  );
}
