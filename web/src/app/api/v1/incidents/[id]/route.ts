import { eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { events, incidents } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const rid = requestId(req);
  const user = await requireUser(req);
  if (!user) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  const { id } = await ctx.params;
  const rows = await db.select().from(incidents).where(eq(incidents.id, id)).limit(1);
  const inc = rows[0];
  if (!inc) return err(404, 'Not found', { code: 'not_found', requestId: rid });
  const ev = await db.select().from(events).where(eq(events.incidentId, id)).limit(50);
  return json(
    {
      incident: {
        id: inc.id,
        publicNumber: inc.publicNumber,
        title: inc.title,
        status: inc.status,
        severity: inc.severity,
        sourceIp: inc.sourceIp,
        riskScore: inc.riskScore,
        eventCount: inc.eventCount,
        summary: inc.summary,
        assignedTo: inc.assignedTo,
        createdAt: inc.createdAt.toISOString(),
        updatedAt: inc.updatedAt.toISOString(),
        resolvedAt: inc.resolvedAt?.toISOString() ?? null,
      },
      events: ev.map((e) => ({
        id: e.id,
        eventType: e.eventType,
        severity: e.severity,
        riskScore: e.riskScore,
        createdAt: e.createdAt.toISOString(),
      })),
    },
    { requestId: rid },
  );
}

export async function PATCH(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const rid = requestId(req);
  const user = await requireUser(req);
  if (!user) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (user.role === 'VIEWER') return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  const { id } = await ctx.params;
  let body: { status?: string; assignedTo?: string | null; summary?: string };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  const rows = await db.select().from(incidents).where(eq(incidents.id, id)).limit(1);
  if (!rows[0]) return err(404, 'Not found', { code: 'not_found', requestId: rid });
  const allowed = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];
  if (body.status && !allowed.includes(body.status)) {
    return err(400, 'Invalid status', { code: 'invalid_body', requestId: rid });
  }
  const patch: Record<string, unknown> = { updatedAt: new Date() };
  if (body.status) {
    patch.status = body.status;
    if (body.status === 'RESOLVED' || body.status === 'FALSE_POSITIVE') {
      patch.resolvedAt = new Date();
      patch.openKey = null;
    }
  }
  if (body.assignedTo !== undefined) patch.assignedTo = body.assignedTo;
  if (body.summary !== undefined) patch.summary = body.summary;
  await db.update(incidents).set(patch).where(eq(incidents.id, id));
  return json({ ok: true }, { requestId: rid });
}
