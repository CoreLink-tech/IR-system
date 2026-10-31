import { desc, eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { events, incidents, incidentStatusHistory, incidentNotes } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';

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
  const notes = await db.select().from(incidentNotes).where(eq(incidentNotes.incidentId, id)).orderBy(desc(incidentNotes.createdAt)).limit(50);
  let history: Array<{ id: string; fromStatus: string | null; toStatus: string; actorId: string | null; createdAt: Date }> = [];
  try {
    history = await db.select().from(incidentStatusHistory).where(eq(incidentStatusHistory.incidentId, id)).orderBy(desc(incidentStatusHistory.createdAt)).limit(50);
  } catch {
    history = [];
  }
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
      notes: notes.map((n) => ({
        id: n.id,
        body: n.body,
        authorId: n.authorId,
        createdAt: n.createdAt.toISOString(),
      })),
      history: history.map((h) => ({
        id: h.id,
        fromStatus: h.fromStatus,
        toStatus: h.toStatus,
        actorId: h.actorId,
        createdAt: h.createdAt.toISOString(),
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
  if (body.status && body.status !== rows[0].status) {
    await db.insert(incidentStatusHistory).values({
      id: newId(),
      incidentId: id,
      fromStatus: rows[0].status,
      toStatus: body.status,
      actorId: user.id,
      createdAt: new Date(),
    });
  }
  await db.update(incidents).set(patch).where(eq(incidents.id, id));
  return json({ ok: true }, { requestId: rid });
}
