import { desc, eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { newId } from '@/server/auth/crypto';
import { db } from '@/server/db/client';
import { incidentNotes, incidents } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  const { id } = await ctx.params;
  const rows = await db.select().from(incidentNotes).where(eq(incidentNotes.incidentId, id)).orderBy(desc(incidentNotes.createdAt));
  return json(
    {
      data: rows.map((n) => ({
        id: n.id,
        body: n.body,
        authorId: n.authorId,
        createdAt: n.createdAt.toISOString(),
      })),
    },
    { requestId: rid },
  );
}

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER') return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  const { id } = await ctx.params;
  const exists = await db.select().from(incidents).where(eq(incidents.id, id)).limit(1);
  if (!exists[0]) return err(404, 'Not found', { code: 'not_found', requestId: rid });
  let body: { body?: string };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  if (!body.body?.trim()) return err(400, 'body required', { code: 'invalid_body', requestId: rid });
  const noteId = newId();
  await db.insert(incidentNotes).values({
    id: noteId,
    incidentId: id,
    authorId: me.id,
    body: body.body.trim(),
    createdAt: new Date(),
  });
  return json({ id: noteId }, { requestId: rid });
}
