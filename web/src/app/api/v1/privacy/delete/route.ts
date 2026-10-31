import { eq } from 'drizzle-orm';
import { err, json, requestId, clientIp } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { events, decisions, logEntries } from '@/server/db/schema';
import { writeAudit } from '@/server/services/audit';

export const runtime = 'nodejs';

/**
 * Subject erasure (best-effort). Anonymizes user_id / session on events and decisions.
 * Does not delete security evidence required for active incidents by default — set hard=true to purge.
 */
export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN') {
    return err(403, 'Only SUPER_ADMIN can erase subject data', { code: 'forbidden', requestId: rid });
  }
  let body: { user_id?: string; ip_address?: string; hard?: boolean };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  if (!body.user_id && !body.ip_address) {
    return err(400, 'user_id or ip_address required', { code: 'invalid_body', requestId: rid });
  }

  let eventsTouched = 0;
  let decisionsTouched = 0;
  let logsTouched = 0;

  if (body.user_id) {
    if (body.hard) {
      await db.delete(events).where(eq(events.userId, body.user_id));
      eventsTouched = 1;
      await db.delete(decisions).where(eq(decisions.userId, body.user_id));
      decisionsTouched = 1;
    } else {
      await db
        .update(events)
        .set({ userId: '[erased]', sessionId: null, userAgent: null, metadata: null })
        .where(eq(events.userId, body.user_id));
      await db
        .update(decisions)
        .set({ userId: '[erased]', sessionId: null })
        .where(eq(decisions.userId, body.user_id));
      eventsTouched = 1;
      decisionsTouched = 1;
    }
  }
  if (body.ip_address && body.hard) {
    await db.delete(events).where(eq(events.ipAddress, body.ip_address));
    await db.delete(decisions).where(eq(decisions.ipAddress, body.ip_address));
    await db.delete(logEntries).where(eq(logEntries.ipAddress, body.ip_address));
    logsTouched = 1;
  }

  await writeAudit({
    requestId: rid,
    actorType: 'USER',
    actorId: me.id,
    actorLabel: me.email,
    action: 'privacy.delete',
    result: 'SUCCESS',
    metadata: { ...body },
    ipAddress: clientIp(req),
  });

  return json(
    {
      ok: true,
      mode: body.hard ? 'hard' : 'anonymize',
      eventsTouched,
      decisionsTouched,
      logsTouched,
    },
    { requestId: rid },
  );
}
