import { eq, or } from 'drizzle-orm';
import { err, json, requestId, clientIp } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { events, decisions, users, auditLog } from '@/server/db/schema';
import { writeAudit } from '@/server/services/audit';

export const runtime = 'nodejs';

/**
 * GDPR/NDPR-style data export for a subject (email or user_id or ip).
 * SUPER_ADMIN / SECURITY_ADMIN only.
 */
export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN' && me.role !== 'SECURITY_ADMIN') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  let body: { email?: string; user_id?: string; ip_address?: string };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  if (!body.email && !body.user_id && !body.ip_address) {
    return err(400, 'email, user_id, or ip_address required', { code: 'invalid_body', requestId: rid });
  }

  const subjectEvents = body.user_id
    ? await db.select().from(events).where(eq(events.userId, body.user_id)).limit(5000)
    : body.ip_address
      ? await db.select().from(events).where(eq(events.ipAddress, body.ip_address)).limit(5000)
      : [];

  const subjectDecisions = body.user_id
    ? await db.select().from(decisions).where(eq(decisions.userId, body.user_id)).limit(2000)
    : body.ip_address
      ? await db.select().from(decisions).where(eq(decisions.ipAddress, body.ip_address)).limit(2000)
      : [];

  let account = null;
  if (body.email) {
    const rows = await db.select().from(users).where(eq(users.email, body.email.toLowerCase())).limit(1);
    if (rows[0]) {
      account = {
        id: rows[0].id,
        email: rows[0].email,
        name: rows[0].name,
        role: rows[0].role,
        createdAt: rows[0].createdAt.toISOString(),
        lastLoginAt: rows[0].lastLoginAt?.toISOString() ?? null,
      };
    }
  }

  await writeAudit({
    requestId: rid,
    actorType: 'USER',
    actorId: me.id,
    actorLabel: me.email,
    action: 'privacy.export',
    metadata: { email: body.email, user_id: body.user_id, ip_address: body.ip_address },
    ipAddress: clientIp(req),
  });

  return json(
    {
      exportedAt: new Date().toISOString(),
      subject: body,
      account,
      events: subjectEvents.map((e) => ({
        id: e.id,
        eventType: e.eventType,
        ipAddress: e.ipAddress,
        userId: e.userId,
        riskScore: e.riskScore,
        createdAt: e.createdAt.toISOString(),
      })),
      decisions: subjectDecisions.map((d) => ({
        id: d.id,
        outcome: d.outcome,
        score: d.score,
        createdAt: d.createdAt.toISOString(),
      })),
      note: 'Password hashes and API key secrets are never exported.',
    },
    { requestId: rid },
  );
}
