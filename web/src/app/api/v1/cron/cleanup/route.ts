import { and, eq, inArray, isNotNull, lt, or } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { db } from '@/server/db/client';
import { events, loginThrottle, refreshTokens, ipBlocks, incidents } from '@/server/db/schema';

export const runtime = 'nodejs';

/**
 * Vercel Cron or external scheduler.
 * Header: Authorization: Bearer $CRON_SECRET
 *
 * Events linked to OPEN / INVESTIGATING / CONTAINED incidents are retained
 * past the 90-day window until the incident is closed.
 */
export async function GET(req: Request) {
  const rid = requestId(req);
  const secret = process.env.CRON_SECRET;
  if (!secret) return err(503, 'CRON_SECRET not configured', { requestId: rid });
  const auth = req.headers.get('authorization') || '';
  if (auth !== `Bearer ${secret}`) return err(401, 'Unauthorized', { requestId: rid });

  const now = new Date();
  const eventCutoff = new Date(Date.now() - 90 * 86400000);
  const tokenCutoff = new Date(Date.now() - 30 * 86400000);

  await db
    .update(ipBlocks)
    .set({ active: false, activeKey: null })
    .where(and(eq(ipBlocks.active, true), isNotNull(ipBlocks.expiresAt), lt(ipBlocks.expiresAt, now)));

  await db
    .delete(refreshTokens)
    .where(
      or(
        lt(refreshTokens.expiresAt, tokenCutoff),
        and(isNotNull(refreshTokens.revokedAt), lt(refreshTokens.revokedAt, tokenCutoff)),
      ),
    );

  await db.delete(loginThrottle).where(and(isNotNull(loginThrottle.lockedUntil), lt(loginThrottle.lockedUntil, now)));

  // Collect active incident IDs to protect their evidence
  const active = await db
    .select({ id: incidents.id })
    .from(incidents)
    .where(or(eq(incidents.status, 'OPEN'), eq(incidents.status, 'INVESTIGATING'), eq(incidents.status, 'CONTAINED')));
  const protect = new Set(active.map((r) => r.id));

  // Delete aged events that are not tied to an active incident
  const aged = await db.select({ id: events.id, incidentId: events.incidentId }).from(events).where(lt(events.createdAt, eventCutoff));
  const toDelete = aged.filter((e) => !e.incidentId || !protect.has(e.incidentId)).map((e) => e.id);
  // batch deletes
  const chunk = 200;
  for (let i = 0; i < toDelete.length; i += chunk) {
    const batch = toDelete.slice(i, i + chunk);
    if (batch.length) {
      await db.delete(events).where(inArray(events.id, batch));
    }
  }

  return json(
    {
      ok: true,
      ranAt: now.toISOString(),
      eventsPurged: toDelete.length,
      eventsProtectedByActiveIncidents: aged.length - toDelete.length,
    },
    { requestId: rid },
  );
}
