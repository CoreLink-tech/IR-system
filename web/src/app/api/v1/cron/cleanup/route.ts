import { and, eq, isNotNull, lt, or } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { db } from '@/server/db/client';
import { events, loginThrottle, refreshTokens, ipBlocks } from '@/server/db/schema';

export const runtime = 'nodejs';

/**
 * Vercel Cron or external scheduler.
 * Header: Authorization: Bearer $CRON_SECRET
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

  // Expire blocks
  await db
    .update(ipBlocks)
    .set({ active: false, activeKey: null })
    .where(and(eq(ipBlocks.active, true), isNotNull(ipBlocks.expiresAt), lt(ipBlocks.expiresAt, now)));

  // Old revoked/expired refresh tokens
  await db
    .delete(refreshTokens)
    .where(or(lt(refreshTokens.expiresAt, tokenCutoff), and(isNotNull(refreshTokens.revokedAt), lt(refreshTokens.revokedAt, tokenCutoff))));

  // Clear stale lockouts
  await db.delete(loginThrottle).where(and(isNotNull(loginThrottle.lockedUntil), lt(loginThrottle.lockedUntil, now)));

  // Optional: trim old low-severity events (keep 90 days)
  await db.delete(events).where(lt(events.createdAt, eventCutoff));

  return json({ ok: true, ranAt: now.toISOString() }, { requestId: rid });
}
