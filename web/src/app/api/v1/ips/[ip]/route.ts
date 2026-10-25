import { desc, eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { events, ipBlocks, ipIntelligence } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function GET(req: Request, ctx: { params: Promise<{ ip: string }> }) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  const { ip } = await ctx.params;
  const decoded = decodeURIComponent(ip);

  const intelRows = await db.select().from(ipIntelligence).where(eq(ipIntelligence.ipAddress, decoded)).limit(1);
  const intel = intelRows[0] || null;
  const recent = await db
    .select()
    .from(events)
    .where(eq(events.ipAddress, decoded))
    .orderBy(desc(events.createdAt))
    .limit(30);
  const blocks = await db.select().from(ipBlocks).where(eq(ipBlocks.ipAddress, decoded)).orderBy(desc(ipBlocks.createdAt)).limit(10);

  return json(
    {
      ip: decoded,
      intelligence: intel
        ? {
            riskScore: intel.riskScore,
            riskLevel: intel.riskLevel,
            eventCount: intel.eventCount,
            failedLogins: intel.failedLogins,
            firstSeenAt: intel.firstSeenAt?.toISOString() ?? null,
            lastSeenAt: intel.lastSeenAt?.toISOString() ?? null,
            country: intel.country,
            isVpn: intel.isVpn,
            isProxy: intel.isProxy,
            isTor: intel.isTor,
            isDatacenter: intel.isDatacenter,
            isMalicious: intel.isMalicious,
          }
        : null,
      events: recent.map((e) => ({
        id: e.id,
        eventType: e.eventType,
        severity: e.severity,
        riskScore: e.riskScore,
        createdAt: e.createdAt.toISOString(),
      })),
      blocks: blocks.map((b) => ({
        id: b.id,
        reason: b.reason,
        active: b.active,
        automatic: b.automatic,
        expiresAt: b.expiresAt?.toISOString() ?? null,
        createdAt: b.createdAt.toISOString(),
      })),
    },
    { requestId: rid },
  );
}
