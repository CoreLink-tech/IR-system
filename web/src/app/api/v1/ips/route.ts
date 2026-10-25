import { desc } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { events, ipIntelligence } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });

  const intel = await db.select().from(ipIntelligence).orderBy(desc(ipIntelligence.lastSeenAt)).limit(100);
  if (intel.length > 0) {
    return json(
      {
        data: intel.map((r) => ({
          ipAddress: r.ipAddress,
          riskScore: r.riskScore,
          riskLevel: r.riskLevel,
          eventCount: r.eventCount,
          failedLogins: r.failedLogins,
          lastSeenAt: r.lastSeenAt?.toISOString() ?? null,
          country: r.country,
        })),
      },
      { requestId: rid },
    );
  }

  // Fallback: recent events' IPs (deduped in app)
  const recent = await db.select().from(events).orderBy(desc(events.createdAt)).limit(500);
  const map = new Map<string, { eventCount: number; lastSeenAt: string }>();
  for (const e of recent) {
    if (!e.ipAddress) continue;
    const cur = map.get(e.ipAddress);
    if (!cur) {
      map.set(e.ipAddress, { eventCount: 1, lastSeenAt: e.createdAt.toISOString() });
    } else {
      cur.eventCount += 1;
    }
  }
  const data = [...map.entries()].map(([ipAddress, v]) => ({
    ipAddress,
    riskScore: 0,
    riskLevel: 'NORMAL',
    eventCount: v.eventCount,
    failedLogins: 0,
    lastSeenAt: v.lastSeenAt,
    country: null as string | null,
  }));
  data.sort((a, b) => b.eventCount - a.eventCount);
  return json({ data: data.slice(0, 100) }, { requestId: rid });
}
