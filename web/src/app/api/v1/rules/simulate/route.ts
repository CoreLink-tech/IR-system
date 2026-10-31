import { and, eq, gte } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { events } from '@/server/db/schema';
import { getRuleRuntime } from '@/server/services/rules';

export const runtime = 'nodejs';

/**
 * Phase 2 backtest-lite: count how many historical login_failed bursts
 * would have matched brute_force in the last N hours (read-only).
 */
export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER') return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });

  let body: { hours?: number; rule?: string };
  try {
    body = await req.json();
  } catch {
    body = {};
  }
  const hours = Math.min(168, Math.max(1, body.hours ?? 24));
  const since = new Date(Date.now() - hours * 3600_000);
  const rules = await getRuleRuntime();
  const bf = rules['brute_force'];
  const windowMinutes = bf?.config.windowMinutes ?? 15;
  const threshold = bf?.config.threshold ?? 5;

  const rows = await db
    .select()
    .from(events)
    .where(and(eq(events.eventType, 'login_failed'), gte(events.createdAt, since)));

  const byIp = new Map<string, Date[]>();
  for (const e of rows) {
    if (!e.ipAddress) continue;
    const list = byIp.get(e.ipAddress) || [];
    list.push(e.createdAt);
    byIp.set(e.ipAddress, list);
  }

  let wouldFire = 0;
  const sample: string[] = [];
  for (const [ip, times] of byIp) {
    times.sort((a, b) => a.getTime() - b.getTime());
    for (let i = 0; i < times.length; i++) {
      const start = times[i].getTime();
      const end = start + windowMinutes * 60_000;
      let count = 0;
      for (let j = i; j < times.length && times[j].getTime() <= end; j++) count++;
      if (count >= threshold) {
        wouldFire += 1;
        if (sample.length < 10) sample.push(ip);
        break;
      }
    }
  }

  return json(
    {
      rule: 'brute_force',
      hours,
      windowMinutes,
      threshold,
      loginFailedEvents: rows.length,
      distinctIps: byIp.size,
      ipsThatWouldMatch: wouldFire,
      sampleIps: sample,
      note: 'Read-only simulation; does not change rules or blocks.',
    },
    { requestId: rid },
  );
}
