import { and, eq, gte } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { events } from '@/server/db/schema';
import { getRuleRuntime } from '@/server/services/rules';

export const runtime = 'nodejs';

type EventRow = { ipAddress: string | null; eventType: string; userId: string | null; createdAt: Date };

function countSliding(times: number[], windowMs: number, threshold: number): boolean {
  times.sort((a, b) => a - b);
  for (let i = 0; i < times.length; i++) {
    const end = times[i] + windowMs;
    let c = 0;
    for (let j = i; j < times.length && times[j] <= end; j++) c++;
    if (c >= threshold) return true;
  }
  return false;
}

/**
 * Read-only backtest against stored events for key Phase 2 rules.
 */
export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER') return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });

  let body: { hours?: number };
  try {
    body = await req.json();
  } catch {
    body = {};
  }
  const hours = Math.min(168, Math.max(1, body.hours ?? 24));
  const since = new Date(Date.now() - hours * 3600_000);
  const rules = await getRuleRuntime();
  const rows = (await db
    .select({
      ipAddress: events.ipAddress,
      eventType: events.eventType,
      userId: events.userId,
      createdAt: events.createdAt,
    })
    .from(events)
    .where(gte(events.createdAt, since))) as EventRow[];

  const results: Record<string, { wouldMatch: number; sample: string[]; params: Record<string, number> }> = {};

  // brute_force
  {
    const bf = rules['brute_force'];
    const windowMs = (bf?.config.windowMinutes ?? 15) * 60_000;
    const threshold = bf?.config.threshold ?? 5;
    const byIp = new Map<string, number[]>();
    for (const e of rows) {
      if (e.eventType !== 'login_failed' || !e.ipAddress) continue;
      const list = byIp.get(e.ipAddress) || [];
      list.push(e.createdAt.getTime());
      byIp.set(e.ipAddress, list);
    }
    let n = 0;
    const sample: string[] = [];
    for (const [ip, times] of byIp) {
      if (countSliding(times, windowMs, threshold)) {
        n++;
        if (sample.length < 8) sample.push(ip);
      }
    }
    results.brute_force = { wouldMatch: n, sample, params: { windowMinutes: windowMs / 60000, threshold } };
  }

  // credential_stuffing — distinct users per IP
  {
    const cs = rules['credential_stuffing'];
    const windowMs = (cs?.config.windowMinutes ?? 30) * 60_000;
    const need = cs?.config.distinctUsers ?? 8;
    const byIp = new Map<string, { t: number; u: string }[]>();
    for (const e of rows) {
      if (e.eventType !== 'login_failed' || !e.ipAddress || !e.userId) continue;
      const list = byIp.get(e.ipAddress) || [];
      list.push({ t: e.createdAt.getTime(), u: e.userId });
      byIp.set(e.ipAddress, list);
    }
    let n = 0;
    const sample: string[] = [];
    for (const [ip, items] of byIp) {
      items.sort((a, b) => a.t - b.t);
      let hit = false;
      for (let i = 0; i < items.length; i++) {
        const end = items[i].t + windowMs;
        const users = new Set<string>();
        for (let j = i; j < items.length && items[j].t <= end; j++) users.add(items[j].u);
        if (users.size >= need) {
          hit = true;
          break;
        }
      }
      if (hit) {
        n++;
        if (sample.length < 8) sample.push(ip);
      }
    }
    results.credential_stuffing = { wouldMatch: n, sample, params: { windowMinutes: windowMs / 60000, distinctUsers: need } };
  }

  // admin_after_fails — admin_access IP had prior login_failed in window
  {
    const rule = rules['admin_after_fails'];
    const windowMs = (rule?.config.windowMinutes ?? 30) * 60_000;
    const failsByIp = new Map<string, number[]>();
    for (const e of rows) {
      if (e.eventType !== 'login_failed' || !e.ipAddress) continue;
      const list = failsByIp.get(e.ipAddress) || [];
      list.push(e.createdAt.getTime());
      failsByIp.set(e.ipAddress, list);
    }
    let n = 0;
    const sample: string[] = [];
    for (const e of rows) {
      if (e.eventType !== 'admin_access' || !e.ipAddress) continue;
      const fails = failsByIp.get(e.ipAddress) || [];
      const t = e.createdAt.getTime();
      if (fails.some((ft) => ft < t && t - ft <= windowMs)) {
        n++;
        if (sample.length < 8) sample.push(e.ipAddress);
      }
    }
    results.admin_after_fails = { wouldMatch: n, sample, params: { windowMinutes: windowMs / 60000 } };
  }

  // checkout_abuse
  {
    const rule = rules['checkout_abuse'];
    const windowMs = (rule?.config.windowMinutes ?? 10) * 60_000;
    const threshold = rule?.config.threshold ?? 4;
    const byIp = new Map<string, number[]>();
    for (const e of rows) {
      if (e.eventType !== 'payment_security_event' || !e.ipAddress) continue;
      const list = byIp.get(e.ipAddress) || [];
      list.push(e.createdAt.getTime());
      byIp.set(e.ipAddress, list);
    }
    let n = 0;
    const sample: string[] = [];
    for (const [ip, times] of byIp) {
      if (countSliding(times, windowMs, threshold)) {
        n++;
        if (sample.length < 8) sample.push(ip);
      }
    }
    results.checkout_abuse = { wouldMatch: n, sample, params: { windowMinutes: windowMs / 60000, threshold } };
  }

  return json(
    {
      hours,
      totalEvents: rows.length,
      results,
      note: 'Read-only simulation; does not change rules or blocks.',
    },
    { requestId: rid },
  );
}
