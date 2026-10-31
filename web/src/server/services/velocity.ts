import { and, eq, gte, sql } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { events, entityScores, ruleCooldowns, logEntries } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';

/** Count events of a type for an IP within a sliding window (DB-backed, multi-instance safe). */
export async function countEventsInWindow(opts: {
  tenantId?: string | null;
  ip: string;
  eventType: string;
  windowMinutes: number;
}): Promise<number> {
  const since = new Date(Date.now() - opts.windowMinutes * 60_000);
  const rows = await db
    .select({ c: sql<number>`count(*)` })
    .from(events)
    .where(
      and(
        eq(events.ipAddress, opts.ip),
        eq(events.eventType, opts.eventType),
        gte(events.createdAt, since),
      ),
    );
  return Number(rows[0]?.c ?? 0);
}

/** Count distinct user_id values for login_failed from one IP (credential stuffing signal). */
export async function countDistinctUsersLoginFailed(opts: {
  ip: string;
  windowMinutes: number;
}): Promise<number> {
  const since = new Date(Date.now() - opts.windowMinutes * 60_000);
  const rows = await db
    .select({ c: sql<number>`count(distinct ${events.userId})` })
    .from(events)
    .where(
      and(
        eq(events.ipAddress, opts.ip),
        eq(events.eventType, 'login_failed'),
        gte(events.createdAt, since),
      ),
    );
  return Number(rows[0]?.c ?? 0);
}

/** Log-derived: count of log lines matching path pattern for IP. */
export async function countLogPathHits(opts: {
  tenantId: string;
  ip: string;
  pathSubstring: string;
  windowMinutes: number;
}): Promise<number> {
  const since = new Date(Date.now() - opts.windowMinutes * 60_000);
  const rows = await db
    .select({ c: sql<number>`count(*)` })
    .from(logEntries)
    .where(
      and(
        eq(logEntries.tenantId, opts.tenantId),
        eq(logEntries.ipAddress, opts.ip),
        gte(logEntries.createdAt, since),
        sql`${logEntries.path} like ${'%' + opts.pathSubstring + '%'}`,
      ),
    );
  return Number(rows[0]?.c ?? 0);
}

export async function isOnCooldown(ruleCode: string, entityKey: string): Promise<boolean> {
  const now = new Date();
  const rows = await db
    .select()
    .from(ruleCooldowns)
    .where(and(eq(ruleCooldowns.ruleCode, ruleCode), eq(ruleCooldowns.entityKey, entityKey)))
    .limit(5);
  return rows.some((r) => r.untilAt && r.untilAt > now);
}

export async function setCooldown(opts: {
  tenantId?: string | null;
  ruleCode: string;
  entityKey: string;
  minutes: number;
}) {
  const until = new Date(Date.now() + opts.minutes * 60_000);
  await db.insert(ruleCooldowns).values({
    id: newId(),
    tenantId: opts.tenantId || null,
    ruleCode: opts.ruleCode,
    entityKey: opts.entityKey,
    untilAt: until,
    createdAt: new Date(),
  });
}

/** Additive entity score with soft cap 100 and light decay toward 0 over days. */
export async function bumpEntityScore(opts: {
  tenantId?: string | null;
  entityType: string;
  entityKey: string;
  delta: number;
}): Promise<number> {
  const existing = await db
    .select()
    .from(entityScores)
    .where(and(eq(entityScores.entityType, opts.entityType), eq(entityScores.entityKey, opts.entityKey)))
    .limit(1);
  const now = new Date();
  if (existing[0]) {
    const days = Math.max(0, (now.getTime() - (existing[0].updatedAt?.getTime() || now.getTime())) / 86400000);
    const decayed = Math.max(0, existing[0].score - Math.floor(days * 5));
    const score = Math.min(100, decayed + opts.delta);
    await db
      .update(entityScores)
      .set({ score, lastEventAt: now, updatedAt: now })
      .where(eq(entityScores.id, existing[0].id));
    return score;
  }
  const score = Math.min(100, Math.max(0, opts.delta));
  await db.insert(entityScores).values({
    id: newId(),
    tenantId: opts.tenantId || null,
    entityType: opts.entityType,
    entityKey: opts.entityKey,
    score,
    lastEventAt: now,
    updatedAt: now,
  });
  return score;
}

export async function countEventsForUser(opts: {
  userId: string;
  eventType: string;
  windowMinutes: number;
}): Promise<number> {
  const since = new Date(Date.now() - opts.windowMinutes * 60_000);
  const rows = await db
    .select({ c: sql<number>`count(*)` })
    .from(events)
    .where(
      and(
        eq(events.userId, opts.userId),
        eq(events.eventType, opts.eventType),
        gte(events.createdAt, since),
      ),
    );
  return Number(rows[0]?.c ?? 0);
}

/** True if eventTypeA occurred for this IP before the current moment within window. */
export async function hasPriorEventType(opts: {
  ip: string;
  eventType: string;
  windowMinutes: number;
}): Promise<boolean> {
  const n = await countEventsInWindow({
    ip: opts.ip,
    eventType: opts.eventType,
    windowMinutes: opts.windowMinutes,
  });
  return n > 0;
}

/** Session-scoped event count. */
export async function countEventsForSession(opts: {
  sessionId: string;
  eventType?: string;
  windowMinutes: number;
}): Promise<number> {
  const since = new Date(Date.now() - opts.windowMinutes * 60_000);
  const conditions = [eq(events.sessionId, opts.sessionId), gte(events.createdAt, since)];
  if (opts.eventType) conditions.push(eq(events.eventType, opts.eventType));
  const rows = await db.select({ c: sql<number>`count(*)` }).from(events).where(and(...conditions));
  return Number(rows[0]?.c ?? 0);
}
