import { desc, eq, gte } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { events, incidents, ipBlocks } from '@/server/db/schema';

function sinceDays(days: number): Date {
  return new Date(Date.now() - days * 86400000);
}

export async function executiveSummary(days = 7) {
  const since = sinceDays(days);
  const openIncidents = await db
    .select()
    .from(incidents)
    .where(eq(incidents.status, 'OPEN'));
  const recentIncidents = await db
    .select()
    .from(incidents)
    .where(gte(incidents.createdAt, since))
    .orderBy(desc(incidents.createdAt))
    .limit(20);
  const recentEvents = await db
    .select()
    .from(events)
    .where(gte(events.createdAt, since))
    .limit(5000);
  const activeBlocks = await db
    .select()
    .from(ipBlocks)
    .where(eq(ipBlocks.active, true));

  const byType: Record<string, number> = {};
  let highRiskEvents = 0;
  for (const e of recentEvents) {
    byType[e.eventType] = (byType[e.eventType] || 0) + 1;
    if (e.riskScore >= 60) highRiskEvents += 1;
  }

  const criticalOpen = openIncidents.filter((i) => i.severity === 'CRITICAL' || i.riskScore >= 85).length;
  const highOpen = openIncidents.filter((i) => i.severity === 'HIGH' || (i.riskScore >= 60 && i.riskScore < 85)).length;

  let posture: 'CALM' | 'ELEVATED' | 'HIGH' | 'CRITICAL' = 'CALM';
  if (criticalOpen > 0) posture = 'CRITICAL';
  else if (highOpen >= 3 || activeBlocks.length >= 10) posture = 'HIGH';
  else if (openIncidents.length > 0 || highRiskEvents > 20) posture = 'ELEVATED';

  return {
    periodDays: days,
    generatedAt: new Date().toISOString(),
    posture,
    summary: {
      openIncidents: openIncidents.length,
      criticalOpen,
      highOpen,
      eventsInPeriod: recentEvents.length,
      highRiskEvents,
      activeBlocks: activeBlocks.length,
    },
    topEventTypes: Object.entries(byType)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([type, count]) => ({ type, count })),
    recentIncidents: recentIncidents.map((i) => ({
      id: i.id,
      publicNumber: i.publicNumber,
      title: i.title,
      status: i.status,
      severity: i.severity,
      riskScore: i.riskScore,
      sourceIp: i.sourceIp,
      createdAt: i.createdAt.toISOString(),
    })),
    plainEnglish: plainEnglish(posture, {
      open: openIncidents.length,
      critical: criticalOpen,
      blocks: activeBlocks.length,
      events: recentEvents.length,
      days,
    }),
  };
}

function plainEnglish(
  posture: string,
  n: { open: number; critical: number; blocks: number; events: number; days: number },
): string {
  if (posture === 'CRITICAL') {
    return `Security posture is critical. There ${n.critical === 1 ? 'is' : 'are'} ${n.critical} critical open incident(s). Review and contain them before routine work.`;
  }
  if (posture === 'HIGH') {
    return `Security posture is high. ${n.open} open incident(s) and ${n.blocks} active block(s) need attention within the next business day.`;
  }
  if (posture === 'ELEVATED') {
    return `Security posture is elevated. ${n.events} events were recorded in the last ${n.days} days with ${n.open} open incident(s). Monitor closely.`;
  }
  return `Security posture is calm. ${n.events} events in the last ${n.days} days and no critical open incidents.`;
}

export async function technicalReport(days = 7) {
  const exec = await executiveSummary(days);
  const since = sinceDays(days);
  const blocks = await db
    .select()
    .from(ipBlocks)
    .where(gte(ipBlocks.createdAt, since))
    .orderBy(desc(ipBlocks.createdAt))
    .limit(50);

  return {
    ...exec,
    blocksInPeriod: blocks.map((b) => ({
      ipAddress: b.ipAddress,
      reason: b.reason,
      automatic: b.automatic,
      active: b.active,
      expiresAt: b.expiresAt?.toISOString() ?? null,
      createdAt: b.createdAt.toISOString(),
    })),
  };
}
