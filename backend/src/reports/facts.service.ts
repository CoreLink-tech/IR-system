import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { IpIntelligenceService } from '../ips/ip-intelligence.service';
import { isPrivateIp } from '../common/utils/ip.util';
import { stripQuery } from './language';
import { IncidentFacts, RuleFired } from './report.types';

/** Events earlier than the incident that still count as part of the same activity. */
export const LOOKBACK_MINUTES = 60;
/** Cap for per-event detail reads so a huge incident cannot exhaust memory. */
export const SAMPLE_CAP = 2000;
const LOGIN_SUCCESS_LOOKBACK_DAYS = 7;

/**
 * Reads verified facts about an incident from the database.
 * This is the only place in the reporting engine that touches the database
 * for incident facts. Everything downstream is pure.
 */
@Injectable()
export class FactsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly intel: IpIntelligenceService,
  ) {}

  async gatherIncidentFacts(id: string, now: Date = new Date()): Promise<IncidentFacts> {
    // Accept either the internal id or the public incident number (INC-...).
    const incident = await this.prisma.securityIncident.findFirst({
      where: { OR: [{ id }, { incidentId: id }] },
      include: { assignee: { select: { email: true } } },
    });
    if (!incident) throw new NotFoundException('Incident not found');

    const from = new Date(incident.createdAt.getTime() - LOOKBACK_MINUTES * 60 * 1000);
    const to = incident.resolvedAt ?? now;
    const ipAddress = incident.sourceIp;

    // Activity is everything from the source address inside the window. An incident
    // with no source address falls back to the events attached to it.
    const where: any = ipAddress
      ? { ipAddress, occurredAt: { gte: from, lte: to } }
      : { incidentId: incident.id };

    const loginSuccessSince = new Date(now.getTime() - LOGIN_SUCCESS_LOOKBACK_DAYS * 86400000);

    const [
      total, bounds, byTypeRows, failedLoginUsers, attached, peak, sample,
      loginSuccessAnywhere, ipRec, allowRow, blockRows, timelineRows, ruleRow, lifetimeEvents,
    ] = await Promise.all([
      this.prisma.securityEvent.count({ where }),
      this.prisma.securityEvent.aggregate({ where, _min: { occurredAt: true }, _max: { occurredAt: true } }),
      this.prisma.securityEvent.groupBy({ by: ['eventType'], where, _count: { _all: true } }),
      this.prisma.securityEvent.findMany({
        where: { ...where, eventType: 'login_failed', userId: { not: null } },
        distinct: ['userId'], select: { userId: true },
      }),
      this.prisma.securityEvent.count({ where: { incidentId: incident.id } }),
      this.prisma.securityEvent.aggregate({ where, _max: { riskScore: true } }),
      this.prisma.securityEvent.findMany({
        where, orderBy: { occurredAt: 'desc' }, take: SAMPLE_CAP,
        select: { requestPath: true, matchedRules: true },
      }),
      this.prisma.securityEvent.count({ where: { eventType: 'login_success', occurredAt: { gte: loginSuccessSince } } }),
      ipAddress ? this.prisma.securityIp.findUnique({ where: { ipAddress } }) : Promise.resolve(null),
      ipAddress ? this.prisma.securityIpAllowlist.findUnique({ where: { ipAddress } }) : Promise.resolve(null),
      ipAddress
        ? this.prisma.securityIpBlock.findMany({
            where: {
              ipAddress,
              OR: [{ createdAt: { gte: from } }, { relatedIncidentId: incident.id }, { active: true }],
            },
            orderBy: { createdAt: 'asc' },
            include: { administrator: { select: { email: true } } },
          })
        : Promise.resolve([] as any[]),
      this.prisma.securityIncidentTimeline.findMany({ where: { incidentId: incident.id }, orderBy: { createdAt: 'asc' } }),
      incident.detectionRule ? this.prisma.securityRule.findUnique({ where: { code: incident.detectionRule } }) : Promise.resolve(null),
      ipAddress ? this.prisma.securityEvent.count({ where: { ipAddress } }) : Promise.resolve(0),
    ]);

    const countOf = (type: string) => byTypeRows.find((r: any) => r.eventType === type)?._count._all ?? 0;
    const failedLogins = countOf('login_failed');

    // Rule and path detail come from the (possibly capped) sample.
    const sampled = total > SAMPLE_CAP;
    const fired = new Map<string, RuleFired>();
    const pathCounts = new Map<string, number>();
    let withRuleData = 0;
    const ruleNames = new Map<string, string>();
    const allRules = await this.prisma.securityRule.findMany({ select: { code: true, name: true } });
    allRules.forEach((r: any) => ruleNames.set(r.code, r.name));

    for (const ev of sample as any[]) {
      if (ev.requestPath) {
        const p = stripQuery(ev.requestPath);
        pathCounts.set(p, (pathCounts.get(p) ?? 0) + 1);
      }
      const rules = Array.isArray(ev.matchedRules) ? ev.matchedRules : null;
      if (!rules) continue;
      withRuleData += 1;
      for (const r of rules) {
        if (!r || typeof r.code !== 'string') continue;
        const cur: RuleFired = fired.get(r.code) ?? {
          code: r.code, name: ruleNames.get(r.code) ?? r.code, events: 0, maxRiskDelta: 0,
        };
        cur.events += 1;
        cur.maxRiskDelta = Math.max(cur.maxRiskDelta, Number(r.riskDelta) || 0);
        if (!cur.lastReason && typeof r.reason === 'string') cur.lastReason = r.reason;
        fired.set(r.code, cur);
      }
    }

    const providers = this.intel.providerNames;
    const flags = ipRec;

    const facts: IncidentFacts = {
      generatedAt: now,
      incident: {
        id: incident.id, incidentId: incident.incidentId, title: incident.title,
        severity: incident.severity, status: incident.status, riskScore: incident.riskScore,
        detectionRule: incident.detectionRule, sourceIp: incident.sourceIp,
        createdAt: incident.createdAt, updatedAt: incident.updatedAt, resolvedAt: incident.resolvedAt,
        resolutionNotes: incident.resolutionNotes, assignee: (incident as any).assignee?.email ?? null,
      },
      rule: ruleRow ? { code: ruleRow.code, name: ruleRow.name, description: ruleRow.description } : null,
      window: { from, to, lookbackMinutes: LOOKBACK_MINUTES },
      activity: {
        totalEvents: total,
        firstEventAt: bounds._min.occurredAt ?? null,
        lastEventAt: bounds._max.occurredAt ?? null,
        byType: byTypeRows
          .map((r: any) => ({ type: r.eventType as string, count: r._count._all as number }))
          .sort((a: any, b: any) => b.count - a.count),
        failedLogins,
        successfulLogins: countOf('login_success'),
        distinctUsersFailed: failedLoginUsers.length,
        passwordResets: countOf('password_reset'),
        paymentEvents: countOf('payment_security_event'),
        sessionAnomalies: countOf('session_anomaly'),
        adminAccesses: countOf('admin_access'),
        attachedEvents: attached,
        peakRisk: peak._max.riskScore ?? 0,
        topPaths: Array.from(pathCounts.entries()).map(([path, count]) => ({ path, count }))
          .sort((a, b) => b.count - a.count).slice(0, 5),
        rulesFired: Array.from(fired.values()).sort((a, b) => b.events - a.events),
        eventsWithRuleData: withRuleData,
        sampled,
      },
      signals: { loginSuccessReported: loginSuccessAnywhere > 0 },
      ip: ipAddress
        ? {
            address: ipAddress,
            isPrivate: isPrivateIp(ipAddress),
            country: flags?.country ?? null, region: flags?.region ?? null, city: flags?.city ?? null,
            isVpn: !!flags?.isVpn, isProxy: !!flags?.isProxy, isTor: !!flags?.isTor,
            isDatacenter: !!flags?.isDatacenter, isMalicious: !!flags?.isMalicious,
            reputationScore: flags?.reputationScore ?? 0,
            // Only trust stored flags if a provider actually exists to have produced them.
            intelligenceChecked: !!flags?.lastIntelUpdate && providers.length > 0,
            firstSeenAt: flags?.firstSeenAt ?? null,
            lifetimeEvents,
          }
        : null,
      intelProviders: providers,
      blocks: (blockRows as any[]).map((b) => ({
        action: b.action,
        createdAt: b.createdAt,
        automatic: b.automatic,
        permanent: b.isPermanent,
        expiresAt: b.expiresAt,
        inForce: b.action === 'BLOCK' && b.active && (b.isPermanent || !b.expiresAt || b.expiresAt > now),
        reason: b.reason,
        administrator: b.administrator?.email ?? null,
      })),
      allowlisted: !!allowRow && (!allowRow.expiresAt || allowRow.expiresAt > now),
      timeline: timelineRows.map((t: any) => ({
        at: t.createdAt, action: t.action, actor: t.actor, details: t.details,
      })),
    };
    return facts;
  }
}
