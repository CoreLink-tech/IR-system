import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { IpIntelligenceService } from '../ips/ip-intelligence.service';
import { FactsService } from './facts.service';
import {
  buildIncidentReport, buildTechnicalReport, renderIncidentReportText, summarizeIncident,
} from './incident-report.builder';
import { buildExecutiveSummary, renderExecutiveSummaryText } from './executive-summary.builder';
import { buildSecuritySummary, renderSecuritySummaryText } from './security-summary.builder';
import {
  ExecutiveSummary, IncidentReport, PeriodFacts, SecurityPeriodFacts, SecuritySummary, TechnicalReport,
} from './report.types';

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const MAX_PERIOD_DAYS = 366;
const SUMMARY_DETAIL_COUNT = 5;
const MAX_PERIOD_INCIDENTS = 500;

/**
 * Entry point for report generation. Gathers verified facts, then hands them
 * to the pure builders. No AI is involved; the same data always produces the
 * same report.
 */
@Injectable()
export class ReportsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly facts: FactsService,
    private readonly intel: IpIntelligenceService,
  ) {}

  async incidentReport(id: string): Promise<IncidentReport> {
    return buildIncidentReport(await this.facts.gatherIncidentFacts(id));
  }

  async incidentReportText(id: string): Promise<string> {
    return renderIncidentReportText(await this.incidentReport(id));
  }

  async technicalReport(id: string): Promise<TechnicalReport> {
    return buildTechnicalReport(await this.facts.gatherIncidentFacts(id));
  }

  async executiveSummary(from: Date, to: Date): Promise<ExecutiveSummary> {
    return buildExecutiveSummary(await this.gatherPeriodFacts(from, to));
  }

  async executiveSummaryText(from: Date, to: Date): Promise<string> {
    return renderExecutiveSummaryText(await this.executiveSummary(from, to));
  }

  async securitySummary(from: Date, to: Date): Promise<SecuritySummary> {
    return buildSecuritySummary(await this.gatherSecurityFacts(from, to));
  }

  async securitySummaryText(from: Date, to: Date): Promise<string> {
    return renderSecuritySummaryText(await this.securitySummary(from, to));
  }

  private assertPeriod(from: Date, to: Date): number {
    if (!(from < to)) throw new BadRequestException('"from" must be earlier than "to"');
    const lengthMs = to.getTime() - from.getTime();
    if (lengthMs > MAX_PERIOD_DAYS * 86400000) {
      throw new BadRequestException(`Reporting period cannot exceed ${MAX_PERIOD_DAYS} days`);
    }
    return lengthMs;
  }

  async gatherSecurityFacts(from: Date, to: Date, now: Date = new Date()): Promise<SecurityPeriodFacts> {
    const lengthMs = this.assertPeriod(from, to);
    const prevFrom = new Date(from.getTime() - lengthMs);
    const range = { gte: from, lte: to };
    const prevRange = { gte: prevFrom, lt: from };

    const [
      events, ipRows, prevEvents, prevIncidents, incidentRows, typeRows, riskRows,
      topIpRows, blockRows, inForceRows, allowlisted, noRuleData, dailyEvents,
    ] = await Promise.all([
      this.prisma.securityEvent.count({ where: { occurredAt: range } }),
      this.prisma.securityEvent.groupBy({ by: ['ipAddress'], where: { occurredAt: range, ipAddress: { not: null } } }),
      this.prisma.securityEvent.count({ where: { occurredAt: prevRange } }),
      this.prisma.securityIncident.count({ where: { createdAt: prevRange } }),
      this.prisma.securityIncident.findMany({
        where: { createdAt: range }, orderBy: { createdAt: 'desc' }, take: MAX_PERIOD_INCIDENTS,
        select: { incidentId: true, severity: true, status: true, detectionRule: true, createdAt: true, resolvedAt: true, assignedTo: true },
      }),
      this.prisma.securityEvent.groupBy({
        by: ['eventType'], where: { occurredAt: range }, _count: { _all: true },
        orderBy: { _count: { eventType: 'desc' } }, take: 15,
      }),
      this.prisma.securityEvent.groupBy({ by: ['riskLevel'], where: { occurredAt: range }, _count: { _all: true } }),
      this.prisma.securityEvent.groupBy({
        by: ['ipAddress'], where: { occurredAt: range, ipAddress: { not: null } },
        _count: { _all: true }, _max: { riskScore: true },
        orderBy: { _count: { ipAddress: 'desc' } }, take: 10,
      }),
      this.prisma.securityIpBlock.findMany({
        where: { action: 'BLOCK', createdAt: range }, orderBy: { createdAt: 'asc' },
        select: { ipAddress: true, automatic: true }, take: 5000,
      }),
      this.prisma.securityIpBlock.findMany({
        where: { action: 'BLOCK', active: true, OR: [{ isPermanent: true }, { expiresAt: { gt: now } }] },
        select: { ipAddress: true },
      }),
      this.prisma.securityIpAllowlist.count(),
      this.eventsWithoutRuleData(from, to),
      this.dailyEventCounts(from, to),
    ]);

    const firstBlock = new Map<string, boolean>();
    for (const b of blockRows as any[]) if (!firstBlock.has(b.ipAddress)) firstBlock.set(b.ipAddress, b.automatic);
    const automatic = Array.from(firstBlock.values()).filter(Boolean).length;
    const inForce = new Set((inForceRows as any[]).map((b) => b.ipAddress));

    // Build one entry per UTC day so the series has no gaps for a chart.
    const incidentsByDay = new Map<string, number>();
    for (const i of incidentRows as any[]) {
      const d = i.createdAt.toISOString().slice(0, 10);
      incidentsByDay.set(d, (incidentsByDay.get(d) ?? 0) + 1);
    }
    const daily: SecurityPeriodFacts['daily'] = [];
    const cursor = new Date(Date.UTC(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate()));
    while (cursor <= to) {
      const d = cursor.toISOString().slice(0, 10);
      daily.push({ date: d, events: dailyEvents.get(d) ?? 0, incidents: incidentsByDay.get(d) ?? 0 });
      cursor.setUTCDate(cursor.getUTCDate() + 1);
    }

    return {
      generatedAt: now, from, to,
      previous: { incidents: prevIncidents, events: prevEvents },
      events, uniqueIps: ipRows.length,
      eventsByType: (typeRows as any[]).map((r) => ({ type: r.eventType, count: r._count._all })),
      eventsByRiskLevel: (riskRows as any[]).map((r) => ({ level: r.riskLevel, count: r._count._all }))
        .sort((a, b) => b.count - a.count),
      topSourceIps: (topIpRows as any[]).map((r) => ({
        ip: r.ipAddress, events: r._count._all, peakRisk: r._max.riskScore ?? 0, blocked: inForce.has(r.ipAddress),
      })),
      incidents: (incidentRows as any[]).map((i) => ({
        incidentId: i.incidentId, severity: i.severity, status: i.status, detectionRule: i.detectionRule,
        createdAt: i.createdAt, resolvedAt: i.resolvedAt, assigned: !!i.assignedTo,
      })),
      daily,
      blocks: { total: firstBlock.size, automatic, manual: firstBlock.size - automatic, stillInForce: inForce.size },
      allowlisted,
      eventsWithoutRuleData: noRuleData as number,
      intelProviders: this.intel.providerNames,
    };
  }

  /** Events recorded before rule detail was saved (column is SQL NULL). */
  private async eventsWithoutRuleData(from: Date, to: Date): Promise<number> {
    const rows: Array<{ c: bigint | number }> = await this.prisma.$queryRaw`
      SELECT COUNT(*) AS c FROM security_events
      WHERE occurredAt >= ${from} AND occurredAt <= ${to} AND matchedRules IS NULL`;
    return Number(rows[0]?.c ?? 0);
  }

  /** Events per UTC day. Uses one grouped query instead of one query per day. */
  private async dailyEventCounts(from: Date, to: Date): Promise<Map<string, number>> {
    const rows: Array<{ d: Date | string; c: bigint | number }> = await this.prisma.$queryRaw`
      SELECT DATE(occurredAt) AS d, COUNT(*) AS c
      FROM security_events
      WHERE occurredAt >= ${from} AND occurredAt <= ${to}
      GROUP BY DATE(occurredAt)`;
    const out = new Map<string, number>();
    for (const r of rows) {
      const key = r.d instanceof Date ? r.d.toISOString().slice(0, 10) : String(r.d).slice(0, 10);
      out.set(key, Number(r.c));
    }
    return out;
  }

  async gatherPeriodFacts(from: Date, to: Date, now: Date = new Date()): Promise<PeriodFacts> {
    const lengthMs = this.assertPeriod(from, to);
    const prevFrom = new Date(from.getTime() - lengthMs);
    const range = { gte: from, lte: to };
    const prevRange = { gte: prevFrom, lt: from };

    const [events, ipRows, prevEvents, prevIncidents, incidentRows, blockRows, inForceRows] = await Promise.all([
      this.prisma.securityEvent.count({ where: { occurredAt: range } }),
      this.prisma.securityEvent.groupBy({ by: ['ipAddress'], where: { occurredAt: range, ipAddress: { not: null } } }),
      this.prisma.securityEvent.count({ where: { occurredAt: prevRange } }),
      this.prisma.securityIncident.count({ where: { createdAt: prevRange } }),
      this.prisma.securityIncident.findMany({
        where: { createdAt: range }, orderBy: { createdAt: 'desc' }, take: MAX_PERIOD_INCIDENTS,
      }),
      this.prisma.securityIpBlock.findMany({
        where: { action: 'BLOCK', createdAt: range },
        orderBy: { createdAt: 'asc' }, select: { ipAddress: true, automatic: true }, take: 5000,
      }),
      this.prisma.securityIpBlock.findMany({
        where: { action: 'BLOCK', active: true, OR: [{ isPermanent: true }, { expiresAt: { gt: now } }] },
        select: { ipAddress: true },
      }),
    ]);

    // Repeated renewals of one block must not inflate the count: one entry per address,
    // classified by how that address was first blocked in the period.
    const firstBlock = new Map<string, boolean>();
    for (const b of blockRows as any[]) {
      if (!firstBlock.has(b.ipAddress)) firstBlock.set(b.ipAddress, b.automatic);
    }
    const automatic = Array.from(firstBlock.values()).filter(Boolean).length;
    const stillInForce = new Set((inForceRows as any[]).map((b) => b.ipAddress)).size;

    // Plain-English summaries are built for the most important incidents only.
    const ranked = [...incidentRows].sort((a: any, b: any) =>
      (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) || b.riskScore - a.riskScore);
    const detailIds = new Set(ranked.slice(0, SUMMARY_DETAIL_COUNT).map((i: any) => i.id));
    const summaries = new Map<string, string>();
    await Promise.all(Array.from(detailIds).map(async (id) => {
      try {
        summaries.set(id, summarizeIncident(await this.facts.gatherIncidentFacts(id, now)));
      } catch {
        /* fall back to the title below */
      }
    }));

    return {
      generatedAt: now, from, to,
      previous: { incidents: prevIncidents, events: prevEvents },
      events,
      uniqueIps: ipRows.length,
      incidents: incidentRows.map((i: any) => ({
        incidentId: i.incidentId, id: i.id, title: i.title, severity: i.severity, status: i.status,
        riskScore: i.riskScore, sourceIp: i.sourceIp, detectionRule: i.detectionRule,
        createdAt: i.createdAt, assigned: !!i.assignedTo,
        summary: summaries.get(i.id) ?? i.title,
      })),
      blocks: { total: firstBlock.size, automatic, manual: firstBlock.size - automatic, stillInForce },
      intelProviders: this.intel.providerNames,
    };
  }
}
