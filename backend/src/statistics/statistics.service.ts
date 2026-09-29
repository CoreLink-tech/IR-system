import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class StatisticsService {
  constructor(private readonly prisma: PrismaService) {}

  async summary() {
    const now = Date.now();
    const since24h = new Date(now - 24 * 3600 * 1000);
    const since7d = new Date(now - 7 * 24 * 3600 * 1000);
    const since30d = new Date(now - 30 * 24 * 3600 * 1000);

    const [
      events24h, events7d, events30d,
      incidentsOpen, incidentsInvestigating, incidentsContained,
      incidentsResolved, incidentsFalsePositive,
      criticalIncidents24h,
      activeBlocks,
      allowlistCount,
    ] = await Promise.all([
      this.prisma.securityEvent.count({ where: { occurredAt: { gte: since24h } } }),
      this.prisma.securityEvent.count({ where: { occurredAt: { gte: since7d } } }),
      this.prisma.securityEvent.count({ where: { occurredAt: { gte: since30d } } }),
      this.prisma.securityIncident.count({ where: { status: 'OPEN' } }),
      this.prisma.securityIncident.count({ where: { status: 'INVESTIGATING' } }),
      this.prisma.securityIncident.count({ where: { status: 'CONTAINED' } }),
      this.prisma.securityIncident.count({ where: { status: 'RESOLVED' } }),
      this.prisma.securityIncident.count({ where: { status: 'FALSE_POSITIVE' } }),
      this.prisma.securityIncident.count({ where: { createdAt: { gte: since24h }, severity: 'CRITICAL' } }),
      this.prisma.securityIpBlock.count({
        where: {
          action: 'BLOCK', active: true,
          OR: [{ isPermanent: true }, { expiresAt: { gt: new Date() } }],
        },
      }),
      this.prisma.securityIpAllowlist.count(),
    ]);

    const topIps = await this.prisma.securityEvent.groupBy({
      by: ['ipAddress'],
      where: { occurredAt: { gte: since24h }, ipAddress: { not: null } },
      _count: { ipAddress: true },
      orderBy: { _count: { ipAddress: 'desc' } },
      take: 10,
    });

    const topEventTypes = await this.prisma.securityEvent.groupBy({
      by: ['eventType'],
      where: { occurredAt: { gte: since24h } },
      _count: { eventType: true },
      orderBy: { _count: { eventType: 'desc' } },
      take: 10,
    });

    const riskDistribution = await this.prisma.securityEvent.groupBy({
      by: ['riskLevel'],
      where: { occurredAt: { gte: since24h } },
      _count: { riskLevel: true },
    });

    return {
      events: { last24h: events24h, last7d: events7d, last30d: events30d },
      incidents: {
        open: incidentsOpen,
        investigating: incidentsInvestigating,
        contained: incidentsContained,
        resolved: incidentsResolved,
        falsePositive: incidentsFalsePositive,
        critical24h: criticalIncidents24h,
      },
      blocking: { active: activeBlocks, allowlisted: allowlistCount },
      topIps: topIps.map((r) => ({ ip: r.ipAddress, count: r._count.ipAddress })),
      topEventTypes: topEventTypes.map((r) => ({ type: r.eventType, count: r._count.eventType })),
      riskDistribution: riskDistribution.map((r) => ({ level: r.riskLevel, count: r._count.riskLevel })),
      generatedAt: new Date().toISOString(),
    };
  }
}
