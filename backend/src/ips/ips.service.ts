import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { isPrivateIp } from '../common/utils/ip.util';
import { riskLevelFor } from '../common/utils/risk.util';
import { IpIntelligenceService } from './ip-intelligence.service';

const FAILED_LOGIN_WEIGHT = 3;

@Injectable()
export class IpsService {
  constructor(private readonly prisma: PrismaService, private readonly intel: IpIntelligenceService) {}

  async touch(ip: string, eventType: string) {
    const now = new Date();
    const failed = eventType === 'login_failed' ? 1 : 0;
    const existing = await this.prisma.securityIp.findUnique({ where: { ipAddress: ip } });

    if (!existing) {
      await this.prisma.securityIp.create({
        data: {
          ipAddress: ip, firstSeenAt: now, lastSeenAt: now,
          eventCount: 1, failedLogins: failed,
        },
      });
      return;
    }

    const failedLogins = existing.failedLogins + failed;
    const rawScore = failedLogins * FAILED_LOGIN_WEIGHT + (existing.isMalicious ? 30 : 0);
    const riskScore = Math.max(0, Math.min(100, rawScore));

    await this.prisma.securityIp.update({
      where: { ipAddress: ip },
      data: {
        lastSeenAt: now,
        eventCount: { increment: 1 },
        failedLogins: { increment: failed },
        riskScore,
        riskLevel: riskLevelFor(riskScore),
      },
    });
  }

  async detail(ip: string) {
    const row = await this.prisma.securityIp.findUnique({ where: { ipAddress: ip } });
    if (!row) {
      const intel = await this.intel.lookup(ip).catch(() => null);
      if (!intel) throw new NotFoundException('IP not found');
      const created = await this.prisma.securityIp.create({
        data: {
          ipAddress: ip,
          isVpn: intel.isVpn, isProxy: intel.isProxy, isTor: intel.isTor,
          isDatacenter: intel.isDatacenter, isMalicious: intel.isMalicious,
          reputationScore: intel.reputationScore,
          country: intel.country, region: intel.region, city: intel.city,
          lastIntelUpdate: new Date(),
        },
      });
      return { ip: created, events: [], blocks: [], intelligence: intel, isPrivate: isPrivateIp(ip) };
    }

    const [events, blocks] = await Promise.all([
      this.prisma.securityEvent.findMany({ where: { ipAddress: ip }, orderBy: { occurredAt: 'desc' }, take: 100 }),
      this.prisma.securityIpBlock.findMany({ where: { ipAddress: ip }, orderBy: { createdAt: 'desc' }, take: 50 }),
    ]);

    return { ip: row, events, blocks, isPrivate: isPrivateIp(ip) };
  }
}
