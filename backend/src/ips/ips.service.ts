import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { isPrivateIp } from '../common/utils/ip.util';
import { isNotFound, isUniqueViolation } from '../common/utils/db-errors';
import { IpIntelligenceService } from './ip-intelligence.service';

@Injectable()
export class IpsService {
  constructor(private readonly prisma: PrismaService, private readonly intel: IpIntelligenceService) {}

  /**
   * Counts an event against its address. Safe when many events from the same new
   * address arrive at once: the counters are incremented by the database itself
   * (never read, add one, write back), and if two requests both try to create the
   * row, the loser falls back to incrementing it. Risk is owned by the detection
   * engine and is not touched here.
   */
  async touch(ip: string, eventType: string) {
    const now = new Date();
    const failed = eventType === 'login_failed' ? 1 : 0;
    const bump = () => this.prisma.securityIp.update({
      where: { ipAddress: ip },
      data: { lastSeenAt: now, eventCount: { increment: 1 }, failedLogins: { increment: failed } },
    });
    try {
      await bump();
    } catch (err) {
      if (!isNotFound(err)) throw err;
      try {
        await this.prisma.securityIp.create({
          data: { ipAddress: ip, firstSeenAt: now, lastSeenAt: now, eventCount: 1, failedLogins: failed },
        });
      } catch (createErr) {
        if (!isUniqueViolation(createErr)) throw createErr;
        await bump(); // another request created the row first
      }
    }
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
