import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { isPrivateIp } from '../common/utils/ip.util';
import { isNotFound, isUniqueViolation } from '../common/utils/db-errors';
import { IpIntelligenceService } from './ip-intelligence.service';
import { RISK_LEVEL } from '../common/constants';

export const IP_LIST_SORTS = ['lastSeenAt', 'firstSeenAt', 'riskScore', 'eventCount', 'failedLogins', 'ipAddress'];

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

  /**
   * The address list. Search matches the start of an address and ignores any character that
   * cannot be part of one, so it uses the index and no wildcard can be smuggled into the query.
   * "Blocked" means an active block in force right now, the same test the website uses.
   */
  async list(params: {
    skip: number; take: number; sortBy: string; sortOrder: 'asc' | 'desc';
    filters?: { riskLevel?: string; blocked?: string; country?: string; search?: string };
  }) {
    const f = params.filters || {};
    const where: any = {};
    if (f.riskLevel) {
      const level = String(f.riskLevel).toUpperCase();
      if (!Object.values(RISK_LEVEL).includes(level as any)) throw new BadRequestException('Unknown risk level');
      where.riskLevel = level;
    }
    if (f.country) where.country = String(f.country).trim();
    const search = String(f.search ?? '').replace(/[^0-9a-fA-F:.]/g, '').slice(0, 45);
    if (search) where.ipAddress = { startsWith: search.toLowerCase() };

    const now = new Date();
    const activeBlocks = await this.prisma.securityIpBlock.findMany({
      where: { action: 'BLOCK', active: true, OR: [{ isPermanent: true }, { expiresAt: { gt: now } }] },
      select: { ipAddress: true },
    });
    const blockedSet = new Set<string>(activeBlocks.map((b: any) => b.ipAddress));
    if (f.blocked === 'true') where.ipAddress = { ...(where.ipAddress ?? {}), in: [...blockedSet] };
    else if (f.blocked === 'false' && blockedSet.size) where.ipAddress = { ...(where.ipAddress ?? {}), notIn: [...blockedSet] };
    else if (f.blocked !== undefined && f.blocked !== '' && f.blocked !== 'true' && f.blocked !== 'false') {
      throw new BadRequestException('blocked must be true or false');
    }

    const [rows, total] = await Promise.all([
      this.prisma.securityIp.findMany({ where, skip: params.skip, take: params.take, orderBy: { [params.sortBy]: params.sortOrder } }),
      this.prisma.securityIp.count({ where }),
    ]);
    return { data: rows.map((r: any) => ({ ...r, blocked: blockedSet.has(r.ipAddress) })), total };
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
