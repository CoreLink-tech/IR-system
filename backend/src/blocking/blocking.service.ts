import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { isInternalAddress, normalizeIp } from '../common/utils/ip.util';
import { isUniqueViolation } from '../common/utils/db-errors';
import { AuditService } from '../audit/audit.service';
import { AUDIT_ACTIONS } from '../common/constants';

@Injectable()
export class BlockingService {
  constructor(private readonly prisma: PrismaService, private readonly audit: AuditService) {}

  private normalize(ip: string): string {
    const n = normalizeIp(ip);
    if (!n) throw new BadRequestException('Invalid IP address');
    return n;
  }

  async isAllowed(ip: string): Promise<boolean> {
    const n = normalizeIp(ip);
    if (!n) return false;
    const now = new Date();
    const row = await this.prisma.securityIpAllowlist.findUnique({ where: { ipAddress: n } });
    if (!row) return false;
    if (row.expiresAt && row.expiresAt < now) return false;
    return true;
  }

  async block(ip: string, input: {
    reason: string; permanent?: boolean; ttlMinutes?: number;
    administratorId?: string; relatedIncidentId?: string; automatic?: boolean;
  }) {
    const n = this.normalize(ip);

    // Blocking a loopback, private or link-local address could lock the website out
    // of its own security system or cut off traffic arriving through an internal proxy.
    if (isInternalAddress(n)) {
      throw new BadRequestException('Internal and private addresses cannot be blocked');
    }
    if (await this.isAllowed(n)) {
      throw new BadRequestException('IP is on the allowlist');
    }

    // Free the one-active-block-per-address slot. An administrator's block replaces whatever
    // is there. An automatic block only clears blocks that have already run out, so a
    // burst of parallel requests cannot keep replacing each other's blocks.
    await this.prisma.securityIpBlock.updateMany({
      where: input.automatic
        ? { ipAddress: n, active: true, isPermanent: false, expiresAt: { lte: new Date() } }
        : { ipAddress: n, active: true },
      data: { active: false, activeKey: null },
    });

    const permanent = !!input.permanent;
    let expiresAt: Date | null = null;
    if (!permanent) {
      const ttl = input.ttlMinutes && input.ttlMinutes > 0
        ? input.ttlMinutes
        : Number(process.env.AUTO_BLOCK_TTL_MINUTES || 60);
      expiresAt = new Date(Date.now() + ttl * 60 * 1000);
    }

    const data = {
      ipAddress: n, action: 'BLOCK', reason: input.reason,
      administratorId: input.administratorId ?? null,
      relatedIncidentId: input.relatedIncidentId ?? null,
      isPermanent: permanent, expiresAt, active: true,
      automatic: !!input.automatic, activeKey: n,
    };
    let created;
    try {
      created = await this.prisma.securityIpBlock.create({ data });
    } catch (err) {
      if (!isUniqueViolation(err)) throw err;
      // Another request blocked this address at the same moment. For an automatic block
      // that is enough: the address is blocked, so return that block. A manual block is an
      // administrator's decision and must win, so it replaces the other and tries again.
      const existing = await this.prisma.securityIpBlock.findFirst({
        where: { ipAddress: n, action: 'BLOCK', active: true }, orderBy: { createdAt: 'desc' },
      });
      if (input.automatic && existing) return existing;
      await this.prisma.securityIpBlock.updateMany({
        where: { ipAddress: n, active: true }, data: { active: false, activeKey: null },
      });
      created = await this.prisma.securityIpBlock.create({ data });
    }

    await this.audit.log({
      actorType: input.automatic ? 'SYSTEM' : 'USER',
      actorId: input.administratorId,
      action: input.automatic ? AUDIT_ACTIONS.AUTO_BLOCK : AUDIT_ACTIONS.IP_BLOCK,
      targetType: 'ip', targetId: n, result: 'SUCCESS',
      metadata: { reason: input.reason, permanent, ttlMinutes: input.ttlMinutes },
    });

    return created;
  }

  /**
   * Automatic blocking never overrides an administrator. An existing manual or
   * permanent block is left exactly as it is. An existing automatic block is only
   * renewed once less than half of its time remains, so a sustained attack does
   * not create a new block record on every event.
   */
  async autoBlock(ip: string, input: { reason: string; incidentId?: string }) {
    const ttl = Number(process.env.AUTO_BLOCK_TTL_MINUTES || 60);
    const n = this.normalize(ip);
    // Nothing to do, and not an error, for addresses that must never be blocked.
    if (isInternalAddress(n) || (await this.isAllowed(n))) return null;
    const now = new Date();
    const existing = await this.prisma.securityIpBlock.findFirst({
      where: { ipAddress: n, action: 'BLOCK', active: true, OR: [{ isPermanent: true }, { expiresAt: { gt: now } }] },
      orderBy: { createdAt: 'desc' },
    });
    if (existing) {
      if (existing.isPermanent || !existing.automatic) return existing;
      const remainingMs = (existing.expiresAt?.getTime() ?? 0) - now.getTime();
      if (remainingMs > (ttl * 60 * 1000) / 2) return existing;
      // Nearly over: retire this one so a fresh block can take its place.
      await this.prisma.securityIpBlock.updateMany({
        where: { id: existing.id, active: true }, data: { active: false, activeKey: null },
      });
    }
    return this.block(ip, {
      reason: input.reason, permanent: false, ttlMinutes: ttl,
      relatedIncidentId: input.incidentId, automatic: true,
    });
  }

  async unblock(ip: string, reason: string, administratorId: string) {
    const n = this.normalize(ip);
    const result = await this.prisma.securityIpBlock.updateMany({
      where: { ipAddress: n, active: true },
      data: { active: false, activeKey: null },
    });

    await this.prisma.securityIpBlock.create({
      data: {
        ipAddress: n, action: 'UNBLOCK', reason,
        administratorId, active: false, automatic: false,
      },
    });

    await this.audit.log({
      actorType: 'USER', actorId: administratorId,
      action: AUDIT_ACTIONS.IP_UNBLOCK, targetType: 'ip', targetId: n,
      result: 'SUCCESS', metadata: { reason, deactivated: result.count },
    });

    return { ok: true, deactivated: result.count };
  }

  async allow(ip: string, reason: string, ttlMinutes: number | undefined, addedBy: string) {
    const n = this.normalize(ip);
    const expiresAt = ttlMinutes && ttlMinutes > 0
      ? new Date(Date.now() + ttlMinutes * 60 * 1000)
      : null;

    const row = await this.prisma.securityIpAllowlist.upsert({
      where: { ipAddress: n },
      update: { reason, expiresAt, addedBy },
      create: { ipAddress: n, reason, expiresAt, addedBy },
    });

    await this.audit.log({
      actorType: 'USER', actorId: addedBy,
      action: AUDIT_ACTIONS.IP_ALLOW, targetType: 'ip', targetId: n,
      result: 'SUCCESS', metadata: { reason, ttlMinutes },
    });

    return row;
  }

  async unallow(ip: string, actorId: string) {
    const n = this.normalize(ip);
    await this.prisma.securityIpAllowlist.deleteMany({ where: { ipAddress: n } });
    await this.audit.log({
      actorType: 'USER', actorId,
      action: AUDIT_ACTIONS.IP_UNALLOW, targetType: 'ip', targetId: n,
      result: 'SUCCESS',
    });
    return { ok: true };
  }

  async activeBlocks() {
    const now = new Date();
    const rows = await this.prisma.securityIpBlock.findMany({
      where: {
        action: 'BLOCK',
        active: true,
        OR: [{ isPermanent: true }, { expiresAt: { gt: now } }],
      },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => ({
      ipAddress: r.ipAddress, reason: r.reason,
      expiresAt: r.expiresAt, permanent: r.isPermanent,
      automatic: r.automatic, createdAt: r.createdAt,
    }));
  }

  async history(ip?: string, limit = 100) {
    const where: any = {};
    if (ip) where.ipAddress = this.normalize(ip);
    return this.prisma.securityIpBlock.findMany({
      where, orderBy: { createdAt: 'desc' }, take: Math.min(limit, 500),
    });
  }

  async allowlist() {
    return this.prisma.securityIpAllowlist.findMany({ orderBy: { createdAt: 'desc' } });
  }
}
