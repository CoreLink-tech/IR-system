import { Controller, Get, NotFoundException, Param, Post, Query, UseGuards } from '@nestjs/common';
import { IP_LIST_SORTS, IpsService } from './ips.service';
import { parsePagination, toPaginated } from '../common/utils/pagination.util';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { normalizeIp } from '../common/utils/ip.util';
import { ActorContext, CurrentActor } from '../common/decorators/current-actor.decorator';
import { IpIntelligenceService } from './ip-intelligence.service';

@Controller('api/v1/ips')
@UseGuards(JwtAuthGuard, RolesGuard)
export class IpsController {
  constructor(
    private readonly service: IpsService,
    private readonly intel: IpIntelligenceService,
  ) {}

  /** Addresses seen so far, with filters. Closed to viewers because it is a view of raw activity. */
  @Get()
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST)
  async list(@Query() q: any) {
    const p = parsePagination(q, { sortBy: 'lastSeenAt', allowedSort: IP_LIST_SORTS });
    const { data, total } = await this.service.list({
      ...p, filters: { riskLevel: q.riskLevel, blocked: q.blocked, country: q.country, search: q.search },
    });
    return toPaginated(data, total, p.page, p.pageSize);
  }

  @Get(':ip')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER)
  async detail(@Param('ip') ip: string, @CurrentActor() actor: ActorContext) {
    const normalized = normalizeIp(ip) || ip;
    const detail = await this.service.detail(normalized);
    // Viewers see the address, its risk and its blocks, but not the raw event history.
    if (actor.role === ROLES.VIEWER) return { ...detail, events: [] };
    return detail;
  }

  /** Force a fresh provider lookup, bypassing the cache. */
  @Post(':ip/refresh-intelligence')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST)
  async refresh(@Param('ip') ip: string) {
    const normalized = normalizeIp(ip);
    if (!normalized) throw new NotFoundException('Invalid IP address');
    const intelligence = await this.intel.lookup(normalized, { force: true });
    return { ip: normalized, intelligence, providers: this.intel.providerNames };
  }
}
