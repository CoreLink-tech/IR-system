import { Controller, Get, NotFoundException, Param, Post, UseGuards } from '@nestjs/common';
import { IpsService } from './ips.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { normalizeIp } from '../common/utils/ip.util';
import { IpIntelligenceService } from './ip-intelligence.service';

@Controller('api/v1/ips')
@UseGuards(JwtAuthGuard, RolesGuard)
export class IpsController {
  constructor(
    private readonly service: IpsService,
    private readonly intel: IpIntelligenceService,
  ) {}

  @Get(':ip')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER)
  detail(@Param('ip') ip: string) {
    const normalized = normalizeIp(ip) || ip;
    return this.service.detail(normalized);
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
