import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { IpsService } from './ips.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { normalizeIp } from '../common/utils/ip.util';

@Controller('api/v1/ips')
@UseGuards(JwtAuthGuard, RolesGuard)
export class IpsController {
  constructor(private readonly service: IpsService) {}

  @Get(':ip')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER)
  detail(@Param('ip') ip: string) {
    const normalized = normalizeIp(ip) || ip;
    return this.service.detail(normalized);
  }
}
