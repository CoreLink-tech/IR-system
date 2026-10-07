import { Controller, Get, UseGuards } from '@nestjs/common';
import { SettingsService } from './settings.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';

@Controller('api/v1/settings')
@UseGuards(JwtAuthGuard, RolesGuard)
export class SettingsController {
  constructor(private readonly service: SettingsService) {}

  /** Read-only. These are set in the server's environment file, not through the API. */
  @Get('operational')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  operational() { return this.service.operational(); }
}
