import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { BlockingService } from '../blocking/blocking.service';
import { JwtOrApiKeyGuard } from '../common/guards/jwt-or-api-key.guard';
import { ApiKeyGuard } from '../common/guards/api-key.guard';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { Scopes } from '../common/decorators/scopes.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES, SCOPES } from '../common/constants';

/**
 * The blocklist routes are read by two kinds of caller: the PishonMarket website
 * (API key with block:read) and administrators using the dashboard (JWT). Both use
 * the same paths, so they are served here by a single guard that accepts either.
 * These routes must not be registered anywhere else.
 */
@Controller('api/v1/security')
@UseGuards(JwtOrApiKeyGuard)
export class SecuritySyncController {
  constructor(private readonly blocking: BlockingService) {}

  @Get('blocked-ips')
  @Scopes(SCOPES.BLOCK_READ)
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER)
  async blocked() {
    return { data: await this.blocking.activeBlocks() };
  }

  @Get('blocks/history')
  @Scopes(SCOPES.BLOCK_READ)
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST)
  history(@Query('ip') ip?: string, @Query('limit') limit?: string) {
    const n = Number(limit);
    return this.blocking.history(ip, Number.isFinite(n) && n > 0 ? Math.min(n, 500) : 100);
  }
}
