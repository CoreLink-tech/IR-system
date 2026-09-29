import { Controller, Get, Query, Req, UseGuards } from '@nestjs/common';
import { ApiKeyGuard } from '../common/guards/api-key.guard';
import { ScopesGuard } from '../common/guards/scopes.guard';
import { Scopes } from '../common/decorators/scopes.decorator';
import { SCOPES } from '../common/constants';
import { BlockingService } from '../blocking/blocking.service';
import { parsePagination } from '../common/utils/pagination.util';

/**
 * Public (API-key-only) endpoints used by Pishon's PHP middleware.
 * Distinct from the JWT-protected dashboard routes under /api/v1/security in BlockingController.
 */
@Controller('api/v1/security')
export class SecuritySyncController {
  constructor(private readonly blocking: BlockingService) {}

  @UseGuards(ApiKeyGuard, ScopesGuard)
  @Scopes(SCOPES.BLOCK_READ)
  @Get('blocked-ips')
  async blockedForPishon(@Req() _req: any) {
    const data = await this.blocking.activeBlocks();
    return { data };
  }

  @UseGuards(ApiKeyGuard, ScopesGuard)
  @Scopes(SCOPES.BLOCK_READ)
  @Get('blocks/history')
  async historyForPishon(@Query('limit') limit?: string) {
    const p = parsePagination({ pageSize: limit ? Number(limit) : 100 });
    return this.blocking.history(undefined, p.take);
  }
}
