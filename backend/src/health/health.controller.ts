import { Controller, Get, Res } from '@nestjs/common';
import type { Response } from 'express';
import { Public } from '../common/decorators/public.decorator';
import { API_VERSION } from '../common/version';

/**
 * A cheap "is the API up" answer for the dashboard and for uptime monitors. No sign-in, no
 * database call, no secrets. (A readiness check that also tests the database is Stage 10.)
 */
@Controller('api/v1/health')
export class HealthController {
  @Public()
  @Get()
  health(@Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return { status: 'ok', service: 'pishon-security-api', version: API_VERSION, time: new Date().toISOString() };
  }
}
