import { Controller, Get, Res, ServiceUnavailableException } from '@nestjs/common';
import type { Response } from 'express';
import { Public } from '../common/decorators/public.decorator';
import { API_VERSION } from '../common/version';
import { PrismaService } from '../prisma/prisma.service';
import { readdirSync } from 'fs';
import { join } from 'path';

/**
 * Liveness: GET /api/v1/health — cheap, no database, for the dashboard and uptime monitors.
 * Readiness: GET /api/v1/health/ready — database reachable and migrations current.
 * When the database was created from SQL files only (no _prisma_migrations table), readiness
 * still checks connectivity and reports migrations: "unknown".
 */
@Controller('api/v1/health')
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Public()
  @Get()
  health(@Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return { status: 'ok', service: 'security-api', version: API_VERSION, time: new Date().toISOString() };
  }

  @Public()
  @Get('ready')
  async ready(@Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    let db = false;
    let migrations: 'current' | 'behind' | 'unknown' = 'unknown';
    try {
      await this.prisma.$queryRawUnsafe('SELECT 1');
      db = true;
      try {
        const applied: Array<{ migration_name: string }> = await this.prisma.$queryRawUnsafe(
          'SELECT migration_name FROM _prisma_migrations WHERE finished_at IS NOT NULL',
        );
        const dir = join(__dirname, '..', '..', 'prisma', 'migrations');
        let expected: string[] = [];
        try {
          expected = readdirSync(dir).filter((n) => n !== 'migration_lock.toml' && !n.startsWith('.'));
        } catch {
          expected = [];
        }
        if (expected.length === 0) {
          migrations = 'unknown';
        } else {
          const names = new Set(applied.map((r) => r.migration_name));
          migrations = expected.every((n) => names.has(n)) ? 'current' : 'behind';
        }
      } catch {
        migrations = 'unknown';
      }
    } catch {
      db = false;
    }

    const ready = db && migrations !== 'behind';
    const body = {
      status: ready ? 'ready' : 'not_ready',
      service: 'security-api',
      version: API_VERSION,
      time: new Date().toISOString(),
      database: db ? 'up' : 'down',
      migrations,
    };
    if (!ready) {
      res.status(503);
      return body;
    }
    return body;
  }
}
