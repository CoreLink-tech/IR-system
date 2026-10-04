import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';

import { PrismaModule } from './prisma/prisma.module';
import { AuditModule } from './audit/audit.module';
import { AuthModule } from './auth/auth.module';
import { ApiKeysModule } from './api-keys/api-keys.module';
import { EventsModule } from './events/events.module';
import { DetectionModule } from './detection/detection.module';
import { IncidentsModule } from './incidents/incidents.module';
import { IpsModule } from './ips/ips.module';
import { BlockingModule } from './blocking/blocking.module';
import { StatisticsModule } from './statistics/statistics.module';
import { ReportsModule } from './reports/reports.module';
import { JwtOrApiKeyGuard } from './common/guards/jwt-or-api-key.guard';
import { ApiKeyGuard } from './common/guards/api-key.guard';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
import { SecuritySyncController } from './security/security.controller';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: ['.env'] }),
    ThrottlerModule.forRoot([
      {
        ttl: Number(process.env.THROTTLE_TTL || 60) * 1000,
        limit: Number(process.env.THROTTLE_LIMIT || 120),
      },
    ]),
    PrismaModule,
    AuditModule,
    AuthModule,
    ApiKeysModule,
    IpsModule,
    IncidentsModule,
    BlockingModule,
    DetectionModule,
    EventsModule,
    StatisticsModule,
    ReportsModule,
  ],
  controllers: [SecuritySyncController],
  providers: [
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    JwtOrApiKeyGuard, ApiKeyGuard, JwtAuthGuard,
  ],
})
export class AppModule {}
