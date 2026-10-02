import { Module } from '@nestjs/common';
import { IpsService } from './ips.service';
import { IpsController } from './ips.controller';
import { IpIntelligenceService } from './ip-intelligence.service';
import { IP_INTEL_PROVIDERS } from './providers/provider.types';
import { buildProvidersFromEnv } from './providers/provider.factory';

@Module({
  providers: [
    IpsService,
    IpIntelligenceService,
    { provide: IP_INTEL_PROVIDERS, useFactory: () => buildProvidersFromEnv() },
  ],
  controllers: [IpsController],
  exports: [IpsService, IpIntelligenceService],
})
export class IpsModule {}
