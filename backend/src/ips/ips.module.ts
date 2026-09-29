import { Module } from '@nestjs/common';
import { IpsService } from './ips.service';
import { IpsController } from './ips.controller';
import { IpIntelligenceService } from './ip-intelligence.service';

@Module({
  providers: [IpsService, IpIntelligenceService],
  controllers: [IpsController],
  exports: [IpsService, IpIntelligenceService],
})
export class IpsModule {}
