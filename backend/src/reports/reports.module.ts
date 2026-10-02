import { Module } from '@nestjs/common';
import { IpsModule } from '../ips/ips.module';
import { FactsService } from './facts.service';
import { ReportsService } from './reports.service';

@Module({
  imports: [IpsModule],
  providers: [FactsService, ReportsService],
  exports: [ReportsService],
})
export class ReportsModule {}
