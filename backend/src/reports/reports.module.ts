import { Module } from '@nestjs/common';
import { IpsModule } from '../ips/ips.module';
import { FactsService } from './facts.service';
import { ReportsService } from './reports.service';
import { ReportsController } from './reports.controller';

@Module({
  imports: [IpsModule],
  controllers: [ReportsController],
  providers: [FactsService, ReportsService],
  exports: [ReportsService],
})
export class ReportsModule {}
