import { Module, forwardRef } from '@nestjs/common';
import { DetectionService } from './detection.service';
import { IpsModule } from '../ips/ips.module';
import { IncidentsModule } from '../incidents/incidents.module';
import { BlockingModule } from '../blocking/blocking.module';

@Module({
  imports: [IpsModule, forwardRef(() => IncidentsModule), forwardRef(() => BlockingModule)],
  providers: [DetectionService],
  exports: [DetectionService],
})
export class DetectionModule {}
