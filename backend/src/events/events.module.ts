import { Module } from '@nestjs/common';
import { EventsService } from './events.service';
import { EventsController } from './events.controller';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { DetectionModule } from '../detection/detection.module';
import { IpsModule } from '../ips/ips.module';

@Module({
  imports: [ApiKeysModule, DetectionModule, IpsModule],
  controllers: [EventsController],
  providers: [EventsService],
})
export class EventsModule {}
