import { Module } from '@nestjs/common';
import { BlockingService } from './blocking.service';
import { BlockingController } from './blocking.controller';

@Module({
  providers: [BlockingService],
  controllers: [BlockingController],
  exports: [BlockingService],
})
export class BlockingModule {}
