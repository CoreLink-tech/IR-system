import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { AuditService } from '../audit/audit.service';
import { RetentionService } from './retention.service';

/** Only what the cleanup command needs: no HTTP controllers, no guards. */
@Module({ imports: [PrismaModule], providers: [AuditService, RetentionService], exports: [RetentionService] })
export class RetentionModule {}
