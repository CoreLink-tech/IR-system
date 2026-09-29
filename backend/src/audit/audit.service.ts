import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export interface AuditEntry {
  requestId?: string;
  actorType: 'USER' | 'API_KEY' | 'SYSTEM' | 'ANONYMOUS';
  actorId?: string;
  actorLabel?: string;
  action: string;
  targetType?: string;
  targetId?: string;
  result: 'SUCCESS' | 'FAILURE';
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  userId?: string;
}

@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  async log(entry: AuditEntry) {
    try {
      return await this.prisma.securityAuditLog.create({
        data: {
          requestId: entry.requestId,
          actorType: entry.actorType,
          actorId: entry.actorId,
          actorLabel: entry.actorLabel,
          action: entry.action,
          targetType: entry.targetType,
          targetId: entry.targetId,
          result: entry.result,
          metadata: (entry.metadata as any) ?? undefined,
          ipAddress: entry.ipAddress,
          userAgent: entry.userAgent,
          userId: entry.actorType === 'USER' ? entry.actorId : undefined,
        },
      });
    } catch {
      return null;
    }
  }
}
