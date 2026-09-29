import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateEventDto } from './dto';
import { normalizeIp } from '../common/utils/ip.util';
import { AuditService } from '../audit/audit.service';
import { AUDIT_ACTIONS } from '../common/constants';
import { DetectionService } from '../detection/detection.service';
import { IpsService } from '../ips/ips.service';

const FORBIDDEN_KEYS = [
  'password','passwd','pwd','secret','api_key','apikey',
  'access_token','refresh_token','authorization','credit_card',
  'card_number','cvv','pin',
];

function sanitizeMetadata(value: unknown, depth = 0): any {
  if (depth > 6) return '[truncated]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return value.length > 4096 ? value.substring(0, 4096) + '...' : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 200).map((v) => sanitizeMetadata(v, depth + 1));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_KEYS.some((fk) => k.toLowerCase().includes(fk))) out[k] = '[REDACTED]';
      else out[k] = sanitizeMetadata(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

@Injectable()
export class EventsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly detection: DetectionService,
    private readonly ips: IpsService,
  ) {}

  async ingest(dto: CreateEventDto, ctx: { apiKeyId?: string; requestId?: string; ip?: string; userAgent?: string }) {
    const ipAddress = dto.ip_address ? normalizeIp(dto.ip_address) : ctx.ip ? normalizeIp(ctx.ip) : undefined;
    const occurredAt = dto.timestamp ? new Date(dto.timestamp) : new Date();
    if (isNaN(occurredAt.getTime())) throw new BadRequestException('Invalid timestamp');

    const metadata = sanitizeMetadata(dto.metadata ?? {});

    const created = await this.prisma.securityEvent.create({
      data: {
        eventType: dto.event_type, severity: dto.severity, ipAddress,
        userId: dto.user_id, sessionId: dto.session_id, userAgent: dto.user_agent,
        requestMethod: dto.request_method, requestPath: dto.request_path,
        requestId: dto.request_id, metadata, occurredAt, apiKeyId: ctx.apiKeyId,
      },
    });

    if (ipAddress) {
      await this.ips.touch(ipAddress, dto.event_type).catch(() => void 0);
    }

    const detectionResult = await this.detection.processEvent(created).catch(() => null);

    await this.audit.log({
      requestId: ctx.requestId, actorType: 'API_KEY', actorId: ctx.apiKeyId,
      action: AUDIT_ACTIONS.EVENT_INGEST, targetType: 'security_event', targetId: created.id,
      result: 'SUCCESS',
      metadata: { eventType: created.eventType, severity: created.severity },
      ipAddress, userAgent: ctx.userAgent,
    });

    return {
      id: created.id,
      riskScore: detectionResult?.riskScore ?? 0,
      riskLevel: detectionResult?.riskLevel ?? 'NORMAL',
      incidentId: detectionResult?.incidentId ?? null,
    };
  }

  async list(params: {
    page: number; pageSize: number; skip: number; take: number;
    sortBy: string; sortOrder: 'asc' | 'desc';
    filters?: { eventType?: string; severity?: string; ipAddress?: string; userId?: string; from?: string; to?: string };
  }) {
    const where: any = {};
    const f = params.filters || {};
    if (f.eventType) where.eventType = f.eventType;
    if (f.severity) where.severity = f.severity;
    if (f.ipAddress) where.ipAddress = normalizeIp(f.ipAddress) || f.ipAddress;
    if (f.userId) where.userId = f.userId;
    if (f.from || f.to) {
      where.occurredAt = {};
      if (f.from) where.occurredAt.gte = new Date(f.from);
      if (f.to) where.occurredAt.lte = new Date(f.to);
    }
    const [data, total] = await Promise.all([
      this.prisma.securityEvent.findMany({ where, skip: params.skip, take: params.take, orderBy: { [params.sortBy]: params.sortOrder } }),
      this.prisma.securityEvent.count({ where }),
    ]);
    return { data, total };
  }

  async findOne(id: string) {
    return this.prisma.securityEvent.findUnique({ where: { id } });
  }
}
