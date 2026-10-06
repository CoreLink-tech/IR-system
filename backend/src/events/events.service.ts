import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateEventDto } from './dto';
import { normalizeIp } from '../common/utils/ip.util';
import { parseDateParam } from '../common/utils/pagination.util';
import { isUniqueViolation } from '../common/utils/db-errors';
import { AuditService } from '../audit/audit.service';
import { AUDIT_ACTIONS } from '../common/constants';
import { DetectionService } from '../detection/detection.service';
import { IpsService } from '../ips/ips.service';

/**
 * Words that mark a field as sensitive. Longer words match anywhere in a key
 * ("user_password", "apiKey"). Short words (pin, otp, cvv, ssn) must be a whole
 * word, so "shipping_address" is kept while "card_pin" is redacted.
 */
const SENSITIVE_SUBSTRINGS = [
  'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'authorization',
  'cookie', 'creditcard', 'cardnumber', 'privatekey', 'bearer', 'credential',
];
const SENSITIVE_WORDS = new Set(['pin', 'cvv', 'cvc', 'otp', 'ssn', 'auth', 'key']);

function words(key: string): string[] {
  // Split on separators and camelCase boundaries: "cardPin" -> ["card", "pin"].
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

export function isSensitiveKey(key: string): boolean {
  const compact = key.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (SENSITIVE_SUBSTRINGS.some((w) => compact.includes(w))) return true;
  return words(key).some((w) => SENSITIVE_WORDS.has(w));
}

export function sanitizeMetadata(value: unknown, depth = 0): any {
  if (depth > 6) return '[truncated]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return value.length > 4096 ? value.substring(0, 4096) + '...' : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 200).map((v) => sanitizeMetadata(v, depth + 1));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSensitiveKey(k) ? '[REDACTED]' : sanitizeMetadata(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

/**
 * Removes the values of sensitive query parameters from a request path, for
 * example a password reset token in "/reset?token=abc". Every other part of the
 * path is kept, so detection can still see injection attempts in it.
 */
export function redactPath(path: string | undefined): string | undefined {
  if (!path) return path;
  const q = path.indexOf('?');
  if (q < 0) return path;
  const head = path.slice(0, q + 1);
  const rest = path.slice(q + 1).replace(/([^&=#]+)=([^&#]*)/g, (m, name: string) => {
    let decoded = name;
    try { decoded = decodeURIComponent(name); } catch { /* keep raw name */ }
    return isSensitiveKey(decoded) ? `${name}=[REDACTED]` : m;
  });
  return head + rest;
}

/** Events may be this far ahead of the server clock before they are rejected. */
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

@Injectable()
export class EventsService {
  private readonly logger = new Logger('EventsService');

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly detection: DetectionService,
    private readonly ips: IpsService,
  ) {}

  private findByExternalId(apiKeyId: string, externalId: string) {
    return this.prisma.securityEvent.findFirst({ where: { apiKeyId, externalId } });
  }

  private duplicateResult(e: { id: string; riskScore: number; riskLevel: string; incidentId: string | null }) {
    return { id: e.id, riskScore: e.riskScore, riskLevel: e.riskLevel, incidentId: e.incidentId, duplicate: true };
  }

  async ingest(dto: CreateEventDto, ctx: { apiKeyId?: string; requestId?: string; ip?: string; userAgent?: string }) {
    const ipAddress = dto.ip_address ? normalizeIp(dto.ip_address) : ctx.ip ? normalizeIp(ctx.ip) : undefined;
    const occurredAt = dto.timestamp ? new Date(dto.timestamp) : new Date();
    if (isNaN(occurredAt.getTime())) throw new BadRequestException('Invalid timestamp');
    // A timestamp in the future would corrupt the time windows detection relies on.
    if (occurredAt.getTime() > Date.now() + MAX_CLOCK_SKEW_MS) {
      throw new BadRequestException('Timestamp is in the future');
    }

    const metadata = sanitizeMetadata(dto.metadata ?? {});

    // A repeat of an event that was already stored (the sender timed out and tried again)
    // is answered with the original result and stored only once. Scoped to the API key, so
    // one sender can never see or collide with another's ids.
    const externalId = dto.event_id && ctx.apiKeyId ? dto.event_id : undefined;
    if (externalId) {
      const prior = await this.findByExternalId(ctx.apiKeyId!, externalId);
      if (prior) return this.duplicateResult(prior);
    }

    let created;
    try {
      created = await this.prisma.securityEvent.create({
        data: {
          eventType: dto.event_type, severity: dto.severity, ipAddress,
          userId: dto.user_id, sessionId: dto.session_id, userAgent: dto.user_agent,
          requestMethod: dto.request_method, requestPath: redactPath(dto.request_path),
          requestId: dto.request_id, metadata, occurredAt, apiKeyId: ctx.apiKeyId, externalId,
        },
      });
    } catch (err) {
      // Two copies of the same event arrived at the same moment; the other one won.
      if (externalId && isUniqueViolation(err)) {
        const prior = await this.findByExternalId(ctx.apiKeyId!, externalId);
        if (prior) return this.duplicateResult(prior);
      }
      throw err;
    }

    if (ipAddress) {
      await this.ips.touch(ipAddress, dto.event_type)
        .catch((err) => this.logger.warn(`IP tracking failed for event ${created.id}: ${err.message}`));
    }

    // The event is already stored. If detection fails the event is still accepted,
    // but the failure must be visible in the logs, never silent.
    const detectionResult = await this.detection.processEvent(created).catch((err) => {
      this.logger.error(`Detection failed for event ${created.id}: ${err.message}`, err.stack);
      return null;
    });

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
    const from = parseDateParam(f.from, 'from');
    const to = parseDateParam(f.to, 'to');
    if (from || to) {
      where.occurredAt = {};
      if (from) where.occurredAt.gte = from;
      if (to) where.occurredAt.lte = to;
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
