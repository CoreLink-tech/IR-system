import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AUDIT_ACTIONS, INCIDENT_STATUS } from '../common/constants';
import { AuditService } from '../audit/audit.service';

let counter = 0;
function nextIncidentId(): string {
  const d = new Date();
  const ymd = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(d.getUTCDate()).padStart(2, '0')}`;
  counter = (counter + 1) % 100000;
  const suffix = String(counter).padStart(5, '0');
  const rnd = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `INC-${ymd}-${suffix}${rnd}`;
}

@Injectable()
export class IncidentsService {
  constructor(private readonly prisma: PrismaService, private readonly audit: AuditService) {}

  async createFromDetection(input: {
    sourceIp: string;
    userId?: string | null;
    sessionId?: string | null;
    ruleCode: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    riskScore: number;
    title: string;
    description: string;
    eventId?: string;
  }) {
    const recent = await this.prisma.securityIncident.findFirst({
      where: {
        sourceIp: input.sourceIp,
        detectionRule: input.ruleCode,
        status: { in: [INCIDENT_STATUS.OPEN, INCIDENT_STATUS.INVESTIGATING] },
        createdAt: { gte: new Date(Date.now() - 30 * 60 * 1000) },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (recent) {
      if (input.eventId) {
        await this.prisma.securityEvent.update({ where: { id: input.eventId }, data: { incidentId: recent.id } });
      }
      await this.prisma.securityIncidentTimeline.create({
        data: {
          incidentId: recent.id, action: 'event.attached', actor: 'system',
          details: `Additional ${input.ruleCode} event attached`,
        },
      });
      return recent;
    }

    const incident = await this.prisma.securityIncident.create({
      data: {
        incidentId: nextIncidentId(),
        title: input.title, description: input.description,
        severity: input.severity, riskScore: input.riskScore,
        status: INCIDENT_STATUS.OPEN,
        sourceIp: input.sourceIp, userId: input.userId ?? null, sessionId: input.sessionId ?? null,
        detectionRule: input.ruleCode,
      },
    });

    await this.prisma.securityIncidentTimeline.create({
      data: {
        incidentId: incident.id, action: 'incident.created', actor: 'system',
        details: `${input.ruleCode} triggered (risk=${input.riskScore})`,
      },
    });

    if (input.eventId) {
      await this.prisma.securityEvent.update({ where: { id: input.eventId }, data: { incidentId: incident.id } });
    }

    await this.audit.log({
      actorType: 'SYSTEM', action: AUDIT_ACTIONS.INCIDENT_CREATE,
      targetType: 'security_incident', targetId: incident.id, result: 'SUCCESS',
      metadata: { ruleCode: input.ruleCode, riskScore: input.riskScore },
    });

    return incident;
  }

  async list(params: {
    skip: number; take: number; sortBy: string; sortOrder: 'asc' | 'desc';
    filters?: { status?: string; severity?: string; sourceIp?: string; assignedTo?: string };
  }) {
    const where: any = {};
    const f = params.filters || {};
    if (f.status) where.status = f.status;
    if (f.severity) where.severity = f.severity;
    if (f.sourceIp) where.sourceIp = f.sourceIp;
    if (f.assignedTo) where.assignedTo = f.assignedTo;

    const [data, total] = await Promise.all([
      this.prisma.securityIncident.findMany({ where, skip: params.skip, take: params.take, orderBy: { [params.sortBy]: params.sortOrder } }),
      this.prisma.securityIncident.count({ where }),
    ]);
    return { data, total };
  }

  async findOne(id: string) {
    const incident = await this.prisma.securityIncident.findUnique({
      where: { id },
      include: {
        timeline: { orderBy: { createdAt: 'asc' } },
        events: { orderBy: { occurredAt: 'desc' }, take: 200 },
      },
    });
    if (!incident) throw new NotFoundException('Incident not found');
    return incident;
  }

  async updateStatus(id: string, status: string, notes: string | undefined, actorId: string, actorLabel: string) {
    const incident = await this.prisma.securityIncident.findUnique({ where: { id } });
    if (!incident) throw new NotFoundException('Incident not found');

    const data: any = { status };
    if (notes) data.resolutionNotes = notes;
    if (status === INCIDENT_STATUS.RESOLVED || status === INCIDENT_STATUS.FALSE_POSITIVE) {
      data.resolvedAt = new Date();
    }

    const updated = await this.prisma.securityIncident.update({ where: { id }, data });

    await this.prisma.securityIncidentTimeline.create({
      data: { incidentId: id, action: `status.${status}`, actor: actorLabel, details: notes || null },
    });

    await this.audit.log({
      actorType: 'USER', actorId, actorLabel,
      action: AUDIT_ACTIONS.INCIDENT_UPDATE, targetType: 'security_incident', targetId: id,
      result: 'SUCCESS', metadata: { status },
    });

    return updated;
  }

  async assign(id: string, assignedTo: string, actorId: string, actorLabel: string) {
    const incident = await this.prisma.securityIncident.findUnique({ where: { id } });
    if (!incident) throw new NotFoundException('Incident not found');
    const user = await this.prisma.securityUser.findUnique({ where: { id: assignedTo } });
    if (!user) throw new NotFoundException('User not found');

    const updated = await this.prisma.securityIncident.update({ where: { id }, data: { assignedTo } });
    await this.prisma.securityIncidentTimeline.create({
      data: { incidentId: id, action: 'assigned', actor: actorLabel, details: `Assigned to ${user.email}` },
    });
    await this.audit.log({
      actorType: 'USER', actorId, actorLabel,
      action: AUDIT_ACTIONS.INCIDENT_ASSIGN, targetType: 'security_incident', targetId: id,
      result: 'SUCCESS', metadata: { assignedTo },
    });
    return updated;
  }
}
