import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AUDIT_ACTIONS, INCIDENT_STATUS } from '../common/constants';
import { AuditService } from '../audit/audit.service';

/** An incident stays open to new events while it has had activity within this time. */
const INCIDENT_ACTIVITY_WINDOW_MS = 30 * 60 * 1000;
const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

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

  /**
   * Opens an incident, or attaches the event to one that is already open.
   *
   * Grouping depends on the scope of the rule that fired:
   *   ip      one open incident per source address, whatever rule fired
   *   account one open incident per targeted account (many addresses)
   *   global  one open incident per rule for platform-wide attacks
   *
   * An incident counts as open while it is OPEN or INVESTIGATING and has seen
   * activity in the last 30 minutes, so a long attack stays one incident
   * instead of producing a new one every half hour.
   *
   * If a later event is more severe or riskier, the incident is escalated and
   * the change is written to its timeline.
   */
  async createFromDetection(input: {
    scope?: 'ip' | 'account' | 'global';
    sourceIp: string | null;
    userId?: string | null;
    sessionId?: string | null;
    ruleCode: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    riskScore: number;
    title: string;
    description: string;
    eventId?: string;
  }) {
    const scope = input.scope ?? 'ip';
    const where: any = {
      status: { in: [INCIDENT_STATUS.OPEN, INCIDENT_STATUS.INVESTIGATING] },
      updatedAt: { gte: new Date(Date.now() - INCIDENT_ACTIVITY_WINDOW_MS) },
    };
    if (scope === 'ip') {
      where.sourceIp = input.sourceIp;
    } else if (scope === 'account') {
      Object.assign(where, { sourceIp: null, userId: input.userId ?? null, detectionRule: input.ruleCode });
    } else {
      Object.assign(where, { sourceIp: null, userId: null, detectionRule: input.ruleCode });
    }
    const recent = await this.prisma.securityIncident.findFirst({ where, orderBy: { createdAt: 'desc' } });

    if (recent) {
      if (input.eventId) {
        await this.prisma.securityEvent.update({ where: { id: input.eventId }, data: { incidentId: recent.id } });
      }
      const update: any = { updatedAt: new Date() };
      const notes: string[] = [];
      if (SEVERITY_ORDER.indexOf(input.severity) > SEVERITY_ORDER.indexOf(recent.severity)) {
        update.severity = input.severity;
        update.detectionRule = input.ruleCode;
        update.title = input.title;
        notes.push(`severity ${recent.severity} to ${input.severity} (${input.ruleCode})`);
      }
      if (input.riskScore > recent.riskScore) {
        update.riskScore = input.riskScore;
        notes.push(`risk ${recent.riskScore} to ${input.riskScore}`);
      }
      await this.prisma.securityIncident.update({ where: { id: recent.id }, data: update });
      await this.prisma.securityIncidentTimeline.create({
        data: {
          incidentId: recent.id, action: 'event.attached', actor: 'system',
          details: `Additional ${input.ruleCode} event attached`,
        },
      });
      if (notes.length) {
        await this.prisma.securityIncidentTimeline.create({
          data: { incidentId: recent.id, action: 'incident.escalated', actor: 'system', details: `Escalated: ${notes.join('; ')}` },
        });
      }
      return { ...recent, ...update };
    }

    const incident = await this.prisma.securityIncident.create({
      data: {
        incidentId: nextIncidentId(),
        title: input.title, description: input.description,
        severity: input.severity, riskScore: input.riskScore,
        status: INCIDENT_STATUS.OPEN,
        sourceIp: scope === 'ip' ? input.sourceIp : null,
        userId: scope === 'global' ? null : input.userId ?? null,
        sessionId: input.sessionId ?? null,
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
      metadata: { ruleCode: input.ruleCode, riskScore: input.riskScore, scope },
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
