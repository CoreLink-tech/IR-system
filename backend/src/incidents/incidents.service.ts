import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AUDIT_ACTIONS, INCIDENT_STATUS } from '../common/constants';
import { AuditService } from '../audit/audit.service';
import { isUniqueViolation } from '../common/utils/db-errors';

/** An incident stays open to new events while it has had activity within this time. */
const INCIDENT_ACTIVITY_WINDOW_MS = 30 * 60 * 1000;
const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
/** Who an incident is assigned to, as shown in lists. Never the password hash. */
const ASSIGNEE_FIELDS = { id: true, email: true, name: true } as const;

/**
 * The slot an open incident occupies: one per address, one per (account, rule), or one per
 * (platform-wide) rule. The database refuses a second open incident for the same slot.
 */
export function openKeyFor(scope: 'ip' | 'account' | 'global', ip: string | null, userId: string | null, rule: string): string {
  if (scope === 'ip') return `ip:${ip}`;
  if (scope === 'account') return `acct:${userId ?? ''}:${rule}`;
  return `glob:${rule}`;
}

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
    const key = openKeyFor(scope, input.sourceIp, input.userId ?? null, input.ruleCode);
    const cutoff = new Date(Date.now() - INCIDENT_ACTIVITY_WINDOW_MS);

    // An incident that has been quiet for over 30 minutes no longer takes new events.
    // Release its slot so a fresh incident can open for new activity.
    // Raw SQL on purpose: an ordinary update would also stamp "last updated" with the
    // current time, making an incident that has been quiet for hours look freshly active.
    await this.prisma.$executeRaw`UPDATE security_incidents SET openKey = NULL WHERE openKey = ${key} AND updatedAt < ${cutoff}`;

    const existing = await this.findOpen(key);
    if (existing) return this.attach(existing, input);

    try {
      return await this.open(input, scope, key);
    } catch (err) {
      if (!isUniqueViolation(err)) throw err;
      // Parallel requests from the same attacker all found no open incident and all tried
      // to open one. The database allowed only one, so join it instead of opening another.
      const winner = await this.findOpen(key);
      if (!winner) throw err;
      return this.attach(winner, input);
    }
  }

  private findOpen(key: string) {
    return this.prisma.securityIncident.findFirst({
      where: { openKey: key, status: { in: [INCIDENT_STATUS.OPEN, INCIDENT_STATUS.INVESTIGATING] } },
    });
  }

  private async open(input: any, scope: 'ip' | 'account' | 'global', key: string) {
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
        openKey: key,
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

  /** Adds an event to an open incident and escalates it if this event is worse. */
  private async attach(recent: any, input: any) {
    if (input.eventId) {
      await this.prisma.securityEvent.update({ where: { id: input.eventId }, data: { incidentId: recent.id } });
    }
    const update: any = { updatedAt: new Date() };
    const notes: string[] = [];
    // Compare against what is in the database right now, not what this request read earlier:
    // parallel requests may already have raised it, and an incident must never go down.
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

  async list(params: {
    skip: number; take: number; sortBy: string; sortOrder: 'asc' | 'desc';
    filters?: { status?: string; severity?: string; sourceIp?: string; assignedTo?: string; search?: string };
  }) {
    const where: any = {};
    const f = params.filters || {};
    if (f.status) where.status = f.status;
    if (f.severity) where.severity = f.severity;
    if (f.sourceIp) where.sourceIp = f.sourceIp;
    if (f.assignedTo) where.assignedTo = f.assignedTo;

    // Search by the start of an address or of the public number (INC-...). Both are indexed
    // prefixes, and only characters that can occur in either are kept.
    const search = String(f.search ?? '').replace(/[^0-9a-zA-Z:.\-]/g, '').slice(0, 45);
    if (search) where.OR = [{ sourceIp: { startsWith: search.toLowerCase() } }, { incidentId: { startsWith: search.toUpperCase() } }];

    const [data, total] = await Promise.all([
      this.prisma.securityIncident.findMany({
        where, skip: params.skip, take: params.take, orderBy: { [params.sortBy]: params.sortOrder },
        include: { assignee: { select: ASSIGNEE_FIELDS } },
      }),
      this.prisma.securityIncident.count({ where }),
    ]);
    return { data, total };
  }

  /** Accepts the internal id or the public number (INC-...), as the report routes do. */
  async findOne(idOrNumber: string) {
    const where = /^INC-/i.test(idOrNumber) ? { incidentId: idOrNumber.toUpperCase() } : { id: idOrNumber };
    const incident = await this.prisma.securityIncident.findUnique({
      where,
      include: {
        assignee: { select: ASSIGNEE_FIELDS },
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
    } else if (incident.resolvedAt) {
      // Reopened: it is no longer resolved, so the old resolution time must not linger.
      data.resolvedAt = null;
    }

    // Only an OPEN or INVESTIGATING incident takes new events, so only those hold the
    // slot. Closing or containing one frees it for a fresh incident.
    const takesEvents = status === INCIDENT_STATUS.OPEN || status === INCIDENT_STATUS.INVESTIGATING;
    let updated;
    if (takesEvents) {
      const scope = incident.sourceIp ? 'ip' : incident.userId ? 'account' : 'global';
      const key = openKeyFor(scope, incident.sourceIp, incident.userId, incident.detectionRule ?? '');
      try {
        updated = await this.prisma.securityIncident.update({ where: { id }, data: { ...data, openKey: key } });
      } catch (err) {
        if (!isUniqueViolation(err)) throw err;
        // A newer incident already covers this address or account. The reopened one still
        // changes status, but it will not take new events.
        updated = await this.prisma.securityIncident.update({ where: { id }, data: { ...data, openKey: null } });
      }
    } else {
      updated = await this.prisma.securityIncident.update({ where: { id }, data: { ...data, openKey: null } });
    }

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

  /**
   * Adds a free-text note to the timeline. It changes nothing else: not the status, not the
   * assignee, and not the incident's own "last updated" time.
   */
  async addNote(idOrNumber: string, note: string, actorId: string, actorLabel: string) {
    const incident = await this.resolve(idOrNumber);
    const entry = await this.prisma.securityIncidentTimeline.create({
      data: { incidentId: incident.id, action: 'note.added', actor: actorLabel, details: note },
    });
    await this.audit.log({
      actorType: 'USER', actorId, actorLabel,
      action: AUDIT_ACTIONS.INCIDENT_NOTE, targetType: 'security_incident', targetId: incident.id,
      result: 'SUCCESS', metadata: { length: note.length },
    });
    return entry;
  }

  private async resolve(idOrNumber: string) {
    const where = /^INC-/i.test(idOrNumber) ? { incidentId: idOrNumber.toUpperCase() } : { id: idOrNumber };
    const incident = await this.prisma.securityIncident.findUnique({ where });
    if (!incident) throw new NotFoundException('Incident not found');
    return incident;
  }
}
