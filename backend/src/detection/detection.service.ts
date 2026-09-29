import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { BUILT_IN_RULES, RuleContext, RuleResult } from './rules';
import { IpIntelligenceService } from '../ips/ip-intelligence.service';
import { IncidentsService } from '../incidents/incidents.service';
import { BlockingService } from '../blocking/blocking.service';
import { clampScore, riskLevelFor } from '../common/utils/risk.util';

export interface DetectionOutcome {
  riskScore: number;
  riskLevel: 'NORMAL' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
  matchedRules: { code: string; reason?: string; riskDelta: number }[];
  incidentId?: string | null;
}

@Injectable()
export class DetectionService {
  private readonly logger = new Logger('DetectionService');

  constructor(
    private readonly prisma: PrismaService,
    private readonly ipIntel: IpIntelligenceService,
    private readonly incidents: IncidentsService,
    private readonly blocking: BlockingService,
  ) {}

  async ensureSeeded() {
    for (const r of BUILT_IN_RULES) {
      await this.prisma.securityRule.upsert({
        where: { code: r.code },
        update: { name: r.name, description: r.description, priority: r.priority },
        create: {
          code: r.code, name: r.name, description: r.description,
          priority: r.priority, isEnabled: true, config: r.defaultConfig as any,
        },
      });
    }
  }

  async processEvent(event: any): Promise<DetectionOutcome> {
    await this.ensureSeeded();

    const ip = event.ipAddress || null;
    const windowMinutes = 10;
    const since = new Date(Date.now() - windowMinutes * 60 * 1000);

    const [failedLoginsLastWindow, eventsLastWindow, distinctUsersRow, passwordResetsLastWindow] = await Promise.all([
      ip ? this.prisma.securityEvent.count({ where: { ipAddress: ip, eventType: 'login_failed', occurredAt: { gte: since } } }) : Promise.resolve(0),
      ip ? this.prisma.securityEvent.count({ where: { ipAddress: ip, occurredAt: { gte: since } } }) : Promise.resolve(0),
      ip ? this.prisma.securityEvent.findMany({
        where: { ipAddress: ip, eventType: 'login_failed', occurredAt: { gte: since }, userId: { not: null } },
        distinct: ['userId'], select: { userId: true },
      }) : Promise.resolve([]),
      ip ? this.prisma.securityEvent.count({ where: { ipAddress: ip, eventType: 'password_reset', occurredAt: { gte: since } } }) : Promise.resolve(0),
    ]);

    const intel = ip ? await this.ipIntel.lookup(ip).catch(() => null) : null;

    const ctx: RuleContext = {
      event: {
        id: event.id, eventType: event.eventType, severity: event.severity,
        ipAddress: ip, userId: event.userId, sessionId: event.sessionId,
        requestPath: event.requestPath, metadata: event.metadata, occurredAt: event.occurredAt,
      },
      stats: {
        failedLoginsLastWindow, eventsLastWindow,
        distinctUsersLastWindow: distinctUsersRow.length,
        passwordResetsLastWindow,
        ipIntel: intel ? {
          isVpn: intel.isVpn, isProxy: intel.isProxy, isTor: intel.isTor,
          isDatacenter: intel.isDatacenter, isMalicious: intel.isMalicious,
          reputationScore: intel.reputationScore,
        } : undefined,
      },
    };

    const rules = await this.prisma.securityRule.findMany({ where: { isEnabled: true }, orderBy: { priority: 'asc' } });

    let totalDelta = 0;
    const matched: { code: string; reason?: string; riskDelta: number }[] = [];
    let shouldCreateIncident = false;
    let topIncidentSeverity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    let topRuleCode = '';

    for (const r of rules) {
      const def = BUILT_IN_RULES.find((d) => d.code === r.code);
      if (!def) continue;
      let result: RuleResult;
      try { result = def.evaluate(ctx, (r.config as any) || def.defaultConfig); }
      catch (err) { this.logger.warn(`Rule ${r.code} failed: ${(err as Error).message}`); continue; }
      if (!result.matched) continue;
      totalDelta += result.riskDelta;
      matched.push({ code: r.code, reason: result.reason, riskDelta: result.riskDelta });
      if (result.createIncident) {
        shouldCreateIncident = true;
        const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        if (order.indexOf(result.incidentSeverity!) > order.indexOf(topIncidentSeverity)) {
          topIncidentSeverity = result.incidentSeverity!;
          topRuleCode = r.code;
        }
      }
    }

    const riskScore = clampScore(totalDelta);
    const riskLevel = riskLevelFor(riskScore);

    await this.prisma.securityEvent.update({
      where: { id: event.id }, data: { riskScore, riskLevel },
    });

    let incidentId: string | null = null;
    if (shouldCreateIncident && ip) {
      const incident = await this.incidents.createFromDetection({
        sourceIp: ip, userId: event.userId, sessionId: event.sessionId,
        ruleCode: topRuleCode || matched[0]?.code || 'detection',
        severity: topIncidentSeverity, riskScore,
        title: this.buildIncidentTitle(topRuleCode || matched[0]?.code, ip),
        description: matched.map((m) => `- ${m.code}: ${m.reason ?? ''}`).join('\n'),
        eventId: event.id,
      });
      incidentId = incident.id;
    }

    const autoBlockEnabled = String(process.env.AUTO_BLOCK_ENABLED || 'true') === 'true';
    const autoBlockMinRisk = Number(process.env.AUTO_BLOCK_MIN_RISK || 85);
    if (autoBlockEnabled && ip && riskLevel === 'CRITICAL' && riskScore >= autoBlockMinRisk) {
      await this.blocking.autoBlock(ip, {
        reason: `Auto-block: risk=${riskScore} (${matched.map((m) => m.code).join(', ')})`,
        incidentId: incidentId ?? undefined,
      }).catch((err) => this.logger.warn(`Auto-block failed: ${err.message}`));
    }

    return { riskScore, riskLevel, matchedRules: matched, incidentId };
  }

  private buildIncidentTitle(ruleCode: string | undefined, ip: string): string {
    const map: Record<string, string> = {
      brute_force_login: 'Brute-force login detected',
      credential_stuffing: 'Credential stuffing suspected',
      high_request_rate: 'Abnormal request rate',
      user_enumeration: 'User enumeration pattern',
      password_reset_abuse: 'Password reset abuse',
      suspicious_admin_access: 'Suspicious admin access',
      known_malicious_ip: 'Known malicious IP activity',
      tor_or_proxy: 'Tor / proxy traffic signal',
      suspicious_payload: 'Suspicious payload',
      order_id_enumeration: 'Order / product ID enumeration',
      payment_abuse_signal: 'Payment abuse signal',
      session_anomaly: 'Session anomaly',
    };
    return `${map[ruleCode || ''] || 'Detection event'} from ${ip}`;
  }
}
