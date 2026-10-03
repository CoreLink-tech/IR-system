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
    const correlation = await this.gatherCorrelation(event, ip);

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
          country: intel.country,
        } : undefined,
        correlation,
      },
    };

    const rules = await this.prisma.securityRule.findMany({ where: { isEnabled: true }, orderBy: { priority: 'asc' } });

    let totalDelta = 0;
    const matched: { code: string; reason?: string; riskDelta: number }[] = [];
    let shouldCreateIncident = false;
    let topIncidentSeverity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    let topRuleCode = '';
    let topScope: 'ip' | 'account' | 'global' = 'ip';

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
          topScope = result.incidentScope ?? 'ip';
        }
      }
    }

    const riskScore = clampScore(totalDelta);
    const riskLevel = riskLevelFor(riskScore);

    await this.prisma.securityEvent.update({
      where: { id: event.id },
      data: {
        riskScore, riskLevel,
        // Persist which rules fired and why, so reports can cite verified evidence.
        // An empty array means "evaluated, nothing fired"; null means "recorded
        // before this field existed". Reports rely on that difference.
        matchedRules: matched as any,
      },
    });

    // Keep the address-level risk current. It is the highest event risk seen from
    // this address in the last 24 hours, so it rises with an attack and decays after.
    if (ip) await this.refreshIpRisk(ip).catch((err) => this.logger.warn(`IP risk refresh failed: ${err.message}`));

    let incidentId: string | null = null;
    const scope = topScope;
    if (shouldCreateIncident && (ip || scope !== 'ip')) {
      const ruleCode = topRuleCode || matched[0]?.code || 'detection';
      const incident = await this.incidents.createFromDetection({
        scope,
        sourceIp: scope === 'ip' ? ip : null,
        userId: scope === 'global' ? null : event.userId,
        sessionId: scope === 'ip' ? event.sessionId : null,
        ruleCode,
        severity: topIncidentSeverity, riskScore,
        title: this.buildIncidentTitle(ruleCode, ip, event.userId, scope),
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

  private buildIncidentTitle(
    ruleCode: string | undefined, ip: string | null, userId: string | null | undefined,
    scope: 'ip' | 'account' | 'global',
  ): string {
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
      possible_account_takeover: 'Possible account takeover',
      distributed_account_attack: 'Distributed attack on one account',
      distributed_login_attack: 'Distributed login attack',
      impossible_travel: 'Impossible travel login',
    };
    const base = map[ruleCode || ''] || 'Detection event';
    if (scope === 'global') return base;
    if (scope === 'account') return `${base} (account ${userId ?? 'unknown'})`;
    return `${base} from ${ip}`;
  }

  /** Raises or lowers the stored address risk to match the last 24 hours of events. */
  private async refreshIpRisk(ip: string) {
    const since = new Date(Date.now() - 24 * 3600 * 1000);
    const agg = await this.prisma.securityEvent.aggregate({
      where: { ipAddress: ip, occurredAt: { gte: since } }, _max: { riskScore: true },
    });
    const score = agg._max.riskScore ?? 0;
    await this.prisma.securityIp.updateMany({
      where: { ipAddress: ip },
      data: { riskScore: score, riskLevel: riskLevelFor(score) },
    });
  }

  /**
   * Cross-address and cross-account statistics. These are only queried for login
   * events, so ordinary traffic does not pay for them.
   */
  private async gatherCorrelation(event: any, ip: string | null): Promise<RuleContext['stats']['correlation']> {
    const isFailed = event.eventType === 'login_failed';
    const isSuccess = event.eventType === 'login_success';
    if (!isFailed && !isSuccess) return undefined;

    const now = Date.now();
    const userSince = new Date(now - 15 * 60 * 1000);
    const globalSince = new Date(now - 10 * 60 * 1000);

    let userFailedLogins = 0;
    let userFailedFromIps = 0;
    if (event.userId) {
      const rows = await this.prisma.securityEvent.findMany({
        where: { userId: event.userId, eventType: 'login_failed', occurredAt: { gte: userSince } },
        select: { ipAddress: true }, take: 1000,
      });
      userFailedLogins = rows.length;
      userFailedFromIps = new Set(rows.map((r) => r.ipAddress).filter(Boolean)).size;
    }

    let globalFailedLogins = 0;
    let globalFailedFromIps = 0;
    if (isFailed) {
      const groups = await this.prisma.securityEvent.groupBy({
        by: ['ipAddress'],
        where: { eventType: 'login_failed', occurredAt: { gte: globalSince }, ipAddress: { not: null } },
        _count: { _all: true },
      });
      globalFailedFromIps = groups.length;
      globalFailedLogins = groups.reduce((n, g) => n + g._count._all, 0);
    }

    let previousLogin: NonNullable<RuleContext['stats']['correlation']>['previousLogin'];
    if (isSuccess && event.userId && ip) {
      const prev = await this.prisma.securityEvent.findFirst({
        where: {
          userId: event.userId, eventType: 'login_success', id: { not: event.id },
          ipAddress: { not: ip }, occurredAt: { gte: new Date(now - 120 * 60 * 1000) },
        },
        orderBy: { occurredAt: 'desc' }, select: { ipAddress: true, occurredAt: true },
      });
      if (prev?.ipAddress) {
        const prevIp = await this.prisma.securityIp.findUnique({ where: { ipAddress: prev.ipAddress } });
        previousLogin = {
          ipAddress: prev.ipAddress,
          country: prevIp?.country ?? undefined,
          minutesAgo: Math.max(0, Math.round((now - prev.occurredAt.getTime()) / 60000)),
        };
      }
    }
    return { userFailedLogins, userFailedFromIps, globalFailedLogins, globalFailedFromIps, previousLogin };
  }
}
