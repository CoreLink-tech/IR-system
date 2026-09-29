export interface RuleContext {
  event: {
    id: string;
    eventType: string;
    severity: string;
    ipAddress: string | null;
    userId: string | null;
    sessionId: string | null;
    requestPath: string | null;
    metadata: any;
    occurredAt: Date;
  };
  stats: {
    failedLoginsLastWindow: number;
    eventsLastWindow: number;
    distinctUsersLastWindow: number;
    passwordResetsLastWindow: number;
    ipIntel?: {
      isVpn: boolean; isProxy: boolean; isTor: boolean;
      isDatacenter: boolean; isMalicious: boolean; reputationScore: number;
    };
  };
}

export interface RuleResult {
  matched: boolean;
  riskDelta: number;
  reason?: string;
  createIncident?: boolean;
  incidentSeverity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface RuleDefinition {
  code: string;
  name: string;
  description: string;
  priority: number;
  defaultConfig: Record<string, any>;
  evaluate: (ctx: RuleContext, config: Record<string, any>) => RuleResult;
}

export const BUILT_IN_RULES: RuleDefinition[] = [
  {
    code: 'brute_force_login',
    name: 'Brute-force login',
    description: 'Multiple failed logins from the same IP within a short window.',
    priority: 10,
    defaultConfig: { windowMinutes: 10, threshold: 5, riskPerAttempt: 8, maxRisk: 70, incidentAt: 5 },
    evaluate: (ctx, cfg) => {
      if (ctx.event.eventType !== 'login_failed') return { matched: false, riskDelta: 0 };
      const n = ctx.stats.failedLoginsLastWindow;
      if (n < cfg.threshold) return { matched: false, riskDelta: 0 };
      const delta = Math.min(cfg.maxRisk, n * cfg.riskPerAttempt);
      return {
        matched: true, riskDelta: delta,
        reason: `${n} failed logins in ${cfg.windowMinutes} min`,
        createIncident: n >= cfg.incidentAt,
        incidentSeverity: n >= 20 ? 'CRITICAL' : n >= 10 ? 'HIGH' : 'MEDIUM',
      };
    },
  },
  {
    code: 'credential_stuffing',
    name: 'Credential stuffing',
    description: 'Many failed logins against distinct users from the same IP.',
    priority: 15,
    defaultConfig: { windowMinutes: 10, distinctUsersThreshold: 4, riskDelta: 35 },
    evaluate: (ctx, cfg) => {
      if (ctx.event.eventType !== 'login_failed') return { matched: false, riskDelta: 0 };
      if (ctx.stats.distinctUsersLastWindow < cfg.distinctUsersThreshold) return { matched: false, riskDelta: 0 };
      return {
        matched: true, riskDelta: cfg.riskDelta,
        reason: `${ctx.stats.distinctUsersLastWindow} distinct users targeted`,
        createIncident: true, incidentSeverity: 'HIGH',
      };
    },
  },
  {
    code: 'high_request_rate',
    name: 'High request rate',
    description: 'Unusually high event volume from a single IP.',
    priority: 40,
    defaultConfig: { windowMinutes: 5, threshold: 60, riskDelta: 25 },
    evaluate: (ctx, cfg) => {
      if (ctx.stats.eventsLastWindow < cfg.threshold) return { matched: false, riskDelta: 0 };
      return {
        matched: true, riskDelta: cfg.riskDelta,
        reason: `${ctx.stats.eventsLastWindow} events in ${cfg.windowMinutes} min`,
      };
    },
  },
  {
    code: 'user_enumeration',
    name: 'User enumeration',
    description: 'Pattern suggesting user id enumeration.',
    priority: 45,
    defaultConfig: { windowMinutes: 10, distinctUsersThreshold: 6, riskDelta: 30 },
    evaluate: (ctx, cfg) => {
      if (!['login_failed', 'password_reset'].includes(ctx.event.eventType)) return { matched: false, riskDelta: 0 };
      if (ctx.stats.distinctUsersLastWindow < cfg.distinctUsersThreshold) return { matched: false, riskDelta: 0 };
      return { matched: true, riskDelta: cfg.riskDelta, reason: 'Enumeration-like pattern detected' };
    },
  },
  {
    code: 'password_reset_abuse',
    name: 'Password reset abuse',
    description: 'Multiple password resets triggered in a short window.',
    priority: 50,
    defaultConfig: { windowMinutes: 15, threshold: 4, riskDelta: 20 },
    evaluate: (ctx, cfg) => {
      if (ctx.event.eventType !== 'password_reset') return { matched: false, riskDelta: 0 };
      if (ctx.stats.passwordResetsLastWindow < cfg.threshold) return { matched: false, riskDelta: 0 };
      return { matched: true, riskDelta: cfg.riskDelta, reason: 'Repeated password resets' };
    },
  },
  {
    code: 'suspicious_admin_access',
    name: 'Suspicious admin access',
    description: 'Admin endpoints hit from a suspicious context.',
    priority: 55,
    defaultConfig: { riskDelta: 30 },
    evaluate: (ctx, cfg) => {
      if (ctx.event.eventType !== 'admin_access') return { matched: false, riskDelta: 0 };
      const intel = ctx.stats.ipIntel;
      if (intel && (intel.isTor || intel.isMalicious)) {
        return { matched: true, riskDelta: cfg.riskDelta, reason: 'Admin access from untrusted network' };
      }
      return { matched: false, riskDelta: 0 };
    },
  },
  {
    code: 'known_malicious_ip',
    name: 'Known malicious IP',
    description: 'IP marked malicious by intelligence provider.',
    priority: 20,
    defaultConfig: { riskDelta: 50 },
    evaluate: (ctx, cfg) => {
      const intel = ctx.stats.ipIntel;
      if (!intel?.isMalicious) return { matched: false, riskDelta: 0 };
      return { matched: true, riskDelta: cfg.riskDelta, reason: 'IP flagged as malicious' };
    },
  },
  {
    code: 'tor_or_proxy',
    name: 'Tor / proxy / VPN signal',
    description: 'Informational — VPN alone is NOT malicious.',
    priority: 90,
    defaultConfig: { torRisk: 20, proxyRisk: 8, vpnRisk: 4 },
    evaluate: (ctx, cfg) => {
      const intel = ctx.stats.ipIntel;
      if (!intel) return { matched: false, riskDelta: 0 };
      let delta = 0;
      const parts: string[] = [];
      if (intel.isTor) { delta += cfg.torRisk; parts.push('Tor'); }
      if (intel.isProxy) { delta += cfg.proxyRisk; parts.push('proxy'); }
      if (intel.isVpn) { delta += cfg.vpnRisk; parts.push('VPN'); }
      if (delta === 0) return { matched: false, riskDelta: 0 };
      return { matched: true, riskDelta: delta, reason: parts.join(' + ') };
    },
  },
  {
    code: 'suspicious_payload',
    name: 'Suspicious payload',
    description: 'Request path or metadata contains injection indicators.',
    priority: 65,
    defaultConfig: { riskDelta: 25 },
    evaluate: (ctx, cfg) => {
      const path = (ctx.event.requestPath || '').toLowerCase();
      const meta = JSON.stringify(ctx.event.metadata || {}).toLowerCase();
      const needles = ['<script', '../', 'union select', 'sleep(', 'benchmark(', 'onerror=', 'javascript:'];
      const hay = `${path} ${meta}`;
      if (needles.some((n) => hay.includes(n))) {
        return { matched: true, riskDelta: cfg.riskDelta, reason: 'Payload contains injection-like content' };
      }
      return { matched: false, riskDelta: 0 };
    },
  },
  {
    code: 'order_id_enumeration',
    name: 'Order / product ID enumeration',
    description: 'Many sequential order/product lookups from one IP.',
    priority: 70,
    defaultConfig: { windowMinutes: 10, threshold: 30, riskDelta: 20 },
    evaluate: (ctx, cfg) => {
      const path = ctx.event.requestPath || '';
      if (!/\/(order|product|item)s?\/\d+/i.test(path)) return { matched: false, riskDelta: 0 };
      if (ctx.stats.eventsLastWindow < cfg.threshold) return { matched: false, riskDelta: 0 };
      return { matched: true, riskDelta: cfg.riskDelta, reason: 'Sequential ID access pattern' };
    },
  },
  {
    code: 'payment_abuse_signal',
    name: 'Payment abuse signal',
    description: 'Multiple payment security events from same IP.',
    priority: 60,
    defaultConfig: { windowMinutes: 20, threshold: 3, riskDelta: 40 },
    evaluate: (ctx, cfg) => {
      if (ctx.event.eventType !== 'payment_security_event') return { matched: false, riskDelta: 0 };
      if (ctx.stats.eventsLastWindow < cfg.threshold) return { matched: false, riskDelta: 0 };
      return {
        matched: true, riskDelta: cfg.riskDelta,
        reason: 'Repeated payment security events',
        createIncident: true, incidentSeverity: 'HIGH',
      };
    },
  },
  {
    code: 'session_anomaly',
    name: 'Session anomaly',
    description: 'Session anomaly events from the same IP.',
    priority: 80,
    defaultConfig: { windowMinutes: 15, threshold: 2, riskDelta: 20 },
    evaluate: (ctx, cfg) => {
      if (ctx.event.eventType !== 'session_anomaly') return { matched: false, riskDelta: 0 };
      if (ctx.stats.eventsLastWindow < cfg.threshold) return { matched: false, riskDelta: 0 };
      return { matched: true, riskDelta: cfg.riskDelta, reason: 'Repeated session anomalies' };
    },
  },
];
