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
      country?: string;
    };
    /**
     * Cross-address and cross-account statistics. Only filled in for the event
     * types that need them, so a plain page view costs no extra queries.
     */
    correlation?: {
      /** Failed logins against this event's account in the last 15 minutes, from any address. */
      userFailedLogins: number;
      /** Distinct addresses behind those failed logins. */
      userFailedFromIps: number;
      /** Failed logins across the whole platform in the last 10 minutes. */
      globalFailedLogins: number;
      /** Distinct addresses behind those failed logins. */
      globalFailedFromIps: number;
      /** The same account's previous successful login from a different address, if recent. */
      previousLogin?: { ipAddress: string; country?: string; minutesAgo: number };
    };
  };
}

/**
 * Compares two country values from IP intelligence providers. Providers disagree
 * on format (a code such as "NG" versus a name such as "Nigeria"), so values in
 * different formats cannot be compared. Returns null when it is not safe to say.
 */
export function sameCountry(a?: string | null, b?: string | null): boolean | null {
  if (!a || !b) return null;
  const x = a.trim().toLowerCase();
  const y = b.trim().toLowerCase();
  if ((x.length === 2) !== (y.length === 2)) return null;
  return x === y;
}

export interface RuleResult {
  matched: boolean;
  riskDelta: number;
  reason?: string;
  createIncident?: boolean;
  incidentSeverity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  /**
   * What an incident from this rule is about. 'ip' (default) groups by source
   * address. 'account' groups by the targeted account across all addresses.
   * 'global' groups an attack on the platform as a whole.
   */
  incidentScope?: 'ip' | 'account' | 'global';
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

  {
    code: 'possible_account_takeover',
    name: 'Possible account takeover',
    description: 'A successful login on an account that just had several failed logins.',
    priority: 12,
    // Severity is HIGH by default. It is CRITICAL only when the failures came from
    // several addresses, which points to a coordinated attack. A customer who simply
    // mistyped their own password from one address must never be treated as critical.
    defaultConfig: { minFailedLogins: 3, riskDelta: 65, criticalFailedLogins: 10, criticalFromIps: 3 },
    evaluate: (ctx, cfg) => {
      if (ctx.event.eventType !== 'login_success' || !ctx.event.userId) return { matched: false, riskDelta: 0 };
      const c = ctx.stats.correlation;
      if (!c || c.userFailedLogins < cfg.minFailedLogins) return { matched: false, riskDelta: 0 };
      return {
        matched: true, riskDelta: cfg.riskDelta,
        reason: `Successful login after ${c.userFailedLogins} failed logins on the same account from ${c.userFailedFromIps} address${c.userFailedFromIps === 1 ? '' : 'es'}`,
        createIncident: true,
        incidentSeverity:
          c.userFailedLogins >= cfg.criticalFailedLogins && c.userFailedFromIps >= cfg.criticalFromIps ? 'CRITICAL' : 'HIGH',
      };
    },
  },
  {
    code: 'distributed_account_attack',
    name: 'Distributed attack on one account',
    description: 'Failed logins against one account from many different addresses.',
    priority: 16,
    defaultConfig: { distinctIpsThreshold: 4, riskDelta: 40 },
    evaluate: (ctx, cfg) => {
      if (ctx.event.eventType !== 'login_failed' || !ctx.event.userId) return { matched: false, riskDelta: 0 };
      const c = ctx.stats.correlation;
      if (!c || c.userFailedFromIps < cfg.distinctIpsThreshold) return { matched: false, riskDelta: 0 };
      return {
        matched: true, riskDelta: cfg.riskDelta,
        reason: `${c.userFailedLogins} failed logins on one account from ${c.userFailedFromIps} different addresses`,
        createIncident: true, incidentSeverity: 'HIGH', incidentScope: 'account',
      };
    },
  },
  {
    code: 'distributed_login_attack',
    name: 'Distributed login attack',
    description: 'A surge of failed logins from many different addresses at once.',
    priority: 17,
    defaultConfig: { distinctIpsThreshold: 15, failedLoginsThreshold: 40, riskDelta: 45, criticalAtIps: 50 },
    evaluate: (ctx, cfg) => {
      if (ctx.event.eventType !== 'login_failed') return { matched: false, riskDelta: 0 };
      const c = ctx.stats.correlation;
      if (!c || c.globalFailedFromIps < cfg.distinctIpsThreshold || c.globalFailedLogins < cfg.failedLoginsThreshold) {
        return { matched: false, riskDelta: 0 };
      }
      return {
        matched: true, riskDelta: cfg.riskDelta,
        reason: `${c.globalFailedLogins} failed logins from ${c.globalFailedFromIps} different addresses in 10 min`,
        createIncident: true,
        incidentSeverity: c.globalFailedFromIps >= cfg.criticalAtIps ? 'CRITICAL' : 'HIGH',
        incidentScope: 'global',
      };
    },
  },
  {
    code: 'impossible_travel',
    name: 'Impossible travel',
    description: 'The same account logged in from two different countries within a short time.',
    priority: 18,
    defaultConfig: { windowMinutes: 120, riskDelta: 50 },
    evaluate: (ctx, cfg) => {
      if (ctx.event.eventType !== 'login_success' || !ctx.event.userId) return { matched: false, riskDelta: 0 };
      const prev = ctx.stats.correlation?.previousLogin;
      if (!prev) return { matched: false, riskDelta: 0 };
      // Only when both countries are known and comparable. Unknown is never treated as different.
      if (sameCountry(prev.country, ctx.stats.ipIntel?.country) !== false) return { matched: false, riskDelta: 0 };
      return {
        matched: true, riskDelta: cfg.riskDelta,
        reason: `Logins from ${prev.country} and ${ctx.stats.ipIntel!.country} ${prev.minutesAgo} min apart`,
        createIncident: true, incidentSeverity: 'HIGH',
      };
    },
  },
];
