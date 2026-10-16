import type {
  ActiveBlock, ApiKeyRow, AuditRow, ExecutiveSummary, IncidentReport, Incident, IpDetail, IpRecord, OperationalSettings,
  Role, RuleRow, SecuritySummary, TechnicalReport, UserRow, User,
} from '@/api/types';

const iso = (minAgo: number) => new Date(Date.now() - minAgo * 60_000).toISOString();

export const user = (role: Role, over: Partial<User> = {}): User => ({ id: `u-${role}`, email: `${role.toLowerCase()}@example.com`, name: `${role} Person`, role, isActive: true, mustChangePassword: false, ...over });

export const incident = (over: Partial<Incident> = {}): Incident => ({
  id: 'inc1', incidentId: 'INC-20261007-00001ABCD', title: 'Repeated failed sign-ins from one address', description: 'x',
  severity: 'HIGH', riskScore: 72, status: 'OPEN', sourceIp: '198.51.100.7', userId: null, detectionRule: 'brute_force_login',
  assignedTo: null, assignee: null, resolutionNotes: null, createdAt: iso(90), updatedAt: iso(5), resolvedAt: null,
  timeline: [
    { id: 't1', incidentId: 'inc1', action: 'incident.created', actor: 'system', details: 'Opened by rule', createdAt: iso(90) },
    { id: 't2', incidentId: 'inc1', action: 'incident.escalated', actor: 'system', details: 'Raised to HIGH', createdAt: iso(30) },
  ],
  events: [
    { id: 'e1', eventType: 'login_failed', severity: 'MEDIUM', ipAddress: '198.51.100.7', userId: null, requestMethod: 'POST', requestPath: '/login', riskScore: 40, riskLevel: 'SUSPICIOUS', occurredAt: iso(80), createdAt: iso(80) },
  ],
  ...over,
});

export const report = (over: Partial<IncidentReport> = {}): IncidentReport => ({
  kind: 'incident', generatedAt: iso(1), incidentId: 'INC-20261007-00001ABCD', headline: 'Someone is guessing passwords', severity: 'HIGH', status: 'OPEN',
  sections: {
    whatHappened: 'An address tried to sign in 40 times and failed every time.',
    whyItMatters: 'Guessing passwords is how accounts get taken over.',
    riskLevel: { level: 'HIGH', score: 72, explanation: 'The pattern matches a password-guessing attack.' },
    evidence: [{ label: 'Failed sign-ins', value: '40' }, { label: 'Address', value: '198.51.100.7' }],
    actionTaken: ['The address was blocked for 60 minutes.'],
    currentStatus: 'Open and not yet assigned.',
    recommendedActions: ['Check the accounts that were targeted.', 'Confirm the website enforces the blocklist.'],
  },
  limitations: ['This system records blocks but cannot confirm that the website actually rejected traffic from the address.'],
  ...over,
});

export const technical = (over: Partial<TechnicalReport> = {}): TechnicalReport => ({
  kind: 'technical', generatedAt: iso(1), incidentId: 'INC-20261007-00001ABCD', incident: {}, window: { from: iso(120), to: iso(0), lookbackMinutes: 120 },
  activity: { totalEvents: 40, byType: [{ type: 'login_failed', count: 40 }], topPaths: [{ path: '/login', count: 40 }] },
  rulesFired: [{ code: 'brute_force_login', name: 'Brute-force login', events: 40, maxRiskDelta: 48, lastReason: '40 failed logins in 10 min' }],
  ip: { address: '198.51.100.7', country: 'NG', isVpn: false, isProxy: false, isTor: false, isDatacenter: false, isMalicious: false, intelligenceChecked: true, reputationScore: 0 },
  blocks: [], allowlisted: false, timeline: [], notes: ['Counts are taken from stored events.'], ...over,
});

export const executive = (over: Partial<ExecutiveSummary> = {}): ExecutiveSummary => ({
  kind: 'executive_summary', generatedAt: iso(1), period: { from: iso(7 * 1440), to: iso(0) }, posture: 'ACTION_NEEDED',
  headline: 'One incident needs someone to look at it', overview: 'In the last 7 days there were 120 events and 2 incidents.',
  keyNumbers: [{ label: 'Incidents', value: '2' }, { label: 'Events', value: '120' }],
  notableIncidents: [{ incidentId: 'INC-20261007-00001ABCD', title: 'Repeated failed sign-ins', severity: 'HIGH', status: 'OPEN', summary: 'Forty failed sign-ins in ten minutes.' }],
  needsAttention: ['1 open incident has nobody assigned.'], trend: 'Incidents are up from 1 to 2.',
  limitations: ['Blocks are recorded by this system. It cannot confirm that the website actually rejected the traffic.'], ...over,
});

export const securitySummary = (over: Partial<SecuritySummary> = {}): SecuritySummary => ({
  kind: 'security_summary', generatedAt: iso(1), period: { from: iso(7 * 1440), to: iso(0) },
  totals: { events: 120, uniqueIps: 9, incidents: 2 }, trend: { incidents: { current: 2, previous: 1 }, events: { current: 120, previous: 80 } },
  eventsByType: [{ type: 'login_failed', count: 90 }], eventsByRiskLevel: [{ level: 'HIGH', count: 10 }],
  incidentsBySeverity: [{ severity: 'HIGH', count: 2 }], incidentsByStatus: [{ status: 'OPEN', count: 2 }],
  incidentsByRule: [{ code: 'brute_force_login', title: 'Password guessing', count: 2 }],
  topSourceIps: [{ ip: '198.51.100.7', events: 90, peakRisk: 72, blocked: true }],
  response: { unassignedOpen: 1, resolved: 0, meanTimeToResolveMinutes: null, oldestUnresolvedAt: iso(90) },
  blocking: { total: 1, automatic: 1, manual: 0, stillInForce: 1, allowlisted: 0 },
  daily: [{ date: '2026-10-05', events: 30, incidents: 0 }, { date: '2026-10-06', events: 40, incidents: 1 }, { date: '2026-10-07', events: 50, incidents: 1 }],
  notes: ['Events stored before rule data was recorded are not counted by rule.'], ...over,
});

export const ipRecord = (over: Partial<IpRecord> = {}): IpRecord => ({
  id: 'ip1', ipAddress: '198.51.100.7', firstSeenAt: iso(3000), lastSeenAt: iso(5), requestCount: 400, eventCount: 90, failedLogins: 40,
  riskScore: 72, riskLevel: 'HIGH', country: 'NG', region: null, city: null, isVpn: false, isProxy: false, isTor: false, isDatacenter: false,
  isMalicious: false, reputationScore: 0, lastIntelUpdate: iso(60), ...over,
});
export const ipDetail = (over: Partial<IpDetail> = {}): IpDetail => ({ ip: ipRecord(), events: incident().events!, blocks: [], isPrivate: false, ...over });
export const activeBlock = (over: Partial<ActiveBlock> = {}): ActiveBlock => ({ ipAddress: '198.51.100.7', reason: 'Automatic: critical risk', expiresAt: new Date(Date.now() + 40 * 60_000).toISOString(), permanent: false, automatic: true, createdAt: iso(20), ...over });

export const userRow = (role: Role, over: Partial<UserRow> = {}): UserRow => ({ ...user(role), lastLoginAt: iso(30), createdAt: iso(9999), ...over });
export const apiKey = (over: Partial<ApiKeyRow> = {}): ApiKeyRow => ({ id: 'k1', name: 'Main website', keyPrefix: 'IRS_ab12cd34', scopes: 'events:write,block:read', isActive: true, expiresAt: null, lastUsedAt: iso(2), revokedAt: null, createdAt: iso(5000), ...over });

export const rule = (over: Partial<RuleRow> = {}): RuleRow => ({
  code: 'brute_force_login', title: 'Password guessing', name: 'Brute-force login', description: 'Many failed sign-ins from one address.', whyItMatters: 'This is how accounts get taken over.',
  isEnabled: true, priority: 10, config: { windowMinutes: 10, threshold: 5, riskPerAttempt: 8, maxRisk: 70, incidentAt: 5 },
  defaultConfig: { windowMinutes: 10, threshold: 5, riskPerAttempt: 8, maxRisk: 70, incidentAt: 5 }, isDefault: true,
  limits: { windowMinutes: { min: 0, max: 0, editable: false }, threshold: { min: 1, max: 1000, editable: true }, riskPerAttempt: { min: 1, max: 100, editable: true }, maxRisk: { min: 1, max: 100, editable: true }, incidentAt: { min: 1, max: 1000, editable: true } },
  updatedAt: null, ...over,
});

export const audit = (over: Partial<AuditRow> = {}): AuditRow => ({
  id: 'a1', requestId: 'req-1', actorType: 'USER', actorId: 'u1', actorLabel: 'sec@example.com', action: 'ip.block', targetType: 'ip', targetId: '198.51.100.7',
  result: 'SUCCESS', metadata: { reason: 'attack' }, ipAddress: '203.0.113.5', createdAt: iso(10), ...over,
});

export const settings = (over: Partial<OperationalSettings> = {}): OperationalSettings => ({
  version: '1.0.0', intelligenceProviders: [], autoBlock: { enabled: true, minimumRisk: 85, blockMinutes: 60 },
  rateLimits: { windowSeconds: 60, perAddress: 120, perWebsiteKey: 6000, signIn: 20 }, riskLevels: { suspicious: 30, high: 60, critical: 80 },
  sessions: { accessTokenLifetime: '15m', refreshTokenDays: 7, secureCookie: true }, ...over,
});

export const page = <T,>(data: T[], over: Partial<{ page: number; pageSize: number; total: number; totalPages: number }> = {}) => ({
  data, meta: { page: 1, pageSize: 20, total: data.length, totalPages: Math.max(1, Math.ceil(data.length / 20)), ...over },
});
