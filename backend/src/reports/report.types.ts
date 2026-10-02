/**
 * Types for the deterministic reporting engine.
 *
 * Reports are built in two steps:
 *   1. A facts gatherer reads verified data from the database (IncidentFacts).
 *   2. Pure builder functions turn facts into plain-English reports.
 *
 * Builders never read the database and never guess. Every number and claim in
 * a report traces back to a field in the facts object.
 */

export interface RuleFired {
  code: string;
  name: string;
  /** Number of events (within the report window) on which this rule fired. */
  events: number;
  maxRiskDelta: number;
  /** Detection's own reason text from the most recent firing, if any. */
  lastReason?: string;
}

export interface BlockFact {
  action: string; // BLOCK or UNBLOCK
  createdAt: Date;
  automatic: boolean;
  permanent: boolean;
  expiresAt: Date | null;
  /** True only if the block is still in force right now (computed, not just the flag). */
  inForce: boolean;
  reason: string;
  administrator: string | null;
}

export interface TimelineFact {
  at: Date;
  action: string;
  actor: string | null;
  details: string | null;
}

export interface IncidentFacts {
  generatedAt: Date;
  incident: {
    id: string;
    incidentId: string;
    title: string;
    severity: string;
    status: string;
    riskScore: number;
    detectionRule: string | null;
    sourceIp: string | null;
    createdAt: Date;
    updatedAt: Date;
    resolvedAt: Date | null;
    resolutionNotes: string | null;
    assignee: string | null;
  };
  rule: { code: string; name: string; description: string } | null;
  window: { from: Date; to: Date; lookbackMinutes: number };
  activity: {
    totalEvents: number;
    firstEventAt: Date | null;
    lastEventAt: Date | null;
    byType: Array<{ type: string; count: number }>;
    failedLogins: number;
    successfulLogins: number;
    distinctUsersFailed: number;
    passwordResets: number;
    paymentEvents: number;
    sessionAnomalies: number;
    adminAccesses: number;
    attachedEvents: number;
    peakRisk: number;
    topPaths: Array<{ path: string; count: number }>;
    rulesFired: RuleFired[];
    /** Events in the window that carry rule data (older events may not). */
    eventsWithRuleData: number;
    /** True when per-event detail was read from a capped sample. */
    sampled: boolean;
  };
  signals: {
    /** False if the website has never reported a login_success event recently. */
    loginSuccessReported: boolean;
  };
  ip: null | {
    address: string;
    isPrivate: boolean;
    country: string | null;
    region: string | null;
    city: string | null;
    isVpn: boolean;
    isProxy: boolean;
    isTor: boolean;
    isDatacenter: boolean;
    isMalicious: boolean;
    reputationScore: number;
    intelligenceChecked: boolean;
    firstSeenAt: Date | null;
    lifetimeEvents: number;
  };
  intelProviders: string[];
  blocks: BlockFact[];
  allowlisted: boolean;
  timeline: TimelineFact[];
}

export interface EvidenceItem {
  label: string;
  value: string;
}

export interface IncidentReport {
  kind: 'incident';
  generatedAt: string;
  incidentId: string;
  headline: string;
  severity: string;
  status: string;
  sections: {
    whatHappened: string;
    whyItMatters: string;
    riskLevel: { level: string; score: number; explanation: string };
    evidence: EvidenceItem[];
    actionTaken: string[];
    currentStatus: string;
    recommendedActions: string[];
  };
  /** Things this report cannot confirm, stated plainly. */
  limitations: string[];
}

export interface TechnicalReport {
  kind: 'technical';
  generatedAt: string;
  incidentId: string;
  incident: Record<string, unknown>;
  window: { from: string; to: string; lookbackMinutes: number };
  activity: Record<string, unknown>;
  rulesFired: Array<Record<string, unknown>>;
  ip: Record<string, unknown> | null;
  blocks: Array<Record<string, unknown>>;
  allowlisted: boolean;
  timeline: Array<Record<string, unknown>>;
  notes: string[];
}

export type Posture = 'ALL_CLEAR' | 'MONITORING' | 'ACTION_NEEDED' | 'URGENT';

export interface PeriodFacts {
  generatedAt: Date;
  from: Date;
  to: Date;
  previous: { incidents: number; events: number };
  events: number;
  uniqueIps: number;
  incidents: Array<{
    incidentId: string;
    id: string;
    title: string;
    severity: string;
    status: string;
    riskScore: number;
    sourceIp: string | null;
    detectionRule: string | null;
    createdAt: Date;
    assigned: boolean;
    /** One-sentence plain-English summary built from the incident's own facts. */
    summary: string;
  }>;
  blocks: { total: number; automatic: number; manual: number; stillInForce: number };
  intelProviders: string[];
}

export interface ExecutiveSummary {
  kind: 'executive_summary';
  generatedAt: string;
  period: { from: string; to: string };
  posture: Posture;
  headline: string;
  overview: string;
  keyNumbers: EvidenceItem[];
  notableIncidents: Array<{
    incidentId: string;
    title: string;
    severity: string;
    status: string;
    summary: string;
  }>;
  needsAttention: string[];
  trend: string;
  limitations: string[];
}

export interface SecurityPeriodFacts {
  generatedAt: Date;
  from: Date;
  to: Date;
  previous: { incidents: number; events: number };
  events: number;
  uniqueIps: number;
  eventsByType: Array<{ type: string; count: number }>;
  eventsByRiskLevel: Array<{ level: string; count: number }>;
  topSourceIps: Array<{ ip: string; events: number; peakRisk: number; blocked: boolean }>;
  incidents: Array<{
    incidentId: string; severity: string; status: string; detectionRule: string | null;
    createdAt: Date; resolvedAt: Date | null; assigned: boolean;
  }>;
  daily: Array<{ date: string; events: number; incidents: number }>;
  blocks: { total: number; automatic: number; manual: number; stillInForce: number };
  allowlisted: number;
  eventsWithoutRuleData: number;
  intelProviders: string[];
}

export interface SecuritySummary {
  kind: 'security_summary';
  generatedAt: string;
  period: { from: string; to: string };
  totals: { events: number; uniqueIps: number; incidents: number };
  trend: { incidents: { current: number; previous: number }; events: { current: number; previous: number } };
  eventsByType: Array<{ type: string; count: number }>;
  eventsByRiskLevel: Array<{ level: string; count: number }>;
  incidentsBySeverity: Array<{ severity: string; count: number }>;
  incidentsByStatus: Array<{ status: string; count: number }>;
  incidentsByRule: Array<{ code: string; title: string; count: number }>;
  topSourceIps: Array<{ ip: string; events: number; peakRisk: number; blocked: boolean }>;
  response: {
    unassignedOpen: number;
    resolved: number;
    meanTimeToResolveMinutes: number | null;
    oldestUnresolvedAt: string | null;
  };
  blocking: { total: number; automatic: number; manual: number; stillInForce: number; allowlisted: number };
  daily: Array<{ date: string; events: number; incidents: number }>;
  notes: string[];
}
