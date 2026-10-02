import { ruleTitle } from './rule-narratives';
import { formatUtc, plural } from './language';
import { SecurityPeriodFacts, SecuritySummary } from './report.types';

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const STATUS_ORDER = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];
const UNRESOLVED = new Set(['OPEN', 'INVESTIGATING', 'CONTAINED']);

function tally(values: string[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const v of values) m.set(v, (m.get(v) ?? 0) + 1);
  return m;
}

function ordered(counts: Map<string, number>, order: string[]) {
  const known = order.filter((k) => counts.has(k)).map((k) => [k, counts.get(k)!] as const);
  const extra = Array.from(counts.entries()).filter(([k]) => !order.includes(k)).sort((a, b) => b[1] - a[1]);
  return [...known, ...extra];
}

/**
 * Technical, aggregate view of a period for the security team and dashboards.
 * Pure: everything comes from SecurityPeriodFacts.
 */
export function buildSecuritySummary(f: SecurityPeriodFacts): SecuritySummary {
  const sev = ordered(tally(f.incidents.map((i) => i.severity)), SEVERITY_ORDER)
    .map(([severity, count]) => ({ severity, count }));
  const status = ordered(tally(f.incidents.map((i) => i.status)), STATUS_ORDER)
    .map(([s, count]) => ({ status: s, count }));
  const rule = Array.from(tally(f.incidents.map((i) => i.detectionRule ?? 'unknown')).entries())
    .map(([code, count]) => ({ code, title: ruleTitle(code), count }))
    .sort((a, b) => b.count - a.count);

  const resolved = f.incidents.filter((i) => i.resolvedAt && (i.status === 'RESOLVED'));
  const mttrMinutes = resolved.length
    ? Math.round(resolved.reduce((sum, i) => sum + (i.resolvedAt!.getTime() - i.createdAt.getTime()), 0) / resolved.length / 60000)
    : null;
  const unresolved = f.incidents.filter((i) => UNRESOLVED.has(i.status));
  const oldest = unresolved.length
    ? new Date(Math.min(...unresolved.map((i) => i.createdAt.getTime())))
    : null;

  const notes: string[] = [
    'Incident figures cover incidents opened inside the period. Event figures cover events inside the period.',
    'Daily figures use UTC calendar days.',
    'Mean time to resolve counts only incidents resolved (not closed as false alarms) that were also opened in this period.',
  ];
  if (f.eventsWithoutRuleData > 0) {
    notes.push(`${plural(f.eventsWithoutRuleData, 'event')} in this period were recorded before rule detail was saved, so rule-based counts may understate activity.`);
  }
  if (f.intelProviders.length === 0) notes.push('No IP intelligence provider is configured.');

  return {
    kind: 'security_summary',
    generatedAt: f.generatedAt.toISOString(),
    period: { from: f.from.toISOString(), to: f.to.toISOString() },
    totals: { events: f.events, uniqueIps: f.uniqueIps, incidents: f.incidents.length },
    trend: {
      incidents: { current: f.incidents.length, previous: f.previous.incidents },
      events: { current: f.events, previous: f.previous.events },
    },
    eventsByType: f.eventsByType,
    eventsByRiskLevel: f.eventsByRiskLevel,
    incidentsBySeverity: sev,
    incidentsByStatus: status,
    incidentsByRule: rule,
    topSourceIps: f.topSourceIps,
    response: {
      unassignedOpen: f.incidents.filter((i) => i.status === 'OPEN' && !i.assigned).length,
      resolved: resolved.length,
      meanTimeToResolveMinutes: mttrMinutes,
      oldestUnresolvedAt: oldest ? oldest.toISOString() : null,
    },
    blocking: { ...f.blocks, allowlisted: f.allowlisted },
    daily: f.daily,
    notes,
  };
}

export function renderSecuritySummaryText(s: SecuritySummary): string {
  const L: string[] = [];
  L.push('SECURITY ACTIVITY SUMMARY');
  L.push(`${formatUtc(new Date(s.period.from))} to ${formatUtc(new Date(s.period.to))}`, '');
  L.push(`Events: ${s.totals.events} from ${s.totals.uniqueIps} addresses. Incidents opened: ${s.totals.incidents}.`, '');
  if (s.incidentsBySeverity.length) L.push('INCIDENTS BY SEVERITY', ...s.incidentsBySeverity.map((x) => `- ${x.severity}: ${x.count}`), '');
  if (s.incidentsByStatus.length) L.push('INCIDENTS BY STATUS', ...s.incidentsByStatus.map((x) => `- ${x.status}: ${x.count}`), '');
  if (s.incidentsByRule.length) L.push('INCIDENTS BY TYPE', ...s.incidentsByRule.map((x) => `- ${x.title}: ${x.count}`), '');
  if (s.topSourceIps.length) {
    L.push('TOP SOURCE ADDRESSES',
      ...s.topSourceIps.map((x) => `- ${x.ip}: ${x.events} events, peak risk ${x.peakRisk}${x.blocked ? ', blocked' : ''}`), '');
  }
  L.push('RESPONSE',
    `- Open incidents with no owner: ${s.response.unassignedOpen}`,
    `- Mean time to resolve: ${s.response.meanTimeToResolveMinutes === null ? 'not available' : `${s.response.meanTimeToResolveMinutes} minutes`}`, '');
  L.push('NOTES', ...s.notes.map((n) => `- ${n}`));
  return L.join('\n');
}
