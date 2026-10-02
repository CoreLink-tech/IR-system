import {
  ExecutiveSummary, EvidenceItem, PeriodFacts, Posture,
} from './report.types';
import {
  formatUtc, plural, severityWord,
} from './language';
import { ruleTitle } from './rule-narratives';

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const UNRESOLVED = new Set(['OPEN', 'INVESTIGATING', 'CONTAINED']);
const ACTIVE = new Set(['OPEN', 'INVESTIGATING']);

const statusWord = (s: string) =>
  ({ OPEN: 'open', INVESTIGATING: 'under investigation', CONTAINED: 'contained', RESOLVED: 'resolved', FALSE_POSITIVE: 'a false alarm' } as Record<string, string>)[s] ?? s.toLowerCase();

/**
 * Overall posture, decided by fixed rules:
 *   URGENT         a critical incident is open or under investigation
 *   ACTION_NEEDED  a high incident is open or under investigation, or any open incident has no owner
 *   MONITORING     other unresolved incidents remain
 *   ALL_CLEAR      nothing unresolved
 */
export function postureOf(p: PeriodFacts): Posture {
  const inc = p.incidents;
  if (inc.some((i) => i.severity === 'CRITICAL' && ACTIVE.has(i.status))) return 'URGENT';
  if (inc.some((i) => (i.severity === 'HIGH' && ACTIVE.has(i.status)) || (i.status === 'OPEN' && !i.assigned))) return 'ACTION_NEEDED';
  if (inc.some((i) => UNRESOLVED.has(i.status))) return 'MONITORING';
  return 'ALL_CLEAR';
}

function countBy<T>(items: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const it of items) out[key(it)] = (out[key(it)] ?? 0) + 1;
  return out;
}

function severityBreakdown(p: PeriodFacts): string {
  const c = countBy(p.incidents, (i) => i.severity);
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    .filter((s) => c[s])
    .map((s) => `${c[s]} ${severityWord(s).toLowerCase()}`)
    .join(', ');
}

function compare(label: string, cur: number, prev: number): string {
  if (prev === 0 && cur === 0) return `${label}: none in either period`;
  if (prev === 0) return `${label}: ${cur} (none in the previous period)`;
  if (cur === prev) return `${label}: ${cur}, unchanged`;
  const pct = Math.round((Math.abs(cur - prev) / prev) * 100);
  return `${label}: ${cur}, ${cur > prev ? 'up' : 'down'} ${pct}% from ${prev}`;
}

export function buildExecutiveSummary(p: PeriodFacts): ExecutiveSummary {
  const posture = postureOf(p);
  const total = p.incidents.length;
  const unresolved = p.incidents.filter((i) => UNRESOLVED.has(i.status));
  const critUnresolved = p.incidents.filter((i) => i.severity === 'CRITICAL' && ACTIVE.has(i.status));
  const needing = p.incidents.filter(
    (i) => (i.severity === 'HIGH' && ACTIVE.has(i.status)) || (i.status === 'OPEN' && !i.assigned) || (i.severity === 'CRITICAL' && ACTIVE.has(i.status)),
  );

  let headline: string;
  switch (posture) {
    case 'URGENT':
      headline = `Urgent: ${plural(critUnresolved.length, 'critical incident')} still unresolved.`;
      break;
    case 'ACTION_NEEDED':
      headline = `Action needed: ${plural(needing.length, 'incident')} ${needing.length === 1 ? 'requires' : 'require'} attention.`;
      break;
    case 'MONITORING':
      headline = `Under watch: ${plural(unresolved.length, 'incident')} being handled, none urgent.`;
      break;
    default:
      headline = total === 0
        ? 'No security incidents in this period.'
        : `All ${plural(total, 'security incident')} in this period ${total === 1 ? 'has' : 'have'} been closed.`;
  }

  const periodText = `${formatUtc(p.from)} to ${formatUtc(p.to)}`;
  let overview = `From ${periodText}, the security system recorded ${plural(p.events, 'event')} from ${plural(p.uniqueIps, 'different address', 'different addresses')}`;
  overview += total === 0
    ? ' and opened no incidents.'
    : ` and opened ${plural(total, 'incident')} (${severityBreakdown(p)}).`;
  if (p.blocks.total > 0) {
    overview += ` ${plural(p.blocks.total, 'address', 'addresses')} ${p.blocks.total === 1 ? 'was' : 'were'} blocked (${p.blocks.automatic} automatically, ${p.blocks.manual} by administrators).`;
  }

  const keyNumbers: EvidenceItem[] = [
    { label: 'Events recorded', value: p.events.toLocaleString('en-US') },
    { label: 'Different addresses seen', value: p.uniqueIps.toLocaleString('en-US') },
    { label: 'Incidents opened', value: total === 0 ? '0' : `${total} (${severityBreakdown(p)})` },
    { label: 'Incidents still unresolved', value: String(unresolved.length) },
    { label: 'Addresses blocked', value: `${p.blocks.total} (${p.blocks.automatic} automatic, ${p.blocks.manual} manual)` },
    { label: 'Blocks currently in force', value: String(p.blocks.stillInForce) },
  ];

  const notable = [...p.incidents]
    .sort((a, b) =>
      (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)
      || b.riskScore - a.riskScore
      || b.createdAt.getTime() - a.createdAt.getTime())
    .slice(0, 5)
    .map((i) => ({
      incidentId: i.incidentId, title: i.title, severity: i.severity, status: i.status, summary: i.summary,
    }));

  const needsAttention = needing
    .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))
    .slice(0, 10)
    .map((i) => `${i.title} (${i.incidentId}): ${severityWord(i.severity).toLowerCase()} severity, ${statusWord(i.status)}${i.assigned ? '' : ', nobody assigned'}.`);

  const trend = p.previous.incidents === 0 && p.previous.events === 0
    ? 'There is no data from the previous period to compare with.'
    : `Compared with the previous period of the same length: ${compare('incidents', total, p.previous.incidents)}; ${compare('events', p.events, p.previous.events)}.`;

  const limitations: string[] = [
    'Figures cover only what the PishonMarket website reports to the security system.',
    'Incident counts include only incidents opened during this period.',
  ];
  if (p.intelProviders.length === 0) {
    limitations.push('No IP intelligence provider is configured, so VPN, proxy, Tor and reputation checks are not included.');
  }
  if (p.blocks.total > 0) {
    limitations.push('Blocks are recorded by this system. It cannot confirm that the website actually rejected the traffic.');
  }

  return {
    kind: 'executive_summary',
    generatedAt: p.generatedAt.toISOString(),
    period: { from: p.from.toISOString(), to: p.to.toISOString() },
    posture,
    headline,
    overview,
    keyNumbers,
    notableIncidents: notable,
    needsAttention,
    trend,
    limitations,
  };
}

export function renderExecutiveSummaryText(s: ExecutiveSummary): string {
  const lines: string[] = [];
  lines.push('SECURITY SUMMARY');
  lines.push(s.headline, '');
  lines.push(s.overview, '');
  lines.push('KEY NUMBERS', ...s.keyNumbers.map((k) => `- ${k.label}: ${k.value}`), '');
  if (s.needsAttention.length) lines.push('NEEDS ATTENTION', ...s.needsAttention.map((x) => `- ${x}`), '');
  if (s.notableIncidents.length) {
    lines.push('NOTABLE INCIDENTS',
      ...s.notableIncidents.map((n) => `- ${n.incidentId} (${severityWord(n.severity)}, ${statusWord(n.status)}): ${n.summary}`), '');
  }
  lines.push('TREND', s.trend, '');
  lines.push('WHAT THIS SUMMARY CANNOT CONFIRM', ...s.limitations.map((x) => `- ${x}`));
  return lines.join('\n');
}

