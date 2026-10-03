import { riskLevelFor, riskThresholds } from '../common/utils/risk.util';
import {
  EvidenceItem, IncidentFacts, IncidentReport, TechnicalReport,
} from './report.types';
import {
  capitalize, formatUtc, humanDuration, joinList, plural, severityWord,
} from './language';
import { narrativeFor, ruleTitle } from './rule-narratives';

const LEVEL_MEANING: Record<string, string> = {
  NORMAL: 'No action is needed.',
  SUSPICIOUS: 'This is worth watching.',
  HIGH: 'This needs prompt attention.',
  CRITICAL: 'This needs immediate attention.',
};

const STILL_ACTIVE_MS = 15 * 60 * 1000;

const isClosed = (status: string) => status === 'RESOLVED' || status === 'FALSE_POSITIVE';

function statusLabel(status: string): string {
  switch (status) {
    case 'OPEN': return 'open';
    case 'INVESTIGATING': return 'under investigation';
    case 'CONTAINED': return 'contained';
    case 'RESOLVED': return 'resolved';
    case 'FALSE_POSITIVE': return 'closed as a false alarm';
    default: return status.toLowerCase();
  }
}

/** Highest risk the system recorded, never lower than what the incident itself stored. */
export function peakRiskOf(f: IncidentFacts): number {
  return Math.max(f.incident.riskScore, f.activity.peakRisk);
}

function narrativeOf(f: IncidentFacts) {
  const rule = f.rule;
  return narrativeFor(f.incident.detectionRule, rule?.name, rule?.description);
}

function blockSentences(f: IncidentFacts): string[] {
  if (f.scope !== 'ip') {
    return [f.scope === 'account'
      ? 'This incident involves many addresses, so no single address was blocked automatically.'
      : 'This incident involves many addresses, so no single address was blocked automatically. The most active addresses are listed in the technical report.'];
  }
  const out: string[] = [];
  const blocks = f.blocks.filter((b) => b.action === 'BLOCK').sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  const unblocks = f.blocks.filter((b) => b.action === 'UNBLOCK').sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

  if (blocks.length > 0) {
    const first = blocks[0];
    const last = blocks[blocks.length - 1];
    out.push(
      `The source address was blocked ${first.automatic ? 'automatically by the system' : `by ${first.administrator ?? 'an administrator'}`} at ${formatUtc(first.createdAt)}.`,
    );
    if (blocks.length > 1) {
      out.push(`The block was renewed ${plural(blocks.length - 1, 'more time')} as activity continued, most recently at ${formatUtc(last.createdAt)}.`);
    }
    // Use the most recent block that is still in force (blocks are sorted oldest first).
    const inForce = [...blocks].reverse().find((b) => b.inForce);
    if (inForce) {
      out.push(inForce.permanent
        ? 'The block is permanent.'
        : `The block is in force until ${inForce.expiresAt ? formatUtc(inForce.expiresAt) : 'further notice'}.`);
    } else if (unblocks.length === 0) {
      out.push('That block has since expired.');
    }
  }
  for (const u of unblocks) {
    out.push(`The address was unblocked by ${u.administrator ?? 'an administrator'} at ${formatUtc(u.createdAt)}.`);
  }
  if (blocks.length === 0 && unblocks.length === 0) {
    out.push(f.allowlisted
      ? 'This address is on the allowlist, so it is exempt from blocking.'
      : 'No block has been applied to this address.');
  }
  return out;
}

function handlingSentences(f: IncidentFacts): string[] {
  const out: string[] = [];
  const attached = f.timeline.filter((t) => t.action === 'event.attached').length;
  if (attached > 0) out.push(`${plural(attached, 'further related event')} ${attached === 1 ? 'was' : 'were'} linked to this incident automatically.`);
  out.push(f.incident.assignee
    ? `The incident is assigned to ${f.incident.assignee}.`
    : 'The incident has not been assigned to anyone.');
  for (const t of f.timeline.filter((x) => x.action.startsWith('status.'))) {
    const status = t.action.slice('status.'.length);
    out.push(`${formatUtc(t.at)}: marked as ${statusLabel(status)} by ${t.actor ?? 'a user'}.`);
  }
  return out;
}

function currentStatusText(f: IncidentFacts): string {
  const i = f.incident;
  const parts: string[] = [];
  switch (i.status) {
    case 'OPEN':
      parts.push(i.assignee
        ? `Open. It is assigned to ${i.assignee} but nobody has marked it as being investigated yet.`
        : 'Open. Nobody has started investigating yet.');
      break;
    case 'INVESTIGATING':
      parts.push(`Under investigation${i.assignee ? ` by ${i.assignee}` : ''}.`);
      break;
    case 'CONTAINED':
      parts.push('Contained. The threat has been stopped, but the incident has not been closed yet.');
      break;
    case 'RESOLVED':
      parts.push(`Resolved${i.resolvedAt ? ` on ${formatUtc(i.resolvedAt)}` : ''}.`);
      break;
    case 'FALSE_POSITIVE':
      parts.push(`Closed as a false alarm${i.resolvedAt ? ` on ${formatUtc(i.resolvedAt)}` : ''}.`);
      break;
    default:
      parts.push(`Status: ${i.status}.`);
  }
  if (isClosed(i.status) && i.resolutionNotes) {
    parts.push(`Notes from the person who closed it: ${i.resolutionNotes.slice(0, 300)}`);
  }
  if (!isClosed(i.status)) {
    parts.push(`It was opened ${humanDuration(f.generatedAt.getTime() - i.createdAt.getTime())} ago.`);
  }
  const last = f.activity.lastEventAt;
  if (last) {
    const sinceMs = f.generatedAt.getTime() - last.getTime();
    const subject = f.scope === 'ip' ? 'from this address' : 'in this incident';
    parts.push(sinceMs <= STILL_ACTIVE_MS
      ? `Activity ${subject} is still ongoing; the latest event was ${humanDuration(sinceMs)} ago.`
      : `No further activity ${subject} has been recorded since ${formatUtc(last)}.`);
  }
  return parts.join(' ');
}

function recommendedActions(f: IncidentFacts): string[] {
  const i = f.incident;
  if (isClosed(i.status)) {
    return ['No further action is needed unless the activity returns.'];
  }
  const out: string[] = [];
  if (!i.assignee) out.push('Assign this incident to a named person so it has an owner.');
  out.push(...narrativeOf(f).actions(f));

  const inForce = f.blocks.some((b) => b.action === 'BLOCK' && b.inForce);
  const level = riskLevelFor(peakRiskOf(f));
  if (f.scope === 'ip' && !inForce && !f.allowlisted && (level === 'HIGH' || level === 'CRITICAL')) {
    out.push('Consider blocking the source address.');
  }
  if (inForce) {
    out.push('Confirm the PishonMarket website is enforcing the blocklist. This system records blocks but cannot see whether the website applied them.');
  }
  if (i.status === 'OPEN') out.push('Mark the incident as under investigation once someone starts looking at it.');
  return Array.from(new Set(out));
}

function evidenceOf(f: IncidentFacts): EvidenceItem[] {
  const a = f.activity;
  const ev: EvidenceItem[] = [];
  if (f.incident.sourceIp) ev.push({ label: 'Source address', value: f.incident.sourceIp });
  if (f.scope === 'account') ev.push({ label: 'Targeted', value: 'One account (identified in the technical report)' });
  if (a.firstEventAt && a.lastEventAt) {
    ev.push({
      label: 'Activity period',
      value: formatUtc(a.firstEventAt) === formatUtc(a.lastEventAt)
        ? formatUtc(a.firstEventAt)
        : `${formatUtc(a.firstEventAt)} to ${formatUtc(a.lastEventAt)}`,
    });
  }
  if (f.scope === 'ip') {
    ev.push({ label: 'Events recorded from this address', value: String(a.totalEvents) });
  } else {
    ev.push({ label: 'Events recorded', value: String(a.totalEvents) });
    ev.push({ label: 'Different source addresses', value: String(a.distinctIps) });
  }
  if (a.failedLogins > 0) ev.push({ label: 'Failed login attempts', value: String(a.failedLogins) });
  if (a.failedLogins > 0) ev.push({ label: 'Accounts targeted', value: String(a.distinctUsersFailed) });
  if (f.signals.loginSuccessReported) {
    ev.push({ label: f.scope === 'ip' ? 'Successful logins from this address' : 'Successful logins', value: String(a.successfulLogins) });
  }
  if (a.passwordResets > 0) ev.push({ label: 'Password reset requests', value: String(a.passwordResets) });
  if (a.paymentEvents > 0) ev.push({ label: 'Payment security events', value: String(a.paymentEvents) });
  if (a.sessionAnomalies > 0) ev.push({ label: 'Session anomaly events', value: String(a.sessionAnomalies) });
  if (a.adminAccesses > 0) ev.push({ label: 'Administrative area accesses', value: String(a.adminAccesses) });

  if (a.rulesFired.length > 0) {
    ev.push({
      label: 'Warning signs detected',
      value: a.rulesFired.map((r) => `${ruleTitle(r.code, r.name)} (${plural(r.events, 'event')})`).join('; '),
    });
  }

  const ip = f.ip;
  if (ip) {
    const place = [ip.city, ip.region, ip.country].filter(Boolean).join(', ');
    if (place) ev.push({ label: 'Approximate location', value: place });
    if (ip.intelligenceChecked) {
      const flags: string[] = [];
      if (ip.isTor) flags.push('Tor network');
      if (ip.isProxy) flags.push('proxy');
      if (ip.isVpn) flags.push('VPN');
      if (ip.isDatacenter) flags.push('data center / hosting');
      ev.push({ label: 'Network type', value: flags.length ? flags.join(', ') : 'No anonymizing or hosting network detected' });
      if (ip.isMalicious) ev.push({ label: 'Reputation', value: `Listed as malicious (score ${ip.reputationScore} out of 100)` });
      else if (ip.reputationScore > 0) ev.push({ label: 'Reputation score', value: `${ip.reputationScore} out of 100 (higher means more abuse reported)` });
    }
  }
  return ev;
}

function limitationsOf(f: IncidentFacts): string[] {
  const a = f.activity;
  const out: string[] = [];
  out.push(`Activity is counted from ${f.window.lookbackMinutes} minutes before the incident was opened.`);
  if (f.intelProviders.length === 0) {
    out.push('No IP intelligence provider is configured, so this report cannot say whether the address uses a VPN, proxy or Tor, or has a bad reputation.');
  }
  if (a.failedLogins > 0 && !f.signals.loginSuccessReported) {
    out.push('The website has not reported any successful logins recently, so this report cannot say whether any of the attempts succeeded.');
  }
  if (a.totalEvents > 0 && a.eventsWithRuleData < a.totalEvents) {
    out.push(`Detection details were saved for ${a.eventsWithRuleData} of ${a.totalEvents} events, so counts of warning signs may understate what happened.`);
  }
  if (a.sampled) {
    out.push('Some figures were read from the most recent events only, because the incident involves a very large number of events.');
  }
  if (f.blocks.some((b) => b.action === 'BLOCK')) {
    out.push('This system records blocks but cannot confirm that the website actually rejected traffic from the address.');
  }
  if (f.incident.riskScore < a.peakRisk) {
    out.push(`The risk score stored on the incident (${f.incident.riskScore}) is lower than the highest score seen on its events (${a.peakRisk}). This report uses the higher figure.`);
  }
  return out;
}

export function buildIncidentReport(f: IncidentFacts): IncidentReport {
  const n = narrativeOf(f);
  const peak = peakRiskOf(f);
  const level = riskLevelFor(peak);
  const t = riskThresholds();

  const primary = f.incident.detectionRule;
  const others = f.activity.rulesFired
    .filter((r) => r.code !== primary)
    .map((r) => ruleTitle(r.code, r.name).toLowerCase());

  let what = n.what(f);
  if (others.length > 0) what += ` Other warning signs were also detected: ${joinList(others)}.`;

  return {
    kind: 'incident',
    generatedAt: f.generatedAt.toISOString(),
    incidentId: f.incident.incidentId,
    headline: n.headline(f),
    severity: f.incident.severity,
    status: f.incident.status,
    sections: {
      whatHappened: what,
      whyItMatters: n.why,
      riskLevel: {
        level,
        score: peak,
        explanation:
          `The highest risk score recorded was ${peak} out of 100, which the system rates as ${level.toLowerCase()}. ${LEVEL_MEANING[level]} ` +
          `(Ratings: suspicious from ${t.suspicious}, high from ${t.high}, critical from ${t.critical}.)`,
      },
      evidence: evidenceOf(f),
      actionTaken: [...blockSentences(f), ...handlingSentences(f)],
      currentStatus: currentStatusText(f),
      recommendedActions: recommendedActions(f),
    },
    limitations: limitationsOf(f),
  };
}

/** One short sentence for lists and the executive summary. */
export function summarizeIncident(f: IncidentFacts): string {
  const n = narrativeOf(f);
  const blocked = f.blocks.some((b) => b.action === 'BLOCK' && b.inForce);
  const everBlocked = f.blocks.some((b) => b.action === 'BLOCK');
  const blockClause = f.scope !== 'ip'
    ? `${plural(f.activity.distinctIps, 'address', 'addresses')} involved.`
    : blocked ? 'The address is blocked.' : everBlocked ? 'The address was blocked earlier.' : 'No block applied.';
  return `${n.headline(f)}. ${plural(f.activity.totalEvents, 'event')} recorded. ${blockClause}`;
}

/** Plain text rendering for email, printing or a PDF generator. */
export function renderIncidentReportText(r: IncidentReport): string {
  const s = r.sections;
  const lines: string[] = [];
  lines.push(`INCIDENT REPORT ${r.incidentId}`);
  lines.push(r.headline);
  lines.push(`Severity: ${severityWord(r.severity)}    Status: ${capitalize(statusLabel(r.status))}`);
  lines.push(`Generated: ${formatUtc(new Date(r.generatedAt))}`, '');
  lines.push('WHAT HAPPENED', s.whatHappened, '');
  lines.push('WHY IT MATTERS', s.whyItMatters, '');
  lines.push(`RISK LEVEL: ${s.riskLevel.level} (${s.riskLevel.score}/100)`, s.riskLevel.explanation, '');
  lines.push('EVIDENCE', ...s.evidence.map((e) => `- ${e.label}: ${e.value}`), '');
  lines.push('ACTION TAKEN', ...s.actionTaken.map((x) => `- ${x}`), '');
  lines.push('CURRENT STATUS', s.currentStatus, '');
  lines.push('RECOMMENDED ACTION', ...s.recommendedActions.map((x) => `- ${x}`), '');
  if (r.limitations.length) lines.push('WHAT THIS REPORT CANNOT CONFIRM', ...r.limitations.map((x) => `- ${x}`));
  return lines.join('\n');
}

export function buildTechnicalReport(f: IncidentFacts): TechnicalReport {
  const a = f.activity;
  const i = f.incident;
  const notes: string[] = [
    'Counts cover events from the source address inside the stated window, read directly from security_events.',
  ];
  if (a.sampled) notes.push('Rule and path detail were read from a capped sample of the most recent events.');
  if (a.eventsWithRuleData < a.totalEvents) notes.push('Events recorded before rule persistence was added carry no rule detail.');
  notes.push('Request paths have query strings removed.');

  return {
    kind: 'technical',
    generatedAt: f.generatedAt.toISOString(),
    incidentId: i.incidentId,
    incident: {
      id: i.id, title: i.title, severity: i.severity, status: i.status, scope: f.scope, userId: i.userId,
      storedRiskScore: i.riskScore, peakEventRisk: a.peakRisk, effectiveRisk: peakRiskOf(f),
      effectiveRiskLevel: riskLevelFor(peakRiskOf(f)),
      detectionRule: i.detectionRule, sourceIp: i.sourceIp, assignee: i.assignee,
      createdAt: i.createdAt.toISOString(), updatedAt: i.updatedAt.toISOString(),
      resolvedAt: i.resolvedAt?.toISOString() ?? null, resolutionNotes: i.resolutionNotes,
    },
    window: { from: f.window.from.toISOString(), to: f.window.to.toISOString(), lookbackMinutes: f.window.lookbackMinutes },
    activity: {
      totalEvents: a.totalEvents, attachedEvents: a.attachedEvents,
      distinctIps: a.distinctIps, topIps: a.topIps,
      firstEventAt: a.firstEventAt?.toISOString() ?? null, lastEventAt: a.lastEventAt?.toISOString() ?? null,
      byType: a.byType, failedLogins: a.failedLogins, successfulLogins: a.successfulLogins,
      distinctUsersFailed: a.distinctUsersFailed, passwordResets: a.passwordResets,
      paymentEvents: a.paymentEvents, sessionAnomalies: a.sessionAnomalies, adminAccesses: a.adminAccesses,
      topPaths: a.topPaths, eventsWithRuleData: a.eventsWithRuleData, sampled: a.sampled,
    },
    rulesFired: a.rulesFired.map((r) => ({
      code: r.code, name: r.name, events: r.events, maxRiskDelta: r.maxRiskDelta, lastReason: r.lastReason ?? null,
    })),
    ip: f.ip && {
      address: f.ip.address, isPrivate: f.ip.isPrivate,
      country: f.ip.country, region: f.ip.region, city: f.ip.city,
      isVpn: f.ip.isVpn, isProxy: f.ip.isProxy, isTor: f.ip.isTor, isDatacenter: f.ip.isDatacenter,
      isMalicious: f.ip.isMalicious, reputationScore: f.ip.reputationScore,
      intelligenceChecked: f.ip.intelligenceChecked, providers: f.intelProviders,
      firstSeenAt: f.ip.firstSeenAt?.toISOString() ?? null, lifetimeEvents: f.ip.lifetimeEvents,
    },
    blocks: f.blocks.map((b) => ({
      action: b.action, createdAt: b.createdAt.toISOString(), automatic: b.automatic,
      permanent: b.permanent, expiresAt: b.expiresAt?.toISOString() ?? null, inForce: b.inForce,
      reason: b.reason, administrator: b.administrator,
    })),
    allowlisted: f.allowlisted,
    timeline: f.timeline.map((t) => ({
      at: t.at.toISOString(), action: t.action, actor: t.actor, details: t.details,
    })),
    notes,
  };
}
