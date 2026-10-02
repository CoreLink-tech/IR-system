import {
  buildIncidentReport, buildTechnicalReport, renderIncidentReportText, summarizeIncident,
} from '../src/reports/incident-report.builder';
import { buildExecutiveSummary, postureOf, renderExecutiveSummaryText } from '../src/reports/executive-summary.builder';
import { describeSpan, humanDuration, stripQuery, joinList } from '../src/reports/language';
import { IncidentFacts, PeriodFacts } from '../src/reports/report.types';

const T0 = new Date('2026-10-02T14:02:00Z');
const T1 = new Date('2026-10-02T14:09:00Z');
const NOW = new Date('2026-10-02T14:10:00Z');

function facts(over: Partial<IncidentFacts> = {}, act: Partial<IncidentFacts['activity']> = {}): IncidentFacts {
  const base: IncidentFacts = {
    generatedAt: NOW,
    incident: {
      id: 'i1', incidentId: 'INC-1', title: 'Credential stuffing suspected', severity: 'HIGH', status: 'OPEN',
      riskScore: 35, detectionRule: 'brute_force_login', sourceIp: '198.51.100.7',
      createdAt: new Date('2026-10-02T14:05:00Z'), updatedAt: T1, resolvedAt: null, resolutionNotes: null, assignee: null,
    },
    rule: { code: 'brute_force_login', name: 'Brute-force login', description: 'x' },
    window: { from: new Date('2026-10-02T13:05:00Z'), to: NOW, lookbackMinutes: 60 },
    activity: {
      totalEvents: 7, firstEventAt: T0, lastEventAt: T1,
      byType: [{ type: 'login_failed', count: 7 }],
      failedLogins: 7, successfulLogins: 0, distinctUsersFailed: 7,
      passwordResets: 0, paymentEvents: 0, sessionAnomalies: 0, adminAccesses: 0,
      attachedEvents: 3, peakRisk: 100, topPaths: [{ path: '/login', count: 7 }],
      rulesFired: [
        { code: 'brute_force_login', name: 'Brute-force login', events: 3, maxRiskDelta: 56 },
        { code: 'credential_stuffing', name: 'Credential stuffing', events: 4, maxRiskDelta: 35 },
      ],
      eventsWithRuleData: 7, sampled: false, ...act,
    },
    signals: { loginSuccessReported: true },
    ip: {
      address: '198.51.100.7', isPrivate: false, country: 'Nigeria', region: null, city: 'Lagos',
      isVpn: false, isProxy: false, isTor: false, isDatacenter: false, isMalicious: false,
      reputationScore: 0, intelligenceChecked: true, firstSeenAt: T0, lifetimeEvents: 7,
    },
    intelProviders: ['tor', 'ipapi'],
    blocks: [], allowlisted: false, timeline: [],
  };
  return { ...base, ...over };
}

describe('language helpers', () => {
  it('describes spans', () => {
    expect(describeSpan(T0, T1)).toBe('between 14:02 and 14:09 UTC on 2 Oct 2026');
    expect(describeSpan(T0, T0)).toBe('at 14:02 UTC on 2 Oct 2026');
    expect(describeSpan(null, null)).toBe('during the monitored period');
  });
  it('formats durations and lists', () => {
    expect(humanDuration(20_000)).toBe('less than a minute');
    expect(humanDuration(5 * 60_000)).toBe('5 minutes');
    expect(humanDuration(3 * 3600_000)).toBe('3 hours');
    expect(joinList(['a', 'b', 'c'])).toBe('a, b and c');
  });
  it('strips query strings so tokens never reach a report', () => {
    expect(stripQuery('/reset?token=abc123&u=1')).toBe('/reset');
    expect(stripQuery('/a#frag')).toBe('/a');
  });
});

describe('incident report', () => {
  it('states only verified numbers and names every section', () => {
    const r = buildIncidentReport(facts());
    expect(r.sections.whatHappened).toContain('7 failed login attempts');
    expect(r.sections.whatHappened).toContain('198.51.100.7');
    expect(r.sections.whatHappened).toContain('7 different accounts');
    expect(r.sections.whatHappened).toContain('No successful logins from this address were recorded');
    expect(r.sections.whatHappened).toContain('Other warning signs were also detected: login attempts across many accounts');
    expect(r.sections.whyItMatters.length).toBeGreaterThan(20);
    expect(r.sections.currentStatus).toContain('Nobody has started investigating');
  });

  it('uses the highest recorded risk, not the stale incident score', () => {
    const r = buildIncidentReport(facts());
    expect(r.sections.riskLevel.score).toBe(100);
    expect(r.sections.riskLevel.level).toBe('CRITICAL');
    expect(r.limitations.join(' ')).toContain('lower than the highest score');
  });

  it('does not talk about login outcomes when the website never reports successes', () => {
    const r = buildIncidentReport(facts({ signals: { loginSuccessReported: false } }));
    expect(r.sections.whatHappened).not.toContain('successful logins');
    expect(r.sections.evidence.find((e) => e.label.startsWith('Successful'))).toBeUndefined();
    expect(r.limitations.join(' ')).toContain('cannot say whether any of the attempts succeeded');
  });

  it('warns clearly when logins from the address succeeded', () => {
    const r = buildIncidentReport(facts({}, { successfulLogins: 2 }));
    expect(r.sections.whatHappened).toContain('2 successful logins');
    expect(r.sections.whatHappened).toContain('may have been accessed');
    expect(r.sections.recommendedActions.join(' ')).toContain('Review the accounts that logged in');
  });

  it('never claims network type when no provider is configured', () => {
    const r = buildIncidentReport(facts({
      intelProviders: [],
      ip: { ...facts().ip!, intelligenceChecked: false },
    }));
    expect(r.sections.evidence.find((e) => e.label === 'Network type')).toBeUndefined();
    expect(r.limitations.join(' ')).toContain('No IP intelligence provider is configured');
  });

  it('describes an automatic block that is in force', () => {
    const r = buildIncidentReport(facts({
      blocks: [{
        action: 'BLOCK', createdAt: new Date('2026-10-02T14:08:00Z'), automatic: true, permanent: false,
        expiresAt: new Date('2026-10-02T15:08:00Z'), inForce: true, reason: 'x', administrator: null,
      }, {
        action: 'BLOCK', createdAt: new Date('2026-10-02T14:09:00Z'), automatic: true, permanent: false,
        expiresAt: new Date('2026-10-02T15:09:00Z'), inForce: true, reason: 'x', administrator: null,
      }],
    }));
    const text = r.sections.actionTaken.join(' ');
    expect(text).toContain('blocked automatically by the system at 2 Oct 2026, 14:08 UTC');
    expect(text).toContain('renewed 1 more time');
    expect(text).toContain('in force until 2 Oct 2026, 15:09 UTC');
    expect(r.limitations.join(' ')).toContain('cannot confirm that the website actually rejected');
    expect(r.sections.recommendedActions.join(' ')).toContain('Confirm the PishonMarket website is enforcing');
  });

  it('says no block was applied, and mentions the allowlist when relevant', () => {
    expect(buildIncidentReport(facts()).sections.actionTaken.join(' ')).toContain('No block has been applied');
    expect(buildIncidentReport(facts({ allowlisted: true })).sections.actionTaken.join(' ')).toContain('allowlist');
  });

  it('recommends blocking only when risk is high, unblocked, and not allowlisted', () => {
    const rec = buildIncidentReport(facts()).sections.recommendedActions.join(' ');
    expect(rec).toContain('Consider blocking the source address');
    const allow = buildIncidentReport(facts({ allowlisted: true })).sections.recommendedActions.join(' ');
    expect(allow).not.toContain('Consider blocking');
  });

  it('reports closed incidents without asking for more work', () => {
    const r = buildIncidentReport(facts({
      incident: { ...facts().incident, status: 'RESOLVED', resolvedAt: new Date('2026-10-02T15:00:00Z'), resolutionNotes: 'Reset affected passwords', assignee: 'ops@pishon.ng' },
    }));
    expect(r.sections.currentStatus).toContain('Resolved on 2 Oct 2026, 15:00 UTC');
    expect(r.sections.currentStatus).toContain('Reset affected passwords');
    expect(r.sections.recommendedActions).toEqual(['No further action is needed unless the activity returns.']);
  });

  it('flags ongoing versus finished activity from real timestamps', () => {
    const live = buildIncidentReport(facts({}, { lastEventAt: new Date(NOW.getTime() - 2 * 60_000) }));
    expect(live.sections.currentStatus).toContain('still ongoing');
    const quiet = buildIncidentReport(facts({}, { lastEventAt: new Date(NOW.getTime() - 3 * 3600_000) }));
    expect(quiet.sections.currentStatus).toContain('No further activity from this address has been recorded since');
  });

  it('is honest when rule detail is missing for older events', () => {
    const r = buildIncidentReport(facts({}, { eventsWithRuleData: 4 }));
    expect(r.limitations.join(' ')).toContain('Detection details were saved for 4 of 7 events');
  });

  it('falls back safely for rules without a custom narrative', () => {
    const r = buildIncidentReport(facts({
      incident: { ...facts().incident, detectionRule: 'custom_rule' },
      rule: { code: 'custom_rule', name: 'Odd refunds', description: 'Many refunds' },
      activity: { ...facts().activity, rulesFired: [] },
    }));
    expect(r.headline).toContain('Odd refunds');
    expect(r.sections.whatHappened).toContain('Odd refunds');
  });

  it('never leaks technical rule codes or raw risk deltas into the plain-English text', () => {
    const text = renderIncidentReportText(buildIncidentReport(facts()));
    expect(text).not.toMatch(/brute_force_login|credential_stuffing|riskDelta/);
    expect(text).toContain('WHAT HAPPENED');
    expect(text).toContain('RECOMMENDED ACTION');
  });

  it('is deterministic: same facts produce identical output', () => {
    expect(JSON.stringify(buildIncidentReport(facts()))).toBe(JSON.stringify(buildIncidentReport(facts())));
  });

  it('summarizes an incident in one short line', () => {
    expect(summarizeIncident(facts())).toBe('Repeated failed logins from 198.51.100.7. 7 events recorded. No block applied.');
  });
});

describe('narrative accuracy per rule', () => {
  const make = (code: string, act: Partial<IncidentFacts['activity']>, ipOver: Partial<NonNullable<IncidentFacts['ip']>> = {}) =>
    buildIncidentReport(facts({
      incident: { ...facts().incident, detectionRule: code },
      ip: { ...facts().ip!, ...ipOver },
    }, { rulesFired: [], ...act })).sections.whatHappened;

  it('payment abuse', () => {
    expect(make('payment_abuse_signal', { paymentEvents: 4 })).toContain('4 payment security events were recorded');
  });
  it('password reset abuse', () => {
    expect(make('password_reset_abuse', { passwordResets: 5 })).toContain('5 password reset requests');
  });
  it('admin access names the network only when intelligence says so', () => {
    expect(make('suspicious_admin_access', { adminAccesses: 2 }, { isTor: true })).toContain('Tor anonymizing network');
    expect(make('suspicious_admin_access', { adminAccesses: 2 }, { isMalicious: true })).toContain('listed as malicious');
  });
  it('suspicious payload uses the rule count when known, otherwise says at least one', () => {
    expect(make('suspicious_payload', { rulesFired: [{ code: 'suspicious_payload', name: 'x', events: 3, maxRiskDelta: 25 }] })).toContain('3 requests');
    expect(make('suspicious_payload', {})).toContain('At least one request');
  });
  it('malicious IP quotes the stored reputation score', () => {
    expect(make('known_malicious_ip', {}, { isMalicious: true, reputationScore: 92 })).toContain('reputation score of 92 out of 100');
  });
  it('tor or proxy is described as a contributing signal, not an attack', () => {
    expect(make('tor_or_proxy', {}, { isTor: true, isProxy: true })).toContain('not an attack by itself');
  });
});

describe('technical report', () => {
  it('carries raw codes, ISO dates and notes', () => {
    const t = buildTechnicalReport(facts());
    expect(t.rulesFired[0]).toMatchObject({ code: 'brute_force_login', events: 3 });
    expect((t.incident as any).effectiveRisk).toBe(100);
    expect((t.incident as any).storedRiskScore).toBe(35);
    expect(t.window.from).toBe('2026-10-02T13:05:00.000Z');
    expect(t.notes.join(' ')).toContain('query strings removed');
  });
});

function period(over: Partial<PeriodFacts> = {}, incidents: PeriodFacts['incidents'] = []): PeriodFacts {
  return {
    generatedAt: NOW, from: new Date('2026-09-25T00:00:00Z'), to: new Date('2026-10-02T00:00:00Z'),
    previous: { incidents: 0, events: 0 }, events: 120, uniqueIps: 14, incidents,
    blocks: { total: 0, automatic: 0, manual: 0, stillInForce: 0 }, intelProviders: ['tor'], ...over,
  };
}
const inc = (o: Partial<PeriodFacts['incidents'][number]> = {}): PeriodFacts['incidents'][number] => ({
  incidentId: 'INC-1', id: 'i', title: 'Repeated failed logins from 1.2.3.4', severity: 'MEDIUM', status: 'OPEN',
  riskScore: 40, sourceIp: '1.2.3.4', detectionRule: 'brute_force_login', createdAt: T0, assigned: true, summary: 'Summary.', ...o,
});

describe('executive summary', () => {
  it('quiet period is ALL_CLEAR with a clear headline', () => {
    const s = buildExecutiveSummary(period());
    expect(s.posture).toBe('ALL_CLEAR');
    expect(s.headline).toBe('No security incidents in this period.');
    expect(s.overview).toContain('120 events from 14 different addresses and opened no incidents');
  });

  it('posture rules', () => {
    expect(postureOf(period({}, [inc({ severity: 'CRITICAL', status: 'INVESTIGATING' })]))).toBe('URGENT');
    expect(postureOf(period({}, [inc({ severity: 'HIGH', status: 'OPEN' })]))).toBe('ACTION_NEEDED');
    expect(postureOf(period({}, [inc({ severity: 'LOW', status: 'OPEN', assigned: false })]))).toBe('ACTION_NEEDED');
    expect(postureOf(period({}, [inc({ severity: 'LOW', status: 'CONTAINED' })]))).toBe('MONITORING');
    expect(postureOf(period({}, [inc({ severity: 'CRITICAL', status: 'RESOLVED' })]))).toBe('ALL_CLEAR');
  });

  it('closed incidents give a reassuring headline', () => {
    const s = buildExecutiveSummary(period({}, [inc({ status: 'RESOLVED' }), inc({ incidentId: 'INC-2', status: 'FALSE_POSITIVE' })]));
    expect(s.headline).toBe('All 2 security incidents in this period have been closed.');
  });

  it('lists what needs attention, naming unassigned incidents', () => {
    const s = buildExecutiveSummary(period({}, [inc({ severity: 'HIGH', assigned: false })]));
    expect(s.needsAttention[0]).toContain('high severity, open, nobody assigned');
  });

  it('counts blocked addresses once and reports the split', () => {
    const s = buildExecutiveSummary(period({ blocks: { total: 3, automatic: 2, manual: 1, stillInForce: 1 } }));
    expect(s.overview).toContain('3 addresses were blocked (2 automatically, 1 by administrators)');
    expect(s.limitations.join(' ')).toContain('cannot confirm that the website actually rejected');
  });

  it('compares with the previous period only when there is data', () => {
    expect(buildExecutiveSummary(period()).trend).toContain('no data from the previous period');
    const t = buildExecutiveSummary(period({ previous: { incidents: 2, events: 100 }, events: 150 }, [inc(), inc({ incidentId: 'INC-2' }), inc({ incidentId: 'INC-3' }), inc({ incidentId: 'INC-4' })])).trend;
    expect(t).toContain('incidents: 4, up 100% from 2');
    expect(t).toContain('events: 150, up 50% from 100');
  });

  it('shows the most severe incidents first and caps the list at five', () => {
    const many = Array.from({ length: 8 }, (_, i) => inc({ incidentId: `INC-${i}`, severity: i === 6 ? 'CRITICAL' : 'LOW', riskScore: i }));
    const s = buildExecutiveSummary(period({}, many));
    expect(s.notableIncidents).toHaveLength(5);
    expect(s.notableIncidents[0].incidentId).toBe('INC-6');
  });

  it('renders readable text', () => {
    const text = renderExecutiveSummaryText(buildExecutiveSummary(period({}, [inc({ severity: 'HIGH' })])));
    expect(text).toContain('SECURITY SUMMARY');
    expect(text).toContain('KEY NUMBERS');
    expect(text).toContain('WHAT THIS SUMMARY CANNOT CONFIRM');
  });
});
