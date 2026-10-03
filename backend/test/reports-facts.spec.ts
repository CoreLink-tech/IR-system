import { FactsService } from '../src/reports/facts.service';

const NOW = new Date('2026-10-02T14:10:00Z');
const created = new Date('2026-10-02T14:05:00Z');

/** Minimal fake of the Prisma calls FactsService makes. */
function fakePrisma(over: any = {}) {
  const events = over.events ?? [
    { eventType: 'login_failed', userId: 'u1', requestPath: '/login?token=SECRET', riskScore: 10, occurredAt: new Date('2026-10-02T14:02:00Z'), matchedRules: [] },
    { eventType: 'login_failed', userId: 'u2', requestPath: '/login?token=SECRET2', riskScore: 60, occurredAt: new Date('2026-10-02T14:03:00Z'),
      matchedRules: [{ code: 'brute_force_login', riskDelta: 40, reason: '5 failed logins in 10 min' }] },
    { eventType: 'login_failed', userId: 'u2', requestPath: '/login', riskScore: 75, occurredAt: new Date('2026-10-02T14:04:00Z'),
      matchedRules: [{ code: 'brute_force_login', riskDelta: 48, reason: '6 failed logins in 10 min' }] },
    { eventType: 'login_success', userId: 'u2', requestPath: '/login', riskScore: 0, occurredAt: new Date('2026-10-02T14:06:00Z'), matchedRules: null },
  ];
  return {
    securityIncident: {
      findFirst: async () => ({
        id: 'i1', incidentId: 'INC-1', title: 't', severity: 'HIGH', status: 'OPEN', riskScore: 35,
        detectionRule: 'brute_force_login', sourceIp: '198.51.100.7', createdAt: created, updatedAt: created,
        resolvedAt: null, resolutionNotes: null, assignedTo: null, assignee: null,
      }),
    },
    securityEvent: {
      count: async ({ where }: any) => {
        if (where.eventType === 'login_success') return 1;
        return where.incidentId ? 2 : events.length;
      },
      aggregate: async ({ _max }: any) => _max?.riskScore
        ? { _max: { riskScore: Math.max(...events.map((e: any) => e.riskScore)) } }
        : { _min: { occurredAt: events[0].occurredAt }, _max: { occurredAt: events[events.length - 1].occurredAt } },
      groupBy: async ({ by }: any) => {
        if (by[0] === 'ipAddress') return [{ ipAddress: '198.51.100.7', _count: { _all: events.length } }];
        const m = new Map<string, number>();
        events.forEach((e: any) => m.set(e.eventType, (m.get(e.eventType) ?? 0) + 1));
        return Array.from(m.entries()).map(([eventType, n]) => ({ eventType, _count: { _all: n } }));
      },
      findMany: async ({ where, select }: any) => {
        if (select?.userId) return [{ userId: 'u1' }, { userId: 'u2' }];
        return events.map((e: any) => ({ requestPath: e.requestPath, matchedRules: e.matchedRules }));
      },
    },
    securityIp: { findUnique: async () => ({ country: 'NG', region: null, city: 'Lagos', isVpn: false, isProxy: false, isTor: true,
      isDatacenter: false, isMalicious: false, reputationScore: 0, lastIntelUpdate: NOW, firstSeenAt: created }) },
    securityIpAllowlist: { findUnique: async () => null },
    securityIpBlock: {
      findMany: async () => over.blocks ?? [
        { action: 'BLOCK', createdAt: created, automatic: true, isPermanent: false, expiresAt: new Date('2026-10-02T15:05:00Z'), active: true, reason: 'r', administrator: null },
        { action: 'BLOCK', createdAt: new Date('2026-10-02T13:30:00Z'), automatic: false, isPermanent: false, expiresAt: new Date('2026-10-02T13:40:00Z'), active: false, reason: 'old', administrator: { email: 'a@b.c' } },
      ],
    },
    securityIncidentTimeline: { findMany: async () => [{ createdAt: created, action: 'incident.created', actor: 'system', details: 'x' }] },
    securityRule: {
      findUnique: async () => ({ code: 'brute_force_login', name: 'Brute-force login', description: 'd' }),
      findMany: async () => [{ code: 'brute_force_login', name: 'Brute-force login' }],
    },
  } as any;
}

const intel = (providers: string[]) => ({ providerNames: providers } as any);

describe('FactsService', () => {
  it('aggregates verified counts and rule detail from stored data', async () => {
    const f = await new FactsService(fakePrisma(), intel(['tor'])).gatherIncidentFacts('i1', NOW);
    expect(f.activity.totalEvents).toBe(4);
    expect(f.activity.failedLogins).toBe(3);
    expect(f.activity.successfulLogins).toBe(1);
    expect(f.activity.distinctUsersFailed).toBe(2);
    expect(f.activity.peakRisk).toBe(75);
    expect(f.activity.rulesFired).toEqual([
      { code: 'brute_force_login', name: 'Brute-force login', events: 2, maxRiskDelta: 48, lastReason: '5 failed logins in 10 min' },
    ]);
  });

  it('treats an empty rule array as data and null as missing data', async () => {
    const f = await new FactsService(fakePrisma(), intel([])).gatherIncidentFacts('i1', NOW);
    // Three events carry an array (one empty); the login_success row carries null.
    expect(f.activity.eventsWithRuleData).toBe(3);
  });

  it('removes query strings from paths so tokens never reach a report', async () => {
    const f = await new FactsService(fakePrisma(), intel([])).gatherIncidentFacts('i1', NOW);
    expect(f.activity.topPaths).toEqual([{ path: '/login', count: 4 }]);
    expect(JSON.stringify(f)).not.toContain('SECRET');
  });

  it('computes whether a block is really in force, ignoring the stored flag alone', async () => {
    const f = await new FactsService(fakePrisma(), intel([])).gatherIncidentFacts('i1', NOW);
    expect(f.blocks.map((b) => b.inForce)).toEqual([true, false]);
    expect(f.blocks[1].administrator).toBe('a@b.c');
    const stale = await new FactsService(fakePrisma({
      blocks: [{ action: 'BLOCK', createdAt: created, automatic: true, isPermanent: false, expiresAt: new Date('2026-10-02T14:06:00Z'), active: true, reason: 'r', administrator: null }],
    }), intel([])).gatherIncidentFacts('i1', NOW);
    expect(stale.blocks[0].inForce).toBe(false);
  });

  it('only trusts stored intelligence flags when a provider is configured', async () => {
    const withProvider = await new FactsService(fakePrisma(), intel(['tor'])).gatherIncidentFacts('i1', NOW);
    expect(withProvider.ip!.intelligenceChecked).toBe(true);
    const without = await new FactsService(fakePrisma(), intel([])).gatherIncidentFacts('i1', NOW);
    expect(without.ip!.intelligenceChecked).toBe(false);
  });

  it('reports whether the website sends login_success events at all', async () => {
    const f = await new FactsService(fakePrisma(), intel([])).gatherIncidentFacts('i1', NOW);
    expect(f.signals.loginSuccessReported).toBe(true);
  });

  it('uses a window that starts before the incident and ends now while open', async () => {
    const f = await new FactsService(fakePrisma(), intel([])).gatherIncidentFacts('i1', NOW);
    expect(f.window.from.toISOString()).toBe('2026-10-02T13:05:00.000Z');
    expect(f.window.to).toEqual(NOW);
  });
});
