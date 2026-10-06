import { BUILT_IN_RULES, RuleContext, sameCountry } from '../src/detection/rules';
import { IncidentsService } from '../src/incidents/incidents.service';
import { BlockingService } from '../src/blocking/blocking.service';
import { DetectionService } from '../src/detection/detection.service';

const rule = (code: string) => BUILT_IN_RULES.find((r) => r.code === code)!;
const run = (code: string, ctx: RuleContext, cfg?: any) => rule(code).evaluate(ctx, cfg ?? rule(code).defaultConfig);

function ctx(eventType: string, stats: Partial<RuleContext['stats']> = {}, event: Partial<RuleContext['event']> = {}): RuleContext {
  return {
    event: {
      id: 'e1', eventType, severity: 'INFO', ipAddress: '198.51.100.7', userId: 'u1', sessionId: null,
      requestPath: null, metadata: null, occurredAt: new Date(), ...event,
    },
    stats: {
      failedLoginsLastWindow: 0, eventsLastWindow: 0, distinctUsersLastWindow: 0, passwordResetsLastWindow: 0, ...stats,
    },
  };
}
const corr = (o: Partial<NonNullable<RuleContext['stats']['correlation']>> = {}) => ({
  userFailedLogins: 0, userFailedFromIps: 0, globalFailedLogins: 0, globalFailedFromIps: 0, ...o,
});

describe('sameCountry', () => {
  it('compares like with like', () => {
    expect(sameCountry('NG', 'ng')).toBe(true);
    expect(sameCountry('NG', 'US')).toBe(false);
    expect(sameCountry('Nigeria', 'Ghana')).toBe(false);
  });
  it('refuses to compare a code with a name, or unknown values', () => {
    expect(sameCountry('NG', 'Nigeria')).toBeNull();
    expect(sameCountry(undefined, 'NG')).toBeNull();
    expect(sameCountry('NG', null)).toBeNull();
  });
});

describe('possible_account_takeover', () => {
  it('fires on a login success after enough failures on the same account', () => {
    const r = run('possible_account_takeover', ctx('login_success', { correlation: corr({ userFailedLogins: 5, userFailedFromIps: 2 }) }));
    expect(r).toMatchObject({ matched: true, createIncident: true, incidentSeverity: 'HIGH' });
    expect(r.reason).toBe('Successful login after 5 failed logins on the same account from 2 addresses');
  });
  it('is critical only for many failures from several addresses', () => {
    expect(run('possible_account_takeover', ctx('login_success', { correlation: corr({ userFailedLogins: 12, userFailedFromIps: 4 }) })).incidentSeverity).toBe('CRITICAL');
  });
  it('treats many failures from a single address as HIGH, not critical (a customer mistyping their own password)', () => {
    const r = run('possible_account_takeover', ctx('login_success', { correlation: corr({ userFailedLogins: 15, userFailedFromIps: 1 }) }));
    expect(r.incidentSeverity).toBe('HIGH');
  });
  it('scores high enough to be rated HIGH on its own but never auto-blocks by itself', () => {
    const r = run('possible_account_takeover', ctx('login_success', { correlation: corr({ userFailedLogins: 5, userFailedFromIps: 2 }) }));
    expect(r.riskDelta).toBe(65);
    expect(r.riskDelta).toBeGreaterThanOrEqual(60);
    expect(r.riskDelta).toBeLessThan(85);
  });
  it('stays quiet below the threshold, for other events, and without an account', () => {
    expect(run('possible_account_takeover', ctx('login_success', { correlation: corr({ userFailedLogins: 2 }) })).matched).toBe(false);
    expect(run('possible_account_takeover', ctx('login_failed', { correlation: corr({ userFailedLogins: 9 }) })).matched).toBe(false);
    expect(run('possible_account_takeover', ctx('login_success', { correlation: corr({ userFailedLogins: 9 }) }, { userId: null })).matched).toBe(false);
    expect(run('possible_account_takeover', ctx('login_success')).matched).toBe(false);
  });
});

describe('distributed_account_attack', () => {
  it('fires when one account is hit from enough different addresses, scoped to the account', () => {
    const r = run('distributed_account_attack', ctx('login_failed', { correlation: corr({ userFailedLogins: 6, userFailedFromIps: 4 }) }));
    expect(r).toMatchObject({ matched: true, incidentScope: 'account', incidentSeverity: 'HIGH' });
  });
  it('does not fire for many attempts from few addresses (that is brute force)', () => {
    expect(run('distributed_account_attack', ctx('login_failed', { correlation: corr({ userFailedLogins: 30, userFailedFromIps: 2 }) })).matched).toBe(false);
  });
});

describe('distributed_login_attack', () => {
  it('needs both enough addresses and enough attempts, and is scoped globally', () => {
    const hit = run('distributed_login_attack', ctx('login_failed', { correlation: corr({ globalFailedLogins: 60, globalFailedFromIps: 20 }) }));
    expect(hit).toMatchObject({ matched: true, incidentScope: 'global', incidentSeverity: 'HIGH' });
    expect(run('distributed_login_attack', ctx('login_failed', { correlation: corr({ globalFailedLogins: 60, globalFailedFromIps: 5 }) })).matched).toBe(false);
    expect(run('distributed_login_attack', ctx('login_failed', { correlation: corr({ globalFailedLogins: 10, globalFailedFromIps: 20 }) })).matched).toBe(false);
  });
  it('is critical for a very wide attack', () => {
    expect(run('distributed_login_attack', ctx('login_failed', { correlation: corr({ globalFailedLogins: 300, globalFailedFromIps: 80 }) })).incidentSeverity).toBe('CRITICAL');
  });
});

describe('impossible_travel', () => {
  const travel = (prevCountry: string | undefined, nowCountry: string | undefined) =>
    run('impossible_travel', ctx('login_success', {
      ipIntel: nowCountry ? { isVpn: false, isProxy: false, isTor: false, isDatacenter: false, isMalicious: false, reputationScore: 0, country: nowCountry } : undefined,
      correlation: corr({ previousLogin: { ipAddress: '203.0.113.9', country: prevCountry, minutesAgo: 35 } }),
    }));
  it('fires for different, comparable countries', () => {
    const r = travel('NG', 'US');
    expect(r).toMatchObject({ matched: true, createIncident: true });
    expect(r.reason).toBe('Logins from NG and US 35 min apart');
  });
  it('never fires on same country, unknown country, or mismatched formats', () => {
    expect(travel('NG', 'NG').matched).toBe(false);
    expect(travel(undefined, 'US').matched).toBe(false);
    expect(travel('NG', undefined).matched).toBe(false);
    expect(travel('Nigeria', 'US').matched).toBe(false);
  });
});

describe('existing rules (regression coverage)', () => {
  it('brute force fires at the threshold and scales risk with attempts', () => {
    expect(run('brute_force_login', ctx('login_failed', { failedLoginsLastWindow: 4 })).matched).toBe(false);
    const r = run('brute_force_login', ctx('login_failed', { failedLoginsLastWindow: 5 }));
    expect(r).toMatchObject({ matched: true, riskDelta: 40, createIncident: true, incidentSeverity: 'MEDIUM' });
    expect(run('brute_force_login', ctx('login_failed', { failedLoginsLastWindow: 25 }))).toMatchObject({ riskDelta: 70, incidentSeverity: 'CRITICAL' });
  });
  it('suspicious payload matches common injection markers only', () => {
    expect(run('suspicious_payload', ctx('page_view', {}, { requestPath: '/search?q=<script>alert(1)</script>' })).matched).toBe(true);
    expect(run('suspicious_payload', ctx('page_view', {}, { requestPath: '/files/../../etc/passwd' })).matched).toBe(true);
    expect(run('suspicious_payload', ctx('page_view', {}, { requestPath: '/products/shoes' })).matched).toBe(false);
  });
  it('tor, proxy and vpn add their own configured risk', () => {
    const intel = { isVpn: true, isProxy: true, isTor: true, isDatacenter: false, isMalicious: false, reputationScore: 0 };
    expect(run('tor_or_proxy', ctx('page_view', { ipIntel: intel })).riskDelta).toBe(32);
    expect(run('tor_or_proxy', ctx('page_view', { ipIntel: { ...intel, isTor: false, isProxy: false } })).riskDelta).toBe(4);
    expect(run('tor_or_proxy', ctx('page_view', { ipIntel: { ...intel, isTor: false, isProxy: false, isVpn: false } })).matched).toBe(false);
  });
  it('every rule has a unique code and a positive priority', () => {
    const codes = BUILT_IN_RULES.map((r) => r.code);
    expect(new Set(codes).size).toBe(codes.length);
    expect(BUILT_IN_RULES.every((r) => r.priority > 0)).toBe(true);
  });
});

/**
 * Fake of the incident table, enough for grouping and escalation. Like the real table it
 * refuses a second row with the same openKey (error code P2002), which is what makes
 * parallel requests converge on one incident.
 */
function incidentStore(seed: any[] = [], opts: { staleReads?: number } = {}) {
  const rows: any[] = seed.map((r, i) => ({
    id: `inc${i}`, createdAt: new Date(), updatedAt: new Date(), status: 'OPEN',
    openKey: r.openKey !== undefined ? r.openKey : (r.sourceIp ? `ip:${r.sourceIp}` : null), ...r,
  }));
  const timeline: any[] = [];
  const events: any[] = [];
  let staleReads = opts.staleReads ?? 0;
  const matches = (row: any, where: any): boolean => Object.entries(where).every(([k, v]: [string, any]) => {
    if (k === 'status') return v.in.includes(row.status);
    if (k === 'updatedAt') return v.lt ? row.updatedAt < v.lt : row.updatedAt >= v.gte;
    return row[k] === v;
  });
  const prisma: any = {
    securityIncident: {
      // staleReads simulates parallel requests that all looked before anyone had created the incident.
      findFirst: async ({ where }: any) => { if (staleReads > 0) { staleReads--; return null; } return rows.find((r) => matches(r, where)) ?? null; },
      updateMany: async ({ where, data }: any) => { const hit = rows.filter((r) => matches(r, where)); hit.forEach((r) => Object.assign(r, data)); return { count: hit.length }; },
      update: async ({ where, data }: any) => { Object.assign(rows.find((r) => r.id === where.id)!, data); },
      create: async ({ data }: any) => {
        if (data.openKey && rows.some((r) => r.openKey === data.openKey)) throw Object.assign(new Error('Unique constraint failed on openKey'), { code: 'P2002' });
        const r = { id: `inc${rows.length}`, createdAt: new Date(), updatedAt: new Date(), ...data }; rows.push(r); return r;
      },
    },
    // Releases the slot of an incident that has been quiet, WITHOUT touching its updatedAt.
    $executeRaw: async (_sql: TemplateStringsArray, key: string, cutoff: Date) => {
      rows.filter((r) => r.openKey === key && r.updatedAt < cutoff).forEach((r) => { r.openKey = null; });
      return 1;
    },
    securityIncidentTimeline: { create: async ({ data }: any) => { timeline.push(data); } },
    securityEvent: { update: async ({ where, data }: any) => { events.push({ id: where.id, ...data }); } },
  };
  const audit: any = { log: jest.fn(async () => undefined) };
  return { svc: new IncidentsService(prisma, audit), rows, timeline, events };
}

const base = {
  sourceIp: '198.51.100.7', userId: 'u1', ruleCode: 'credential_stuffing', severity: 'HIGH' as const,
  riskScore: 35, title: 'Credential stuffing suspected from 198.51.100.7', description: 'd', eventId: 'ev1',
};

describe('incident grouping and escalation', () => {
  it('opens a new incident when none is open', async () => {
    const s = incidentStore();
    const inc = await s.svc.createFromDetection(base);
    expect(inc.sourceIp).toBe('198.51.100.7');
    expect(s.rows).toHaveLength(1);
    expect(s.timeline[0].action).toBe('incident.created');
  });

  it('groups by address across different rules instead of opening a duplicate', async () => {
    const s = incidentStore([{ sourceIp: '198.51.100.7', detectionRule: 'credential_stuffing', severity: 'HIGH', riskScore: 35 }]);
    await s.svc.createFromDetection({ ...base, ruleCode: 'brute_force_login', severity: 'HIGH' });
    expect(s.rows).toHaveLength(1);
    expect(s.events[0]).toMatchObject({ id: 'ev1', incidentId: 'inc0' });
  });

  it('escalates severity, primary rule and risk when a worse event arrives, and records it', async () => {
    const s = incidentStore([{ sourceIp: '198.51.100.7', detectionRule: 'credential_stuffing', severity: 'HIGH', riskScore: 35, title: 'old' }]);
    await s.svc.createFromDetection({ ...base, ruleCode: 'brute_force_login', severity: 'CRITICAL', riskScore: 100, title: 'Brute-force login detected from 198.51.100.7' });
    expect(s.rows[0]).toMatchObject({ severity: 'CRITICAL', riskScore: 100, detectionRule: 'brute_force_login', title: 'Brute-force login detected from 198.51.100.7' });
    const esc = s.timeline.find((t) => t.action === 'incident.escalated');
    expect(esc.details).toContain('severity HIGH to CRITICAL');
    expect(esc.details).toContain('risk 35 to 100');
  });

  it('never downgrades an incident', async () => {
    const s = incidentStore([{ sourceIp: '198.51.100.7', detectionRule: 'brute_force_login', severity: 'CRITICAL', riskScore: 100 }]);
    await s.svc.createFromDetection({ ...base, severity: 'MEDIUM', riskScore: 20 });
    expect(s.rows[0]).toMatchObject({ severity: 'CRITICAL', riskScore: 100, detectionRule: 'brute_force_login' });
    expect(s.timeline.find((t) => t.action === 'incident.escalated')).toBeUndefined();
  });

  it('keeps a long attack in one incident by measuring recent activity, not age', async () => {
    const s = incidentStore([{
      sourceIp: '198.51.100.7', detectionRule: 'brute_force_login', severity: 'HIGH', riskScore: 60,
      createdAt: new Date(Date.now() - 3 * 3600_000), updatedAt: new Date(Date.now() - 2 * 60_000),
    }]);
    await s.svc.createFromDetection(base);
    expect(s.rows).toHaveLength(1);
  });

  it('opens a fresh incident once the old one has been quiet for over 30 minutes', async () => {
    const s = incidentStore([{
      sourceIp: '198.51.100.7', detectionRule: 'brute_force_login', severity: 'HIGH', riskScore: 60,
      updatedAt: new Date(Date.now() - 45 * 60_000),
    }]);
    await s.svc.createFromDetection(base);
    expect(s.rows).toHaveLength(2);
  });

  it('groups account attacks by account across many addresses, with no source address', async () => {
    const s = incidentStore();
    const a = { ...base, scope: 'account' as const, sourceIp: null, userId: 'u9', ruleCode: 'distributed_account_attack' };
    await s.svc.createFromDetection({ ...a, eventId: 'e1' });
    await s.svc.createFromDetection({ ...a, eventId: 'e2' });
    await s.svc.createFromDetection({ ...a, userId: 'u10', eventId: 'e3' });
    expect(s.rows).toHaveLength(2);
    expect(s.rows[0]).toMatchObject({ sourceIp: null, userId: 'u9' });
  });

  it('groups platform-wide attacks into one incident per rule', async () => {
    const s = incidentStore();
    const g = { ...base, scope: 'global' as const, sourceIp: null, userId: null, ruleCode: 'distributed_login_attack' };
    await s.svc.createFromDetection({ ...g, eventId: 'e1' });
    await s.svc.createFromDetection({ ...g, userId: 'someone', eventId: 'e2' });
    expect(s.rows).toHaveLength(1);
    expect(s.rows[0]).toMatchObject({ sourceIp: null, userId: null });
  });

  it('does not attach to closed or contained incidents', async () => {
    const s = incidentStore([{ sourceIp: '198.51.100.7', detectionRule: 'x', severity: 'HIGH', riskScore: 50, status: 'RESOLVED', openKey: null }]);
    await s.svc.createFromDetection(base);
    expect(s.rows).toHaveLength(2);
  });
});

describe('parallel requests from one attacker', () => {
  it('converge on a single incident even when every request looked before anyone created it', async () => {
    const s = incidentStore([], { staleReads: 12 });
    const calls = Array.from({ length: 12 }, (_, i) => s.svc.createFromDetection({ ...base, eventId: `ev${i}`, riskScore: 30 + i }));
    await Promise.all(calls);
    expect(s.rows).toHaveLength(1);
    expect(s.events).toHaveLength(12);
    expect(s.events.every((e) => e.incidentId === s.rows[0].id)).toBe(true);
    expect(s.rows[0].openKey).toBe('ip:198.51.100.7');
  });

  it('keeps the highest severity and risk whichever request finishes last', async () => {
    const s = incidentStore([], { staleReads: 3 });
    await Promise.all([
      s.svc.createFromDetection({ ...base, severity: 'HIGH', riskScore: 35 }),
      s.svc.createFromDetection({ ...base, severity: 'CRITICAL', riskScore: 100, ruleCode: 'brute_force_login' }),
      s.svc.createFromDetection({ ...base, severity: 'MEDIUM', riskScore: 10 }),
    ]);
    expect(s.rows).toHaveLength(1);
    expect(s.rows[0].riskScore).toBeGreaterThanOrEqual(35);
  });

  it('still opens separate incidents for different addresses', async () => {
    const s = incidentStore([], { staleReads: 4 });
    await Promise.all(['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4'].map((ip) => s.svc.createFromDetection({ ...base, sourceIp: ip })));
    expect(s.rows).toHaveLength(4);
  });

  it('gives a quiet incident up its slot so a new one can open', async () => {
    const s = incidentStore([{ sourceIp: '198.51.100.7', detectionRule: 'x', severity: 'HIGH', riskScore: 50, updatedAt: new Date(Date.now() - 45 * 60_000) }]);
    await s.svc.createFromDetection(base);
    expect(s.rows).toHaveLength(2);
    expect(s.rows[0].openKey).toBeNull();
    expect(s.rows[1].openKey).toBe('ip:198.51.100.7');
  });

  it('releasing a quiet incident does not make it look recently active', async () => {
    const quietSince = new Date(Date.now() - 3 * 3600_000);
    const s = incidentStore([{ sourceIp: '198.51.100.7', detectionRule: 'x', severity: 'HIGH', riskScore: 50, updatedAt: quietSince }]);
    await s.svc.createFromDetection(base);
    expect(s.rows[0].updatedAt).toEqual(quietSince);
  });

  it('gives each kind of incident its own slot', () => {
    const { openKeyFor } = require('../src/incidents/incidents.service');
    expect(openKeyFor('ip', '198.51.100.7', null, 'x')).toBe('ip:198.51.100.7');
    expect(openKeyFor('account', null, 'u9', 'distributed_account_attack')).toBe('acct:u9:distributed_account_attack');
    expect(openKeyFor('global', null, null, 'distributed_login_attack')).toBe('glob:distributed_login_attack');
  });
});

describe('closing and reopening frees and retakes the slot', () => {
  function withStatus(initial: any, rivalOpen = false) {
    const rows: any[] = [{ id: 'i1', status: 'OPEN', sourceIp: '198.51.100.7', userId: null, detectionRule: 'brute_force_login', resolvedAt: null, openKey: 'ip:198.51.100.7', ...initial }];
    if (rivalOpen) rows.push({ id: 'i2', status: 'OPEN', openKey: 'ip:198.51.100.7' });
    const prisma: any = {
      securityIncident: {
        findUnique: async ({ where }: any) => rows.find((r) => r.id === where.id) ?? null,
        update: async ({ where, data }: any) => {
          if (data.openKey && rows.some((r) => r.id !== where.id && r.openKey === data.openKey)) throw Object.assign(new Error('Unique constraint'), { code: 'P2002' });
          return Object.assign(rows.find((r) => r.id === where.id)!, data);
        },
      },
      securityIncidentTimeline: { create: async () => undefined },
    };
    return { svc: new IncidentsService(prisma, { log: jest.fn(async () => undefined) } as any), rows };
  }

  it('frees the slot when an incident is contained, resolved or closed as a false alarm', async () => {
    for (const status of ['CONTAINED', 'RESOLVED', 'FALSE_POSITIVE']) {
      const m = withStatus({});
      await m.svc.updateStatus('i1', status, undefined, 'u1', 'a');
      expect(m.rows[0].openKey).toBeNull();
    }
  });

  it('keeps the slot while an incident is only moved between open and investigating', async () => {
    const m = withStatus({});
    await m.svc.updateStatus('i1', 'INVESTIGATING', undefined, 'u1', 'a');
    expect(m.rows[0].openKey).toBe('ip:198.51.100.7');
  });

  it('retakes the slot when a closed incident is reopened', async () => {
    const m = withStatus({ status: 'RESOLVED', openKey: null, resolvedAt: new Date() });
    await m.svc.updateStatus('i1', 'OPEN', undefined, 'u1', 'a');
    expect(m.rows[0]).toMatchObject({ status: 'OPEN', openKey: 'ip:198.51.100.7', resolvedAt: null });
  });

  it('reopens without the slot if a newer incident already holds it, instead of failing', async () => {
    const m = withStatus({ status: 'RESOLVED', openKey: null }, true);
    await m.svc.updateStatus('i1', 'OPEN', undefined, 'u1', 'a');
    expect(m.rows[0]).toMatchObject({ status: 'OPEN', openKey: null });
    expect(m.rows[1].openKey).toBe('ip:198.51.100.7');
  });
});

describe('automatic blocking never overrides an administrator', () => {
  function blockingWith(existing: any | null) {
    const created: any[] = []; const deactivated: any[] = [];
    const prisma: any = {
      securityIpAllowlist: { findUnique: async () => null },
      securityIpBlock: {
        findFirst: async () => existing,
        updateMany: async (a: any) => { deactivated.push(a); return { count: 1 }; },
        create: async ({ data }: any) => { created.push(data); return data; },
      },
    };
    return { svc: new BlockingService(prisma, { log: jest.fn(async () => undefined) } as any), created, deactivated };
  }
  const inMin = (m: number) => new Date(Date.now() + m * 60_000);

  it('creates a block when none exists', async () => {
    const b = blockingWith(null);
    await b.svc.autoBlock('198.51.100.7', { reason: 'r' });
    expect(b.created).toHaveLength(1);
    expect(b.created[0]).toMatchObject({ automatic: true, isPermanent: false });
  });
  it('leaves a permanent block alone', async () => {
    const existing = { isPermanent: true, automatic: false, expiresAt: null };
    const b = blockingWith(existing);
    expect(await b.svc.autoBlock('198.51.100.7', { reason: 'r' })).toBe(existing);
    expect(b.created).toHaveLength(0);
  });
  it('leaves a manual temporary block alone', async () => {
    const existing = { isPermanent: false, automatic: false, expiresAt: inMin(5) };
    const b = blockingWith(existing);
    await b.svc.autoBlock('198.51.100.7', { reason: 'r' });
    expect(b.created).toHaveLength(0);
  });
  it('does not renew an automatic block that still has most of its time', async () => {
    const b = blockingWith({ isPermanent: false, automatic: true, expiresAt: inMin(50) });
    await b.svc.autoBlock('198.51.100.7', { reason: 'r' });
    expect(b.created).toHaveLength(0);
  });
  it('renews an automatic block that is nearly over, retiring the old one first', async () => {
    const b = blockingWith({ id: 'old', isPermanent: false, automatic: true, expiresAt: inMin(10) });
    await b.svc.autoBlock('198.51.100.7', { reason: 'r' });
    expect(b.created).toHaveLength(1);
    expect(b.deactivated.some((d: any) => d.where.id === 'old')).toBe(true);
  });
  it('an automatic block only clears blocks that have already run out, never a live one', async () => {
    const b = blockingWith(null);
    await b.svc.autoBlock('198.51.100.7', { reason: 'r' });
    const where = b.deactivated[0].where;
    expect(where.expiresAt).toEqual({ lte: expect.any(Date) });
    expect(where.isPermanent).toBe(false);
  });
  it('an administrator block replaces whatever is in force', async () => {
    const b = blockingWith(null);
    await b.svc.block('198.51.100.7', { reason: 'r', administratorId: 'u1' });
    expect(b.deactivated[0].where).toEqual({ ipAddress: '198.51.100.7', active: true });
  });
});

describe('detection helpers', () => {
  function service(prisma: any) {
    return new DetectionService(prisma, {} as any, {} as any, {} as any);
  }

  it('counts failures on an account across addresses, and distinct addresses', async () => {
    const prisma: any = { securityEvent: {
      findMany: async () => [{ ipAddress: '1.1.1.1' }, { ipAddress: '1.1.1.1' }, { ipAddress: '2.2.2.2' }, { ipAddress: '3.3.3.3' }],
      groupBy: async () => [{ _count: { _all: 3 } }, { _count: { _all: 9 } }],
    } };
    const c = await (service(prisma) as any).gatherCorrelation({ eventType: 'login_failed', userId: 'u1', id: 'e' }, '9.9.9.9');
    expect(c).toMatchObject({ userFailedLogins: 4, userFailedFromIps: 3, globalFailedLogins: 12, globalFailedFromIps: 2 });
  });

  it('skips all correlation queries for ordinary events', async () => {
    const prisma: any = { securityEvent: { findMany: jest.fn(), groupBy: jest.fn(), findFirst: jest.fn() } };
    const c = await (service(prisma) as any).gatherCorrelation({ eventType: 'page_view', userId: 'u1', id: 'e' }, '9.9.9.9');
    expect(c).toBeUndefined();
    expect(prisma.securityEvent.findMany).not.toHaveBeenCalled();
    expect(prisma.securityEvent.groupBy).not.toHaveBeenCalled();
  });

  it('finds the previous login from another address with its country and age', async () => {
    const prisma: any = {
      securityEvent: {
        findMany: async () => [],
        findFirst: async () => ({ ipAddress: '5.5.5.5', occurredAt: new Date(Date.now() - 35 * 60_000) }),
      },
      securityIp: { findUnique: async () => ({ country: 'NG' }) },
    };
    const c = await (service(prisma) as any).gatherCorrelation({ eventType: 'login_success', userId: 'u1', id: 'e' }, '9.9.9.9');
    expect(c.previousLogin).toEqual({ ipAddress: '5.5.5.5', country: 'NG', minutesAgo: 35 });
  });

  it('writes the highest recent event risk to the address, and its level', async () => {
    const updateMany = jest.fn(async () => ({ count: 1 }));
    const prisma: any = {
      securityEvent: { aggregate: async () => ({ _max: { riskScore: 85 } }) },
      securityIp: { updateMany },
    };
    await (service(prisma) as any).refreshIpRisk('198.51.100.7');
    expect(updateMany).toHaveBeenCalledWith({ where: { ipAddress: '198.51.100.7' }, data: { riskScore: 85, riskLevel: 'CRITICAL' } });
  });

  it('resets the address risk to zero when nothing risky happened recently', async () => {
    const updateMany = jest.fn(async () => ({ count: 1 }));
    const prisma: any = { securityEvent: { aggregate: async () => ({ _max: { riskScore: null } }) }, securityIp: { updateMany } };
    await (service(prisma) as any).refreshIpRisk('198.51.100.7');
    expect(updateMany).toHaveBeenCalledWith({ where: { ipAddress: '198.51.100.7' }, data: { riskScore: 0, riskLevel: 'NORMAL' } });
  });

  it('builds titles that fit the scope of the incident', () => {
    const t = (rule: string, ip: string | null, user: string | null, scope: any) => (service({}) as any).buildIncidentTitle(rule, ip, user, scope);
    expect(t('brute_force_login', '1.2.3.4', null, 'ip')).toBe('Brute-force login detected from 1.2.3.4');
    expect(t('distributed_account_attack', '1.2.3.4', 'u9', 'account')).toBe('Distributed attack on one account (account u9)');
    expect(t('distributed_login_attack', '1.2.3.4', 'u9', 'global')).toBe('Distributed login attack');
  });
});
