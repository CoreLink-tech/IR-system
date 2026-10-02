import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ExecutionContext } from '@nestjs/common';
import request from 'supertest';
import { ReportsController } from '../src/reports/reports.controller';
import { ReportsService } from '../src/reports/reports.service';
import { AuditService } from '../src/audit/audit.service';
import { JwtAuthGuard } from '../src/common/guards/jwt-auth.guard';
import { resolvePeriod } from '../src/reports/dto';
import { buildSecuritySummary, renderSecuritySummaryText } from '../src/reports/security-summary.builder';
import { SecurityPeriodFacts } from '../src/reports/report.types';

/** Test double for the JWT guard: the role comes from a header, no header means unauthenticated. */
class FakeAuth {
  canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest();
    const role = req.headers['x-role'];
    if (!role) return false;
    req.actor = { type: 'USER', id: 'u1', label: 'tester@pishon.ng', role, ip: '10.0.0.1' };
    return true;
  }
}

describe('Reports API', () => {
  let app: INestApplication;
  const svc = {
    incidentReport: jest.fn(async (id: string) => ({ kind: 'incident', incidentId: id })),
    incidentReportText: jest.fn(async (id: string) => `INCIDENT REPORT ${id}`),
    technicalReport: jest.fn(async (id: string) => ({ kind: 'technical', incidentId: id })),
    executiveSummary: jest.fn(async () => ({ kind: 'executive_summary' })),
    executiveSummaryText: jest.fn(async () => 'SECURITY SUMMARY'),
    securitySummary: jest.fn(async () => ({ kind: 'security_summary' })),
    securitySummaryText: jest.fn(async () => 'SECURITY ACTIVITY SUMMARY'),
  };
  const audit = { log: jest.fn(async () => undefined) };

  beforeAll(async () => {
    const mod = await Test.createTestingModule({
      controllers: [ReportsController],
      providers: [{ provide: ReportsService, useValue: svc }, { provide: AuditService, useValue: audit }],
    }).overrideGuard(JwtAuthGuard).useClass(FakeAuth as any).compile();
    app = mod.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({
      whitelist: true, forbidNonWhitelisted: true, transform: true, transformOptions: { enableImplicitConversion: true },
    }));
    await app.init();
  });
  afterAll(() => app.close());
  beforeEach(() => jest.clearAllMocks());

  const get = (path: string, role?: string) => {
    const r = request(app.getHttpServer()).get(path);
    return role ? r.set('x-role', role) : r;
  };

  it('rejects unauthenticated requests', async () => {
    await get('/api/v1/reports/incidents/abc').expect(403);
    expect(svc.incidentReport).not.toHaveBeenCalled();
  });

  it('serves a plain-English incident report as JSON by default', async () => {
    const res = await get('/api/v1/reports/incidents/INC-1', 'VIEWER').expect(200);
    expect(res.body).toEqual({ kind: 'incident', incidentId: 'INC-1' });
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('serves text when asked, with a text content type', async () => {
    const res = await get('/api/v1/reports/incidents/INC-1?format=text', 'ANALYST').expect(200);
    expect(res.headers['content-type']).toContain('text/plain');
    expect(res.text).toBe('INCIDENT REPORT INC-1');
  });

  it('rejects unknown formats and unknown query parameters', async () => {
    await get('/api/v1/reports/incidents/INC-1?format=pdf', 'ANALYST').expect(400);
    await get('/api/v1/reports/incidents/INC-1?foo=bar', 'ANALYST').expect(400);
  });

  it('keeps technical reports away from viewers', async () => {
    await get('/api/v1/reports/technical/INC-1', 'VIEWER').expect(403);
    await get('/api/v1/reports/security-summary', 'VIEWER').expect(403);
    expect(svc.technicalReport).not.toHaveBeenCalled();
    expect(svc.securitySummary).not.toHaveBeenCalled();
    await get('/api/v1/reports/technical/INC-1', 'ANALYST').expect(200);
    await get('/api/v1/reports/security-summary', 'SECURITY_ADMIN').expect(200);
  });

  it('lets viewers read the executive summary', async () => {
    await get('/api/v1/reports/executive-summary', 'VIEWER').expect(200);
  });

  it('defaults to the last 7 days and honours days, from and to', async () => {
    await get('/api/v1/reports/executive-summary', 'VIEWER').expect(200);
    const [f1, t1] = (svc.executiveSummary.mock.calls[0] as unknown) as [Date, Date];
    expect(Math.round((t1.getTime() - f1.getTime()) / 86400000)).toBe(7);

    await get('/api/v1/reports/executive-summary?days=30', 'VIEWER').expect(200);
    const [f2, t2] = (svc.executiveSummary.mock.calls[1] as unknown) as [Date, Date];
    expect(Math.round((t2.getTime() - f2.getTime()) / 86400000)).toBe(30);

    await get('/api/v1/reports/executive-summary?from=2026-09-01T00:00:00Z&to=2026-09-08T00:00:00Z', 'VIEWER').expect(200);
    const [f3, t3] = (svc.executiveSummary.mock.calls[2] as unknown) as [Date, Date];
    expect(f3.toISOString()).toBe('2026-09-01T00:00:00.000Z');
    expect(t3.toISOString()).toBe('2026-09-08T00:00:00.000Z');
  });

  it('validates dates and day counts', async () => {
    await get('/api/v1/reports/executive-summary?from=not-a-date', 'VIEWER').expect(400);
    await get('/api/v1/reports/executive-summary?days=0', 'VIEWER').expect(400);
    await get('/api/v1/reports/executive-summary?days=400', 'VIEWER').expect(400);
  });

  it('returns text for summaries', async () => {
    const res = await get('/api/v1/reports/executive-summary?format=text', 'VIEWER').expect(200);
    expect(res.text).toBe('SECURITY SUMMARY');
    const res2 = await get('/api/v1/reports/security-summary?format=text', 'ANALYST').expect(200);
    expect(res2.text).toBe('SECURITY ACTIVITY SUMMARY');
  });

  it('writes every successful read to the audit log, including who and what', async () => {
    await get('/api/v1/reports/technical/INC-9', 'ANALYST').expect(200);
    expect(audit.log).toHaveBeenCalledTimes(1);
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'report.technical', targetType: 'report', targetId: 'INC-9',
      actorId: 'u1', actorLabel: 'tester@pishon.ng', result: 'SUCCESS',
    }));
  });

  it('does not audit a request that was refused', async () => {
    await get('/api/v1/reports/technical/INC-9', 'VIEWER').expect(403);
    expect(audit.log).not.toHaveBeenCalled();
  });
});

describe('resolvePeriod', () => {
  const now = new Date('2026-10-02T12:00:00Z');
  it('uses days before to when from is missing', () => {
    const { from, to } = resolvePeriod({ days: 2 }, now);
    expect(to).toEqual(now);
    expect(from.toISOString()).toBe('2026-09-30T12:00:00.000Z');
  });
  it('prefers an explicit from over days', () => {
    const { from } = resolvePeriod({ from: '2026-09-01T00:00:00Z', days: 2 }, now);
    expect(from.toISOString()).toBe('2026-09-01T00:00:00.000Z');
  });
});

function facts(over: Partial<SecurityPeriodFacts> = {}): SecurityPeriodFacts {
  const d = (s: string) => new Date(s);
  return {
    generatedAt: d('2026-10-02T12:00:00Z'), from: d('2026-09-25T00:00:00Z'), to: d('2026-10-02T00:00:00Z'),
    previous: { incidents: 1, events: 50 }, events: 200, uniqueIps: 9,
    eventsByType: [{ type: 'login_failed', count: 120 }], eventsByRiskLevel: [{ level: 'NORMAL', count: 150 }],
    topSourceIps: [{ ip: '198.51.100.7', events: 60, peakRisk: 100, blocked: true }],
    incidents: [
      { incidentId: 'A', severity: 'HIGH', status: 'OPEN', detectionRule: 'brute_force_login', createdAt: d('2026-09-30T10:00:00Z'), resolvedAt: null, assigned: false },
      { incidentId: 'B', severity: 'CRITICAL', status: 'RESOLVED', detectionRule: 'credential_stuffing', createdAt: d('2026-09-28T10:00:00Z'), resolvedAt: d('2026-09-28T12:00:00Z'), assigned: true },
      { incidentId: 'C', severity: 'HIGH', status: 'RESOLVED', detectionRule: 'brute_force_login', createdAt: d('2026-09-29T10:00:00Z'), resolvedAt: d('2026-09-29T10:30:00Z'), assigned: true },
      { incidentId: 'D', severity: 'LOW', status: 'FALSE_POSITIVE', detectionRule: null, createdAt: d('2026-09-27T10:00:00Z'), resolvedAt: d('2026-09-27T10:05:00Z'), assigned: true },
    ],
    daily: [{ date: '2026-09-25', events: 10, incidents: 0 }],
    blocks: { total: 2, automatic: 1, manual: 1, stillInForce: 1 }, allowlisted: 3,
    eventsWithoutRuleData: 0, intelProviders: ['tor'], ...over,
  };
}

describe('security summary builder', () => {
  it('counts incidents by severity, status and rule in a stable order', () => {
    const s = buildSecuritySummary(facts());
    expect(s.incidentsBySeverity).toEqual([
      { severity: 'CRITICAL', count: 1 }, { severity: 'HIGH', count: 2 }, { severity: 'LOW', count: 1 },
    ]);
    expect(s.incidentsByStatus).toEqual([
      { status: 'OPEN', count: 1 }, { status: 'RESOLVED', count: 2 }, { status: 'FALSE_POSITIVE', count: 1 },
    ]);
    expect(s.incidentsByRule[0]).toEqual({ code: 'brute_force_login', title: 'Repeated failed logins', count: 2 });
    expect(s.totals).toEqual({ events: 200, uniqueIps: 9, incidents: 4 });
  });

  it('computes mean time to resolve from resolved incidents only', () => {
    // 120 minutes and 30 minutes -> mean 75. The false alarm is excluded.
    expect(buildSecuritySummary(facts()).response.meanTimeToResolveMinutes).toBe(75);
    expect(buildSecuritySummary(facts({ incidents: [] })).response.meanTimeToResolveMinutes).toBeNull();
  });

  it('reports unassigned open incidents and the oldest unresolved one', () => {
    const r = buildSecuritySummary(facts()).response;
    expect(r.unassignedOpen).toBe(1);
    expect(r.oldestUnresolvedAt).toBe('2026-09-30T10:00:00.000Z');
  });

  it('includes blocking numbers and the daily series for charts', () => {
    const s = buildSecuritySummary(facts());
    expect(s.blocking).toEqual({ total: 2, automatic: 1, manual: 1, stillInForce: 1, allowlisted: 3 });
    expect(s.daily).toHaveLength(1);
  });

  it('notes missing rule detail only when it exists', () => {
    expect(buildSecuritySummary(facts()).notes.join(' ')).not.toContain('recorded before rule detail');
    expect(buildSecuritySummary(facts({ eventsWithoutRuleData: 5 })).notes.join(' ')).toContain('5 events');
  });

  it('renders readable text', () => {
    const t = renderSecuritySummaryText(buildSecuritySummary(facts()));
    expect(t).toContain('SECURITY ACTIVITY SUMMARY');
    expect(t).toContain('198.51.100.7: 60 events, peak risk 100, blocked');
    expect(t).toContain('Mean time to resolve: 75 minutes');
  });
});

describe('JwtAuthGuard actor attribution', () => {
  // Regression: logged-in administrators were recorded as ANONYMOUS because
  // request.actor was only ever set by the API key guard.
  it('records the signed-in user as the actor', () => {
    const { JwtAuthGuard: Real } = require('../src/common/guards/jwt-auth.guard');
    const guard = new Real({ getAllAndOverride: () => false });
    const req: any = { headers: { 'user-agent': 'jest', 'x-forwarded-for': '203.0.113.5' }, requestId: 'r1', socket: {} };
    const ctx: any = { switchToHttp: () => ({ getRequest: () => req }) };
    const user = { id: 'u1', email: 'admin@pishon.ng', role: 'SECURITY_ADMIN' };
    expect(guard.handleRequest(null, user, null, ctx)).toBe(user);
    expect(req.actor).toMatchObject({ type: 'USER', id: 'u1', label: 'admin@pishon.ng', role: 'SECURITY_ADMIN', requestId: 'r1', userAgent: 'jest' });
  });

  it('still rejects when the token is invalid', () => {
    const { JwtAuthGuard: Real } = require('../src/common/guards/jwt-auth.guard');
    const guard = new Real({ getAllAndOverride: () => false });
    const req: any = { headers: {}, socket: {} };
    const ctx: any = { switchToHttp: () => ({ getRequest: () => req }) };
    expect(() => guard.handleRequest(null, false, null, ctx)).toThrow();
    expect(req.actor).toBeUndefined();
  });
});
