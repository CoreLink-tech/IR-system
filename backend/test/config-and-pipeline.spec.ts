import 'reflect-metadata';
import { CallHandler, ExecutionContext } from '@nestjs/common';
import { of, throwError, lastValueFrom } from 'rxjs';
import { assertValidConfig, validateConfig } from '../src/config/validate-config';
import { DetectionService } from '../src/detection/detection.service';
import { AuditInterceptor } from '../src/common/interceptors/audit.interceptor';
import { JwtStrategy } from '../src/auth/jwt.strategy';

const good = {
  NODE_ENV: 'production',
  DATABASE_URL: 'mysql://pishon_user:x9f2kq81vb@db:3306/pishon_market',
  JWT_SECRET: 'a'.repeat(20) + 'B'.repeat(20) + '1'.repeat(24),
  JWT_REFRESH_SECRET: 'z'.repeat(20) + 'Y'.repeat(20) + '9'.repeat(24),
  API_KEY_HASH_PEPPER: 'p3pp3r-value-0123456789',
  CORS_ORIGINS: 'https://security.pishonmarket.com',
} as any;

describe('startup configuration check', () => {
  it('accepts a proper configuration with no complaints', () => {
    expect(validateConfig(good)).toEqual({ errors: [], warnings: [] });
    expect(assertValidConfig(good)).toEqual([]);
  });

  it('refuses the sample .env values, because anyone could forge an administrator login with them', () => {
    const sample = {
      ...good,
      JWT_SECRET: 'CHANGE_ME_TO_LONG_RANDOM_STRING_AT_LEAST_64_CHARS',
      JWT_REFRESH_SECRET: 'CHANGE_ME_TO_ANOTHER_LONG_RANDOM_STRING_64_CHARS',
      API_KEY_HASH_PEPPER: 'CHANGE_ME_RANDOM_PEPPER',
      DATABASE_URL: 'mysql://pishon_user:CHANGE_ME@localhost:3306/pishon_market',
    };
    const { errors } = validateConfig(sample);
    expect(errors).toHaveLength(4);
    expect(errors.join(' ')).toContain('npm run gen:secrets');
    expect(() => assertValidConfig(sample)).toThrow(/Refusing to start/);
  });

  it('refuses missing secrets', () => {
    const { errors } = validateConfig({ NODE_ENV: 'development' } as any);
    expect(errors.some((e) => e.startsWith('JWT_SECRET is not set'))).toBe(true);
    expect(errors.some((e) => e.startsWith('JWT_REFRESH_SECRET is not set'))).toBe(true);
    expect(errors.some((e) => e.startsWith('API_KEY_HASH_PEPPER is not set'))).toBe(true);
    expect(errors).toContain('DATABASE_URL is not set.');
  });

  it('applies in development too, because the server listens on every network interface', () => {
    expect(validateConfig({ ...good, NODE_ENV: 'development', JWT_SECRET: 'short' }).errors.join(' ')).toContain('too short');
  });

  it('refuses short secrets and an identical access and refresh secret', () => {
    expect(validateConfig({ ...good, JWT_SECRET: 'x'.repeat(31) }).errors.join(' ')).toContain('JWT_SECRET is too short');
    expect(validateConfig({ ...good, API_KEY_HASH_PEPPER: 'short' }).errors.join(' ')).toContain('API_KEY_HASH_PEPPER is too short');
    expect(validateConfig({ ...good, JWT_REFRESH_SECRET: good.JWT_SECRET }).errors.join(' ')).toContain('must be different');
  });

  it('refuses a wildcard CORS origin and an empty key prefix', () => {
    expect(validateConfig({ ...good, CORS_ORIGINS: '*' }).errors.join(' ')).toContain('CORS_ORIGINS');
    expect(validateConfig({ ...good, API_KEY_PREFIX: '  ' }).errors.join(' ')).toContain('API_KEY_PREFIX');
  });

  it('warns, but does not fail, about risky production settings', () => {
    const { errors, warnings } = validateConfig({ ...good, CORS_ORIGINS: 'http://localhost:3000', AUTO_BLOCK_ENABLED: 'false' });
    expect(errors).toEqual([]);
    expect(warnings).toHaveLength(2);
  });
});

/** Builds the detection pipeline over an in-memory store, with the real rules. */
function pipeline(over: { rules?: any[]; intel?: any; stats?: Partial<Record<string, number>> } = {}) {
  const s = { failed: 0, events: 0, users: 0, resets: 0, maxRisk: 0, ...(over.stats ?? {}) };
  const updates: any[] = []; const ipUpdates: any[] = []; const incidents: any[] = []; const blocks: any[] = [];
  const prisma: any = {
    securityRule: {
      upsert: async () => undefined,
      findMany: async () => over.rules ?? ALL_RULES,
    },
    securityEvent: {
      count: async ({ where }: any) => (where.eventType === 'login_failed' ? s.failed : where.eventType === 'password_reset' ? s.resets : s.events),
      findMany: async ({ where }: any) => (where.eventType === 'login_failed' && where.userId ? Array.from({ length: s.users }, (_, i) => ({ userId: `u${i}` })) : []),
      groupBy: async () => [],
      findFirst: async () => null,
      update: async (a: any) => { updates.push(a); },
      aggregate: async () => ({ _max: { riskScore: s.maxRisk } }),
    },
    securityIp: { updateMany: async (a: any) => { ipUpdates.push(a); }, findUnique: async () => null },
  };
  const intel = { lookup: jest.fn(async () => over.intel ?? null) };
  const incidentSvc = { createFromDetection: jest.fn(async (i: any) => { incidents.push(i); return { id: 'inc1' }; }) };
  const blocking = { autoBlock: jest.fn(async (ip: string, i: any) => { blocks.push({ ip, ...i }); }) };
  const svc = new DetectionService(prisma, intel as any, incidentSvc as any, blocking as any);
  return { svc, updates, ipUpdates, incidents, blocks, incidentSvc, blocking, intel };
}
const { BUILT_IN_RULES } = require('../src/detection/rules');
const ALL_RULES = BUILT_IN_RULES.map((r: any) => ({ code: r.code, config: r.defaultConfig, priority: r.priority, isEnabled: true }));
const ev = (o: any = {}) => ({ id: 'e1', eventType: 'login_failed', severity: 'MEDIUM', ipAddress: '198.51.100.7', userId: 'u1', sessionId: 's1', requestPath: '/login', metadata: {}, occurredAt: new Date(), ...o });

describe('DetectionService.processEvent', () => {
  beforeEach(() => { delete process.env.AUTO_BLOCK_ENABLED; delete process.env.AUTO_BLOCK_MIN_RISK; });

  it('scores a quiet event as normal, stores an empty rule list, and opens nothing', async () => {
    const p = pipeline();
    const r = await p.svc.processEvent(ev({ eventType: 'page_view' }));
    expect(r).toEqual({ riskScore: 0, riskLevel: 'NORMAL', matchedRules: [], incidentId: null });
    expect(p.updates[0].data).toEqual({ riskScore: 0, riskLevel: 'NORMAL', matchedRules: [] });
    expect(p.incidentSvc.createFromDetection).not.toHaveBeenCalled();
    expect(p.blocking.autoBlock).not.toHaveBeenCalled();
  });

  it('adds the risk of every rule that matches, and records which rules and why', async () => {
    const p = pipeline({ stats: { failed: 6, users: 5 } });
    const r = await p.svc.processEvent(ev());
    expect(r.matchedRules.map((m) => m.code).sort()).toEqual(['brute_force_login', 'credential_stuffing']);
    expect(r.riskScore).toBe(r.matchedRules.reduce((n, m) => n + m.riskDelta, 0));
    expect(p.updates[0].data.matchedRules).toHaveLength(2);
    expect(p.updates[0].data.matchedRules[0]).toMatchObject({ code: expect.any(String), reason: expect.any(String), riskDelta: expect.any(Number) });
  });

  it('caps the score at 100', async () => {
    const p = pipeline({ stats: { failed: 50, users: 9, events: 500 } });
    expect((await p.svc.processEvent(ev())).riskScore).toBe(100);
  });

  it('opens an incident with the most severe rule, the right scope and a readable title', async () => {
    const p = pipeline({ stats: { failed: 25 } });
    await p.svc.processEvent(ev());
    expect(p.incidents).toHaveLength(1);
    expect(p.incidents[0]).toMatchObject({
      scope: 'ip', sourceIp: '198.51.100.7', ruleCode: 'brute_force_login', severity: 'CRITICAL',
      title: 'Brute-force login detected from 198.51.100.7', eventId: 'e1',
    });
    expect(p.incidents[0].description).toContain('- brute_force_login:');
  });

  it('returns the incident id so the caller can tell the website', async () => {
    const p = pipeline({ stats: { failed: 6 } });
    expect((await p.svc.processEvent(ev())).incidentId).toBe('inc1');
  });

  it('does not open an incident for rules that only add risk', async () => {
    const p = pipeline({ stats: { events: 100 } });
    const r = await p.svc.processEvent(ev({ eventType: 'page_view' }));
    expect(r.matchedRules.map((m) => m.code)).toContain('high_request_rate');
    expect(p.incidentSvc.createFromDetection).not.toHaveBeenCalled();
  });

  it('blocks automatically only when the score is critical and above the threshold', async () => {
    const hot = pipeline({ stats: { failed: 50, users: 9, events: 500 } });
    await hot.svc.processEvent(ev());
    expect(hot.blocks).toHaveLength(1);
    expect(hot.blocks[0]).toMatchObject({ ip: '198.51.100.7', incidentId: 'inc1' });
    expect(hot.blocks[0].reason).toContain('Auto-block: risk=100');

    const warm = pipeline({ stats: { failed: 6 } });
    await warm.svc.processEvent(ev());
    expect(warm.blocks).toHaveLength(0);
  });

  it('respects AUTO_BLOCK_ENABLED=false and a raised AUTO_BLOCK_MIN_RISK', async () => {
    process.env.AUTO_BLOCK_ENABLED = 'false';
    const off = pipeline({ stats: { failed: 50, users: 9, events: 500 } });
    await off.svc.processEvent(ev());
    expect(off.blocks).toHaveLength(0);
    process.env.AUTO_BLOCK_ENABLED = 'true'; process.env.AUTO_BLOCK_MIN_RISK = '101';
    const strict = pipeline({ stats: { failed: 50, users: 9, events: 500 } });
    await strict.svc.processEvent(ev());
    expect(strict.blocks).toHaveLength(0);
  });

  it('still returns a result when blocking fails', async () => {
    const p = pipeline({ stats: { failed: 50, users: 9, events: 500 } });
    p.blocking.autoBlock.mockRejectedValueOnce(new Error('allowlisted'));
    await expect(p.svc.processEvent(ev())).resolves.toMatchObject({ riskLevel: 'CRITICAL' });
  });

  it('refreshes the address risk, and skips that for events with no address', async () => {
    const p = pipeline({ stats: { maxRisk: 72 } });
    await p.svc.processEvent(ev({ eventType: 'page_view' }));
    expect(p.ipUpdates[0]).toEqual({ where: { ipAddress: '198.51.100.7' }, data: { riskScore: 72, riskLevel: 'HIGH' } });
    const none = pipeline();
    await none.svc.processEvent(ev({ ipAddress: null, eventType: 'page_view' }));
    expect(none.ipUpdates).toHaveLength(0);
    expect(none.intel.lookup).not.toHaveBeenCalled();
  });

  it('feeds IP intelligence into the rules', async () => {
    const p = pipeline({ intel: { isVpn: false, isProxy: true, isTor: true, isDatacenter: false, isMalicious: true, reputationScore: 90, country: 'RU' } });
    const r = await p.svc.processEvent(ev({ eventType: 'page_view' }));
    expect(r.matchedRules.map((m) => m.code).sort()).toEqual(['known_malicious_ip', 'tor_or_proxy']);
  });

  it('keeps going when intelligence lookup fails', async () => {
    const p = pipeline();
    p.intel.lookup.mockRejectedValueOnce(new Error('provider down'));
    await expect(p.svc.processEvent(ev({ eventType: 'page_view' }))).resolves.toMatchObject({ riskScore: 0 });
  });

  it('ignores disabled rules, and rules it has no code for', async () => {
    const rules = [
      { code: 'brute_force_login', config: BUILT_IN_RULES.find((r: any) => r.code === 'brute_force_login').defaultConfig, priority: 1, isEnabled: true },
      { code: 'a_rule_that_was_removed', config: {}, priority: 2, isEnabled: true },
    ];
    const p = pipeline({ rules, stats: { failed: 6, users: 9 } });
    const r = await p.svc.processEvent(ev());
    expect(r.matchedRules.map((m) => m.code)).toEqual(['brute_force_login']);
  });

  it('one rule crashing does not stop the others or lose the event', async () => {
    const original = BUILT_IN_RULES.find((r: any) => r.code === 'credential_stuffing').evaluate;
    BUILT_IN_RULES.find((r: any) => r.code === 'credential_stuffing').evaluate = () => { throw new Error('bug in rule'); };
    try {
      const p = pipeline({ stats: { failed: 6, users: 9 } });
      const r = await p.svc.processEvent(ev());
      const codes = r.matchedRules.map((m) => m.code);
      expect(codes).toContain('brute_force_login');
      expect(codes).not.toContain('credential_stuffing');
      expect(p.updates).toHaveLength(1);
    } finally {
      BUILT_IN_RULES.find((r: any) => r.code === 'credential_stuffing').evaluate = original;
    }
  });

  it('uses the rule settings stored in the database, so thresholds can be tuned without a deploy', async () => {
    const rules = ALL_RULES.map((r: any) => (r.code === 'brute_force_login' ? { ...r, config: { threshold: 2, windowMinutes: 10, baseRisk: 10, perAttempt: 1, maxRisk: 20, mediumAt: 2, highAt: 10, criticalAt: 20 } } : r));
    const p = pipeline({ rules, stats: { failed: 2 } });
    expect((await p.svc.processEvent(ev())).matchedRules.map((m) => m.code)).toContain('brute_force_login');
  });

  it('sets up every built-in rule when the database has none', async () => {
    const upserts: string[] = [];
    const prisma: any = { securityRule: { upsert: async ({ where }: any) => { upserts.push(where.code); } } };
    await new DetectionService(prisma, {} as any, {} as any, {} as any).ensureSeeded();
    expect(upserts).toEqual(BUILT_IN_RULES.map((r: any) => r.code));
    expect(upserts).toHaveLength(16);
  });
});

describe('AuditInterceptor', () => {
  function run(method: string, url: string, result: 'ok' | 'fail', actor?: any) {
    const log = jest.fn(async () => undefined);
    const req: any = { method, originalUrl: url, url, headers: { 'user-agent': 'jest' }, requestId: 'r1', params: { id: 'i1' }, route: { path: url.split('?')[0] }, actor, socket: { remoteAddress: '203.0.113.5' } };
    const ctx = { switchToHttp: () => ({ getRequest: () => req }) } as unknown as ExecutionContext;
    const next: CallHandler = { handle: () => (result === 'ok' ? of('x') : throwError(() => new Error('boom'))) };
    const out = new AuditInterceptor({ log } as any).intercept(ctx, next);
    return { log, out };
  }

  it('records who changed what, with the outcome and duration', async () => {
    const { log, out } = run('POST', '/api/v1/security/block', 'ok', { type: 'USER', id: 'u1', label: 'admin@pishon.ng' });
    await lastValueFrom(out);
    expect(log).toHaveBeenCalledWith(expect.objectContaining({
      actorType: 'USER', actorId: 'u1', actorLabel: 'admin@pishon.ng', action: 'POST /api/v1/security/block',
      targetId: 'i1', result: 'SUCCESS', ipAddress: '203.0.113.5', metadata: { durationMs: expect.any(Number) },
    }));
  });

  it('records a failed change as a failure', async () => {
    const { log, out } = run('POST', '/api/v1/incidents/i1/status', 'fail', { type: 'USER', id: 'u1' });
    await expect(lastValueFrom(out)).rejects.toThrow('boom');
    expect(log).toHaveBeenCalledWith(expect.objectContaining({ result: 'FAILURE' }));
  });

  it('records an anonymous actor when nobody is identified', async () => {
    const { log, out } = run('DELETE', '/api/v1/api-keys/k1', 'ok');
    await lastValueFrom(out);
    expect(log).toHaveBeenCalledWith(expect.objectContaining({ actorType: 'ANONYMOUS' }));
  });

  it('skips reads, and paths it does not cover', async () => {
    for (const [m, u] of [['GET', '/api/v1/security/blocked-ips'], ['POST', '/api/v1/events'], ['POST', '/api/v1/auth/login']]) {
      const { log, out } = run(m, u, 'ok');
      await lastValueFrom(out);
      expect(log).not.toHaveBeenCalled();
    }
  });

  it('never lets a failing audit write break the request', async () => {
    const log = jest.fn(async () => { throw new Error('db down'); });
    const req: any = { method: 'POST', originalUrl: '/api/v1/security/block', headers: {}, params: {}, socket: {} };
    const ctx = { switchToHttp: () => ({ getRequest: () => req }) } as unknown as ExecutionContext;
    await expect(lastValueFrom(new AuditInterceptor({ log } as any).intercept(ctx, { handle: () => of('done') }))).resolves.toBe('done');
  });
});

describe('JwtStrategy', () => {
  beforeAll(() => { process.env.JWT_SECRET = 'x'.repeat(40); });
  const strategy = (user: any) => new JwtStrategy({ securityUser: { findUnique: async () => user } } as any);

  it('returns the current user, taking the role from the database rather than the token', async () => {
    const s = strategy({ id: 'u1', email: 'a@b.ng', role: 'VIEWER', name: 'A', isActive: true });
    expect(await s.validate({ sub: 'u1', email: 'a@b.ng', role: 'SUPER_ADMIN', type: 'access' })).toEqual({ id: 'u1', email: 'a@b.ng', role: 'VIEWER', name: 'A' });
  });
  it('refuses a refresh token used as an access token, and an empty payload', async () => {
    const s = strategy({ id: 'u1', isActive: true });
    await expect(s.validate({ sub: 'u1', type: 'refresh' } as any)).rejects.toThrow();
    await expect(s.validate(null as any)).rejects.toThrow();
  });
  it('refuses a user who was disabled or deleted after the token was issued', async () => {
    await expect(strategy({ id: 'u1', isActive: false }).validate({ sub: 'u1', type: 'access' } as any)).rejects.toThrow('User inactive');
    await expect(strategy(null).validate({ sub: 'u1', type: 'access' } as any)).rejects.toThrow('User inactive');
  });
});
