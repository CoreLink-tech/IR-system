import 'reflect-metadata';
import { BadRequestException, ExecutionContext, ForbiddenException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { IncidentsService } from '../src/incidents/incidents.service';
import { IpsService, IP_LIST_SORTS } from '../src/ips/ips.service';
import { SettingsService } from '../src/settings/settings.service';
import { HealthController } from '../src/health/health.controller';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';
import { JwtAuthGuard } from '../src/common/guards/jwt-auth.guard';
import { BUILT_IN_RULES } from '../src/detection/rules';
import { Reflector } from '@nestjs/core';

const page = { skip: 0, take: 25, sortBy: 'lastSeenAt', sortOrder: 'desc' as const };

describe('IpsService.list', () => {
  function make(blocks: any[] = [], rows: any[] = [{ ipAddress: '198.51.100.7' }, { ipAddress: '203.0.113.9' }]) {
    const seen: any = {};
    const prisma: any = {
      securityIpBlock: { findMany: async (a: any) => { seen.blocks = a; return blocks; } },
      securityIp: {
        findMany: async (a: any) => { seen.find = a; return rows; },
        count: async (a: any) => { seen.count = a; return rows.length; },
      },
    };
    return { svc: new IpsService(prisma, {} as any), seen };
  }
  it('marks each address as blocked or not, using the same rule as the website (active and not expired)', async () => {
    const m = make([{ ipAddress: '198.51.100.7' }]);
    const r = await m.svc.list(page);
    expect(r.data).toEqual([{ ipAddress: '198.51.100.7', blocked: true }, { ipAddress: '203.0.113.9', blocked: false }]);
    expect(m.seen.blocks.where).toMatchObject({ action: 'BLOCK', active: true });
    expect(JSON.stringify(m.seen.blocks.where.OR)).toContain('isPermanent');
  });
  it('filters by risk level (any case), country and the start of an address', async () => {
    const m = make();
    await m.svc.list({ ...page, filters: { riskLevel: 'high', country: ' NG ', search: '198.51' } });
    expect(m.seen.find.where).toEqual({ riskLevel: 'HIGH', country: 'NG', ipAddress: { startsWith: '198.51' } });
    expect(m.seen.count.where).toEqual(m.seen.find.where);
  });
  it('strips anything that is not part of an address from the search, so no wildcard reaches the query', async () => {
    const m = make();
    await m.svc.list({ ...page, filters: { search: "1%_2'; DROP--.3" } });
    expect(m.seen.find.where.ipAddress).toEqual({ startsWith: '12d.3' }); // only hex digits, colon and dot survive
    const n = make();
    await n.svc.list({ ...page, filters: { search: "%_';" } });
    expect(n.seen.find.where).not.toHaveProperty('ipAddress');
  });
  it('shows only blocked addresses, or only unblocked ones', async () => {
    const blocked = make([{ ipAddress: '198.51.100.7' }]);
    await blocked.svc.list({ ...page, filters: { blocked: 'true' } });
    expect(blocked.seen.find.where.ipAddress).toEqual({ in: ['198.51.100.7'] });
    const free = make([{ ipAddress: '198.51.100.7' }]);
    await free.svc.list({ ...page, filters: { blocked: 'false' } });
    expect(free.seen.find.where.ipAddress).toEqual({ notIn: ['198.51.100.7'] });
    const none = make([]);
    await none.svc.list({ ...page, filters: { blocked: 'false' } });
    expect(none.seen.find.where).toEqual({});
  });
  it('combines the blocked filter with a search instead of replacing it', async () => {
    const m = make([{ ipAddress: '198.51.100.7' }]);
    await m.svc.list({ ...page, filters: { blocked: 'true', search: '198' } });
    expect(m.seen.find.where.ipAddress).toEqual({ startsWith: '198', in: ['198.51.100.7'] });
  });
  it('rejects an unknown risk level or a blocked value that is not true or false', async () => {
    await expect(make().svc.list({ ...page, filters: { riskLevel: 'EXTREME' } })).rejects.toBeInstanceOf(BadRequestException);
    await expect(make().svc.list({ ...page, filters: { blocked: 'maybe' } })).rejects.toBeInstanceOf(BadRequestException);
  });
  it('offers only real columns for sorting', () => {
    expect(IP_LIST_SORTS).toEqual(['lastSeenAt', 'firstSeenAt', 'riskScore', 'eventCount', 'failedLogins', 'ipAddress']);
  });
});

describe('IncidentsService additions', () => {
  function make(incident: any | null = { id: 'i1', incidentId: 'INC-20261007-00001ABCD' }) {
    const seen: any = {}; const timeline: any[] = [];
    const prisma: any = {
      securityIncident: {
        findMany: async (a: any) => { seen.find = a; return []; },
        count: async (a: any) => 0,
        findUnique: async (a: any) => { seen.unique = a; return incident; },
      },
      securityIncidentTimeline: { create: async ({ data }: any) => { timeline.push(data); return { id: 't1', ...data }; } },
    };
    const audit = { log: jest.fn(async () => undefined) };
    return { svc: new IncidentsService(prisma, audit as any), seen, timeline, audit };
  }
  const p = { page: 1, pageSize: 25, skip: 0, take: 25, sortBy: 'createdAt', sortOrder: 'desc' as const };

  it('REGRESSION incident lookup by public number: GET incidents/:id accepted only the internal id', async () => {
    const m = make();
    await m.svc.findOne('INC-20261007-00001ABCD');
    expect(m.seen.unique.where).toEqual({ incidentId: 'INC-20261007-00001ABCD' });
    await m.svc.findOne('inc-20261007-00001abcd');
    expect(m.seen.unique.where).toEqual({ incidentId: 'INC-20261007-00001ABCD' });
    await m.svc.findOne('cl123internal');
    expect(m.seen.unique.where).toEqual({ id: 'cl123internal' });
  });
  it('REGRESSION assignee: lists and details carry who an incident is assigned to, without a password hash', async () => {
    const m = make();
    await m.svc.list({ ...p });
    expect(m.seen.find.include.assignee.select).toEqual({ id: true, email: true, name: true });
    await m.svc.findOne('i1');
    expect(m.seen.unique.include.assignee.select).toEqual({ id: true, email: true, name: true });
  });
  it('searches by the start of an address or of the public number, keeping only safe characters', async () => {
    const m = make();
    await m.svc.list({ ...p, filters: { search: "198.51%_'" } });
    expect(m.seen.find.where.OR).toEqual([{ sourceIp: { startsWith: '198.51' } }, { incidentId: { startsWith: '198.51' } }]);
    await m.svc.list({ ...p, filters: { search: 'inc-2026' } });
    expect(m.seen.find.where.OR[1]).toEqual({ incidentId: { startsWith: 'INC-2026' } });
    await m.svc.list({ ...p, filters: { search: "%'_" } });
    expect(m.seen.find.where).not.toHaveProperty('OR');
  });
  it('adds a note to the timeline with the author, and changes nothing else', async () => {
    const m = make();
    const entry = await m.svc.addNote('i1', 'Called the customer', 'u1', 'ana@pishon.ng');
    expect(m.timeline).toEqual([{ incidentId: 'i1', action: 'note.added', actor: 'ana@pishon.ng', details: 'Called the customer' }]);
    expect(entry).toMatchObject({ action: 'note.added' });
    expect(m.audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'incident.note', targetId: 'i1', actorId: 'u1', result: 'SUCCESS', metadata: { length: 19 },
    }));
  });
  it('does not put the note text in the audit log, and finds the incident by public number too', async () => {
    const m = make();
    await m.svc.addNote('INC-20261007-00001ABCD', 'secret detail', 'u1', 'ana');
    expect(JSON.stringify(m.audit.log.mock.calls)).not.toContain('secret detail');
    expect(m.seen.unique.where).toEqual({ incidentId: 'INC-20261007-00001ABCD' });
  });
  it('answers 404 for a note on an unknown incident, and writes nothing', async () => {
    const m = make(null);
    await expect(m.svc.addNote('nope', 'x', 'u1', 'a')).rejects.toBeInstanceOf(NotFoundException);
    expect(m.timeline).toEqual([]);
  });
});

describe('detection wording', () => {
  const byCode = (c: string) => BUILT_IN_RULES.find((r) => r.code === c)!;
  it('REGRESSION window in reasons: high_request_rate said "5 min" while counting a 10 minute window', () => {
    const rule = byCode('high_request_rate');
    const ctx: any = { event: { eventType: 'suspicious_request' }, stats: { eventsLastWindow: 80, windowMinutes: 10 } };
    const r = rule.evaluate(ctx, rule.defaultConfig);
    expect(r.matched).toBe(true);
    expect(r.reason).toBe('80 events in 10 min');
    expect(r.reason).not.toContain('5 min');
  });
  it('REGRESSION window in reasons: the number in the text follows the real window, not the rule setting', () => {
    const rule = byCode('brute_force_login');
    const ctx: any = { event: { eventType: 'login_failed' }, stats: { failedLoginsLastWindow: 6, windowMinutes: 10 } };
    expect(rule.evaluate(ctx, { ...rule.defaultConfig, windowMinutes: 99 }).reason).toBe('6 failed logins in 10 min');
  });
});

describe('SettingsService', () => {
  const svc = new SettingsService({ providerNames: ['ipapi', 'tor'] } as any);
  it('reports defaults when nothing is configured', () => {
    const s = svc.operational({} as any);
    expect(s.autoBlock).toEqual({ enabled: true, minimumRisk: 85, blockMinutes: 60 });
    expect(s.rateLimits).toEqual({ windowSeconds: 60, perAddress: 120, perWebsiteKey: 6000, signIn: 20 });
    expect(s.riskLevels).toEqual({ suspicious: 30, high: 60, critical: 80 });
    expect(s.intelligenceProviders).toEqual(['ipapi', 'tor']);
  });
  it('follows the environment, and ignores values that are not numbers', () => {
    const s = svc.operational({ AUTO_BLOCK_ENABLED: 'false', AUTO_BLOCK_MIN_RISK: '90', THROTTLE_LIMIT: 'lots', NODE_ENV: 'production' } as any);
    expect(s.autoBlock.enabled).toBe(false);
    expect(s.autoBlock.minimumRisk).toBe(90);
    expect(s.rateLimits.perAddress).toBe(120);
    expect(s.sessions.secureCookie).toBe(true);
  });
  it('never includes a secret, key, token, connection string or origin', () => {
    const secretEnv: any = {
      JWT_SECRET: 'SECRETVALUE1', JWT_REFRESH_SECRET: 'SECRETVALUE2', API_KEY_HASH_PEPPER: 'SECRETVALUE3',
      DATABASE_URL: 'mysql://root:SECRETVALUE4@db/x', ABUSEIPDB_API_KEY: 'SECRETVALUE5', IPINFO_TOKEN: 'SECRETVALUE6',
      CORS_ORIGINS: 'https://dash.pishon.ng', BOOTSTRAP_ADMIN_PASSWORD: 'SECRETVALUE7',
    };
    const out = JSON.stringify(svc.operational(secretEnv));
    expect(out).not.toMatch(/SECRETVALUE/);
    expect(out).not.toContain('dash.pishon.ng');
  });
});

describe('HealthController', () => {
  it('answers ok with no secrets, and is not cached', () => {
    const headers: any = {};
    const r: any = new HealthController().health({ setHeader: (k: string, v: string) => { headers[k] = v; } } as any);
    expect(r.status).toBe('ok');
    expect(Object.keys(r).sort()).toEqual(['service', 'status', 'time', 'version']);
    expect(headers['Cache-Control']).toBe('no-store');
  });
});

describe('error filter code', () => {
  const run = (exception: any) => {
    let body: any; let status = 0;
    const host: any = { switchToHttp: () => ({
      getResponse: () => ({ status: (s: number) => { status = s; return { json: (b: any) => { body = b; } }; } }),
      getRequest: () => ({ url: '/x', method: 'GET', requestId: 'rid' }),
    }) };
    new AllExceptionsFilter().catch(exception, host);
    return { status, body };
  };
  it('includes a code only when the thrown error gave one', () => {
    expect(run(new UnauthorizedException({ message: 'gone', code: 'refresh_token_reuse' })).body).toMatchObject({ statusCode: 401, message: 'gone', code: 'refresh_token_reuse', requestId: 'rid' });
    expect(run(new UnauthorizedException('plain')).body).not.toHaveProperty('code');
    expect(run(new Error('boom')).body).not.toHaveProperty('code');
  });
});

describe('JwtAuthGuard password-change enforcement', () => {
  const guard = new JwtAuthGuard(new Reflector());
  const ctxFor = (url: string) => ({
    switchToHttp: () => ({ getRequest: () => ({ originalUrl: url, headers: {}, socket: { remoteAddress: '203.0.113.5' } }) }),
  }) as unknown as ExecutionContext;
  const user = (mustChangePassword: boolean) => ({ id: 'u1', email: 'a@b.ng', role: 'ANALYST', mustChangePassword });

  it('lets an account that must change its password reach only "me" and "change password"', () => {
    for (const ok of ['/api/v1/auth/me', '/api/v1/auth/change-password', '/api/v1/auth/me?x=1']) {
      expect(guard.handleRequest(null, user(true), null, ctxFor(ok))).toMatchObject({ id: 'u1' });
    }
    for (const blocked of ['/api/v1/incidents', '/api/v1/statistics', '/api/v1/auth/users', '/api/v1/auth/me/', '/api/v1/auth/me/../users', '/api/v1/auth/change-password2']) {
      const err: any = (() => { try { guard.handleRequest(null, user(true), null, ctxFor(blocked)); } catch (e) { return e; } })();
      expect([blocked, err instanceof ForbiddenException, err?.getResponse?.().code]).toEqual([blocked, true, 'password_change_required']);
    }
  });
  it('does not restrict an account that has no such requirement', () => {
    expect(guard.handleRequest(null, user(false), null, ctxFor('/api/v1/incidents'))).toMatchObject({ id: 'u1' });
  });
});
