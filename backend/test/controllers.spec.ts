import 'reflect-metadata';
import { ExecutionContext, INestApplication, UnauthorizedException, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AuthController } from '../src/auth/auth.controller';
import { AuthService } from '../src/auth/auth.service';
import { AuditController } from '../src/audit/audit.controller';
import { BlockingController } from '../src/blocking/blocking.controller';
import { BlockingService } from '../src/blocking/blocking.service';
import { StatisticsController } from '../src/statistics/statistics.controller';
import { StatisticsService } from '../src/statistics/statistics.service';
import { IncidentsController } from '../src/incidents/incidents.controller';
import { IncidentsService } from '../src/incidents/incidents.service';
import { IpsController } from '../src/ips/ips.controller';
import { IpsService } from '../src/ips/ips.service';
import { IpIntelligenceService } from '../src/ips/ip-intelligence.service';
import { ApiKeysController } from '../src/api-keys/api-keys.controller';
import { ApiKeysService } from '../src/api-keys/api-keys.service';
import { PrismaService } from '../src/prisma/prisma.service';
import { JwtAuthGuard } from '../src/common/guards/jwt-auth.guard';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';

class FakeJwt {
  canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest();
    const role = req.headers['x-role'];
    if (!role) throw new UnauthorizedException();
    req.actor = { type: 'USER', id: 'u1', label: 'tester@pishon.ng', role, ip: '203.0.113.5', userAgent: 'jest', requestId: 'r1' };
    return true;
  }
}

describe('Controllers (real validation and role checks, services stubbed)', () => {
  let app: INestApplication;
  const auth = {
    login: jest.fn(async () => ({ accessToken: 'a', refreshToken: 'r', user: { id: 'u1' } })),
    refresh: jest.fn(async () => ({ accessToken: 'a2', refreshToken: 'r2' })),
    logout: jest.fn(async () => undefined),
    createUser: jest.fn(async (d: any) => ({ id: 'u9', email: d.email, role: d.role })),
    changePassword: jest.fn(async () => ({ ok: true })),
  };
  const blocking = {
    allowlist: jest.fn(async () => []), block: jest.fn(async () => ({ id: 'b1' })), unblock: jest.fn(async () => ({ ok: true })),
    allow: jest.fn(async () => ({ id: 'a1' })), unallow: jest.fn(async () => ({ ok: true })),
  };
  const stats = { summary: jest.fn(async () => ({ events: {} })) };
  const incidents = { list: jest.fn(async () => ({ data: [], total: 0 })), findOne: jest.fn(), updateStatus: jest.fn(async () => ({ ok: true })), assign: jest.fn(async () => ({ ok: true })) };
  const ips = { detail: jest.fn() };
  const intel = { lookup: jest.fn(async () => ({ isTor: true })), providerNames: ['tor'] };
  const keys = { create: jest.fn(async () => ({ id: 'k1', apiKey: 'PMS_x' })), list: jest.fn(async () => []), revoke: jest.fn(async () => ({ ok: true })), rotate: jest.fn(async () => ({ id: 'k2' })) };
  const auditLogs = { findMany: jest.fn(async () => []), count: jest.fn(async () => 0) };
  const prisma = { securityAuditLog: auditLogs };

  beforeAll(async () => {
    const mod = await Test.createTestingModule({
      controllers: [AuthController, AuditController, BlockingController, StatisticsController, IncidentsController, IpsController, ApiKeysController],
      providers: [
        { provide: AuthService, useValue: auth }, { provide: BlockingService, useValue: blocking },
        { provide: StatisticsService, useValue: stats }, { provide: IncidentsService, useValue: incidents },
        { provide: IpsService, useValue: ips }, { provide: IpIntelligenceService, useValue: intel },
        { provide: ApiKeysService, useValue: keys }, { provide: PrismaService, useValue: prisma },
      ],
    }).overrideGuard(JwtAuthGuard).useClass(FakeJwt).compile();
    app = mod.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true, transformOptions: { enableImplicitConversion: true } }));
    app.useGlobalFilters(new AllExceptionsFilter());
    await app.init();
  });
  afterAll(() => app.close());
  beforeEach(() => jest.clearAllMocks());

  const as = (r: request.Test, role: string) => r.set('x-role', role);
  const http = () => request(app.getHttpServer());

  describe('authentication routes', () => {
    it('login is open and passes the address, agent and request id along', async () => {
      await http().post('/api/v1/auth/login').set('User-Agent', 'jest').set('X-Forwarded-For', '203.0.113.9')
        .send({ email: 'a@pishon.ng', password: 'long-enough-1' }).expect(201);
      expect(auth.login).toHaveBeenCalledWith('a@pishon.ng', 'long-enough-1', expect.objectContaining({ ip: '203.0.113.9', userAgent: 'jest' }));
    });
    it('validates login input', async () => {
      await http().post('/api/v1/auth/login').send({ email: 'not-an-email', password: 'long-enough-1' }).expect(400);
      await http().post('/api/v1/auth/login').send({ email: 'a@pishon.ng', password: 'short' }).expect(400);
      await http().post('/api/v1/auth/login').send({ email: 'a@pishon.ng', password: 'long-enough-1', admin: true }).expect(400);
      expect(auth.login).not.toHaveBeenCalled();
    });
    it('refresh and logout are open but need a token in the body', async () => {
      await http().post('/api/v1/auth/refresh').send({ refreshToken: 'abc' }).expect(201);
      await http().post('/api/v1/auth/refresh').send({}).expect(400);
      expect(await http().post('/api/v1/auth/logout').send({ refreshToken: 'abc' }).expect(201).then((r) => r.body)).toEqual({ ok: true });
      await http().post('/api/v1/auth/logout').send({}).expect(400);
    });
    it('only the super admin can create users, with a strong password and a valid email', async () => {
      const body = { email: 'n@pishon.ng', password: 'a-long-password-1', role: 'ANALYST' };
      await as(http().post('/api/v1/auth/users').send(body), 'SECURITY_ADMIN').expect(403);
      await http().post('/api/v1/auth/users').send(body).expect(401);
      await as(http().post('/api/v1/auth/users').send({ ...body, password: 'short' }), 'SUPER_ADMIN').expect(400);
      await as(http().post('/api/v1/auth/users').send({ ...body, email: 'nope' }), 'SUPER_ADMIN').expect(400);
      expect(auth.createUser).not.toHaveBeenCalled();
      await as(http().post('/api/v1/auth/users').send(body), 'SUPER_ADMIN').expect(201);
      expect(auth.createUser).toHaveBeenCalledWith(body, expect.objectContaining({ id: 'u1', label: 'tester@pishon.ng' }));
    });
    it('any signed-in role can change their own password, which needs a 12 character new one', async () => {
      const body = { currentPassword: 'old-password-1', newPassword: 'a-much-longer-new-pw' };
      await http().post('/api/v1/auth/change-password').send(body).expect(401);
      await as(http().post('/api/v1/auth/change-password').send({ ...body, newPassword: 'too-short' }), 'VIEWER').expect(400);
      await as(http().post('/api/v1/auth/change-password').send(body), 'VIEWER').expect(201);
      expect(auth.changePassword).toHaveBeenCalledWith('u1', 'old-password-1', 'a-much-longer-new-pw', expect.objectContaining({ ip: '203.0.113.5' }));
    });
  });

  describe('blocking', () => {
    const block = { ipAddress: '198.51.100.7', reason: 'abuse' };
    it('only administrators can block, and the administrator is recorded', async () => {
      await as(http().post('/api/v1/security/block').send(block), 'ANALYST').expect(403);
      await as(http().post('/api/v1/security/block').send(block), 'SECURITY_ADMIN').expect(201);
      expect(blocking.block).toHaveBeenCalledWith('198.51.100.7', expect.objectContaining({ administratorId: 'u1', automatic: false, reason: 'abuse' }));
    });
    it('validates the block request', async () => {
      await as(http().post('/api/v1/security/block').send({ ipAddress: '198.51.100.7' }), 'SECURITY_ADMIN').expect(400);
      await as(http().post('/api/v1/security/block').send({ ...block, ttlMinutes: 0 }), 'SECURITY_ADMIN').expect(400);
      await as(http().post('/api/v1/security/block').send({ ...block, reason: 'x'.repeat(2001) }), 'SECURITY_ADMIN').expect(400);
      await as(http().post('/api/v1/security/block').send({ ...block, permanent: 'yes-please' }), 'SECURITY_ADMIN').expect(400);
    });
    it('unblock, allow and remove-from-allowlist are administrator only and carry the actor', async () => {
      await as(http().post('/api/v1/security/unblock').send(block), 'ANALYST').expect(403);
      await as(http().post('/api/v1/security/unblock').send(block), 'SUPER_ADMIN').expect(201);
      expect(blocking.unblock).toHaveBeenCalledWith('198.51.100.7', 'abuse', 'u1');
      await as(http().post('/api/v1/security/allow').send({ ...block, ttlMinutes: 30 }), 'SUPER_ADMIN').expect(201);
      expect(blocking.allow).toHaveBeenCalledWith('198.51.100.7', 'abuse', 30, 'u1');
      await as(http().delete('/api/v1/security/allow/198.51.100.7'), 'VIEWER').expect(403);
      await as(http().delete('/api/v1/security/allow/198.51.100.7'), 'SECURITY_ADMIN').expect(200);
      expect(blocking.unallow).toHaveBeenCalledWith('198.51.100.7', 'u1');
    });
    it('any signed-in role can see the allowlist', async () => {
      await as(http().get('/api/v1/security/allowlist'), 'VIEWER').expect(200);
      await http().get('/api/v1/security/allowlist').expect(401);
    });
  });

  describe('audit log', () => {
    it('is closed to viewers and filters by what is asked', async () => {
      await as(http().get('/api/v1/audit-logs'), 'VIEWER').expect(403);
      await as(http().get('/api/v1/audit-logs?action=ip.block&result=SUCCESS&actorType=USER&from=2026-10-01T00:00:00Z'), 'ANALYST').expect(200);
      expect(auditLogs.findMany).toHaveBeenCalledWith(expect.objectContaining({
        where: expect.objectContaining({ action: { contains: 'ip.block' }, result: 'SUCCESS', actorType: 'USER', createdAt: { gte: new Date('2026-10-01T00:00:00Z') } }),
      }));
    });
    it('rejects a bad date and ignores a sort column that is not allowed', async () => {
      await as(http().get('/api/v1/audit-logs?from=whenever'), 'ANALYST').expect(400);
      await as(http().get('/api/v1/audit-logs?sortBy=metadata'), 'ANALYST').expect(200);
      expect(auditLogs.findMany).toHaveBeenLastCalledWith(expect.objectContaining({ orderBy: { createdAt: 'desc' } }));
    });
  });

  describe('statistics, incidents and addresses', () => {
    it('statistics are for any signed-in role', async () => {
      await as(http().get('/api/v1/statistics'), 'VIEWER').expect(200);
      await http().get('/api/v1/statistics').expect(401);
    });
    it('analysts can change incident status but cannot assign; admins can assign', async () => {
      await as(http().post('/api/v1/incidents/i1/status').send({ status: 'INVESTIGATING' }), 'ANALYST').expect(201);
      expect(incidents.updateStatus).toHaveBeenCalledWith('i1', 'INVESTIGATING', undefined, 'u1', 'tester@pishon.ng');
      await as(http().post('/api/v1/incidents/i1/assign').send({ assignedTo: 'u2' }), 'ANALYST').expect(403);
      await as(http().post('/api/v1/incidents/i1/assign').send({ assignedTo: 'u2' }), 'SECURITY_ADMIN').expect(201);
      expect(incidents.assign).toHaveBeenCalledWith('i1', 'u2', 'u1', 'tester@pishon.ng');
    });
    it('rejects an invalid incident status', async () => {
      await as(http().post('/api/v1/incidents/i1/status').send({ status: 'EXPLODED' }), 'ANALYST').expect(400);
      expect(incidents.updateStatus).not.toHaveBeenCalled();
    });
    it('forces a fresh intelligence lookup for an address, and refuses an invalid one', async () => {
      await as(http().post('/api/v1/ips/198.51.100.7/refresh-intelligence'), 'VIEWER').expect(403);
      const ok = await as(http().post('/api/v1/ips/198.51.100.7/refresh-intelligence'), 'ANALYST').expect(201);
      expect(intel.lookup).toHaveBeenCalledWith('198.51.100.7', { force: true });
      expect(ok.body).toMatchObject({ ip: '198.51.100.7', providers: ['tor'] });
      await as(http().post('/api/v1/ips/not-an-ip/refresh-intelligence'), 'ANALYST').expect(404);
      await as(http().post('/api/v1/ips/127.1/refresh-intelligence'), 'ANALYST').expect(404);
    });
  });

  describe('API keys', () => {
    it('are managed by administrators only, and only with known scopes', async () => {
      const body = { name: 'website', scopes: ['events:write'] };
      await as(http().post('/api/v1/api-keys').send(body), 'ANALYST').expect(403);
      await as(http().post('/api/v1/api-keys').send({ ...body, scopes: ['everything'] }), 'SECURITY_ADMIN').expect(400);
      expect(keys.create).not.toHaveBeenCalled();
      await as(http().post('/api/v1/api-keys').send(body), 'SECURITY_ADMIN').expect(201);
      await as(http().get('/api/v1/api-keys'), 'VIEWER').expect(403);
      await as(http().delete('/api/v1/api-keys/k1'), 'ANALYST').expect(403);
      await as(http().post('/api/v1/api-keys/k1/rotate'), 'SECURITY_ADMIN').expect(201);
    });
  });
});

describe('block request booleans', () => {
  it('the string "false" is rejected rather than silently becoming a permanent block', async () => {
    const { plainToInstance } = require('class-transformer');
    const { validate } = require('class-validator');
    const { BlockIpDto } = require('../src/blocking/dto');
    const check = async (permanent: any) => (await validate(plainToInstance(BlockIpDto, { ipAddress: '198.51.100.7', reason: 'r', permanent }, { enableImplicitConversion: true }))).length;
    expect(await check('false')).toBe(1);
    expect(await check('yes-please')).toBe(1);
    expect(await check(1)).toBe(1);
    expect(await check(true)).toBe(0);
    expect(await check(false)).toBe(0);
    expect(await check(undefined)).toBe(0);
  });
});
