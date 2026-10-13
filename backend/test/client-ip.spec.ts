import 'reflect-metadata';
import { readFileSync } from 'fs';
import { join } from 'path';
import { Controller, ForbiddenException, Get, INestApplication, Post, Req, UnauthorizedException, CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { ThrottlerModule } from '@nestjs/throttler';
import request from 'supertest';
import * as bcrypt from 'bcryptjs';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';
import { AppThrottlerGuard } from '../src/common/guards/app-throttler.guard';
import { AuditInterceptor } from '../src/common/interceptors/audit.interceptor';
import { RequestIdInterceptor } from '../src/common/interceptors/request-id.interceptor';
import { configureApp } from '../src/common/configure-app';
import { newRequestId } from '../src/common/request-id';
import { extractIp, parseTrustedProxies, resolveClientIp, trustedProxyProblems } from '../src/common/utils/ip.util';
import { validateConfig } from '../src/config/validate-config';
import { AuthController } from '../src/auth/auth.controller';
import { AuthService } from '../src/auth/auth.service';
import { UsersService } from '../src/auth/users.service';
import { PrismaService } from '../src/prisma/prisma.service';
import { AuditService } from '../src/audit/audit.service';

process.env.JWT_SECRET = 'access-secret-for-tests-0123456789abcdef0123456789abcdef';
process.env.JWT_REFRESH_SECRET = 'refresh-secret-for-tests-fedcba9876543210fedcba9876543210';

const LOCAL = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];
const setProxies = (v?: string) => { if (v === undefined) delete process.env.TRUSTED_PROXIES; else process.env.TRUSTED_PROXIES = v; };
afterEach(() => { setProxies(undefined); delete process.env.CLIENT_IP_HEADER; });

describe('shared forwarding vectors (the PHP client must agree with these exactly)', () => {
  const file = JSON.parse(readFileSync(join(__dirname, '../../integration/shared/forwarding-vectors.json'), 'utf8'));
  it('has a meaningful number of cases', () => { expect(file.vectors.length).toBeGreaterThan(40); });
  it.each(file.vectors.map((v: any) => [v.name, v]))('%s', (_n: string, v: any) => {
    const got = resolveClientIp(v.remote, v.xff, v.clientHeader, { trusted: v.trusted, header: v.header ?? undefined });
    expect(got ?? null).toBe(v.expected);
  });
});

describe('extractIp', () => {
  const req = (remote: string, headers: Record<string, any>) => ({ socket: { remoteAddress: remote }, headers }) as any;

  it('never reads X-Real-IP, trusted proxy or not', () => {
    expect(extractIp(req('198.51.100.9', { 'x-real-ip': '1.1.1.1' }))).toBe('198.51.100.9');
    setProxies('10.0.0.1');
    expect(extractIp(req('10.0.0.1', { 'x-real-ip': '1.1.1.1' }))).toBe('10.0.0.1');
  });

  it('ignores X-Forwarded-For from an untrusted peer (spoofing)', () => {
    expect(extractIp(req('198.51.100.9', { 'x-forwarded-for': '1.2.3.4' }))).toBe('198.51.100.9');
  });

  it('reads it from a trusted peer, from the right', () => {
    setProxies('10.0.0.1');
    expect(extractIp(req('10.0.0.1', { 'x-forwarded-for': '9.9.9.9, 203.0.113.7' }))).toBe('203.0.113.7');
  });

  it('joins a header that arrived as an array (duplicate headers)', () => {
    setProxies('10.0.0.1');
    expect(extractIp(req('10.0.0.1', { 'x-forwarded-for': ['9.9.9.9', '203.0.113.7'] }))).toBe('203.0.113.7');
  });

  it('follows a changed TRUSTED_PROXIES without a restart of the module', () => {
    const r = req('10.0.0.1', { 'x-forwarded-for': '203.0.113.7' });
    expect(extractIp(r)).toBe('10.0.0.1');
    setProxies('10.0.0.1');
    expect(extractIp(r)).toBe('203.0.113.7');
  });

  it('uses the configured client header only behind a trusted proxy, in any letter case', () => {
    setProxies('10.0.0.1'); process.env.CLIENT_IP_HEADER = 'CF-Connecting-IP';
    expect(extractIp(req('10.0.0.1', { 'cf-connecting-ip': '203.0.113.7', 'x-forwarded-for': '8.8.8.8' }))).toBe('203.0.113.7');
    expect(extractIp(req('198.51.100.9', { 'cf-connecting-ip': '203.0.113.7' }))).toBe('198.51.100.9');
  });
});

describe('trusted proxy settings', () => {
  it('parses a list and drops blanks', () => { expect(parseTrustedProxies(' 10.0.0.1, ,private,')).toEqual(['10.0.0.1', 'private']); });
  it('accepts addresses, CIDR blocks and the word private', () => {
    expect(trustedProxyProblems(['10.0.0.1', '10.0.0.0/8', '2400:cb00::/32', 'PRIVATE'])).toEqual([]);
  });
  it('explains each bad entry', () => {
    const p = trustedProxyProblems(['banana', '10.0.0.0/99', '1.2.3.4/8/9']);
    expect(p).toHaveLength(3);
    expect(p[0]).toContain('"banana"');
  });
  const base = { NODE_ENV: 'production', JWT_SECRET: process.env.JWT_SECRET, JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET, DATABASE_URL: 'mysql://u:realpass@db/x', CORS_ORIGINS: 'https://d.example' } as any;
  it('refuses to start with an invalid entry', () => {
    expect(validateConfig({ ...base, TRUSTED_PROXIES: '10.0.0.0/99' }).errors.join(' ')).toContain('TRUSTED_PROXIES');
  });
  it('warns in production when none are listed, and when a client header has no proxies', () => {
    expect(validateConfig({ ...base }).warnings.join(' ')).toContain('TRUSTED_PROXIES is empty');
    expect(validateConfig({ ...base, TRUSTED_PROXIES: 'private' }).warnings.join(' ')).not.toContain('TRUSTED_PROXIES is empty');
    expect(validateConfig({ ...base, CLIENT_IP_HEADER: 'CF-Connecting-IP' }).warnings.join(' ')).toContain('CLIENT_IP_HEADER');
  });
});

describe('request ids', () => {
  it('keeps a plain id and replaces anything that could forge a log line', () => {
    expect(newRequestId('abc12345-req')).toBe('abc12345-req');
    for (const bad of ['short', 'has space in it', 'x'.repeat(65), '<script>alert(1)</script>', 'line\nbreak12345', 42, undefined]) {
      const id = newRequestId(bad as any);
      expect(id).toMatch(/^[0-9a-f-]{36}$/);
    }
  });
});

@Injectable() class DenyGuard implements CanActivate {
  canActivate(ctx: ExecutionContext) {
    const h = ctx.switchToHttp().getRequest().headers['x-test-fail'];
    if (h === '401') throw new UnauthorizedException('no token');
    if (h === '403') throw new ForbiddenException('wrong role');
    return true;
  }
}

@Controller()
class Probe {
  @Get('t/ip') ip(@Req() req: any) { return { ip: extractIp(req) }; }
  @Get('t/admin') admin() { return { ok: true }; }
  @Get('t/express') express(@Req() req: any) { return { ip: req.ip }; }
  @Post('api/v1/security/probe') audited() { return { ok: true }; }
}

describe('over HTTP: a spoofed X-Forwarded-For changes nothing', () => {
  let app: INestApplication; let audit: any[];
  beforeEach(async () => {
    audit = [];
    const mod = await Test.createTestingModule({
      imports: [ThrottlerModule.forRoot([{ name: 'ip', ttl: 60000, limit: 5 }, { name: 'key', ttl: 60000, limit: 50 }])],
      controllers: [Probe],
      providers: [
        { provide: APP_GUARD, useClass: AppThrottlerGuard },
        { provide: APP_GUARD, useClass: DenyGuard },
        { provide: AuditService, useValue: { log: async (e: any) => { audit.push(e); } } },
        { provide: APP_INTERCEPTOR, useClass: RequestIdInterceptor },
        { provide: APP_INTERCEPTOR, useFactory: (a: AuditService) => new AuditInterceptor(a), inject: [AuditService] },
      ],
    }).compile();
    app = mod.createNestApplication();
    configureApp(app);
    app.useGlobalFilters(new AllExceptionsFilter());
    await app.init();
  });
  afterEach(() => app.close());
  const http = () => request(app.getHttpServer());
  const statuses = async (n: number, make: (i: number) => request.Test) => {
    const out: number[] = []; for (let i = 0; i < n; i++) out.push((await make(i)).status); return out;
  };

  it('rate limit: an untrusted caller cannot get a fresh allowance by changing the header', async () => {
    const s = await statuses(8, (i) => http().get('/t/admin').set('X-Forwarded-For', `203.0.113.${i + 10}`));
    expect(s).toEqual([200, 200, 200, 200, 200, 429, 429, 429]);
  });

  it('rate limit: spoofed left-hand entries behind a trusted proxy stay in the real visitor\'s bucket', async () => {
    setProxies('127.0.0.1, ::1');
    const s = await statuses(7, (i) => http().get('/t/admin').set('X-Forwarded-For', `10.9.9.${i}, 203.0.113.50`));
    expect(s).toEqual([200, 200, 200, 200, 200, 429, 429]);
  });

  it('rate limit: two real visitors behind a trusted proxy are counted separately', async () => {
    setProxies('127.0.0.1, ::1');
    await statuses(6, () => http().get('/t/admin').set('X-Forwarded-For', '203.0.113.51'));
    const other = await http().get('/t/admin').set('X-Forwarded-For', '203.0.113.52');
    expect(other.status).toBe(200);
  });

  it('the address a request is credited to is the connection, not the header, without trusted proxies', async () => {
    const r = await http().get('/t/ip').set('X-Forwarded-For', '9.9.9.9').set('X-Real-IP', '8.8.8.8');
    expect(LOCAL).toContain(r.body.ip === '127.0.0.1' ? '127.0.0.1' : r.body.ip);
    expect(r.body.ip).not.toBe('9.9.9.9');
    expect(r.body.ip).not.toBe('8.8.8.8');
  });

  it('audit record: carries the connection address, not a forged one', async () => {
    await http().post('/api/v1/security/probe').set('X-Forwarded-For', '9.9.9.9').expect(201);
    expect(audit).toHaveLength(1);
    expect(audit[0].ipAddress).not.toBe('9.9.9.9');
    expect(LOCAL).toContain(audit[0].ipAddress);
  });

  it('audit record: carries the real visitor behind a trusted proxy', async () => {
    setProxies('127.0.0.1, ::1');
    await http().post('/api/v1/security/probe').set('X-Forwarded-For', '9.9.9.9, 203.0.113.60').expect(201);
    expect(audit[0].ipAddress).toBe('203.0.113.60');
  });

  it('Express itself follows the same trust rule as the address function (req.ip)', async () => {
    const untrusted = await http().get('/t/express').set('X-Forwarded-For', '203.0.113.55');
    expect(untrusted.body.ip).not.toBe('203.0.113.55');
    setProxies('127.0.0.1, ::1');
    const trusted = await http().get('/t/express').set('X-Forwarded-For', '203.0.113.55');
    expect(trusted.body.ip).toBe('203.0.113.55');
  });

  it('a 401 from a guard carries a request id in the body and the header', async () => {
    const r = await http().get('/t/admin').set('X-Test-Fail', '401').expect(401);
    expect(r.body.requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(r.headers['x-request-id']).toBe(r.body.requestId);
  });

  it('a 403 from a guard carries a request id, and a safe caller id is echoed back', async () => {
    const r = await http().get('/t/admin').set('X-Test-Fail', '403').set('X-Request-Id', 'support-ref-0001').expect(403);
    expect(r.body.requestId).toBe('support-ref-0001');
    expect(r.headers['x-request-id']).toBe('support-ref-0001');
  });

  it('a 429 carries a request id too, and an unsafe caller id is replaced', async () => {
    await statuses(5, () => http().get('/t/admin'));
    const r = await http().get('/t/admin').set('X-Request-Id', '<script>alert(1)</script>').expect(429);
    expect(r.body.requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(r.headers['x-request-id']).toBe(r.body.requestId);
  });

  it('a request id is on successful responses as well', async () => {
    const r = await http().get('/t/ip').expect(200);
    expect(r.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('over HTTP: the login record uses the one address function', () => {
  let app: INestApplication; let audit: any[];
  beforeEach(async () => {
    audit = [];
    const users = [{ id: 'u1', email: 'admin@pishon.ng', passwordHash: await bcrypt.hash('CorrectHorse!1', 4), role: 'SECURITY_ADMIN', isActive: true, name: 'Admin', mustChangePassword: false }];
    const tokens: any[] = []; let seq = 0;
    const prisma: any = {
      securityUser: {
        findUnique: async ({ where }: any) => users.find((u) => (where.email ? u.email === where.email : u.id === where.id)) ?? null,
        update: async ({ where, data }: any) => Object.assign(users.find((u) => u.id === where.id)!, data),
      },
      securityRefreshToken: { create: async ({ data }: any) => { const t = { id: `t${++seq}`, revokedAt: null, ...data }; tokens.push(t); return t; } },
    };
    const mod = await Test.createTestingModule({
      imports: [JwtModule.register({})],
      controllers: [AuthController],
      providers: [
        AuthService, { provide: UsersService, useValue: {} }, { provide: PrismaService, useValue: prisma },
        { provide: AuditService, useValue: { log: async (e: any) => { audit.push(e); } } },
      ],
    }).compile();
    app = mod.createNestApplication();
    configureApp(app);
    app.useGlobalFilters(new AllExceptionsFilter());
    await app.init();
  });
  afterEach(() => app.close());
  const login = (pw: string, xff: string) => request(app.getHttpServer()).post('/api/v1/auth/login').set('X-Forwarded-For', xff).send({ email: 'admin@pishon.ng', password: pw });

  it('failed and successful sign-ins record the connection address when the header is forged', async () => {
    await login('wrong-password-1', '9.9.9.9').expect(401);
    await login('CorrectHorse!1', '9.9.9.9').expect(201);
    expect(audit.map((a) => a.result)).toEqual(['FAILURE', 'SUCCESS']);
    for (const a of audit) { expect(a.ipAddress).not.toBe('9.9.9.9'); expect(LOCAL).toContain(a.ipAddress); }
  });

  it('record the real visitor behind a trusted proxy', async () => {
    setProxies('127.0.0.1, ::1');
    await login('CorrectHorse!1', '9.9.9.9, 203.0.113.70').expect(201);
    expect(audit[0].ipAddress).toBe('203.0.113.70');
  });

  it('a failed sign-in error carries a request id', async () => {
    const r = await login('wrong-password-1', '9.9.9.9').expect(401);
    expect(r.body.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });
});
