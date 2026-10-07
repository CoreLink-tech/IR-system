import 'reflect-metadata';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import * as bcrypt from 'bcryptjs';
import { AuthController } from '../src/auth/auth.controller';
import { AuthService } from '../src/auth/auth.service';
import { UsersService } from '../src/auth/users.service';
import { PrismaService } from '../src/prisma/prisma.service';
import { AuditService } from '../src/audit/audit.service';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';

process.env.JWT_SECRET = 'access-secret-for-tests-0123456789abcdef0123456789abcdef';
process.env.JWT_REFRESH_SECRET = 'refresh-secret-for-tests-fedcba9876543210fedcba9876543210';
process.env.CORS_ORIGINS = 'https://dash.pishon.ng';
process.env.NODE_ENV = 'production';

const ORIGIN = 'https://dash.pishon.ng';

/** The real AuthService and controller, with an in-memory database. */
describe('browser cookie session (real AuthService over HTTP)', () => {
  let app: INestApplication;
  let tokens: any[]; let users: any[]; let audit: any[]; let seq: number;

  beforeEach(async () => {
    tokens = []; audit = []; seq = 0;
    users = [{ id: 'u1', email: 'admin@pishon.ng', passwordHash: await bcrypt.hash('CorrectHorse!1', 4), role: 'SECURITY_ADMIN', isActive: true, name: 'Admin', mustChangePassword: false }];
    const prisma: any = {
      securityUser: {
        findUnique: async ({ where }: any) => users.find((u) => (where.email ? u.email === where.email : u.id === where.id)) ?? null,
        update: async ({ where, data }: any) => Object.assign(users.find((u) => u.id === where.id), data),
      },
      securityRefreshToken: {
        create: async ({ data }: any) => { const t = { id: `t${++seq}`, revokedAt: null, ...data }; tokens.push(t); return t; },
        findUnique: async ({ where }: any) => tokens.find((t) => t.tokenHash === where.tokenHash) ?? null,
        update: async ({ where, data }: any) => Object.assign(tokens.find((t) => t.id === where.id), data),
        updateMany: async ({ where, data }: any) => {
          const hit = tokens.filter((t) => (where.tokenHash ? t.tokenHash === where.tokenHash : t.userId === where.userId) && t.revokedAt === null);
          hit.forEach((t) => Object.assign(t, data));
          return { count: hit.length };
        },
      },
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
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new AllExceptionsFilter());
    await app.init();
  });
  afterEach(() => app.close());

  const http = () => request(app.getHttpServer());
  const cookieOf = (res: request.Response) => ((res.headers['set-cookie'] as unknown as string[]) || []).find((c) => c.startsWith('pishon_rt='));
  const pair = (c?: string) => (c || '').split(';')[0];
  const login = (extra: any = {}) => http().post('/api/v1/auth/login').send({ email: 'admin@pishon.ng', password: 'CorrectHorse!1', useCookie: true, ...extra });

  it('signs in with the token in an httpOnly cookie and never in the body', async () => {
    const res = await login().expect(201);
    const c = cookieOf(res)!;
    expect(c).toMatch(/HttpOnly/); expect(c).toMatch(/SameSite=Strict/); expect(c).toMatch(/Secure/); expect(c).toMatch(/Path=\/api\/v1\/auth/);
    expect(res.body.refreshToken).toBeUndefined();
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.csrfToken).toBeTruthy();
    expect(res.headers['cache-control']).toBe('no-store');
    // The raw token appears nowhere in the body.
    const raw = decodeURIComponent(pair(c).split('=')[1]);
    expect(JSON.stringify(res.body)).not.toContain(raw);
  });

  it('keeps the original flow for non-browser clients: token in the body, no cookie', async () => {
    const res = await login({ useCookie: undefined }).expect(201);
    expect(res.body.refreshToken).toBeTruthy();
    expect(cookieOf(res)).toBeUndefined();
    const again = await http().post('/api/v1/auth/refresh').send({ refreshToken: res.body.refreshToken }).expect(201);
    expect(again.body.refreshToken).toBeTruthy();
    expect(cookieOf(again)).toBeUndefined();
  });

  it('refreshes from the cookie with the right origin and token, and rotates both', async () => {
    const first = await login().expect(201);
    const cookie = pair(cookieOf(first));
    const res = await http().post('/api/v1/auth/refresh').set('Cookie', cookie).set('Origin', ORIGIN).set('X-CSRF-Token', first.body.csrfToken).send({}).expect(201);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.refreshToken).toBeUndefined();
    expect(res.body.csrfToken).not.toBe(first.body.csrfToken);
    expect(pair(cookieOf(res))).not.toBe(cookie);
  });

  it('refuses a refresh with no origin, a foreign origin, or no or wrong token, and keeps the session', async () => {
    const first = await login().expect(201);
    const cookie = pair(cookieOf(first));
    const send = (origin: string | undefined, token: string | undefined) => {
      let r = http().post('/api/v1/auth/refresh').set('Cookie', cookie);
      if (origin) r = r.set('Origin', origin);
      if (token) r = r.set('X-CSRF-Token', token);
      return r.send({});
    };
    expect((await send(undefined, first.body.csrfToken).expect(403)).body.code).toBe('origin_not_allowed');
    expect((await send('https://evil.test', first.body.csrfToken).expect(403)).body.code).toBe('origin_not_allowed');
    expect((await send(ORIGIN, undefined).expect(403)).body.code).toBe('csrf_invalid');
    expect((await send(ORIGIN, 'wrong').expect(403)).body.code).toBe('csrf_invalid');
    expect(tokens.filter((t) => t.revokedAt === null)).toHaveLength(1); // nothing was consumed
    await send(ORIGIN, first.body.csrfToken).expect(201); // and the genuine request still works
  });

  it('gives the token for a reloaded page only to someone holding a valid cookie', async () => {
    const first = await login().expect(201);
    const ok = await http().get('/api/v1/auth/csrf').set('Cookie', pair(cookieOf(first))).expect(200);
    expect(ok.body.csrfToken).toBe(first.body.csrfToken);
    expect((await http().get('/api/v1/auth/csrf').expect(401)).body.code).toBe('no_session');
    const forged = await http().get('/api/v1/auth/csrf').set('Cookie', 'pishon_rt=not.a.jwt').expect(401);
    expect(forged.body.code).toBe('no_session');
  });

  it('answers a missing cookie with no_session', async () => {
    expect((await http().post('/api/v1/auth/refresh').set('Origin', ORIGIN).send({}).expect(401)).body.code).toBe('no_session');
  });

  it('detects a reused token, ends every session, says so with a code, and clears the cookie', async () => {
    const first = await login().expect(201);
    const old = pair(cookieOf(first));
    const second = await http().post('/api/v1/auth/refresh').set('Cookie', old).set('Origin', ORIGIN).set('X-CSRF-Token', first.body.csrfToken).send({}).expect(201);
    expect(second.body.accessToken).toBeTruthy();
    // The old cookie value is presented again: a copy was kept.
    const replay = await http().post('/api/v1/auth/refresh').set('Cookie', old).set('Origin', ORIGIN).set('X-CSRF-Token', first.body.csrfToken).send({}).expect(401);
    expect(replay.body.code).toBe('refresh_token_reuse');
    expect(cookieOf(replay)).toMatch(/Max-Age=0/);
    expect(tokens.every((t) => t.revokedAt !== null)).toBe(true); // the genuine newest session is gone too
    expect(audit.some((e) => e.metadata?.reason === 'refresh_token_reuse')).toBe(true);
  });

  it('signs out with the same protections, revokes the token and clears the cookie', async () => {
    const first = await login().expect(201);
    const cookie = pair(cookieOf(first));
    await http().post('/api/v1/auth/logout').set('Cookie', cookie).set('Origin', 'https://evil.test').set('X-CSRF-Token', first.body.csrfToken).send({}).expect(403);
    expect(tokens[0].revokedAt).toBeNull();
    const out = await http().post('/api/v1/auth/logout').set('Cookie', cookie).set('Origin', ORIGIN).set('X-CSRF-Token', first.body.csrfToken).send({}).expect(201);
    expect(out.body).toEqual({ ok: true });
    expect(cookieOf(out)).toMatch(/Max-Age=0/);
    expect(tokens[0].revokedAt).toBeInstanceOf(Date);
  });

  it('does not reveal which part of a failed sign-in was wrong, and sets no cookie', async () => {
    const a = await login({ password: 'WrongPassword!1' }).expect(401);
    const b = await login({ email: 'nobody@pishon.ng' }).expect(401);
    expect(a.body.message).toBe(b.body.message);
    expect(cookieOf(a)).toBeUndefined(); expect(cookieOf(b)).toBeUndefined();
  });

  it('REGRESSION cookie plus body: a token in the body wins, so an old client behaves as before', async () => {
    const first = await login({ useCookie: undefined }).expect(201);
    const res = await http().post('/api/v1/auth/refresh').set('Cookie', 'pishon_rt=garbage').send({ refreshToken: first.body.refreshToken }).expect(201);
    expect(res.body.refreshToken).toBeTruthy();
  });
});
