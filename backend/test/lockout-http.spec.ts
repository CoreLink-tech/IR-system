import { TwoFactorService } from '../src/auth/two-factor.service';
import 'reflect-metadata';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ThrottlerModule } from '@nestjs/throttler';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import * as bcrypt from 'bcryptjs';
import { AuthController } from '../src/auth/auth.controller';
import { AuthService } from '../src/auth/auth.service';
import { UsersService } from '../src/auth/users.service';
import { SessionsService } from '../src/auth/sessions.service';
import { LoginThrottleService } from '../src/auth/login-throttle.service';
import { JwtStrategy } from '../src/auth/jwt.strategy';
import { PrismaService } from '../src/prisma/prisma.service';
import { AuditService } from '../src/audit/audit.service';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';
import { AppThrottlerGuard } from '../src/common/guards/app-throttler.guard';
import { configureApp } from '../src/common/configure-app';
import { loginKey } from '../src/auth/login-throttle';
import { InMemoryThrottle } from './helpers/in-memory-throttle';

process.env.JWT_SECRET = 'access-secret-for-tests-0123456789abcdef0123456789abcdef';
process.env.JWT_REFRESH_SECRET = 'refresh-secret-for-tests-fedcba9876543210fedcba9876543210';
process.env.NODE_ENV = 'test';
const PW = 'CorrectHorse!1';
const WRONG = 'Wrong-Guess-0001';

/** The real login path, the real per-address rate limiter, and a clock the test moves. */
describe('sign-in lockout (real login path over HTTP)', () => {
  let app: INestApplication; let users: any[]; let audit: any[]; let throttle: InMemoryThrottle;

  async function boot(env: Record<string, string> = {}, perIpLimit = 20) {
    audit = []; throttle = new InMemoryThrottle(env);
    const hash = await bcrypt.hash(PW, 4);
    users = ['admin', 'viewer', 'other'].map((n, i) => ({ id: n, email: `${n}@example.com`, passwordHash: hash, role: i === 0 ? 'SUPER_ADMIN' : 'VIEWER', isActive: true, name: n, mustChangePassword: false, tokenVersion: 0, createdAt: new Date(i) }));
    const prisma: any = {
      securityUser: {
        findUnique: async ({ where, select }: any) => {
          const u = users.find((x) => (where.email ? x.email === where.email : x.id === where.id)) ?? null;
          return u && select ? Object.fromEntries(Object.keys(select).map((k) => [k, u[k]])) : u;
        },
        findMany: async () => users.map((u) => ({ ...u })),
        update: async ({ where, data }: any) => Object.assign(users.find((u) => u.id === where.id), Object.fromEntries(Object.entries<any>(data).map(([k, v]) => [k, v && typeof v === 'object' && 'increment' in v ? 1 : v]))),
      },
      securityRefreshToken: { create: async ({ data }: any) => ({ id: 't', ...data }), findUnique: async () => null, update: async () => ({}), updateMany: async () => ({ count: 0 }), findMany: async () => [] },
      $transaction: async (ops: any) => (Array.isArray(ops) ? Promise.all(ops) : ops({})),
    };
    const mod = await Test.createTestingModule({
      imports: [PassportModule, JwtModule.register({}), ThrottlerModule.forRoot([{ name: 'ip', ttl: 60_000, limit: 120 }, { name: 'key', ttl: 60_000, limit: 6000 }])],
      controllers: [AuthController],
      providers: [
        { provide: APP_GUARD, useClass: AppThrottlerGuard },
        AuthService, TwoFactorService, UsersService, SessionsService, JwtStrategy,
        { provide: LoginThrottleService, useValue: throttle },
        { provide: PrismaService, useValue: prisma },
        { provide: AuditService, useValue: { log: async (e: any) => { audit.push(e); } } },
      ],
    }).compile();
    app = mod.createNestApplication();
    configureApp(app);
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new AllExceptionsFilter());
    await app.init();
  }

  beforeEach(() => { process.env.TRUSTED_PROXIES = '127.0.0.1, ::1'; process.env.THROTTLE_LOGIN_LIMIT = '20'; });
  afterEach(async () => { delete process.env.TRUSTED_PROXIES; delete process.env.THROTTLE_LOGIN_LIMIT; if (app) await app.close(); });

  const login = (email: string, password: string, from = '203.0.113.10') =>
    request(app.getHttpServer()).post('/api/v1/auth/login').set('X-Forwarded-For', from).send({ email, password });
  const bearer = async (email = 'admin@example.com') => (await login(email, PW, '198.51.100.1').expect(201)).body.accessToken as string;
  // A password that was actually checked writes an auth.login entry (success or failure). A refusal during a lock writes none.
  const checkedPasswords = () => audit.filter((a) => a.action === 'auth.login').length;
  const lockEntries = () => audit.filter((a) => a.action === 'auth.lockout');

  it('five wrong attempts are free; the fifth says how long to wait; the sixth is refused with 429 and a Retry-After header', async () => {
    await boot();
    for (let i = 1; i <= 4; i++) { const r = await login('viewer@example.com', WRONG).expect(401); expect(r.body.retryAfterSeconds).toBeUndefined(); }
    const fifth = await login('viewer@example.com', WRONG).expect(401);
    expect(fifth.body).toMatchObject({ code: 'invalid_credentials', retryAfterSeconds: 30 });
    expect(fifth.body.message).toContain('try again in 30 seconds');
    const sixth = await login('viewer@example.com', WRONG).expect(429);
    expect(sixth.body).toMatchObject({ code: 'account_locked', retryAfterSeconds: 30 });
    expect(sixth.body.message).toBe('Too many sign-in attempts. Try again in 30 seconds.');
    expect(sixth.headers['retry-after']).toBe('30');
    expect(sixth.body.requestId).toBeTruthy();
  });

  it('while locked the password is not even checked, so the right password does not get in and the guess count is capped', async () => {
    await boot();
    for (let i = 0; i < 5; i++) await login('viewer@example.com', WRONG);
    const before = checkedPasswords();
    for (let i = 0; i < 20; i++) await login('viewer@example.com', i % 2 ? WRONG : PW).expect(429);
    expect(checkedPasswords()).toBe(before);
  });

  it('after the delay the right password works at once and wipes the count', async () => {
    await boot();
    for (let i = 0; i < 5; i++) await login('viewer@example.com', WRONG);
    throttle.advance(29); await login('viewer@example.com', PW).expect(429);
    throttle.advance(2);  await login('viewer@example.com', PW).expect(201);
    expect(throttle.store.has(loginKey('viewer@example.com'))).toBe(false);
    for (let i = 0; i < 4; i++) await login('viewer@example.com', WRONG).expect(401);   // five free attempts again
  });

  it('a right password on the fifth try is not penalised', async () => {
    await boot();
    for (let i = 0; i < 4; i++) await login('viewer@example.com', WRONG);
    await login('viewer@example.com', PW).expect(201);
    expect(throttle.store.has(loginKey('viewer@example.com'))).toBe(false);
    expect(lockEntries()).toHaveLength(0);
  });

  it('each further wrong attempt after a lock doubles the wait, up to a cap, and it never becomes permanent', async () => {
    await boot();
    for (let i = 0; i < 5; i++) await login('viewer@example.com', WRONG);
    const seen: number[] = [30];
    for (let level = 0; level < 7; level++) {
      throttle.advance(seen[seen.length - 1] + 1);
      const r = await login('viewer@example.com', WRONG).expect(401);
      seen.push(r.body.retryAfterSeconds);
    }
    expect(seen).toEqual([30, 60, 120, 240, 480, 900, 900, 900]);
    throttle.advance(901);
    await login('viewer@example.com', PW).expect(201);                                   // still gets in after the longest delay
  });

  it('hammering during a lock never makes it longer', async () => {
    await boot();
    for (let i = 0; i < 5; i++) await login('viewer@example.com', WRONG);
    const until = throttle.store.get(loginKey('viewer@example.com'))!.lockedUntil!.getTime();
    for (let i = 0; i < 100; i++) await login('viewer@example.com', WRONG, `192.0.2.${i % 200}`).expect(i < 0 ? 401 : 429);
    expect(throttle.store.get(loginKey('viewer@example.com'))!.lockedUntil!.getTime()).toBe(until);
    expect(throttle.store.get(loginKey('viewer@example.com'))!.failures).toBe(5);
  });

  it('failures are forgotten after an hour of quiet', async () => {
    await boot();
    for (let i = 0; i < 4; i++) await login('viewer@example.com', WRONG);
    throttle.advance(61 * 60);
    for (let i = 0; i < 4; i++) await login('viewer@example.com', WRONG).expect(401);
    expect(lockEntries()).toHaveLength(0);
  });

  describe('credential stuffing against the administrator login', () => {
    it('MANY ADDRESSES, ONE ACCOUNT: 60 addresses guess at the admin; only five guesses are ever checked, and the real admin gets in after the delay', async () => {
      await boot();
      const before = checkedPasswords();
      const codes: number[] = [];
      for (let i = 0; i < 60; i++) codes.push((await login('admin@example.com', `Guess-${i}-Wrong-Pw`, `203.0.${i}.9`)).status);
      expect(codes.filter((c) => c === 401)).toHaveLength(5);
      expect(codes.filter((c) => c === 429)).toHaveLength(55);
      expect(checkedPasswords() - before).toBe(5);
      await login('admin@example.com', PW, '198.51.100.1').expect(429);              // the real admin is held up too ...
      throttle.advance(31);
      await login('admin@example.com', PW, '198.51.100.1').expect(201);              // ... but only for the delay
    });

    it('MANY ADDRESSES AT ONCE: a simultaneous burst still gets no more than five password checks', async () => {
      await boot();
      const before = checkedPasswords();
      const results = await Promise.all(Array.from({ length: 60 }, (_, i) => login('admin@example.com', `Burst-${i}-Wrong-Pw`, `203.0.${i}.77`)));
      expect(results.filter((r) => r.status === 401)).toHaveLength(5);
      expect(checkedPasswords() - before).toBe(5);
    });

    it('ONE ADDRESS, MANY ACCOUNTS: no account is locked by it, the address is stopped by the per-address limit, and the real admin signs in', async () => {
      await boot();
      const emails = Array.from({ length: 40 }, (_, i) => (i % 3 === 0 ? 'viewer@example.com'.replace('viewer', `viewer${i}`) : `nobody${i}@example.com`));
      const codes: number[] = [];
      for (const e of emails) codes.push((await login(e, WRONG, '203.0.113.200')).status);
      expect(codes.filter((c) => c === 401)).toHaveLength(20);                           // the per-address limit (20 a minute) stops it
      expect(codes.filter((c) => c === 429)).toHaveLength(20);
      expect(throttle.store.size).toBe(20);                                               // one failure each, nothing locked
      expect([...throttle.store.values()].every((s) => s.lockedUntil === null)).toBe(true);
      await login('admin@example.com', PW, '198.51.100.1').expect(201);                  // the admin is untouched
    });

    it('a pause in the attack lets the real admin in immediately, even before the delay if the attack stops at five', async () => {
      await boot();
      for (let i = 0; i < 4; i++) await login('admin@example.com', WRONG, `203.0.${i}.9`);
      await login('admin@example.com', PW, '198.51.100.1').expect(201);                  // one guess short of a lock: no harm done
    });
  });

  it('a real and an invented address look the same: same statuses, same messages, same shape', async () => {
    await boot();
    const run = async (email: string) => {
      const out: any[] = [];
      for (let i = 0; i < 7; i++) { const r = await login(email, WRONG, `203.0.113.${50 + i}`); out.push({ s: r.status, code: r.body.code, msg: r.body.message, ra: r.body.retryAfterSeconds, keys: Object.keys(r.body).sort().join() }); }
      return out;
    };
    expect(await run('viewer@example.com')).toEqual(await run('nobody-at-all@example.com'));
  });

  it('an email address is stored only as a hash', async () => {
    await boot();
    await login('viewer@example.com', WRONG);
    expect([...throttle.store.keys()][0]).toMatch(/^login:[0-9a-f]{64}$/);
    expect(JSON.stringify([...throttle.store.keys()])).not.toContain('viewer');
    expect(loginKey(' Viewer@Example.COM ')).toBe(loginKey('viewer@example.com'));
  });

  it('every lock is audited once, with the number of failures and the delay, and never the password', async () => {
    await boot();
    for (let i = 0; i < 8; i++) await login('viewer@example.com', WRONG);
    expect(lockEntries()).toHaveLength(1);
    expect(lockEntries()[0]).toMatchObject({ actorLabel: 'viewer@example.com', result: 'FAILURE', metadata: { failures: 5, lockedForSeconds: 30 } });
    throttle.advance(31); await login('viewer@example.com', WRONG);
    expect(lockEntries()).toHaveLength(2);
    expect(lockEntries()[1].metadata).toMatchObject({ failures: 6, lockedForSeconds: 60 });
    expect(JSON.stringify(audit)).not.toContain(WRONG);
    await login('nobody@example.com', WRONG);                                           // invented address: still recorded as a failure
  });

  describe('trusted networks', () => {
    it('are never locked out, and everyone else still is', async () => {
      await boot({ LOCKOUT_EXEMPT_NETWORKS: '10.0.0.0/8' });
      for (let i = 0; i < 12; i++) await login('viewer@example.com', WRONG, '10.1.2.3').expect(401);
      expect(throttle.store.size).toBe(0);
      await login('viewer@example.com', PW, '10.1.2.3').expect(201);
      for (let i = 0; i < 5; i++) await login('other@example.com', WRONG, '203.0.113.5');
      await login('other@example.com', PW, '10.1.2.3').expect(201);                       // the trusted network is exempt even when the account is locked from outside
    });
    it('are decided from the address the server sees, not a header an outsider can set', async () => {
      process.env.TRUSTED_PROXIES = '';
      await boot({ LOCKOUT_EXEMPT_NETWORKS: '10.0.0.0/8' });
      for (let i = 0; i < 5; i++) await login('viewer@example.com', WRONG, '10.1.2.3');
      await login('viewer@example.com', PW, '10.1.2.3').expect(429);                      // forged X-Forwarded-For earns no exemption
    });
  });

  describe('a super admin can unlock', () => {
    it('unlocking lets the person in at once, and is audited', async () => {
      await boot();
      const admin = await bearer();
      for (let i = 0; i < 5; i++) await login('viewer@example.com', WRONG);
      await login('viewer@example.com', PW).expect(429);
      const list = (await request(app.getHttpServer()).get('/api/v1/auth/users').set('Authorization', `Bearer ${admin}`).expect(200)).body.data;
      expect(list.find((u: any) => u.email === 'viewer@example.com').lockedUntil).toBeTruthy();
      expect(list.find((u: any) => u.email === 'other@example.com').lockedUntil).toBeNull();
      await request(app.getHttpServer()).post('/api/v1/auth/users/viewer/unlock').set('Authorization', `Bearer ${admin}`).expect(201);
      await login('viewer@example.com', PW).expect(201);
      expect(audit.find((a) => a.action === 'auth.unlock')).toMatchObject({ actorId: 'admin', targetId: 'viewer', metadata: { email: 'viewer@example.com' } });
      await request(app.getHttpServer()).post('/api/v1/auth/users/nobody/unlock').set('Authorization', `Bearer ${admin}`).expect(404);
    });
    it('only a super admin can', async () => {
      await boot();
      const viewer = await bearer('viewer@example.com');
      await request(app.getHttpServer()).post('/api/v1/auth/users/other/unlock').set('Authorization', `Bearer ${viewer}`).expect(403);
      await request(app.getHttpServer()).post('/api/v1/auth/users/other/unlock').expect(401);
    });
    it('an administrator password reset also clears the lock, so the temporary password can be used', async () => {
      await boot();
      const admin = await bearer();
      for (let i = 0; i < 5; i++) await login('viewer@example.com', WRONG);
      await request(app.getHttpServer()).post('/api/v1/auth/users/viewer/reset-password').set('Authorization', `Bearer ${admin}`).send({ newPassword: 'Temporary-Violet-Lantern-9' }).expect(201);
      await login('viewer@example.com', 'Temporary-Violet-Lantern-9').expect(201);
    });
  });
});
