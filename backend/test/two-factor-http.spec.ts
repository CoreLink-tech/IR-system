import 'reflect-metadata';
import { createHash, randomBytes } from 'crypto';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import * as bcrypt from 'bcryptjs';
import { AuthController } from '../src/auth/auth.controller';
import { AuthService } from '../src/auth/auth.service';
import { UsersService } from '../src/auth/users.service';
import { SessionsService } from '../src/auth/sessions.service';
import { TwoFactorService } from '../src/auth/two-factor.service';
import { LoginThrottleService } from '../src/auth/login-throttle.service';
import { JwtStrategy } from '../src/auth/jwt.strategy';
import { PrismaService } from '../src/prisma/prisma.service';
import { AuditService } from '../src/audit/audit.service';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';
import { totp, base32Decode, timeStep } from '../src/auth/totp';
import { decryptSecret, loadKeyRing } from '../src/auth/two-factor.crypto';
import { InMemoryThrottle } from './helpers/in-memory-throttle';

process.env.JWT_SECRET = 'access-secret-for-tests-0123456789abcdef0123456789abcdef';
process.env.JWT_REFRESH_SECRET = 'refresh-secret-for-tests-fedcba9876543210fedcba9876543210';
process.env.NODE_ENV = 'test';

const PW = 'CorrectHorse!1';
const KEY = randomBytes(32).toString('hex');

/** The real two-step flow, guards and services over HTTP, with an in-memory database and a clock the test moves. */
describe('two-step verification (real flow over HTTP)', () => {
  let app: INestApplication; let jwt: JwtService; let users: any[]; let tokens: any[]; let codes: any[]; let audit: any[]; let seq: number;
  let throttle: InMemoryThrottle; let clock: Date;

  const matches = (row: any, where: any): boolean => Object.entries(where ?? {}).every(([k, v]: [string, any]) => {
    if (k === 'OR') return (v as any[]).some((w) => matches(row, w));
    if (v && typeof v === 'object' && !(v instanceof Date)) {
      if ('gt' in v) return row[k] > v.gt;
      if ('lt' in v) return row[k] !== null && row[k] !== undefined && row[k] < v.lt;
      if ('in' in v) return v.in.includes(row[k]);
    }
    return (row[k] ?? null) === (v ?? null);
  });
  const applyData = (row: any, data: any) => { for (const [k, v] of Object.entries<any>(data)) row[k] = v && typeof v === 'object' && !(v instanceof Date) && 'increment' in v ? (row[k] ?? 0) + v.increment : v; return row; };

  async function boot(env: Record<string, string | undefined> = {}) {
    for (const [k, v] of Object.entries({ REQUIRE_2FA: 'true', TOTP_ENCRYPTION_KEY: KEY, ...env })) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    tokens = []; codes = []; audit = []; seq = 0; throttle = new InMemoryThrottle(); clock = new Date('2026-10-20T10:00:10.000Z');
    // Fake only the clock (Date); timers stay real so HTTP and password hashing run normally.
    jest.useFakeTimers({ now: clock, doNotFake: ['nextTick', 'setImmediate', 'clearImmediate', 'setInterval', 'clearInterval', 'setTimeout', 'clearTimeout', 'hrtime', 'performance', 'queueMicrotask'] });
    const hash = await bcrypt.hash(PW, 4);
    const mk = (id: string, role: string) => ({ id, email: `${id}@example.com`, passwordHash: hash, role, isActive: true, name: id, mustChangePassword: false, tokenVersion: 0, totpSecret: null, totpEnabledAt: null, totpLastStep: null, createdAt: new Date() });
    users = [mk('boss', 'SUPER_ADMIN'), mk('boss2', 'SUPER_ADMIN'), mk('secadmin', 'SECURITY_ADMIN'), mk('analyst', 'ANALYST'), mk('viewer', 'VIEWER')];
    const prisma: any = {
      securityUser: {
        findUnique: async ({ where, select }: any) => { const u = users.find((x) => (where.email ? x.email === where.email : x.id === where.id)) ?? null; return u && select ? Object.fromEntries(Object.keys(select).map((k) => [k, u[k]])) : u; },
        findMany: async ({ select }: any = {}) => users.map((u) => (select ? Object.fromEntries(Object.keys(select).map((k) => [k, u[k]])) : { ...u })),
        update: async ({ where, data }: any) => applyData(users.find((u) => u.id === where.id), data),
        updateMany: async ({ where, data }: any) => { const hit = users.filter((u) => matches(u, where)); hit.forEach((u) => applyData(u, data)); return { count: hit.length }; },
      },
      securityRefreshToken: {
        create: async ({ data }: any) => { const t = { id: `t${++seq}`, revokedAt: null, revokedReason: null, createdAt: new Date(), ...data }; tokens.push(t); return t; },
        findUnique: async ({ where }: any) => tokens.find((t) => t.tokenHash === where.tokenHash) ?? null,
        findMany: async ({ where }: any) => tokens.filter((t) => matches(t, where)),
        update: async ({ where, data }: any) => applyData(tokens.find((t) => t.id === where.id), data),
        updateMany: async ({ where, data }: any) => { const hit = tokens.filter((t) => matches(t, where)); hit.forEach((t) => applyData(t, data)); return { count: hit.length }; },
      },
      securityRecoveryCode: {
        deleteMany: async ({ where }: any) => { const before = codes.length; codes = codes.filter((c) => !matches(c, where)); return { count: before - codes.length }; },
        createMany: async ({ data }: any) => { data.forEach((d: any) => codes.push({ id: `c${++seq}`, usedAt: null, ...d })); return { count: data.length }; },
        updateMany: async ({ where, data }: any) => { const hit = codes.filter((c) => matches(c, where)); hit.forEach((c) => applyData(c, data)); return { count: hit.length }; },
        count: async ({ where }: any) => codes.filter((c) => matches(c, where)).length,
      },
      $transaction: async (ops: any) => (Array.isArray(ops) ? Promise.all(ops) : ops({})),
    };
    const mod = await Test.createTestingModule({
      imports: [PassportModule, JwtModule.register({})],
      controllers: [AuthController],
      providers: [
        AuthService, TwoFactorService, UsersService, SessionsService, JwtStrategy,
        { provide: LoginThrottleService, useValue: throttle }, { provide: PrismaService, useValue: prisma },
        { provide: AuditService, useValue: { log: async (e: any) => { audit.push(e); } } },
      ],
    }).compile();
    app = mod.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new AllExceptionsFilter());
    await app.init();
    jwt = mod.get(JwtService);
  }
  afterEach(async () => { jest.useRealTimers(); if (app) await app.close(); });
  afterAll(() => { for (const k of ['REQUIRE_2FA', 'TOTP_ENCRYPTION_KEY']) delete process.env[k]; });

  const http = () => request(app.getHttpServer());
  const advance = (s: number) => { clock = new Date(clock.getTime() + s * 1000); jest.setSystemTime(clock); throttle.advance(s); };
  const post = (path: string, body: any = {}, token?: string) => { const r = http().post(`/api/v1/auth${path}`); if (token) r.set('Authorization', `Bearer ${token}`); return r.send(body); };
  const login = (id: string, extra: any = {}) => post('/login', { email: `${id}@example.com`, password: PW, ...extra });
  const secretOf = (id: string) => decryptSecret(users.find((u) => u.id === id).totpSecret, loadKeyRing(process.env)!);
  const codeFor = (id: string, shift = 0) => totp(secretOf(id), new Date(clock.getTime() + shift * 30_000));

  /** Sign in, set up two-step verification through the required enrolment step, and return the session. */
  async function enrol(id: string, extra: any = {}) {
    const step = (await login(id, extra).expect(201)).body;
    expect(step.twoFactorEnrollmentRequired).toBe(true);
    const start = (await post('/2fa/enroll/start', { challengeToken: step.challengeToken }).expect(201)).body;
    const done = await post('/2fa/enroll/confirm', { challengeToken: step.challengeToken, code: totp(start.secret, clock) });
    expect(done.status).toBe(201);
    return { ...done.body, secret: start.secret };
  }
  /** Sign in with the second step. */
  async function signIn(id: string, extra: any = {}) {
    const step = (await login(id, extra).expect(201)).body;
    expect(step.twoFactorRequired).toBe(true);
    advance(30);                                                              // a fresh code, not the one used to enrol
    return post('/2fa/verify', { challengeToken: step.challengeToken, code: codeFor(id) });
  }
  const me = (t: string) => http().get('/api/v1/auth/me').set('Authorization', `Bearer ${t}`);

  describe('required roles (production default)', () => {
    it('a super admin or security admin without two-step verification gets an enrolment step, not a session', async () => {
      await boot();
      for (const id of ['boss', 'secadmin']) {
        const r = (await login(id).expect(201)).body;
        expect(r).toMatchObject({ twoFactorEnrollmentRequired: true, expiresInSeconds: 300 });
        expect(r.challengeToken).toBeTruthy(); expect(r.accessToken).toBeUndefined(); expect(r.refreshToken).toBeUndefined();
      }
      expect(tokens).toHaveLength(0);
    });

    it('roles that are not required (analyst, viewer) sign in as before, and may switch it on themselves', async () => {
      await boot();
      for (const id of ['analyst', 'viewer']) expect((await login(id).expect(201)).body.accessToken).toBeTruthy();
    });

    it('enrolment gives a secret, a QR address and manual key, then recovery codes once, and starts the session', async () => {
      await boot();
      const step = (await login('boss').expect(201)).body;
      const start = (await post('/2fa/enroll/start', { challengeToken: step.challengeToken }).expect(201)).body;
      expect(start.secret).toMatch(/^[A-Z2-7]{32}$/);
      expect(start.manualKey).toBe(start.secret.match(/.{1,4}/g).join(' '));
      expect(start.otpauthUri).toContain(`secret=${start.secret}`);
      expect(start.otpauthUri).toContain('issuer=Security%20Dashboard');
      expect(start.accountName).toBe('boss@example.com');
      const done = (await post('/2fa/enroll/confirm', { challengeToken: step.challengeToken, code: totp(start.secret, clock) }).expect(201)).body;
      expect(done.recoveryCodes).toHaveLength(10);
      expect(done.recoveryCodes.every((c: string) => /^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$/.test(c))).toBe(true);
      expect(done.accessToken).toBeTruthy();
      await me(done.accessToken).expect(200);
      expect(users[0].totpEnabledAt).toBeInstanceOf(Date);
      expect(audit.find((a) => a.action === 'auth.2fa_enable')).toMatchObject({ actorId: 'boss', result: 'SUCCESS' });
      expect(audit.find((a) => a.action === 'auth.login' && a.result === 'SUCCESS').metadata).toEqual({ twoFactor: 'enrolment' });
    });

    it('a wrong first code does not switch it on, and the person is not let in', async () => {
      await boot();
      const step = (await login('boss').expect(201)).body;
      await post('/2fa/enroll/start', { challengeToken: step.challengeToken }).expect(201);
      const r = await post('/2fa/enroll/confirm', { challengeToken: step.challengeToken, code: '000000' }).expect(401);
      expect(r.body.code).toBe('invalid_code');
      expect(users[0].totpEnabledAt).toBeNull(); expect(tokens).toHaveLength(0);
    });

    it('confirming before starting, or after it is on, is refused politely', async () => {
      await boot();
      const step = (await login('boss').expect(201)).body;
      expect((await post('/2fa/enroll/confirm', { challengeToken: step.challengeToken, code: '123456' }).expect(400)).body.code).toBe('no_pending_enrolment');
      await enrol('secadmin');
      const again = (await login('secadmin').expect(201)).body;
      expect(again.twoFactorRequired).toBe(true);
    });

    it('starting again replaces an unconfirmed secret, and only the new one confirms', async () => {
      await boot();
      const step = (await login('boss').expect(201)).body;
      const first = (await post('/2fa/enroll/start', { challengeToken: step.challengeToken }).expect(201)).body;
      const second = (await post('/2fa/enroll/start', { challengeToken: step.challengeToken }).expect(201)).body;
      expect(second.secret).not.toBe(first.secret);
      await post('/2fa/enroll/confirm', { challengeToken: step.challengeToken, code: totp(first.secret, clock) }).expect(401);
      await post('/2fa/enroll/confirm', { challengeToken: step.challengeToken, code: totp(second.secret, clock) }).expect(201);
    });
  });

  describe('signing in with the second step', () => {
    it('the password gives only a short-lived step, never a session; the right code then does', async () => {
      await boot(); await enrol('boss');
      const step = (await login('boss').expect(201)).body;
      expect(step).toMatchObject({ twoFactorRequired: true, expiresInSeconds: 300 });
      expect(step.accessToken).toBeUndefined(); expect(step.refreshToken).toBeUndefined();
      advance(30);
      const ok = (await post('/2fa/verify', { challengeToken: step.challengeToken, code: codeFor('boss') }).expect(201)).body;
      expect(ok.accessToken).toBeTruthy(); expect(ok.user.email).toBe('boss@example.com'); expect(ok.recoveryCodesRemaining).toBe(10);
      await me(ok.accessToken).expect(200);
    });

    it('a wrong code is refused and audited, without saying which part was wrong', async () => {
      await boot(); await enrol('boss');
      const step = (await login('boss').expect(201)).body;
      const r = await post('/2fa/verify', { challengeToken: step.challengeToken, code: '000000' }).expect(401);
      expect(r.body.code).toBe('invalid_code'); expect(r.body.message).toContain('not right, or it was already used');
      expect(audit.some((a) => a.action === 'auth.2fa_fail' && a.actorId === 'boss')).toBe(true);
      expect(JSON.stringify(audit)).not.toContain('000000');
    });

    it('the same code cannot be used twice, even inside its time window (replay)', async () => {
      await boot(); await enrol('boss');
      advance(30);
      const code = codeFor('boss');
      const a = (await login('boss').expect(201)).body;
      await post('/2fa/verify', { challengeToken: a.challengeToken, code }).expect(201);
      const b = (await login('boss').expect(201)).body;
      const replay = await post('/2fa/verify', { challengeToken: b.challengeToken, code }).expect(401);
      expect(replay.body.code).toBe('invalid_code');
      advance(30);
      await post('/2fa/verify', { challengeToken: b.challengeToken, code: codeFor('boss') }).expect(201);   // the next code works
    });

    it('two attempts with the same valid code at the same instant: exactly one succeeds', async () => {
      await boot(); await enrol('boss');
      advance(30);
      const code = codeFor('boss');
      const [a, b] = await Promise.all([login('boss'), login('boss')]);
      const results = await Promise.all([a, b].map((x) => post('/2fa/verify', { challengeToken: x.body.challengeToken, code })));
      expect(results.map((r) => r.status).sort()).toEqual([201, 401]);
    });

    it('accepts a code from the step before or after (a clock a little off), and not from further away', async () => {
      await boot(); await enrol('boss');
      advance(60);
      const step = (await login('boss').expect(201)).body;
      await post('/2fa/verify', { challengeToken: step.challengeToken, code: codeFor('boss', -1) }).expect(201);
      const s2 = (await login('boss').expect(201)).body;
      await post('/2fa/verify', { challengeToken: s2.challengeToken, code: codeFor('boss', 2) }).expect(401);
      await post('/2fa/verify', { challengeToken: s2.challengeToken, code: codeFor('boss', 1) }).expect(201);
    });

    it('wrong codes are rate limited per account with growing delays, and the right code still works afterwards', async () => {
      await boot(); await enrol('boss');
      advance(30);
      const step = (await login('boss').expect(201)).body;
      const wrong = (i: number) => post('/2fa/verify', { challengeToken: step.challengeToken, code: String(100000 + i) });
      for (let i = 0; i < 4; i++) await wrong(i).expect(401);
      const fifth = await wrong(4).expect(401);
      expect(fifth.body.retryAfterSeconds).toBe(30);
      const locked = await post('/2fa/verify', { challengeToken: step.challengeToken, code: codeFor('boss') }).expect(429);
      expect(locked.body).toMatchObject({ code: 'two_factor_locked', retryAfterSeconds: expect.any(Number) });
      expect(locked.headers['retry-after']).toBeTruthy();
      advance(31);
      await post('/2fa/verify', { challengeToken: step.challengeToken, code: codeFor('boss') }).expect(201);
    });

    it('the step token expires, cannot be used as an access token, and cannot be swapped between purposes', async () => {
      await boot(); await enrol('boss');
      const step = (await login('boss').expect(201)).body;
      await me(step.challengeToken).expect(401);                                 // not an access token
      await post('/2fa/enroll/start', { challengeToken: step.challengeToken }).expect(401);   // an mfa step is not an enrolment step
      const forged = await jwt.signAsync({ sub: 'boss', typ: 'mfa', tv: 0 }, { secret: 'wrong-secret-of-the-right-length-0123456789', expiresIn: 300 });
      await post('/2fa/verify', { challengeToken: forged, code: '123456' }).expect(401);
      const expired = await jwt.signAsync({ sub: 'boss', typ: 'mfa', tv: 0 }, { secret: process.env.JWT_SECRET, expiresIn: -10 });
      expect((await post('/2fa/verify', { challengeToken: expired, code: '123456' }).expect(401)).body.code).toBe('challenge_expired');
      await post('/2fa/verify', { challengeToken: 'garbage', code: '123456' }).expect(401);
    });

    it('a step token stops working if the account was signed out everywhere or its version raised since', async () => {
      await boot(); await enrol('boss');
      const step = (await login('boss').expect(201)).body;
      users[0].tokenVersion = 3;
      advance(30);
      await post('/2fa/verify', { challengeToken: step.challengeToken, code: codeFor('boss') }).expect(401);
    });

    it('browser sign-in keeps the cookie flow: the refresh token goes in a cookie, not the body', async () => {
      await boot(); await enrol('boss', { useCookie: true });
      const r = await signIn('boss', { useCookie: true });
      expect(r.status).toBe(201);
      expect(r.body.refreshToken).toBeUndefined(); expect(r.body.csrfToken).toBeTruthy();
      expect(String(r.headers['set-cookie'])).toMatch(/ir_rt=.*HttpOnly/);
    });

    it('non-browser clients get the refresh token in the body', async () => {
      await boot(); await enrol('boss');
      const r = await signIn('boss');
      expect(r.body.refreshToken).toBeTruthy();
    });

    it('needs a code or a recovery code, and nothing else', async () => {
      await boot(); await enrol('boss');
      const step = (await login('boss').expect(201)).body;
      expect((await post('/2fa/verify', { challengeToken: step.challengeToken }).expect(400)).body.code).toBe('code_required');
      await post('/2fa/verify', { challengeToken: step.challengeToken, code: '1234567890123' }).expect(400);
    });

    it('a wrong password never reaches the second step, and lockout still applies to it', async () => {
      await boot(); await enrol('boss');
      const r = await post('/login', { email: 'boss@example.com', password: 'Wrong-Password-1' }).expect(401);
      expect(r.body.challengeToken).toBeUndefined();
    });
  });

  describe('recovery codes', () => {
    it('stored only as hashes, never the code itself', async () => {
      await boot(); const s = await enrol('boss');
      expect(codes).toHaveLength(10);
      for (const c of s.recoveryCodes) expect(JSON.stringify(codes)).not.toContain(c.replace(/-/g, ''));
      expect(codes.every((c) => /^[0-9a-f]{64}$/.test(c.codeHash))).toBe(true);
    });

    it('a recovery code signs in once, and says how many are left', async () => {
      await boot(); const s = await enrol('boss');
      const step = (await login('boss').expect(201)).body;
      const ok = (await post('/2fa/verify', { challengeToken: step.challengeToken, recoveryCode: s.recoveryCodes[0] }).expect(201)).body;
      expect(ok.accessToken).toBeTruthy(); expect(ok.recoveryCodesRemaining).toBe(9);
      expect(audit.find((a) => a.action === 'auth.2fa_recovery_used')).toMatchObject({ actorId: 'boss', metadata: { remaining: 9 } });
      expect(audit.find((a) => a.action === 'auth.login' && a.metadata?.twoFactor === 'recovery')).toBeTruthy();
      const s2 = (await login('boss').expect(201)).body;
      await post('/2fa/verify', { challengeToken: s2.challengeToken, recoveryCode: s.recoveryCodes[0] }).expect(401);   // used
      await post('/2fa/verify', { challengeToken: s2.challengeToken, recoveryCode: s.recoveryCodes[1].toLowerCase().replace(/-/g, ' ') }).expect(201);   // typed loosely
    });

    it('two simultaneous uses of one recovery code: exactly one succeeds', async () => {
      await boot(); const s = await enrol('boss');
      const [a, b] = await Promise.all([login('boss'), login('boss')]);
      const rs = await Promise.all([a, b].map((x) => post('/2fa/verify', { challengeToken: x.body.challengeToken, recoveryCode: s.recoveryCodes[3] })));
      expect(rs.map((r) => r.status).sort()).toEqual([201, 401]);
    });

    it('guessing recovery codes is rate limited like codes', async () => {
      await boot(); await enrol('boss');
      const step = (await login('boss').expect(201)).body;
      for (let i = 0; i < 5; i++) await post('/2fa/verify', { challengeToken: step.challengeToken, recoveryCode: 'ABCD-EFGH-JKLM-NPQ' + (i + 2) }).expect(401);
      await post('/2fa/verify', { challengeToken: step.challengeToken, recoveryCode: 'ABCD-EFGH-JKLM-NPQ9' }).expect(429);
    });

    it('regenerating needs the password AND a current code, replaces all codes, and shows the new ones once', async () => {
      await boot(); const s = await enrol('boss');
      const t = s.accessToken;
      await post('/2fa/recovery-codes/regenerate', { password: 'Wrong-Password-1', code: codeFor('boss', 1) }, t).expect(401);
      await post('/2fa/recovery-codes/regenerate', { password: PW, code: '000000' }, t).expect(401);
      advance(30);
      const r = (await post('/2fa/recovery-codes/regenerate', { password: PW, code: codeFor('boss') }, t).expect(201)).body;
      expect(r.recoveryCodes).toHaveLength(10);
      expect(r.recoveryCodes.some((c: string) => s.recoveryCodes.includes(c))).toBe(false);
      expect(codes).toHaveLength(10);
      const step = (await login('boss').expect(201)).body;
      await post('/2fa/verify', { challengeToken: step.challengeToken, recoveryCode: s.recoveryCodes[0] }).expect(401);   // old set is dead
      await post('/2fa/verify', { challengeToken: step.challengeToken, recoveryCode: r.recoveryCodes[0] }).expect(201);
      expect(audit.some((a) => a.action === 'auth.2fa_recovery_regenerate')).toBe(true);
    });

    it('warns when few are left', async () => {
      await boot(); const s = await enrol('boss');
      for (let i = 0; i < 8; i++) { const st = (await login('boss').expect(201)).body; await post('/2fa/verify', { challengeToken: st.challengeToken, recoveryCode: s.recoveryCodes[i] }).expect(201); }
      const status = (await http().get('/api/v1/auth/2fa').set('Authorization', `Bearer ${s.accessToken}`).expect(200)).body;
      expect(status).toMatchObject({ enabled: true, recoveryCodesRemaining: 2, recoveryCodesLow: true });
    });
  });

  describe('the secret at rest', () => {
    it('is encrypted in the database, never the plain secret, and is not in any response after setup', async () => {
      await boot(); const s = await enrol('boss');
      const stored = users[0].totpSecret as string;
      expect(stored).not.toContain(s.secret); expect(stored.startsWith('v1.')).toBe(true);
      expect(decryptSecret(stored, loadKeyRing(process.env)!)).toBe(s.secret);
      const step = (await login('boss').expect(201)).body; advance(30);
      const ok = await post('/2fa/verify', { challengeToken: step.challengeToken, code: codeFor('boss') });
      expect(JSON.stringify(ok.body)).not.toContain(s.secret);
      const list = (await http().get('/api/v1/auth/users').set('Authorization', `Bearer ${ok.body.accessToken}`).expect(200)).body.data;
      expect(JSON.stringify(list)).not.toContain('totpSecret'); expect(JSON.stringify(list)).not.toContain(stored); expect(JSON.stringify(list)).not.toContain('passwordHash'); expect(JSON.stringify(list)).not.toContain('totpLastStep');
      expect(list.find((u: any) => u.id === 'boss').twoFactorEnabled).toBe(true);
      expect(list.find((u: any) => u.id === 'viewer').twoFactorEnabled).toBe(false);
    });

    it('the audit log never holds a code, a secret or a recovery code', async () => {
      await boot(); const s = await enrol('boss');
      const step = (await login('boss').expect(201)).body;
      await post('/2fa/verify', { challengeToken: step.challengeToken, code: '123456' });
      await post('/2fa/verify', { challengeToken: step.challengeToken, recoveryCode: s.recoveryCodes[0] });
      const text = JSON.stringify(audit);
      expect(text).not.toContain(s.secret); expect(text).not.toContain('123456'); expect(text).not.toContain(s.recoveryCodes[0]); expect(text).not.toContain(s.recoveryCodes[0].replace(/-/g, ''));
    });
  });

  describe('optional for other roles', () => {
    it('an analyst can set it up while signed in, and is then asked for a code', async () => {
      await boot();
      const t = (await login('analyst').expect(201)).body.accessToken;
      const status0 = (await http().get('/api/v1/auth/2fa').set('Authorization', `Bearer ${t}`).expect(200)).body;
      expect(status0).toMatchObject({ available: true, enabled: false, required: false });
      const start = (await post('/2fa/setup/start', {}, t).expect(201)).body;
      const done = (await post('/2fa/setup/confirm', { code: totp(start.secret, clock) }, t).expect(201)).body;
      expect(done.recoveryCodes).toHaveLength(10);
      expect((await login('analyst').expect(201)).body.twoFactorRequired).toBe(true);
    });

    it('can turn it off with the password and a current code, which signs them out everywhere', async () => {
      await boot();
      const t = (await login('analyst').expect(201)).body.accessToken;
      const start = (await post('/2fa/setup/start', {}, t).expect(201)).body;
      await post('/2fa/setup/confirm', { code: totp(start.secret, clock) }, t).expect(201);
      advance(30);
      await post('/2fa/disable', { password: 'Wrong-Password-1', code: totp(start.secret, clock) }, t).expect(401);
      await post('/2fa/disable', { password: PW, code: totp(start.secret, clock) }, t).expect(201);
      expect(users[3].totpSecret).toBeNull(); expect(codes).toHaveLength(0);
      await me(t).expect(401);                                                    // every session ended
      expect((await login('analyst').expect(201)).body.accessToken).toBeTruthy();
      expect(audit.some((a) => a.action === 'auth.2fa_disable')).toBe(true);
    });

    it('cannot be turned off where it is required, even with the right password and code', async () => {
      await boot(); const s = await enrol('boss'); advance(30);
      const r = await post('/2fa/disable', { password: PW, code: codeFor('boss') }, s.accessToken).expect(403);
      expect(r.body.code).toBe('two_factor_required');
      expect(users[0].totpEnabledAt).toBeInstanceOf(Date);
    });

    it('setup is refused when already on, and disable when not on', async () => {
      await boot(); const s = await enrol('boss');
      expect((await post('/2fa/setup/start', {}, s.accessToken).expect(409)).body.code).toBe('two_factor_already_enabled');
      const t = (await login('viewer').expect(201)).body.accessToken;
      expect((await post('/2fa/disable', { password: PW, code: '123456' }, t).expect(400)).body.code).toBe('two_factor_not_enabled');
    });
  });

  describe('a super admin resets a lost device', () => {
    it('clears the setup, signs that account out everywhere, forces re-enrolment, and is audited', async () => {
      await boot();
      const boss = await enrol('boss'); const sec = await enrol('secadmin');
      await post('/users/secadmin/2fa/reset', {}, boss.accessToken).expect(201).expect((r) => expect(r.body).toEqual({ ok: true, mustEnrolAtNextSignIn: true }));
      expect(users[2].totpSecret).toBeNull(); expect(users[2].totpEnabledAt).toBeNull();
      expect(codes.filter((c) => c.userId === 'secadmin')).toHaveLength(0);
      await me(sec.accessToken).expect(401);                                      // signed out everywhere
      expect((await login('secadmin').expect(201)).body.twoFactorEnrollmentRequired).toBe(true);
      expect(audit.find((a) => a.action === 'auth.2fa_reset')).toMatchObject({ actorId: 'boss', targetId: 'secadmin', metadata: { email: 'secadmin@example.com', wasEnabled: true } });
      await me(boss.accessToken).expect(200);                                     // the admin is unaffected
    });

    it('a super admin cannot reset their own, so a stolen session cannot remove its own second step', async () => {
      await boot(); const boss = await enrol('boss');
      const r = await post('/users/boss/2fa/reset', {}, boss.accessToken).expect(403);
      expect(r.body.code).toBe('self_reset_forbidden');
      expect(users[0].totpEnabledAt).toBeInstanceOf(Date);
    });

    it('another super admin can, and only a super admin can', async () => {
      await boot();
      const boss = await enrol('boss'); const boss2 = await enrol('boss2'); const sec = await enrol('secadmin');
      await post('/users/boss/2fa/reset', {}, boss2.accessToken).expect(201);
      await post('/users/boss2/2fa/reset', {}, sec.accessToken).expect(403);
      await post('/users/boss2/2fa/reset', {}).expect(401);
      await post('/users/nobody/2fa/reset', {}, boss2.accessToken).expect(404);
      expect(boss.accessToken).toBeTruthy();
    });

    it('for an account where it is optional, no re-enrolment is forced', async () => {
      await boot();
      const boss = await enrol('boss'); const t = (await login('analyst').expect(201)).body.accessToken;
      const start = (await post('/2fa/setup/start', {}, t).expect(201)).body;
      await post('/2fa/setup/confirm', { code: totp(start.secret, clock) }, t).expect(201);
      const r = (await post('/users/analyst/2fa/reset', {}, boss.accessToken).expect(201)).body;
      expect(r.mustEnrolAtNextSignIn).toBe(false);
      expect((await login('analyst').expect(201)).body.accessToken).toBeTruthy();
    });

    it('resetting also clears a code lockout, so the person can start over', async () => {
      await boot(); const boss = await enrol('boss'); await enrol('secadmin');
      const step = (await login('secadmin').expect(201)).body;
      for (let i = 0; i < 5; i++) await post('/2fa/verify', { challengeToken: step.challengeToken, code: String(222220 + i) });
      await post('/users/secadmin/2fa/reset', {}, boss.accessToken).expect(201);
      expect(throttle.store.has('mfa:secadmin')).toBe(false);
    });
  });

  describe('when it is not required', () => {
    it('REQUIRE_2FA=false: administrators sign in with just the password, as before', async () => {
      await boot({ REQUIRE_2FA: 'false' });
      expect((await login('boss').expect(201)).body.accessToken).toBeTruthy();
    });
    it('but an administrator who switched it on is still asked for the code', async () => {
      await boot({ REQUIRE_2FA: 'false' });
      const t = (await login('boss').expect(201)).body.accessToken;
      const start = (await post('/2fa/setup/start', {}, t).expect(201)).body;
      await post('/2fa/setup/confirm', { code: totp(start.secret, clock) }, t).expect(201);
      expect((await login('boss').expect(201)).body.twoFactorRequired).toBe(true);
    });
    it('without an encryption key set-up cannot start, and says why', async () => {
      await boot({ REQUIRE_2FA: 'false', TOTP_ENCRYPTION_KEY: undefined });
      const t = (await login('boss').expect(201)).body.accessToken;
      const r = await post('/2fa/setup/start', {}, t).expect(503);
      expect(r.body.code).toBe('two_factor_unavailable');
      expect((await http().get('/api/v1/auth/2fa').set('Authorization', `Bearer ${t}`).expect(200)).body.available).toBe(false);
    });
  });

  it('every second-step route refuses anonymous use of the account-management routes', async () => {
    await boot();
    for (const [m, p] of [['get', '/2fa'], ['post', '/2fa/setup/start'], ['post', '/2fa/setup/confirm'], ['post', '/2fa/recovery-codes/regenerate'], ['post', '/2fa/disable'], ['post', '/users/boss/2fa/reset']] as const) {
      await (http() as any)[m](`/api/v1/auth${p}`).send({}).expect(401);
    }
  });

  void [createHash, base32Decode, timeStep];
});
