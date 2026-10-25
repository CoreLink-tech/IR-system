import { TwoFactorService } from '../src/auth/two-factor.service';
import { LoginThrottleService } from '../src/auth/login-throttle.service';
import { InMemoryThrottle } from './helpers/in-memory-throttle';
import 'reflect-metadata';
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
import { JwtStrategy } from '../src/auth/jwt.strategy';
import { PrismaService } from '../src/prisma/prisma.service';
import { AuditService } from '../src/audit/audit.service';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';
import { deviceLabel } from '../src/auth/device-label';

process.env.JWT_SECRET = 'access-secret-for-tests-0123456789abcdef0123456789abcdef';
process.env.JWT_REFRESH_SECRET = 'refresh-secret-for-tests-fedcba9876543210fedcba9876543210';
process.env.NODE_ENV = 'test';

const PW = 'CorrectHorse!1';
const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';

/** Real AuthService, SessionsService, JwtStrategy, guards and controller over HTTP, with an in-memory database. */
describe('sessions and access-token revocation (real guards over HTTP)', () => {
  let app: INestApplication; let jwt: JwtService;
  let users: any[]; let tokens: any[]; let audit: any[]; let seq: number; let throttle: InMemoryThrottle;

  const matches = (row: any, where: any): boolean => Object.entries(where ?? {}).every(([k, v]: [string, any]) => {
    if (v && typeof v === 'object' && 'gt' in v) return row[k] > v.gt;
    return row[k] === v;
  });
  const applyData = (row: any, data: any) => {
    for (const [k, v] of Object.entries<any>(data)) row[k] = v && typeof v === 'object' && 'increment' in v ? (row[k] ?? 0) + v.increment : v;
    return row;
  };

  beforeEach(async () => {
    tokens = []; audit = []; seq = 0; throttle = new InMemoryThrottle();
    const hash = await bcrypt.hash(PW, 4);
    users = [
      { id: 'admin', email: 'admin@example.com', passwordHash: hash, role: 'SUPER_ADMIN', isActive: true, name: 'Admin', mustChangePassword: false, tokenVersion: 0 },
      { id: 'viewer', email: 'viewer@example.com', passwordHash: hash, role: 'VIEWER', isActive: true, name: 'Viewer', mustChangePassword: false, tokenVersion: 0 },
      { id: 'other', email: 'other@example.com', passwordHash: hash, role: 'VIEWER', isActive: true, name: 'Other', mustChangePassword: false, tokenVersion: 0 },
    ];
    const prisma: any = {
      securityUser: {
        findUnique: async ({ where, select }: any) => {
          const u = users.find((x) => (where.email ? x.email === where.email : x.id === where.id)) ?? null;
          return u && select ? Object.fromEntries(Object.keys(select).map((k) => [k, u[k]])) : u;
        },
        update: async ({ where, data }: any) => applyData(users.find((u) => u.id === where.id), data),
        create: async ({ data }: any) => { const u = { id: `new${users.length}`, isActive: true, mustChangePassword: false, tokenVersion: 0, ...data }; users.push(u); return u; },
      },
      securityRefreshToken: {
        create: async ({ data }: any) => { const t = { id: `t${++seq}`, revokedAt: null, revokedReason: null, createdAt: new Date(), ...data }; tokens.push(t); return t; },
        findUnique: async ({ where }: any) => tokens.find((t) => t.tokenHash === where.tokenHash) ?? null,
        findMany: async ({ where, orderBy }: any) => tokens.filter((t) => matches(t, where)).sort((a, b) => +(b.lastUsedAt ?? 0) - +(a.lastUsedAt ?? 0)),
        update: async ({ where, data }: any) => applyData(tokens.find((t) => t.id === where.id), data),
        updateMany: async ({ where, data }: any) => {
          const hit = tokens.filter((t) => matches(t, where));
          hit.forEach((t) => applyData(t, data));
          return { count: hit.length };
        },
      },
      $transaction: async (ops: Promise<any>[]) => Promise.all(ops),
    };
    const mod = await Test.createTestingModule({
      imports: [PassportModule, JwtModule.register({})],
      controllers: [AuthController],
      providers: [
        AuthService, TwoFactorService, UsersService, SessionsService, JwtStrategy, { provide: LoginThrottleService, useValue: throttle },
        { provide: PrismaService, useValue: prisma },
        { provide: AuditService, useValue: { log: async (e: any) => { audit.push(e); } } },
      ],
    }).compile();
    app = mod.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new AllExceptionsFilter());
    await app.init();
    jwt = mod.get(JwtService);
  });
  afterEach(() => app.close());

  const http = () => request(app.getHttpServer());
  const login = async (email = 'admin@example.com', ua = CHROME) => {
    const r = await http().post('/api/v1/auth/login').set('User-Agent', ua).send({ email, password: PW }).expect(201);
    return { access: r.body.accessToken as string, refresh: r.body.refreshToken as string };
  };
  const me = (access: string) => http().get('/api/v1/auth/me').set('Authorization', `Bearer ${access}`);
  const sessions = (access: string) => http().get('/api/v1/auth/sessions').set('Authorization', `Bearer ${access}`);
  const refresh = (token: string) => http().post('/api/v1/auth/refresh').send({ refreshToken: token });

  it('tokens carry the account token version and the session they belong to', async () => {
    const { access, refresh: rt } = await login();
    const a: any = jwt.decode(access); const r: any = jwt.decode(rt);
    expect(a).toMatchObject({ sub: 'admin', tv: 0 }); expect(r).toMatchObject({ sub: 'admin', tv: 0 });
    expect(a.sid).toBeTruthy(); expect(a.sid).toBe(r.sid);
  });

  it('lists the account\'s sessions with a device label, marks the current one, and a refresh keeps the same session', async () => {
    const desktop = await login('admin@example.com', CHROME);
    const phone = await login('admin@example.com', IPHONE);
    let list = (await sessions(desktop.access).expect(200)).body.data;
    expect(list.map((s: any) => s.device).sort()).toEqual(['Chrome on Windows', 'Safari on iOS']);
    expect(list.filter((s: any) => s.current)).toHaveLength(1);
    expect(list.find((s: any) => s.current).device).toBe('Chrome on Windows');
    const before = list.find((s: any) => s.current);

    const next = (await refresh(desktop.refresh).expect(201)).body;           // the browser rotates its token
    list = (await sessions(next.accessToken).expect(200)).body.data;
    expect(list).toHaveLength(2);                                              // still two sessions, not three
    const after = list.find((s: any) => s.current);
    expect(after.id).toBe(before.id);                                          // same session
    expect(new Date(after.createdAt).getTime()).toBe(new Date(before.createdAt).getTime());
    expect(phone.refresh).toBeTruthy();
  });

  it('only shows the account\'s own sessions, and nothing about tokens', async () => {
    await login('viewer@example.com'); await login('other@example.com');
    const { access } = await login('admin@example.com');
    const r = await sessions(access).expect(200);
    expect(r.body.data).toHaveLength(1);
    expect(JSON.stringify(r.body)).not.toMatch(/tokenHash|refreshToken|eyJ/);
    expect(r.headers['cache-control']).toBe('no-store');
  });

  it('ending one session stops its refresh token, leaves the others working, and does NOT end every session', async () => {
    const desktop = await login('admin@example.com', CHROME);
    const phone = await login('admin@example.com', IPHONE);
    const list = (await sessions(desktop.access).expect(200)).body.data;
    const phoneSession = list.find((s: any) => s.device === 'Safari on iOS');
    await http().delete(`/api/v1/auth/sessions/${phoneSession.id}`).set('Authorization', `Bearer ${desktop.access}`).expect(200);

    const dead = await refresh(phone.refresh).expect(401);
    expect(dead.body.code).toBe('session_ended');
    await refresh(desktop.refresh).expect(201);                                // the other device is unaffected
    expect(audit.some((a) => a.action === 'auth.session_revoke' && a.metadata.byOwner === true)).toBe(true);
  });

  it('a token that was already replaced and is presented again still ends every session (theft response kept)', async () => {
    const desktop = await login('admin@example.com', CHROME);
    const phone = await login('admin@example.com', IPHONE);
    await refresh(desktop.refresh).expect(201);                                // desktop token is now "rotated"
    const reuse = await refresh(desktop.refresh).expect(401);                  // someone presents the old one again
    expect(reuse.body.code).toBe('refresh_token_reuse');
    await refresh(phone.refresh).expect(401);                                  // the phone was signed out too
  });

  it('a session cannot be ended through another account\'s id', async () => {
    const viewer = await login('viewer@example.com'); const other = await login('other@example.com');
    const otherId = ((await sessions(other.access)).body.data[0]).id;
    await http().delete(`/api/v1/auth/sessions/${otherId}`).set('Authorization', `Bearer ${viewer.access}`).expect(404);
    await refresh(other.refresh).expect(201);                                  // untouched
  });

  it('"sign out everywhere" ends this device\'s access token at once, not after 15 minutes', async () => {
    const desktop = await login('admin@example.com', CHROME); const phone = await login('admin@example.com', IPHONE);
    await me(desktop.access).expect(200);
    const r = await http().post('/api/v1/auth/sessions/revoke-all').set('Authorization', `Bearer ${desktop.access}`).expect(201);
    expect(r.body.sessionsEnded).toBe(2);
    const gone = await me(desktop.access).expect(401);
    expect(gone.body.code).toBe('session_ended');
    await me(phone.access).expect(401);
    await refresh(phone.refresh).expect(401);
    expect(users[0].tokenVersion).toBe(1);
    expect(audit.some((a) => a.action === 'auth.sessions_revoke_all')).toBe(true);
  });

  it('changing your own password ends the access tokens of your other devices at once (open item 2)', async () => {
    const desktop = await login('viewer@example.com', CHROME); const phone = await login('viewer@example.com', IPHONE);
    await me(phone.access).expect(200);
    await http().post('/api/v1/auth/change-password').set('Authorization', `Bearer ${desktop.access}`)
      .send({ currentPassword: PW, newPassword: 'A-Different-Passw0rd!' }).expect(201);
    const gone = await me(phone.access).expect(401);                            // before this fix: 200 for up to 15 minutes
    expect(gone.body.code).toBe('session_ended');
    await me(desktop.access).expect(401);
    await refresh(phone.refresh).expect(401);
    expect(users[1].passwordChangedAt).toBeInstanceOf(Date);
  });

  it('an administrator resetting a password ends the target\'s access tokens at once', async () => {
    const admin = await login('admin@example.com'); const victim = await login('viewer@example.com');
    await me(victim.access).expect(200);
    await http().post('/api/v1/auth/users/viewer/reset-password').set('Authorization', `Bearer ${admin.access}`).send({ newPassword: 'Temporary-Passw0rd!' }).expect(201);
    await me(victim.access).expect(401);
    await me(admin.access).expect(200);                                         // the administrator is unaffected
  });

  it('tokens issued before this feature existed (no version in them) keep working', async () => {
    const legacy = await jwt.signAsync({ sub: 'viewer', email: 'viewer@example.com', role: 'VIEWER', type: 'access' }, { secret: process.env.JWT_SECRET, expiresIn: '15m' });
    await me(legacy).expect(200);
    users[1].tokenVersion = 1;                                                  // but once the account's version is raised they stop
    await me(legacy).expect(401);
  });

  it('a refresh token issued before the account\'s version was raised is refused, even if it was never revoked', async () => {
    const { refresh: rt } = await login('viewer@example.com');
    users[1].tokenVersion = 1;
    const r = await refresh(rt).expect(401);
    expect(r.body.code).toBe('session_ended');
  });

  it('an older revoked token with no recorded reason is treated as replaced, as before this feature', async () => {
    const desktop = await login('viewer@example.com', CHROME); const phone = await login('viewer@example.com', IPHONE);
    const row = tokens.find((t) => t.userId === 'viewer')!;
    row.revokedAt = new Date(); row.revokedReason = null;
    const r = await refresh(desktop.refresh).expect(401);
    expect(r.body.code).toBe('refresh_token_reuse');
    await refresh(phone.refresh).expect(401);
  });

  it('a refresh token from before sessions existed (no session or version in it) still works and starts a session', async () => {
    const raw = await jwt.signAsync({ sub: 'viewer', nonce: 'legacy-nonce', type: 'refresh' }, { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d' });
    const { createHash } = await import('crypto');
    tokens.push({ id: 'legacy1', userId: 'viewer', tokenHash: createHash('sha256').update(raw).digest('hex'), expiresAt: new Date(Date.now() + 86_400_000), revokedAt: null, revokedReason: null, createdAt: new Date() });
    const r = await refresh(raw).expect(201);
    const a: any = jwt.decode(r.body.accessToken);
    expect(a.sid).toBeTruthy(); expect(a.tv).toBe(0);
    expect((await sessions(r.body.accessToken).expect(200)).body.data).toHaveLength(1);
  });

  it('a super admin can list and end another account\'s sessions; other roles cannot', async () => {
    const admin = await login('admin@example.com'); const viewer = await login('viewer@example.com');
    const theirs = (await http().get('/api/v1/auth/users/viewer/sessions').set('Authorization', `Bearer ${admin.access}`).expect(200)).body.data;
    expect(theirs).toHaveLength(1);
    await http().get('/api/v1/auth/users/admin/sessions').set('Authorization', `Bearer ${viewer.access}`).expect(403);
    await http().delete(`/api/v1/auth/users/viewer/sessions/${theirs[0].id}`).set('Authorization', `Bearer ${admin.access}`).expect(200);
    await refresh(viewer.refresh).expect(401);
    const entry = audit.find((a) => a.action === 'auth.session_revoke');
    expect(entry).toMatchObject({ actorId: 'admin', targetId: 'viewer', metadata: { byOwner: false, email: 'viewer@example.com' } });
    await http().get('/api/v1/auth/users/nobody/sessions').set('Authorization', `Bearer ${admin.access}`).expect(404);
  });

  it('a super admin can sign another account out everywhere', async () => {
    const admin = await login('admin@example.com'); const viewer = await login('viewer@example.com');
    await http().post('/api/v1/auth/users/viewer/sessions/revoke-all').set('Authorization', `Bearer ${admin.access}`).expect(201);
    await me(viewer.access).expect(401);
  });

  describe('password policy over HTTP', () => {
    const asAdmin = async () => (await login('admin@example.com')).access;
    const weak = 'password1234';
    const strong = 'Violet-Harbor-Lantern-84';

    it('a weak password is refused when creating an account, with every reason as a readable sentence', async () => {
      const t = await asAdmin();
      const r = await http().post('/api/v1/auth/users').set('Authorization', `Bearer ${t}`).send({ email: 'new@example.com', password: weak, role: 'ANALYST' }).expect(400);
      expect(r.body.code).toBe('weak_password');
      expect(Array.isArray(r.body.message)).toBe(true);
      expect(r.body.message.join(' ')).toMatch(/common password/);
      expect(users.find((u) => u.email === 'new@example.com')).toBeUndefined();
      expect(JSON.stringify(r.body)).not.toContain(weak);
      await http().post('/api/v1/auth/users').set('Authorization', `Bearer ${t}`).send({ email: 'new@example.com', password: strong, role: 'ANALYST' }).expect(201);
    });

    it('a password with the person\'s own email in it is refused when creating an account', async () => {
      const t = await asAdmin();
      const r = await http().post('/api/v1/auth/users').set('Authorization', `Bearer ${t}`).send({ email: 'chidinma.eze@example.com', name: 'Chidinma Eze', password: 'Chidinma-and-her-Violet-Lantern', role: 'ANALYST' }).expect(400);
      expect(r.body.message.join(' ')).toMatch(/email address or your name/);
    });

    it('a too-short password gets the plain length message from the request check', async () => {
      const t = await asAdmin();
      const r = await http().post('/api/v1/auth/users').set('Authorization', `Bearer ${t}`).send({ email: 'n@example.com', password: 'short', role: 'ANALYST' }).expect(400);
      expect(JSON.stringify(r.body.message)).toContain('at least 12 characters long');
    });

    it('changing your own password: the current password is still required, a weak new one is refused and nothing else changes', async () => {
      const { access } = await login('viewer@example.com'); const other = await login('viewer@example.com', IPHONE);
      const before = users[1].passwordHash;
      await http().post('/api/v1/auth/change-password').set('Authorization', `Bearer ${access}`).send({ currentPassword: 'Wrong-Current-Pw-1', newPassword: strong }).expect(401);
      const r = await http().post('/api/v1/auth/change-password').set('Authorization', `Bearer ${access}`).send({ currentPassword: PW, newPassword: weak }).expect(400);
      expect(r.body.code).toBe('weak_password');
      expect(users[1].passwordHash).toBe(before);
      expect(users[1].tokenVersion).toBe(0);                                  // a refused change signs nobody out
      await me(other.access).expect(200);
      expect(audit.some((a) => a.action === 'auth.password_change' && a.result === 'FAILURE' && a.metadata.reason === 'weak_password')).toBe(true);
      expect(JSON.stringify(audit)).not.toContain(weak);
      await http().post('/api/v1/auth/change-password').set('Authorization', `Bearer ${access}`).send({ currentPassword: PW, newPassword: strong }).expect(201);
    });

    it('an administrator\'s temporary password must pass the same policy, checked against the target account', async () => {
      const t = await asAdmin();
      await http().post('/api/v1/auth/users/viewer/reset-password').set('Authorization', `Bearer ${t}`).send({ newPassword: weak }).expect(400);
      const own = await http().post('/api/v1/auth/users/viewer/reset-password').set('Authorization', `Bearer ${t}`).send({ newPassword: 'viewer-is-my-name-1' }).expect(400);
      expect(own.body.message.join(' ')).toMatch(/email address or your name/);
      expect(users[1].tokenVersion).toBe(0);
      await http().post('/api/v1/auth/users/viewer/reset-password').set('Authorization', `Bearer ${t}`).send({ newPassword: strong }).expect(201);
    });
  });

  it('refuses a missing, unknown or over-long session id', async () => {
    const { access } = await login('admin@example.com');
    await http().delete('/api/v1/auth/sessions/does-not-exist').set('Authorization', `Bearer ${access}`).expect(404);
    await http().delete(`/api/v1/auth/sessions/${'x'.repeat(500)}`).set('Authorization', `Bearer ${access}`).expect(404);
    await http().delete("/api/v1/auth/sessions/' OR 1=1 --").set('Authorization', `Bearer ${access}`).expect(404);
  });
});

describe('device labels', () => {
  it.each([
    [CHROME, 'Chrome on Windows'], [IPHONE, 'Safari on iOS'],
    ['Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0', 'Firefox on Linux'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0 Safari/537.36 Edg/126.0', 'Edge on macOS'],
    ['Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36', 'Chrome on Android'],
    ['curl/8.5.0', 'curl'], ['', 'Unknown device'], [undefined, 'Unknown device'], ['totally-unknown', 'Unknown device'],
  ])('%s', (ua, expected) => { expect(deviceLabel(ua as any)).toBe(expected); });
  it('is bounded and never throws on odd input', () => { expect(deviceLabel('x'.repeat(100000)).length).toBeLessThan(40); });
});
