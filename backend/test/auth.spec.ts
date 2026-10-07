import { JwtService } from '@nestjs/jwt';
import { BadRequestException, ConflictException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { AuthService } from '../src/auth/auth.service';

process.env.JWT_SECRET = 'access-secret-for-tests-0123456789abcdef0123456789abcdef';
process.env.JWT_REFRESH_SECRET = 'refresh-secret-for-tests-fedcba9876543210fedcba9876543210';

const ctx = { ip: '203.0.113.5', userAgent: 'jest', requestId: 'r1' };

/** In-memory stand-in for the three tables the auth service touches. */
function store() {
  const users: any[] = [];
  const tokens: any[] = [];
  let seq = 0;
  const prisma: any = {
    securityUser: {
      findUnique: async ({ where }: any) => users.find((u) => (where.email ? u.email === where.email : u.id === where.id)) ?? null,
      update: async ({ where, data }: any) => Object.assign(users.find((u) => u.id === where.id), data),
      create: async ({ data }: any) => { const u = { id: `u${++seq}`, isActive: true, ...data }; users.push(u); return u; },
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
  const audit = { log: jest.fn(async () => undefined) };
  return { users, tokens, prisma, audit, svc: new AuthService(prisma, new JwtService(), audit as any) };
}

async function withUser(s: ReturnType<typeof store>, over: any = {}) {
  const passwordHash = await bcrypt.hash('CorrectHorse!1', 4);
  s.users.push({ id: 'u0', email: 'admin@pishon.ng', passwordHash, role: 'SECURITY_ADMIN', isActive: true, name: 'Admin', ...over });
  return s;
}

describe('AuthService.login', () => {
  it('returns tokens and a public user without the password hash', async () => {
    const s = await withUser(store());
    const r = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    expect(r.user).toEqual({ id: 'u0', email: 'admin@pishon.ng', name: 'Admin', role: 'SECURITY_ADMIN', isActive: true, mustChangePassword: false });
    expect(JSON.stringify(r)).not.toContain('passwordHash');
    expect(r.accessToken).toBeTruthy();
    expect(r.refreshToken).toBeTruthy();
    expect(s.users[0].lastLoginAt).toBeInstanceOf(Date);
    expect(s.audit.log).toHaveBeenCalledWith(expect.objectContaining({ action: 'auth.login', result: 'SUCCESS', actorLabel: 'admin@pishon.ng' }));
  });

  it('matches the email case-insensitively', async () => {
    const s = await withUser(store());
    await expect(s.svc.login('ADMIN@Pishon.NG', 'CorrectHorse!1', ctx)).resolves.toBeDefined();
  });

  it('stores only a hash of the refresh token', async () => {
    const s = await withUser(store());
    const r = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    expect(s.tokens).toHaveLength(1);
    expect(s.tokens[0].tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(s.tokens)).not.toContain(r.refreshToken);
  });

  it('issues an access token that names the user, role and type', async () => {
    const s = await withUser(store());
    const r = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    const p: any = await new JwtService().verifyAsync(r.accessToken, { secret: process.env.JWT_SECRET });
    expect(p).toMatchObject({ sub: 'u0', email: 'admin@pishon.ng', role: 'SECURITY_ADMIN', type: 'access' });
  });

  it('rejects a wrong password with a generic message and records the failure', async () => {
    const s = await withUser(store());
    await expect(s.svc.login('admin@pishon.ng', 'wrong-password', ctx)).rejects.toThrow(new UnauthorizedException('Invalid credentials'));
    expect(s.audit.log).toHaveBeenCalledWith(expect.objectContaining({ action: 'auth.login', result: 'FAILURE', actorId: 'u0' }));
    expect(s.users[0].lastLoginAt).toBeUndefined();
    expect(s.tokens).toHaveLength(0);
  });

  it('gives the same answer for an unknown email as for a wrong password', async () => {
    const s = await withUser(store());
    const wrong = await s.svc.login('admin@pishon.ng', 'nope-nope-nope', ctx).catch((e) => e);
    const unknown = await s.svc.login('ghost@pishon.ng', 'nope-nope-nope', ctx).catch((e) => e);
    expect(unknown.message).toBe(wrong.message);
    expect(unknown.getStatus()).toBe(wrong.getStatus());
  });

  it('compares the password even when the email is unknown, so response time does not reveal which emails exist', async () => {
    const s = await withUser(store());
    const spy = jest.spyOn(require('bcryptjs'), 'compare');
    await s.svc.login('ghost@pishon.ng', 'whatever-password', ctx).catch(() => undefined);
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockClear();
    await s.svc.login('admin@pishon.ng', 'whatever-password', ctx).catch(() => undefined);
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });

  it('rejects a disabled account even with the right password, and still does a password comparison', async () => {
    const s = await withUser(store(), { isActive: false });
    const spy = jest.spyOn(require('bcryptjs'), 'compare');
    await expect(s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx)).rejects.toThrow('Invalid credentials');
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
    expect(s.tokens).toHaveLength(0);
  });
});

describe('AuthService.refresh', () => {
  it('rotates: the old token stops working and a new pair is issued', async () => {
    const s = await withUser(store());
    const first = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    const second = await s.svc.refresh(first.refreshToken, ctx);
    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect(s.tokens.filter((t) => t.revokedAt === null)).toHaveLength(1);
    await expect(s.svc.refresh(first.refreshToken, ctx)).rejects.toThrow('Refresh token expired or revoked');
  });

  it('treats reuse of an already-used token as theft and ends every session for that user', async () => {
    const s = await withUser(store());
    const first = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    const second = await s.svc.refresh(first.refreshToken, ctx);
    // An attacker (or the owner) replays the old token.
    await expect(s.svc.refresh(first.refreshToken, ctx)).rejects.toBeInstanceOf(UnauthorizedException);
    // The newest token, which was legitimately issued, is now also dead.
    expect(s.tokens.every((t) => t.revokedAt !== null)).toBe(true);
    await expect(s.svc.refresh(second.refreshToken, ctx)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(s.audit.log).toHaveBeenCalledWith(expect.objectContaining({
      result: 'FAILURE', metadata: expect.objectContaining({ reason: 'refresh_token_reuse' }),
    }));
  });

  it('does not touch other users sessions when one user token is reused', async () => {
    const s = await withUser(store());
    s.users.push({ id: 'u9', email: 'other@pishon.ng', passwordHash: await bcrypt.hash('OtherPass!123', 4), role: 'ANALYST', isActive: true });
    const other = await s.svc.login('other@pishon.ng', 'OtherPass!123', ctx);
    const mine = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    await s.svc.refresh(mine.refreshToken, ctx);
    await s.svc.refresh(mine.refreshToken, ctx).catch(() => undefined);
    await expect(s.svc.refresh(other.refreshToken, ctx)).resolves.toBeDefined();
  });

  it('rejects garbage, tampered tokens and tokens signed with the wrong secret', async () => {
    const s = await withUser(store());
    await expect(s.svc.refresh('not-a-token', ctx)).rejects.toThrow('Invalid refresh token');
    const forged = await new JwtService().signAsync({ sub: 'u0', type: 'refresh' }, { secret: 'attacker-secret' });
    await expect(s.svc.refresh(forged, ctx)).rejects.toThrow('Invalid refresh token');
  });

  it('refuses an access token presented as a refresh token', async () => {
    const s = await withUser(store());
    const login = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    await expect(s.svc.refresh(login.accessToken, ctx)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('refuses a validly signed refresh token that the server never stored', async () => {
    const s = await withUser(store());
    const unknown = await new JwtService().signAsync({ sub: 'u0', type: 'refresh', nonce: 'x' }, { secret: process.env.JWT_REFRESH_SECRET });
    await expect(s.svc.refresh(unknown, ctx)).rejects.toThrow('Refresh token expired or revoked');
  });

  it('refuses an expired stored token', async () => {
    const s = await withUser(store());
    const login = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    s.tokens[0].expiresAt = new Date(Date.now() - 1000);
    await expect(s.svc.refresh(login.refreshToken, ctx)).rejects.toThrow('Refresh token expired or revoked');
  });

  it('refuses to refresh for a user who was disabled after login', async () => {
    const s = await withUser(store());
    const login = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    s.users[0].isActive = false;
    await expect(s.svc.refresh(login.refreshToken, ctx)).rejects.toThrow('User inactive');
  });
});

describe('AuthService.logout', () => {
  it('revokes the presented token so it cannot be refreshed', async () => {
    const s = await withUser(store());
    const login = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    await s.svc.logout(login.refreshToken);
    await expect(s.svc.refresh(login.refreshToken, ctx)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('does nothing, and does not fail, without a token', async () => {
    const s = await withUser(store());
    await expect(s.svc.logout('')).resolves.toBeUndefined();
  });
});

describe('AuthService.createUser', () => {
  it('hashes the password and never returns the hash', async () => {
    const s = store();
    const u = await s.svc.createUser({ email: 'New@Pishon.ng', password: 'a-long-password-1', name: 'New', role: 'ANALYST' });
    expect(u).toEqual({ id: expect.any(String), email: 'new@pishon.ng', name: 'New', role: 'ANALYST', isActive: true, mustChangePassword: false });
    expect(s.users[0].passwordHash).not.toContain('a-long-password-1');
    expect(await bcrypt.compare('a-long-password-1', s.users[0].passwordHash)).toBe(true);
  });

  it('rejects a duplicate email', async () => {
    const s = await withUser(store());
    await expect(s.svc.createUser({ email: 'ADMIN@pishon.ng', password: 'a-long-password-1', role: 'ANALYST' })).rejects.toBeInstanceOf(ConflictException);
  });

  it('rejects an unknown role with a 400, not a conflict', async () => {
    await expect(store().svc.createUser({ email: 'x@pishon.ng', password: 'a-long-password-1', role: 'GOD' })).rejects.toBeInstanceOf(BadRequestException);
  });
});

describe('AuthService.createUser auditing', () => {
  it('records who created the account, and its role, but never the password', async () => {
    const s = store();
    await s.svc.createUser(
      { email: 'new@pishon.ng', password: 'a-long-password-1', role: 'ANALYST' },
      { id: 'u0', label: 'root@pishon.ng', ip: '203.0.113.5', userAgent: 'jest', requestId: 'r9' } as any,
    );
    expect(s.audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'user.create', actorType: 'USER', actorId: 'u0', actorLabel: 'root@pishon.ng', targetType: 'user',
      result: 'SUCCESS', metadata: { email: 'new@pishon.ng', role: 'ANALYST', requirePasswordChange: false },
    }));
    expect(JSON.stringify((s.audit.log as jest.Mock).mock.calls)).not.toContain('a-long-password-1');
  });
});

describe('AuthService.changePassword', () => {
  const change = (s: ReturnType<typeof store>, cur: string, next: string) => s.svc.changePassword('u0', cur, next, ctx);

  it('changes the password, revokes every refresh token, and audits it', async () => {
    const s = await withUser(store());
    const login = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    await expect(change(s, 'CorrectHorse!1', 'A-Brand-New-Passphrase-9')).resolves.toEqual({ ok: true });
    expect(await bcrypt.compare('A-Brand-New-Passphrase-9', s.users[0].passwordHash)).toBe(true);
    expect(s.tokens.every((t) => t.revokedAt !== null)).toBe(true);
    await expect(s.svc.refresh(login.refreshToken, ctx)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(s.audit.log).toHaveBeenCalledWith(expect.objectContaining({ action: 'auth.password_change', result: 'SUCCESS', actorId: 'u0' }));
  });

  it('the old password stops working and the new one works', async () => {
    const s = await withUser(store());
    await change(s, 'CorrectHorse!1', 'A-Brand-New-Passphrase-9');
    await expect(s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx)).rejects.toThrow('Invalid credentials');
    await expect(s.svc.login('admin@pishon.ng', 'A-Brand-New-Passphrase-9', ctx)).resolves.toBeDefined();
  });

  it('refuses a wrong current password, changes nothing, and audits the failure', async () => {
    const s = await withUser(store());
    const before = s.users[0].passwordHash;
    await expect(change(s, 'wrong-current-pw', 'A-Brand-New-Passphrase-9')).rejects.toThrow('Current password invalid');
    expect(s.users[0].passwordHash).toBe(before);
    expect(s.audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'auth.password_change', result: 'FAILURE', metadata: { reason: 'wrong_current_password' },
    }));
  });

  it('refuses to "change" to the same password', async () => {
    const s = await withUser(store());
    await expect(change(s, 'CorrectHorse!1', 'CorrectHorse!1')).rejects.toBeInstanceOf(BadRequestException);
    expect(s.audit.log).toHaveBeenCalledWith(expect.objectContaining({ result: 'FAILURE', metadata: { reason: 'same_password' } }));
  });

  it('refuses a missing or disabled user', async () => {
    const s = await withUser(store(), { isActive: false });
    await expect(change(s, 'CorrectHorse!1', 'A-Brand-New-Passphrase-9')).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(store().svc.changePassword('ghost', 'x', 'y', ctx)).rejects.toBeInstanceOf(UnauthorizedException);
  });
});


describe('AuthService.me', () => {
  it('returns the signed-in account, including whether it must change its password', async () => {
    const s = await withUser(store(), { mustChangePassword: true });
    expect(await s.svc.me('u0')).toEqual({ id: 'u0', email: 'admin@pishon.ng', name: 'Admin', role: 'SECURITY_ADMIN', isActive: true, mustChangePassword: true });
  });
  it('refuses an account that no longer exists or has been switched off', async () => {
    const s = await withUser(store(), { isActive: false });
    await expect(s.svc.me('u0')).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(s.svc.me('missing')).rejects.toBeInstanceOf(UnauthorizedException);
  });
});

describe('AuthService.verifyRefreshJwt', () => {
  it('accepts a real refresh token', async () => {
    const s = await withUser(store());
    const { refreshToken } = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    await expect(s.svc.verifyRefreshJwt(refreshToken)).resolves.toBeUndefined();
  });
  it('rejects an access token, a tampered token and garbage, with the no_session code', async () => {
    const s = await withUser(store());
    const { accessToken, refreshToken } = await s.svc.login('admin@pishon.ng', 'CorrectHorse!1', ctx);
    for (const bad of [accessToken, refreshToken.slice(0, -3) + 'abc', 'garbage', '']) {
      const err: any = await s.svc.verifyRefreshJwt(bad).catch((e) => e);
      expect(err).toBeInstanceOf(UnauthorizedException);
      expect(err.getResponse().code).toBe('no_session');
    }
  });
});
