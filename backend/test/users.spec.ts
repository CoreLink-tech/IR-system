import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../src/auth/users.service';

const actor = { type: 'USER' as const, id: 'root', label: 'root@pishon.ng', ip: '203.0.113.5', userAgent: 'jest', requestId: 'r1' };

function make(users: any[]) {
  const tokens: any[] = users.map((u) => ({ userId: u.id, revokedAt: null }));
  const prisma: any = {
    securityUser: {
      findMany: jest.fn(async (a: any) => users.filter((u) => !a.where || u.isActive === a.where.isActive)),
      findUnique: async ({ where }: any) => { const u = users.find((x) => x.id === where.id); return u ? { ...u } : null; },
      count: async ({ where }: any) => users.filter((u) => u.role === where.role && u.isActive === where.isActive && u.id !== where.id.not).length,
      update: jest.fn(async ({ where, data }: any) => Object.assign(users.find((u) => u.id === where.id), data)),
    },
    securityRefreshToken: {
      updateMany: jest.fn(async ({ where, data }: any) => {
        const hit = tokens.filter((t) => t.userId === where.userId && t.revokedAt === null);
        hit.forEach((t) => Object.assign(t, data));
        return { count: hit.length };
      }),
    },
    $transaction: jest.fn(async (fn: any, opts: any) => fn(prisma)),
  };
  const audit = { log: jest.fn(async () => undefined) };
  return { svc: new UsersService(prisma, audit as any), prisma, audit, tokens, users };
}
const user = (id: string, role: string, over: any = {}) => ({ id, email: `${id}@pishon.ng`, name: id, role, isActive: true, mustChangePassword: false, passwordHash: 'HASH', ...over });

describe('UsersService.list and assignable', () => {
  it('never selects the password hash', async () => {
    const m = make([user('a', 'ANALYST')]);
    await m.svc.list();
    await m.svc.assignable();
    for (const call of m.prisma.securityUser.findMany.mock.calls) expect(JSON.stringify(call[0].select)).not.toContain('passwordHash');
  });
  it('offers only active accounts for assignment, with just names and roles', async () => {
    const m = make([user('a', 'ANALYST'), user('b', 'ANALYST', { isActive: false })]);
    await m.svc.assignable();
    expect(m.prisma.securityUser.findMany.mock.calls[0][0].where).toEqual({ isActive: true });
    expect(Object.keys(m.prisma.securityUser.findMany.mock.calls[0][0].select).sort()).toEqual(['email', 'id', 'name', 'role']);
  });
});

describe('UsersService.update', () => {
  it('changes a role and records the old and new values', async () => {
    const m = make([user('root', 'SUPER_ADMIN'), user('a', 'ANALYST')]);
    const r = await m.svc.update('a', { role: 'SECURITY_ADMIN' }, actor);
    expect(r.role).toBe('SECURITY_ADMIN');
    expect(JSON.stringify(r)).not.toContain('HASH');
    expect(m.audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'user.update', targetId: 'a', result: 'SUCCESS',
      metadata: { email: 'a@pishon.ng', old: { role: 'ANALYST', isActive: true }, new: { role: 'SECURITY_ADMIN', isActive: true } },
    }));
  });
  it('runs the check and the change in one serializable transaction', async () => {
    const m = make([user('root', 'SUPER_ADMIN'), user('a', 'ANALYST')]);
    await m.svc.update('a', { isActive: false }, actor);
    expect(m.prisma.$transaction.mock.calls[0][1]).toEqual({ isolationLevel: 'Serializable' });
  });
  it('ends the sessions of an account that is switched off, and not for a role change', async () => {
    const off = make([user('root', 'SUPER_ADMIN'), user('a', 'ANALYST')]);
    await off.svc.update('a', { isActive: false }, actor);
    expect(off.tokens.find((t) => t.userId === 'a').revokedAt).toBeInstanceOf(Date);
    const role = make([user('root', 'SUPER_ADMIN'), user('a', 'ANALYST')]);
    await role.svc.update('a', { role: 'VIEWER' }, actor);
    expect(role.tokens.find((t) => t.userId === 'a').revokedAt).toBeNull();
  });
  it('does not let anyone change their own role or switch themselves off', async () => {
    const m = make([user('root', 'SUPER_ADMIN'), user('other', 'SUPER_ADMIN')]);
    const err: any = await m.svc.update('root', { role: 'VIEWER' }, actor).catch((e) => e);
    expect(err).toBeInstanceOf(BadRequestException);
    expect(err.getResponse().code).toBe('self_change_forbidden');
    await expect(m.svc.update('root', { isActive: false }, actor)).rejects.toBeInstanceOf(BadRequestException);
    expect(m.users[0]).toMatchObject({ role: 'SUPER_ADMIN', isActive: true });
    expect(m.audit.log).toHaveBeenCalledWith(expect.objectContaining({ result: 'FAILURE', metadata: expect.objectContaining({ reason: 'self_change_forbidden' }) }));
  });
  it('never removes the last active super admin, by demotion or by switching off', async () => {
    const m = make([user('root', 'SUPER_ADMIN'), user('boss', 'SUPER_ADMIN', { isActive: true })]);
    m.users[0].isActive = false; // the actor's own row is irrelevant here; only one active super admin remains: boss
    const err: any = await m.svc.update('boss', { role: 'ANALYST' }, actor).catch((e) => e);
    expect(err).toBeInstanceOf(ConflictException);
    expect(err.getResponse().code).toBe('last_super_admin');
    await expect(m.svc.update('boss', { isActive: false }, actor)).rejects.toBeInstanceOf(ConflictException);
    expect(m.users[1]).toMatchObject({ role: 'SUPER_ADMIN', isActive: true });
  });
  it('allows removing a super admin while another active one remains', async () => {
    const m = make([user('root', 'SUPER_ADMIN'), user('boss', 'SUPER_ADMIN')]);
    await expect(m.svc.update('boss', { role: 'ANALYST' }, actor)).resolves.toMatchObject({ role: 'ANALYST' });
  });
  it('does not count an inactive super admin as a remaining one', async () => {
    const m = make([user('boss', 'SUPER_ADMIN'), user('gone', 'SUPER_ADMIN', { isActive: false })]);
    await expect(m.svc.update('boss', { isActive: false }, actor)).rejects.toBeInstanceOf(ConflictException);
  });
  it('answers 404 for an unknown account and 400 for an empty or invalid change', async () => {
    const m = make([user('root', 'SUPER_ADMIN')]);
    await expect(m.svc.update('nope', { role: 'VIEWER' }, actor)).rejects.toBeInstanceOf(NotFoundException);
    await expect(m.svc.update('root', {}, actor)).rejects.toBeInstanceOf(BadRequestException);
    await expect(m.svc.update('root', { role: 'GOD' }, actor)).rejects.toBeInstanceOf(BadRequestException);
  });
  it('does nothing, and records nothing, when the request changes nothing', async () => {
    const m = make([user('root', 'SUPER_ADMIN'), user('a', 'ANALYST')]);
    await m.svc.update('a', { role: 'ANALYST', isActive: true }, actor);
    expect(m.prisma.securityUser.update).not.toHaveBeenCalled();
    expect(m.audit.log).not.toHaveBeenCalled();
  });
  it('turns a database serialization failure into a plain "try again"', async () => {
    const m = make([user('root', 'SUPER_ADMIN'), user('a', 'ANALYST')]);
    m.prisma.$transaction.mockRejectedValueOnce(Object.assign(new Error('write conflict'), { code: 'P2034' }));
    await expect(m.svc.update('a', { role: 'VIEWER' }, actor)).rejects.toBeInstanceOf(ConflictException);
  });
});

describe('UsersService.resetPassword', () => {
  it('sets a hashed temporary password, forces a change, ends every session and returns nothing sensitive', async () => {
    const m = make([user('root', 'SUPER_ADMIN'), user('a', 'ANALYST')]);
    const r = await m.svc.resetPassword('a', 'temporary-password-1', actor);
    expect(r).toEqual({ ok: true });
    const a = m.users[1];
    expect(a.mustChangePassword).toBe(true);
    expect(a.passwordHash).not.toContain('temporary-password-1');
    expect(await bcrypt.compare('temporary-password-1', a.passwordHash)).toBe(true);
    expect(m.tokens.find((t) => t.userId === 'a').revokedAt).toBeInstanceOf(Date);
    const entry = (m.audit.log.mock.calls[0] as any[])[0];
    expect(entry).toMatchObject({ action: 'user.password_reset', targetId: 'a', result: 'SUCCESS' });
    expect(JSON.stringify(entry)).not.toContain('temporary-password-1');
  });
  it('refuses to reset your own password this way, and an unknown account', async () => {
    const m = make([user('root', 'SUPER_ADMIN')]);
    const err: any = await m.svc.resetPassword('root', 'temporary-password-1', actor).catch((e) => e);
    expect(err).toBeInstanceOf(BadRequestException);
    expect(err.getResponse().code).toBe('self_reset_forbidden');
    await expect(m.svc.resetPassword('nope', 'temporary-password-1', actor)).rejects.toBeInstanceOf(NotFoundException);
  });
});
