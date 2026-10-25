import 'reflect-metadata';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../src/auth/../prisma/prisma.service';
import { TwoFactorService } from '../src/auth/two-factor.service';
import { totp } from '../src/auth/totp';
import { InMemoryThrottle } from './helpers/in-memory-throttle';
import { randomBytes } from 'crypto';

/**
 * The guarantees that depend on the database doing the work atomically, on a REAL MySQL or MariaDB: a code
 * works once even when used many times at the same instant, a recovery code works once, and secrets are
 * encrypted at rest. Skipped unless explicitly enabled, because it empties the security_* user tables:
 *
 *   RETENTION_TEST_CONFIRM=yes DATABASE_URL=mysql://user:pass@host/ir_twofactor_test npx jest test/two-factor-db
 */
const enabled = process.env.RETENTION_TEST_CONFIRM === 'yes' && /\/ir_[A-Za-z0-9_]+(\?.*)?$/.test(process.env.DATABASE_URL ?? '');
const d = enabled ? describe : describe.skip;

d('two-step verification against a real database', () => {
  let prisma: PrismaService; let svc: TwoFactorService; const audit: any[] = [];
  const ctx = { ip: '203.0.113.5', requestId: 'r1' };
  const raw = (sql: string, ...p: any[]) => (prisma as any).$queryRawUnsafe(sql, ...p) as Promise<any[]>;

  beforeAll(async () => {
    process.env.TOTP_ENCRYPTION_KEY = randomBytes(32).toString('hex');
    process.env.REQUIRE_2FA = 'true';
    prisma = new PrismaService(); await prisma.$connect();
    // many attempts at once must not be stopped by the lockout counter in this test: it is not what is being tested
    svc = new TwoFactorService(prisma as any, { log: async (e: any) => { audit.push(e); } } as any, new InMemoryThrottle({ LOCKOUT_THRESHOLD: '20' }) as any, new JwtService());
  });
  afterAll(async () => { await prisma?.$disconnect(); delete process.env.TOTP_ENCRYPTION_KEY; delete process.env.REQUIRE_2FA; });
  beforeEach(async () => {
    for (const t of ['security_recovery_codes', 'security_refresh_tokens', 'security_users']) await (prisma as any).$executeRawUnsafe(`DELETE FROM ${t}`);
    audit.length = 0;
    await prisma.securityUser.create({ data: { id: 'u1', email: 'admin@example.com', passwordHash: 'x', role: 'SUPER_ADMIN' } });
  });

  async function enrol() {
    const s = await svc.startEnrolment('u1');
    const { recoveryCodes } = await svc.confirmEnrolment('u1', totp(s.secret, new Date()), ctx);
    return { secret: s.secret, recoveryCodes };
  }
  const nextCode = (secret: string, stepsAhead = 1) => totp(secret, new Date(Date.now() + stepsAhead * 30_000));

  it('enrolment encrypts the secret at rest and stores recovery codes only as hashes', async () => {
    const { secret, recoveryCodes } = await enrol();
    const [u] = await raw('SELECT totpSecret, totpEnabledAt, totpLastStep FROM security_users WHERE id = ?', 'u1');
    expect(u.totpSecret).not.toContain(secret); expect(String(u.totpSecret).startsWith('v1.')).toBe(true);
    expect(u.totpEnabledAt).toBeTruthy(); expect(Number(u.totpLastStep)).toBeGreaterThan(0);
    const rows = await raw('SELECT codeHash FROM security_recovery_codes WHERE userId = ?', 'u1');
    expect(rows).toHaveLength(10);
    for (const c of recoveryCodes) expect(JSON.stringify(rows)).not.toContain(c.replace(/-/g, ''));
  });

  it('the same valid code used twelve times at the same instant succeeds exactly once', async () => {
    const { secret } = await enrol();
    const code = nextCode(secret);                                             // a code for the next step, not the one used to enrol
    const user = await prisma.securityUser.findUnique({ where: { id: 'u1' } });
    const results = await Promise.allSettled(Array.from({ length: 12 }, () => svc.verifySignIn(user, { code }, ctx)));
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((r) => r.status === 'rejected')).toHaveLength(11);
  });

  it('the same recovery code used twelve times at the same instant succeeds exactly once', async () => {
    const { recoveryCodes } = await enrol();
    const user = await prisma.securityUser.findUnique({ where: { id: 'u1' } });
    const results = await Promise.allSettled(Array.from({ length: 12 }, () => svc.verifySignIn(user, { recoveryCode: recoveryCodes[2] }, ctx)));
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    const [left] = await raw('SELECT COUNT(*) AS n FROM security_recovery_codes WHERE userId = ? AND usedAt IS NULL', 'u1');
    expect(Number(left.n)).toBe(9);
  });

  it('two different recovery codes used at once both work, and each only once', async () => {
    const { recoveryCodes } = await enrol();
    const user = await prisma.securityUser.findUnique({ where: { id: 'u1' } });
    const results = await Promise.allSettled([0, 1, 0, 1].map((i) => svc.verifySignIn(user, { recoveryCode: recoveryCodes[i] }, ctx)));
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(2);
  });

  it('confirming an enrolment twice at once switches it on once and issues one set of recovery codes', async () => {
    const s = await svc.startEnrolment('u1');
    const code = totp(s.secret, new Date());
    const results = await Promise.allSettled([svc.confirmEnrolment('u1', code, ctx), svc.confirmEnrolment('u1', code, ctx), svc.confirmEnrolment('u1', code, ctx)]);
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    const [n] = await raw('SELECT COUNT(*) AS n FROM security_recovery_codes WHERE userId = ?', 'u1');
    expect(Number(n.n)).toBe(10);
  });

  it('regenerating replaces all codes in one step: the old ones stop working, there are exactly ten', async () => {
    const { secret, recoveryCodes } = await enrol();
    const code = nextCode(secret);
    // password check is bypassed here by a real bcrypt hash set on the row
    const bcrypt = await import('bcryptjs');
    await prisma.securityUser.update({ where: { id: 'u1' }, data: { passwordHash: await bcrypt.hash('CorrectHorse!1', 4) } });
    const fresh = await svc.regenerateRecoveryCodes('u1', 'CorrectHorse!1', code, ctx);
    expect(fresh.recoveryCodes).toHaveLength(10);
    const [n] = await raw('SELECT COUNT(*) AS n FROM security_recovery_codes WHERE userId = ?', 'u1');
    expect(Number(n.n)).toBe(10);
    const user = await prisma.securityUser.findUnique({ where: { id: 'u1' } });
    await expect(svc.verifySignIn(user, { recoveryCode: recoveryCodes[0] }, ctx)).rejects.toBeTruthy();
    await expect(svc.verifySignIn(user, { recoveryCode: fresh.recoveryCodes[0] }, ctx)).resolves.toMatchObject({ method: 'recovery' });
  });

  it('recovery code hashes are unique in the database, and deleting an account deletes its codes', async () => {
    await enrol();
    await expect((prisma as any).securityRecoveryCode.create({ data: { userId: 'u1', codeHash: (await raw('SELECT codeHash FROM security_recovery_codes LIMIT 1'))[0].codeHash } })).rejects.toBeTruthy();
    await (prisma as any).$executeRawUnsafe('DELETE FROM security_users WHERE id = ?', 'u1');
    expect(Number((await raw('SELECT COUNT(*) AS n FROM security_recovery_codes'))[0].n)).toBe(0);
  });

  it('a super admin reset clears the secret, the codes and ends the sessions, in one step', async () => {
    await enrol();
    await prisma.securityUser.create({ data: { id: 'u2', email: 'second@example.com', passwordHash: 'x', role: 'SUPER_ADMIN' } });
    await (prisma as any).securityRefreshToken.create({ data: { userId: 'u1', tokenHash: 'h', expiresAt: new Date(Date.now() + 1e9), sessionId: 's1', sessionStartedAt: new Date() } });
    const out = await svc.adminReset('u1', { id: 'u2', label: 'second@example.com' } as any);
    expect(out).toEqual({ ok: true, mustEnrolAtNextSignIn: true });
    const [u] = await raw('SELECT totpSecret, totpEnabledAt, totpLastStep, tokenVersion FROM security_users WHERE id = ?', 'u1');
    expect(u.totpSecret).toBeNull(); expect(u.totpEnabledAt).toBeNull(); expect(Number(u.tokenVersion)).toBe(1);
    expect(Number((await raw('SELECT COUNT(*) AS n FROM security_recovery_codes WHERE userId = ?', 'u1'))[0].n)).toBe(0);
    expect((await raw('SELECT revokedReason FROM security_refresh_tokens WHERE userId = ?', 'u1'))[0].revokedReason).toBe('two_factor_reset');
  });
});
