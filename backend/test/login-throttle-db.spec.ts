import 'reflect-metadata';
import { PrismaService } from '../src/prisma/prisma.service';
import { LoginThrottleService } from '../src/auth/login-throttle.service';
import { loginKey } from '../src/auth/login-throttle';

/**
 * The lockout counter on a REAL MySQL or MariaDB, including many attempts at the same instant over many
 * connections. Skipped unless explicitly enabled, because it empties security_login_throttle:
 *
 *   RETENTION_TEST_CONFIRM=yes DATABASE_URL=mysql://user:pass@host/ir_lockout_test npx jest test/login-throttle-db
 *
 * The database name must start with "ir_" and its migrations must already be applied.
 */
const enabled = process.env.RETENTION_TEST_CONFIRM === 'yes' && /\/ir_[A-Za-z0-9_]+(\?.*)?$/.test(process.env.DATABASE_URL ?? '');
const d = enabled ? describe : describe.skip;

d('lockout counter against a real database', () => {
  let prisma: PrismaService; let now: Date; let svc: LoginThrottleService;
  const advance = (s: number) => { now = new Date(now.getTime() + s * 1000); };
  const row = async (k: string) => ((await (prisma as any).$queryRawUnsafe('SELECT failures, lockedUntil FROM security_login_throttle WHERE `key` = ?', k)) as any[])[0];

  beforeAll(async () => { prisma = new PrismaService(); await prisma.$connect(); });
  afterAll(async () => { await prisma?.$disconnect(); });
  beforeEach(async () => {
    await (prisma as any).$executeRawUnsafe('DELETE FROM security_login_throttle');
    now = new Date();
    svc = new LoginThrottleService(prisma, () => now);
  });

  it('forty attempts at the same instant on one address: exactly five are let through', async () => {
    const key = loginKey('admin@example.com');
    const ds = await Promise.all(Array.from({ length: 40 }, () => svc.reserve(key)));
    expect(ds.filter((x) => x.allowed)).toHaveLength(5);
    expect(ds.filter((x) => x.lockedNow)).toHaveLength(1);                    // one attempt starts the lock
    expect(ds.filter((x) => !x.allowed).every((x) => x.retryAfterSeconds >= 1 && x.retryAfterSeconds <= 30)).toBe(true);
    const r = await row(key);
    expect(Number(r.failures)).toBe(5);                                          // refused attempts were not counted
    expect(new Date(r.lockedUntil).getTime()).toBeGreaterThan(now.getTime());
  });

  it('many accounts at once do not interfere: each gets its own five', async () => {
    const keys = Array.from({ length: 12 }, (_, i) => loginKey(`user${i}@example.com`));
    const ds = await Promise.all(keys.flatMap((k) => Array.from({ length: 10 }, () => svc.reserve(k).then((x) => ({ k, x })))));
    for (const k of keys) expect(ds.filter((r) => r.k === k && r.x.allowed)).toHaveLength(5);
  });

  it('a lock ends after its time, one more attempt is let through, and the next lock is longer', async () => {
    const key = loginKey('admin@example.com');
    for (let i = 0; i < 5; i++) await svc.reserve(key);
    expect((await svc.reserve(key)).allowed).toBe(false);
    advance(31);
    const d = await svc.reserve(key);
    expect(d).toMatchObject({ allowed: true, lockedNow: true, retryAfterSeconds: 60 });
  });

  it('failures from long ago are forgotten', async () => {
    const key = loginKey('admin@example.com');
    for (let i = 0; i < 4; i++) await svc.reserve(key);
    advance(61 * 60);
    await svc.reserve(key);
    expect(Number((await row(key)).failures)).toBe(1);
  });

  it('a correct password (reset) clears the count, and an unlock clears a lock', async () => {
    const key = loginKey('admin@example.com');
    for (let i = 0; i < 5; i++) await svc.reserve(key);
    expect((await svc.lockedUntil([key])).has(key)).toBe(true);
    await svc.reset(key);
    expect(await row(key)).toBeUndefined();
    expect((await svc.reserve(key)).allowed).toBe(true);
  });

  it('reports which of several accounts are locked right now', async () => {
    const a = loginKey('a@example.com'); const b = loginKey('b@example.com'); const c = loginKey('c@example.com');
    for (let i = 0; i < 5; i++) await svc.reserve(a);
    await svc.reserve(b);
    const m = await svc.lockedUntil([a, b, c]);
    expect([...m.keys()]).toEqual([a]);
    advance(31);
    expect((await svc.lockedUntil([a])).size).toBe(0);
    expect((await svc.lockedUntil([])).size).toBe(0);
  });

  it('survives a heavy mix of simultaneous attempts without errors (deadlocks are retried)', async () => {
    const keys = Array.from({ length: 5 }, (_, i) => loginKey(`mix${i}@example.com`));
    const errors: string[] = []; const t: number[] = [];
    await Promise.all(Array.from({ length: 300 }, async (_, i) => {
      const s = Date.now();
      try { await svc.reserve(keys[i % 5]); } catch (e: any) { errors.push(String(e.message).slice(0, 80)); }
      t.push(Date.now() - s);
    }));
    expect(errors).toEqual([]);
    t.sort((a, b) => a - b);
    // eslint-disable-next-line no-console
    console.log(`300 simultaneous attempts over 5 accounts: p50 ${t[150]} ms, p95 ${t[285]} ms, max ${t[299]} ms`);
    for (const k of keys) expect(Number((await row(k)).failures)).toBe(5);
  });

  it('the cleanup job removes old counters and keeps recent ones', async () => {
    const { RetentionService } = await import('../src/retention/retention.service');
    await (prisma as any).$executeRawUnsafe("INSERT INTO security_login_throttle (`key`, failures, lockedUntil, lastFailureAt, updatedAt) VALUES ('login:old1', 3, NULL, NOW(3) - INTERVAL 5 DAY, NOW(3)), ('login:old2', 9, NOW(3) - INTERVAL 5 DAY, NOW(3) - INTERVAL 5 DAY, NOW(3)), ('login:fresh', 2, NULL, NOW(3) - INTERVAL 1 HOUR, NOW(3))");
    const r = new RetentionService(prisma as any, { log: async () => undefined } as any);
    const rep = await r.run({ config: { eventDays: 0, auditDays: 0, ingestAuditDays: 0, incidentDays: 0, blockHistoryDays: 0, tokenGraceDays: 7, expiredEntryDays: 7, batchSize: 100, pauseMs: 0, maxSeconds: 60 } });
    expect(rep.errors).toEqual([]);
    expect(rep.jobs.find((j) => j.job === 'login_throttle')!.affected).toBe(2);
    expect(await row('login:fresh')).toBeTruthy(); expect(await row('login:old1')).toBeUndefined();
  });
});
