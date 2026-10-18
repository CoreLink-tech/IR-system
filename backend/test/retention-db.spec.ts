import 'reflect-metadata';
import { PrismaService } from '../src/prisma/prisma.service';
import { RetentionService } from '../src/retention/retention.service';
import { RetentionConfig } from '../src/retention/retention.config';

/**
 * Runs the cleanup against a REAL MySQL or MariaDB. Skipped unless explicitly enabled, because it
 * empties the security_* tables of the database in DATABASE_URL:
 *
 *   RETENTION_TEST_CONFIRM=yes DATABASE_URL=mysql://user:pass@host/ir_retention_test npx jest test/retention-db
 *
 * The database name must start with "ir_" and its migrations must already be applied.
 */
const enabled = process.env.RETENTION_TEST_CONFIRM === 'yes' && /\/ir_[A-Za-z0-9_]+(\?.*)?$/.test(process.env.DATABASE_URL ?? '');
const d = enabled ? describe : describe.skip;
const DAY = 86_400_000;
const ago = (days: number) => new Date(Date.now() - days * DAY);
const cfg = (over: Partial<RetentionConfig> = {}): RetentionConfig => ({
  eventDays: 90, auditDays: 365, ingestAuditDays: 30, incidentDays: 730, blockHistoryDays: 365, tokenGraceDays: 7, expiredEntryDays: 7,
  batchSize: 100, pauseMs: 0, maxSeconds: 600, ...over,
});

d('cleanup against a real database', () => {
  // Created in beforeAll: a skipped describe still runs its body, and the client may not be generated.
  let prisma: PrismaService;
  let svc: RetentionService;
  const auditCalls: any[] = [];
  const count = (t: string, where = '1=1') => (prisma as any).$queryRawUnsafe(`SELECT COUNT(*) AS n FROM ${t} WHERE ${where}`).then((r: any[]) => Number(r[0].n));
  const chunked = async (rows: any[], fn: (c: any[]) => Promise<any>) => { for (let i = 0; i < rows.length; i += 4000) await fn(rows.slice(i, i + 4000)); };
  const ev = (n: number, over: any) => Array.from({ length: n }, (_, i) => ({ eventType: 'page_view', severity: 'INFO', ipAddress: `203.0.113.${i % 250}`, ...over }));

  async function reset() {
    for (const t of ['security_incident_timeline', 'security_events', 'security_incidents', 'security_audit_logs', 'security_refresh_tokens', 'security_ip_blocks', 'security_ip_allowlist', 'security_users']) {
      await prisma.$executeRawUnsafe(`DELETE FROM ${t}`);
    }
    auditCalls.length = 0;
  }

  async function seed(opts: { oldEvents?: number } = {}) {
    await prisma.securityUser.create({ data: { id: 'u1', email: 'a@example.com', passwordHash: 'x', role: 'SECURITY_ADMIN' } });
    const inc = (id: string, status: string, resolvedAt: Date | null, updatedAt: Date) => prisma.securityIncident.create({ data: { id, incidentId: `INC-${id}`, title: 't', description: 'd', severity: 'HIGH', riskScore: 50, status, resolvedAt, updatedAt } });
    await inc('R1', 'RESOLVED', ago(800), ago(800));        // old and resolved: goes
    await inc('R2', 'FALSE_POSITIVE', ago(800), ago(800));  // old false positive: goes
    await inc('R3', 'RESOLVED', ago(10), ago(10));          // resolved recently: stays
    await inc('O1', 'OPEN', null, ago(900));                // open, ancient: stays, with its evidence
    await inc('O2', 'CONTAINED', null, ago(900));           // contained is not resolved: stays
    await prisma.securityIncidentTimeline.createMany({ data: [{ incidentId: 'R1', action: 'created' }, { incidentId: 'R1', action: 'resolved' }, { incidentId: 'R2', action: 'created' }, { incidentId: 'O1', action: 'created' }] });

    const old = ago(120), fresh = ago(2);
    await chunked(ev(opts.oldEvents ?? 2000, { occurredAt: old }), (c) => prisma.securityEvent.createMany({ data: c }));          // old, no incident: go
    await prisma.securityEvent.createMany({ data: ev(300, { occurredAt: old, incidentId: 'O1' }) });                             // old, open incident: stay
    await prisma.securityEvent.createMany({ data: ev(50, { occurredAt: old, incidentId: 'O2' }) });                              // old, contained incident: stay
    await prisma.securityEvent.createMany({ data: ev(100, { occurredAt: old, incidentId: 'R1' }) });                             // old, resolved incident: go
    await prisma.securityEvent.createMany({ data: ev(40, { occurredAt: old, incidentId: 'R3' }) });                              // old, recently resolved incident: go (event limit applies)
    await prisma.securityEvent.createMany({ data: ev(200, { occurredAt: fresh }) });                                             // recent: stay

    await prisma.securityAuditLog.createMany({ data: [...Array.from({ length: 500 }, () => ({ actorType: 'USER', action: 'x', result: 'SUCCESS', createdAt: ago(400) })), ...Array.from({ length: 100 }, () => ({ actorType: 'USER', action: 'x', result: 'SUCCESS', createdAt: ago(5) })),
      ...Array.from({ length: 300 }, () => ({ actorType: 'API_KEY', action: 'event.ingest', result: 'SUCCESS', createdAt: ago(40) })),   // per-event audit rows past 30 days: go
      ...Array.from({ length: 50 }, () => ({ actorType: 'API_KEY', action: 'event.ingest', result: 'SUCCESS', createdAt: ago(5) })),     // recent ones stay
      ...Array.from({ length: 20 }, () => ({ actorType: 'USER', action: 'ip.block', result: 'SUCCESS', createdAt: ago(40) }))] });  // other actions are not touched by the shorter limit

    const tok = (i: number, expires: Date, revoked: Date | null) => ({ userId: 'u1', tokenHash: `h${i}`, expiresAt: expires, revokedAt: revoked, sessionId: `s${i}`, sessionStartedAt: ago(1) });
    await prisma.securityRefreshToken.createMany({ data: [
      ...Array.from({ length: 100 }, (_, i) => tok(i, ago(30), null)),            // long expired: go
      ...Array.from({ length: 10 }, (_, i) => tok(1000 + i, ago(30), ago(40))),   // revoked and long expired: go
      ...Array.from({ length: 50 }, (_, i) => tok(2000 + i, ago(2), null)),       // expired 2 days ago: inside the grace period, stay
      ...Array.from({ length: 20 }, (_, i) => tok(3000 + i, new Date(Date.now() + 5 * DAY), null)), // valid: stay
      ...Array.from({ length: 5 }, (_, i) => tok(4000 + i, new Date(Date.now() + 5 * DAY), ago(1))), // revoked but not expired: stay (reuse detection)
    ] });

    const blk = (i: number, over: any) => ({ ipAddress: `198.51.100.${i}`, action: 'BLOCK', reason: 'r', ...over });
    await prisma.securityIpBlock.createMany({ data: [
      ...Array.from({ length: 10 }, (_, i) => blk(i + 1, { isPermanent: false, expiresAt: ago(1), active: true, activeKey: `198.51.100.${i + 1}` })),  // expired but still marked active: switched off
      blk(50, { isPermanent: true, active: true, activeKey: '198.51.100.50' }),                                                                          // permanent: stays active
      blk(51, { isPermanent: false, expiresAt: new Date(Date.now() + DAY), active: true, activeKey: '198.51.100.51' }),                                  // still running: stays
      ...Array.from({ length: 20 }, (_, i) => blk(100 + i, { isPermanent: false, expiresAt: ago(399), active: false, createdAt: ago(400) })),            // old history: goes
      blk(60, { isPermanent: false, expiresAt: ago(20), active: false, createdAt: ago(21) }),                                                           // recent history: stays
    ] });

    await prisma.securityIpAllowlist.createMany({ data: [
      { ipAddress: '192.0.2.1', reason: 'r', expiresAt: ago(30) }, { ipAddress: '192.0.2.2', reason: 'r', expiresAt: ago(2) }, { ipAddress: '192.0.2.3', reason: 'r' },
    ] });
  }

  const snapshot = async () => ({
    events: await count('security_events'), eventsOpen: await count('security_events', "incidentId IN ('O1','O2')"),
    incidents: await count('security_incidents'), timeline: await count('security_incident_timeline'),
    audit: await count('security_audit_logs'), tokens: await count('security_refresh_tokens'),
    blocks: await count('security_ip_blocks'), activeBlocks: await count('security_ip_blocks', 'active = 1'),
    allow: await count('security_ip_allowlist'),
  });

  beforeAll(async () => {
    prisma = new PrismaService();
    svc = new RetentionService(prisma as any, { log: async (e: any) => { auditCalls.push(e); } } as any);
    await prisma.$connect();
  });
  afterAll(async () => { await prisma?.$disconnect(); });

  it('removes what is past its limit and keeps everything else', async () => {
    await reset(); await seed();
    const before = await snapshot();
    expect(before.events).toBe(2690);
    const r = await svc.run({ config: cfg() });
    expect(r.errors).toEqual([]);
    const after = await snapshot();
    expect(after.events).toBe(300 + 50 + 200);                // evidence of open incidents and recent events
    expect(after.eventsOpen).toBe(350);
    expect(after.incidents).toBe(3);                            // R3, O1, O2
    expect(await count('security_incidents', "id IN ('R1','R2')")).toBe(0);
    expect(after.timeline).toBe(1);                             // R1 and R2 timelines went with them
    expect(after.audit).toBe(100 + 50 + 20);
    expect(after.tokens).toBe(50 + 20 + 5);                     // grace period, valid, and revoked-but-not-expired
    expect(after.allow).toBe(2);
    expect(after.blocks).toBe(10 + 1 + 1 + 1);                  // 10 switched off but kept, 2 live, 1 recent history
    expect(after.activeBlocks).toBe(2);
    expect(await count('security_ip_blocks', 'active = 0 AND activeKey IS NOT NULL')).toBe(0);
    expect(r.jobs.find((j) => j.job === 'events')!.batches).toBeGreaterThan(20);
    expect(auditCalls.at(-1)).toMatchObject({ action: 'retention.run', actorType: 'SYSTEM', result: 'SUCCESS' });
  });

  it('a second run finds nothing to do', async () => {
    const r = await svc.run({ config: cfg() });
    expect(r.errors).toEqual([]);
    for (const j of r.jobs) expect(j.affected).toBe(0);
  });

  it('a dry run predicts exactly what the real run then does, and changes nothing', async () => {
    await reset(); await seed();
    const before = await snapshot();
    const dry = await svc.run({ config: cfg(), dryRun: true });
    expect(await snapshot()).toEqual(before);
    const real = await svc.run({ config: cfg() });
    for (const j of dry.jobs) expect(real.jobs.find((x) => x.job === j.job)!.affected).toBe(j.wouldAffect);
    expect(auditCalls.map((a) => a.action)).toEqual(['retention.dry_run', 'retention.run']);
  });

  it('can be stopped part-way and finished by the next run, ending in the same state as one uninterrupted run', async () => {
    await reset(); await seed();
    let t = Date.now(); let looks = 0;
    const clock = () => { looks++; return looks > 8 ? t + 10_000_000 : t; };   // runs out of time after a handful of batches
    const partial = await svc.run({ config: cfg({ maxSeconds: 60 }), clock });
    expect(partial.jobs.some((j) => j.stoppedEarly)).toBe(true);
    const mid = await snapshot();
    expect(mid.events).toBeGreaterThan(550);                    // not finished
    const rest = await svc.run({ config: cfg() });
    expect(rest.errors).toEqual([]);
    expect(await snapshot()).toMatchObject({ events: 550, incidents: 3, audit: 170, tokens: 75, allow: 2 });
  });

  it('only one run can hold the lock; the other says so and changes nothing', async () => {
    await reset(); await seed({ oldEvents: 6000 });
    const slow = cfg({ batchSize: 200, pauseMs: 15 });
    const [a, b] = await Promise.all([svc.run({ config: slow }), (async () => { await new Promise((r) => setTimeout(r, 250)); return svc.run({ config: slow }); })()]);
    const skipped = [a, b].filter((r) => r.skipped);
    expect(skipped).toHaveLength(1);
    const ran = [a, b].find((r) => !r.skipped)!;
    expect(ran.jobs.find((j) => j.job === 'events')!.affected).toBe(6000 + 100 + 40);
    expect(ran.errors).toEqual([]);
  });

  it('live ingestion keeps working while a large cleanup runs, and no recent row is lost', async () => {
    await reset(); await seed({ oldEvents: 30000 });
    let running = true; let inserted = 0; let failures = 0; let maxMs = 0; let maxRead = 0;
    const writer = (async () => {
      while (running) {
        const s = Date.now();
        try { await prisma.securityEvent.create({ data: { eventType: 'login_failed', severity: 'LOW', ipAddress: '198.51.100.250', occurredAt: new Date() } }); inserted++; } catch { failures++; }
        maxMs = Math.max(maxMs, Date.now() - s);
        const r0 = Date.now();
        await prisma.securityEvent.count({ where: { ipAddress: '198.51.100.250', occurredAt: { gte: new Date(Date.now() - 600_000) } } });
        maxRead = Math.max(maxRead, Date.now() - r0);
      }
    })();
    const t0 = Date.now();
    const r = await svc.run({ config: cfg({ batchSize: 500, pauseMs: 10 }) });
    const took = Date.now() - t0;
    running = false; await writer;
    expect(r.errors).toEqual([]);
    expect(r.jobs.find((j) => j.job === 'events')!.affected).toBe(30000 + 100 + 40);
    expect(failures).toBe(0);
    expect(inserted).toBeGreaterThan(50);
    expect(await count('security_events', "ipAddress = '198.51.100.250'")).toBe(inserted);
    // eslint-disable-next-line no-console
    console.log(`cleanup of ~30k events took ${took} ms; meanwhile ${inserted} live inserts, 0 failures, slowest insert ${maxMs} ms, slowest windowed read ${maxRead} ms`);
    expect(maxMs).toBeLessThan(1500);
  }, 120_000);

  it('switching an expired block off frees its address for a new block (the unique slot is released)', async () => {
    await reset(); await seed({ oldEvents: 10 });
    await expect(prisma.securityIpBlock.create({ data: { ipAddress: '198.51.100.1', action: 'BLOCK', reason: 'again', active: true, activeKey: '198.51.100.1' } })).rejects.toThrow();
    await svc.run({ config: cfg() });
    await expect(prisma.securityIpBlock.create({ data: { ipAddress: '198.51.100.1', action: 'BLOCK', reason: 'again', active: true, activeKey: '198.51.100.1' } })).resolves.toBeDefined();
  });
});
