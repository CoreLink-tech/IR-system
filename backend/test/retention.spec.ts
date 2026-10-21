import 'reflect-metadata';
import { loadRetentionConfig, RetentionConfig } from '../src/retention/retention.config';
import { JOBS, RetentionService } from '../src/retention/retention.service';
import { validateConfig } from '../src/config/validate-config';

const DAY = 86_400_000;
const NOW = new Date('2026-10-14T12:00:00.000Z');
const cfg = (over: Partial<RetentionConfig> = {}): RetentionConfig => ({
  eventDays: 90, auditDays: 365, ingestAuditDays: 30, incidentDays: 730, blockHistoryDays: 365, tokenGraceDays: 7, expiredEntryDays: 7,
  batchSize: 2, pauseMs: 50, maxSeconds: 600, ...over,
});

interface Call { kind: 'query' | 'exec'; text: string; values: any[] }
class FakeDb {
  calls: Call[] = [];
  lockGranted = true;
  released = 0;
  /** rows returned for batch selects, per table, consumed in order */
  batches: Record<string, any[][]> = {};
  failExec: Record<string, any[]> = {};
  txOpts: any;
  private tableOf(t: string) { return JOBS.find((j) => t.includes(`FROM ${j.from} WHERE ${j.where.split('?')[0]}`))?.name ?? '?'; }
  $transaction = async (fn: (tx: any) => Promise<any>, opts: any) => {
    this.txOpts = opts;
    return fn({
      $queryRaw: async (s: any) => {
        if (s.sql.includes('GET_LOCK')) return [{ got: this.lockGranted ? 1n : 0n }];
        if (s.sql.includes('RELEASE_LOCK')) { this.released++; return [{ released: 1n }]; }
        throw new Error('unexpected tx query');
      },
    });
  };
  $queryRaw = async (s: any) => {
    this.calls.push({ kind: 'query', text: s.sql, values: s.values });
    if (s.sql.includes('COUNT(*)')) return [{ n: 7n }];
    const name = this.tableOf(s.sql);
    const q = this.batches[name] ?? [];
    return q.shift() ?? [];
  };
  $executeRaw = async (s: any) => {
    this.calls.push({ kind: 'exec', text: s.sql, values: s.values });
    const table = /(?:DELETE FROM|UPDATE) (\w+)/.exec(s.sql)![1];
    const f = this.failExec[table];
    if (f && f.length) { const e = f.shift(); if (e) throw e; }
    return s.values.length;
  };
  execs() { return this.calls.filter((c) => c.kind === 'exec'); }
  selects() { return this.calls.filter((c) => c.kind === 'query'); }
}
const audit = () => ({ log: jest.fn(async () => undefined) });
const rows = (...ids: string[]) => ids.map((id, i) => ({ id, ts: new Date(NOW.getTime() - (200 - i) * DAY) }));
const make = (db: FakeDb, a = audit()) => ({ svc: new RetentionService(db as any, a as any), audit: a });
const noSleep = () => { const calls: number[] = []; return { fn: async (ms: number) => { calls.push(ms); }, calls }; };

describe('retention settings', () => {
  it('have safe defaults', () => {
    const { config, errors } = loadRetentionConfig({});
    expect(errors).toEqual([]);
    expect(config).toEqual({ eventDays: 90, auditDays: 365, ingestAuditDays: 30, incidentDays: 730, blockHistoryDays: 365, tokenGraceDays: 7, expiredEntryDays: 7, batchSize: 5000, pauseMs: 200, maxSeconds: 600 });
  });
  it('read overrides, and 0 keeps a table forever', () => {
    const { config, errors } = loadRetentionConfig({ RETENTION_EVENT_DAYS: '30', RETENTION_AUDIT_DAYS: '0', RETENTION_BATCH_SIZE: '1000' });
    expect(errors).toEqual([]);
    expect(config.eventDays).toBe(30); expect(config.auditDays).toBe(0); expect(config.batchSize).toBe(1000);
  });
  it('refuse values that could erase recent evidence', () => {
    const { errors } = loadRetentionConfig({ RETENTION_EVENT_DAYS: '1', RETENTION_AUDIT_DAYS: '5', RETENTION_TOKEN_GRACE_DAYS: '0', RETENTION_BATCH_SIZE: '5', RETENTION_MAX_SECONDS: '1' });
    expect(errors).toHaveLength(5);
    expect(errors[0]).toContain('RETENTION_EVENT_DAYS must be between 7 and 3650');
  });
  it('refuse words, decimals and negatives', () => {
    expect(loadRetentionConfig({ RETENTION_EVENT_DAYS: 'ninety' }).errors[0]).toContain('whole number');
    expect(loadRetentionConfig({ RETENTION_EVENT_DAYS: '1.5' }).errors).toHaveLength(1);
    expect(loadRetentionConfig({ RETENTION_EVENT_DAYS: '-5' }).errors).toHaveLength(1);
  });
  it('make the server refuse to start when invalid', () => {
    const env: any = { NODE_ENV: 'development', JWT_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), API_KEY_HASH_PEPPER: 'c'.repeat(20), DATABASE_URL: 'mysql://u:p@h/d', RETENTION_EVENT_DAYS: '2' };
    expect(validateConfig(env).errors.join(' ')).toContain('RETENTION_EVENT_DAYS');
    delete env.RETENTION_EVENT_DAYS;
    expect(validateConfig(env).errors).toEqual([]);
  });
});

describe('cleanup run', () => {
  it('does nothing but report when another run holds the lock', async () => {
    const db = new FakeDb(); db.lockGranted = false; const { svc, audit: a } = make(db);
    const r = await svc.run({ config: cfg(), now: NOW });
    expect(r.skipped).toMatch(/another cleanup run/);
    expect(db.calls).toHaveLength(0); expect(db.released).toBe(0); expect(a.log).not.toHaveBeenCalled();
  });

  it('holds the lock for the run, releases it after, and gives the transaction room to last', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    await svc.run({ config: cfg({ maxSeconds: 600 }), now: NOW, sleep: noSleep().fn });
    expect(db.released).toBe(1);
    expect(db.txOpts.timeout).toBeGreaterThan(600 * 1000);
  });

  it('releases the lock even when a job fails, and carries on with the other jobs', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    db.batches.events = [rows('e1')]; db.failExec.security_events = [new Error('disk is on fire')];
    db.batches.audit_log = [rows('a1')];
    const r = await svc.run({ config: cfg(), now: NOW, sleep: noSleep().fn });
    expect(r.errors).toEqual(['events: disk is on fire']);
    expect(r.jobs.find((j) => j.job === 'events')!.error).toBe('disk is on fire');
    expect(r.jobs.find((j) => j.job === 'audit_log')!.affected).toBe(1);
    expect(db.released).toBe(1);
  });

  it('works in small batches by primary key, pausing between full batches only', async () => {
    const db = new FakeDb(); const sl = noSleep(); const { svc } = make(db);
    db.batches.events = [rows('e1', 'e2'), rows('e3', 'e4'), rows('e5')];
    const r = await svc.run({ config: cfg({ batchSize: 2, pauseMs: 50 }), now: NOW, sleep: sl.fn });
    const ev = db.execs().filter((c) => c.text.includes('security_events'));
    expect(ev.map((c) => c.values)).toEqual([['e1', 'e2'], ['e3', 'e4'], ['e5']]);
    ev.forEach((c) => expect(c.text).toMatch(/^DELETE FROM security_events WHERE id IN \(\?(,\?)*\)$/));
    expect(r.jobs[0]).toMatchObject({ job: 'events', affected: 5, batches: 3 });
    expect(sl.calls.filter((m) => m === 50)).toHaveLength(2);
  });

  it('continues from where the last batch ended (keyset), so protected rows are not rescanned', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    const first = rows('e1', 'e2');
    db.batches.events = [first, rows('e3')];
    await svc.run({ config: cfg({ batchSize: 2 }), now: NOW, sleep: noSleep().fn });
    const ev = db.selects().filter((c) => c.text.includes('FROM security_events e'));
    expect(ev[0].values).not.toContain('e2');
    expect(ev[1].values).toContain('e2');
    expect(ev[1].text).toContain('e.occurredAt >');
  });

  it('never selects events of an unresolved incident', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    db.batches.events = [rows('e1')];
    await svc.run({ config: cfg(), now: NOW, sleep: noSleep().fn });
    const sel = db.selects().find((c) => c.text.includes('security_events e'))!.text;
    expect(sel).toContain('e.incidentId IS NULL OR i.status IN (\'RESOLVED\', \'FALSE_POSITIVE\')');
  });

  it('computes each cutoff from its own setting', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    const r = await svc.run({ config: cfg(), now: NOW, sleep: noSleep().fn });
    const cut = (name: string) => new Date(r.jobs.find((j) => j.job === name)!.cutoff!).getTime();
    expect(cut('events')).toBe(NOW.getTime() - 90 * DAY);
    expect(cut('audit_log')).toBe(NOW.getTime() - 365 * DAY);
    expect(cut('audit_ingest')).toBe(NOW.getTime() - 30 * DAY);
    expect(cut('incidents')).toBe(NOW.getTime() - 730 * DAY);
    expect(cut('refresh_tokens')).toBe(NOW.getTime() - 7 * DAY);
    expect(cut('block_history')).toBe(NOW.getTime() - 365 * DAY);
    expect(cut('expired_allowlist')).toBe(NOW.getTime() - 7 * DAY);
    expect(cut('expire_blocks')).toBe(NOW.getTime());
    expect(cut('login_throttle')).toBe(NOW.getTime() - 2 * DAY);
  });

  it('switches expired temporary blocks off instead of deleting them', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    db.batches.expire_blocks = [rows('b1')];
    await svc.run({ config: cfg(), now: NOW, sleep: noSleep().fn });
    const up = db.execs().find((c) => c.text.includes('UPDATE security_ip_blocks'))!;
    expect(up.text).toContain('SET active = 0, activeKey = NULL');
    expect(up.text).not.toMatch(/DELETE/);
    const sel = db.selects().find((c) => c.text.includes('security_ip_blocks b') && c.text.includes('isPermanent = 0'))!.text;
    expect(sel).toContain('b.isPermanent = 0');
    expect(sel).toContain('b.active = 1');
  });

  it('removes only inactive blocks from history', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    db.batches.block_history = [rows('b9')];
    await svc.run({ config: cfg(), now: NOW, sleep: noSleep().fn });
    const sel = db.selects().find((c) => c.text.includes('b.active = 0'))!.text;
    expect(sel).toContain('b.active = 0');
  });

  it('uses smaller batches for incidents, which cascade to their timeline', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    await svc.run({ config: cfg({ batchSize: 5000 }), now: NOW, sleep: noSleep().fn });
    const inc = db.selects().find((c) => c.text.includes('security_incidents s'))!;
    expect(inc.values[inc.values.length - 1]).toBe(500);
  });

  it('stops starting batches when the time limit is reached, and says so', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    db.batches.events = [rows('e1', 'e2'), rows('e3', 'e4')];
    let t = 1_000_000; const clock = () => (t += 40_000); // each look at the clock costs 40 s
    const r = await svc.run({ config: cfg({ maxSeconds: 100, batchSize: 2 }), now: NOW, sleep: noSleep().fn, clock });
    expect(r.jobs.some((j) => j.stoppedEarly)).toBe(true);
    expect(db.execs().length).toBeLessThan(4);
  });

  it('retries a deadlock a few times, then gives up on a persistent one', async () => {
    const db = new FakeDb(); const sl = noSleep(); const { svc } = make(db);
    db.batches.events = [rows('e1')];
    db.failExec.security_events = [new Error('Deadlock found when trying to get lock'), undefined];
    const r = await svc.run({ config: cfg(), now: NOW, sleep: sl.fn });
    expect(r.jobs[0].affected).toBe(1); expect(r.errors).toEqual([]);
    expect(sl.calls.some((m) => m >= 200)).toBe(true);

    const db2 = new FakeDb(); const { svc: svc2 } = make(db2);
    db2.batches.events = [rows('e1')];
    db2.failExec.security_events = Array(10).fill(new Error('Lock wait timeout exceeded'));
    const r2 = await svc2.run({ config: cfg(), now: NOW, sleep: noSleep().fn });
    expect(r2.errors[0]).toContain('events: Lock wait timeout');
    expect(db2.execs().filter((c) => c.text.includes('security_events'))).toHaveLength(4);
  });

  it('does not retry an ordinary error', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    db.batches.events = [rows('e1')]; db.failExec.security_events = [new Error('syntax error'), undefined];
    const r = await svc.run({ config: cfg(), now: NOW, sleep: noSleep().fn });
    expect(r.errors).toHaveLength(1);
    expect(db.execs().filter((c) => c.text.includes('security_events'))).toHaveLength(1);
  });

  it('skips a job whose retention is 0 (keep forever)', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    const r = await svc.run({ config: cfg({ auditDays: 0, ingestAuditDays: 0, eventDays: 0 }), now: NOW, sleep: noSleep().fn });
    expect(r.jobs.find((j) => j.job === 'audit_log')).toMatchObject({ disabled: true, affected: 0 });
    expect(db.calls.some((c) => c.text.includes('security_audit_logs'))).toBe(false);
    expect(db.calls.some((c) => c.text.includes('security_events'))).toBe(false);
  });

  it('dry run counts and changes nothing', async () => {
    const db = new FakeDb(); const { svc, audit: a } = make(db);
    const r = await svc.run({ config: cfg(), now: NOW, dryRun: true, sleep: noSleep().fn });
    expect(db.execs()).toHaveLength(0);
    expect(db.selects().every((c) => c.text.startsWith('SELECT COUNT(*)'))).toBe(true);
    expect(r.dryRun).toBe(true);
    expect(r.jobs.every((j) => j.wouldAffect === 7 && j.affected === 0)).toBe(true);
    expect(a.log).toHaveBeenCalledWith(expect.objectContaining({ action: 'retention.dry_run' }));
  });

  it('removes the per-event audit rows on their own, shorter, limit', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    db.batches.audit_ingest = [rows('a1')];
    const r = await svc.run({ config: cfg(), now: NOW, sleep: noSleep().fn });
    expect(r.jobs.find((j) => j.job === 'audit_ingest')!.affected).toBe(1);
    const sel = db.selects().find((c) => c.text.includes("a.action = 'event.ingest'"))!;
    expect(sel.text).toContain('a.createdAt <');
  });

  it('records what it did in the audit log', async () => {
    const db = new FakeDb(); const { svc, audit: a } = make(db);
    db.batches.audit_log = [rows('a1')];
    await svc.run({ config: cfg(), now: NOW, sleep: noSleep().fn });
    expect(a.log).toHaveBeenCalledWith(expect.objectContaining({ actorType: 'SYSTEM', action: 'retention.run', result: 'SUCCESS' }));
    const meta = (a.log.mock.calls[0] as any[])[0].metadata;
    expect(meta.jobs.find((j: any) => j.job === 'audit_log').affected).toBe(1);
  });

  it('marks the audit entry as a failure when a job failed', async () => {
    const db = new FakeDb(); const { svc, audit: a } = make(db);
    db.batches.events = [rows('e1')]; db.failExec.security_events = [new Error('boom')];
    await svc.run({ config: cfg(), now: NOW, sleep: noSleep().fn });
    expect(a.log).toHaveBeenCalledWith(expect.objectContaining({ result: 'FAILURE' }));
  });

  it('refuses to run with invalid settings and touches nothing', async () => {
    const db = new FakeDb(); const { svc } = make(db);
    const saved = process.env.RETENTION_EVENT_DAYS; process.env.RETENTION_EVENT_DAYS = '1';
    try {
      const r = await svc.run({ now: NOW });
      expect(r.errors[0]).toContain('RETENTION_EVENT_DAYS');
      expect(db.calls).toHaveLength(0);
    } finally { if (saved === undefined) delete process.env.RETENTION_EVENT_DAYS; else process.env.RETENTION_EVENT_DAYS = saved; }
  });

  it('every job selects and changes rows by primary key, never by a bare time condition', () => {
    for (const j of JOBS) {
      expect(j.idExpr).toMatch(/\.(id|`key`)$/);
      expect(j.where).toContain('?');
      expect(j.where.split('?')).toHaveLength(2);
    }
  });
});
