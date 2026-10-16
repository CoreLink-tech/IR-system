import { Injectable, Logger } from '@nestjs/common';
// The SQL helpers come from Prisma's runtime library, which exists in every Prisma 5 and 6 install
// without running the code generator.
import { sqltag as sql, join, raw, Sql } from '@prisma/client/runtime/library';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { RetentionConfig, loadRetentionConfig } from './retention.config';

const LOCK_NAME = 'ir_retention';
const DAY_MS = 86_400_000;

interface Job {
  name: string;
  description: string;
  /** Retention in days, or null when the job has no age rule. 0 switches the job off. */
  days: (c: RetentionConfig) => number | null;
  /** Rows older than this are affected. */
  cutoff: (c: RetentionConfig, now: Date) => Date;
  table: string;
  from: string;      // static SQL, never user input
  idExpr: string;
  tsExpr: string;
  where: string;     // uses ? placeholders replaced by the cutoff, see build()
  action: 'delete' | 'update';
  batchCap?: number; // some jobs cascade, so they use smaller batches
  keyset: boolean;   // false when processed rows stop matching the filter
}

/**
 * The jobs, in the order they run. Everything is selected by primary key in small batches and
 * changed by primary key, so each statement locks only the rows it touches.
 */
export const JOBS: Job[] = [
  {
    name: 'events',
    description: 'Security events older than the limit. Events attached to an incident that is not resolved are kept as evidence.',
    days: (c) => c.eventDays, cutoff: (c, now) => new Date(now.getTime() - c.eventDays * DAY_MS),
    table: 'security_events',
    from: 'security_events e LEFT JOIN security_incidents i ON i.id = e.incidentId',
    idExpr: 'e.id', tsExpr: 'e.occurredAt',
    where: "e.occurredAt < ? AND (e.incidentId IS NULL OR i.status IN ('RESOLVED', 'FALSE_POSITIVE'))",
    action: 'delete', keyset: true,
  },
  {
    name: 'incidents',
    description: 'Resolved and false-positive incidents older than the limit, with their timeline. Events stay until the event limit.',
    days: (c) => c.incidentDays, cutoff: (c, now) => new Date(now.getTime() - c.incidentDays * DAY_MS),
    table: 'security_incidents',
    from: 'security_incidents s',
    idExpr: 's.id', tsExpr: 'COALESCE(s.resolvedAt, s.updatedAt)',
    where: "s.status IN ('RESOLVED', 'FALSE_POSITIVE') AND COALESCE(s.resolvedAt, s.updatedAt) < ?",
    action: 'delete', batchCap: 500, keyset: true,
  },
  {
    name: 'audit_ingest',
    description: 'The audit row written for each accepted event (event.ingest). The event is its own record, so these are removed sooner than the rest of the audit log.',
    days: (c) => c.ingestAuditDays, cutoff: (c, now) => new Date(now.getTime() - c.ingestAuditDays * DAY_MS),
    table: 'security_audit_logs',
    from: 'security_audit_logs a', idExpr: 'a.id', tsExpr: 'a.createdAt',
    where: "a.action = 'event.ingest' AND a.createdAt < ?", action: 'delete', keyset: true,
  },
  {
    name: 'audit_log',
    description: 'Audit log entries older than the limit.',
    days: (c) => c.auditDays, cutoff: (c, now) => new Date(now.getTime() - c.auditDays * DAY_MS),
    table: 'security_audit_logs',
    from: 'security_audit_logs a', idExpr: 'a.id', tsExpr: 'a.createdAt',
    where: 'a.createdAt < ?', action: 'delete', keyset: true,
  },
  {
    name: 'refresh_tokens',
    description: 'Refresh tokens that expired more than the grace period ago (revoked or not).',
    days: (c) => c.tokenGraceDays, cutoff: (c, now) => new Date(now.getTime() - c.tokenGraceDays * DAY_MS),
    table: 'security_refresh_tokens',
    from: 'security_refresh_tokens t', idExpr: 't.id', tsExpr: 't.expiresAt',
    where: 't.expiresAt < ?', action: 'delete', keyset: true,
  },
  {
    name: 'expire_blocks',
    description: 'Temporary blocks whose time has passed are switched off, freeing their slot. The row stays as history.',
    days: () => null, cutoff: (_c, now) => now,
    table: 'security_ip_blocks',
    from: 'security_ip_blocks b', idExpr: 'b.id', tsExpr: 'b.expiresAt',
    where: 'b.active = 1 AND b.isPermanent = 0 AND b.expiresAt IS NOT NULL AND b.expiresAt < ?',
    action: 'update', keyset: false,
  },
  {
    name: 'block_history',
    description: 'Inactive blocks older than the limit.',
    days: (c) => c.blockHistoryDays, cutoff: (c, now) => new Date(now.getTime() - c.blockHistoryDays * DAY_MS),
    table: 'security_ip_blocks',
    from: 'security_ip_blocks b', idExpr: 'b.id', tsExpr: 'b.createdAt',
    where: 'b.active = 0 AND b.createdAt < ?', action: 'delete', keyset: true,
  },
  {
    name: 'expired_allowlist',
    description: 'Allowlist entries that expired more than the grace period ago.',
    days: (c) => c.expiredEntryDays, cutoff: (c, now) => new Date(now.getTime() - c.expiredEntryDays * DAY_MS),
    table: 'security_ip_allowlist',
    from: 'security_ip_allowlist w', idExpr: 'w.id', tsExpr: 'w.expiresAt',
    where: 'w.expiresAt IS NOT NULL AND w.expiresAt < ?', action: 'delete', keyset: true,
  },
];

export interface JobReport {
  job: string;
  description: string;
  disabled?: boolean;
  cutoff?: string;
  /** Dry run: rows that would be changed. */
  wouldAffect?: number;
  /** Rows changed (deleted, or switched off for expire_blocks). */
  affected: number;
  batches: number;
  stoppedEarly?: boolean;
  error?: string;
}
export interface RunReport {
  startedAt: string; finishedAt: string; durationMs: number; dryRun: boolean;
  skipped?: string;
  jobs: JobReport[];
  errors: string[];
}
export interface RunOptions {
  dryRun?: boolean;
  now?: Date;
  config?: RetentionConfig;
  sleep?: (ms: number) => Promise<void>;
  clock?: () => number;
}

const isRetryable = (e: any) => /deadlock|lock wait timeout|P2034|40001|1213|1205/i.test(String(e?.message ?? e) + String(e?.code ?? ''));

@Injectable()
export class RetentionService {
  private readonly logger = new Logger('Retention');
  constructor(private readonly prisma: PrismaService, private readonly audit: AuditService) {}

  /** Builds the batch SELECT for a job. Cutoff and cursor are bound parameters; the rest is static text. */
  private bind(job: Job, cutoff: Date, cursor: { at: Date; id: string } | null, limit: number | null): Sql {
    // The where text contains exactly one "?"; split around it so the cutoff is a bound value.
    const [before, after] = job.where.split('?');
    let q = sql`SELECT ${raw(job.idExpr)} AS id, ${raw(job.tsExpr)} AS ts FROM ${raw(job.from)} WHERE ${raw(before)}${cutoff}${raw(after)}`;
    if (cursor && job.keyset) {
      q = sql`${q} AND (${raw(job.tsExpr)} > ${cursor.at} OR (${raw(job.tsExpr)} = ${cursor.at} AND ${raw(job.idExpr)} > ${cursor.id}))`;
    }
    if (limit !== null) q = sql`${q} ORDER BY ${raw(job.tsExpr)} ASC, ${raw(job.idExpr)} ASC LIMIT ${limit}`;
    return q;
  }

  private countSql(job: Job, cutoff: Date): Sql {
    const [before, after] = job.where.split('?');
    return sql`SELECT COUNT(*) AS n FROM ${raw(job.from)} WHERE ${raw(before)}${cutoff}${raw(after)}`;
  }

  private applySql(job: Job, ids: string[]): Sql {
    if (job.action === 'update') {
      return sql`UPDATE ${raw(job.table)} SET active = 0, activeKey = NULL, updatedAt = NOW(3) WHERE active = 1 AND id IN (${join(ids)})`;
    }
    return sql`DELETE FROM ${raw(job.table)} WHERE id IN (${join(ids)})`;
  }

  private async retry<T>(fn: () => Promise<T>, sleep: (ms: number) => Promise<void>): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      try { return await fn(); } catch (e) {
        if (attempt >= 4 || !isRetryable(e)) throw e;
        await sleep(200 * attempt * attempt);
      }
    }
  }

  async run(opts: RunOptions = {}): Promise<RunReport> {
    const loaded = opts.config ? { config: opts.config, errors: [] as string[] } : loadRetentionConfig();
    const started = (opts.clock ?? Date.now)();
    const startedAt = new Date(started);
    if (loaded.errors.length) {
      return { startedAt: startedAt.toISOString(), finishedAt: startedAt.toISOString(), durationMs: 0, dryRun: !!opts.dryRun, jobs: [], errors: loaded.errors };
    }
    const cfg = loaded.config;
    // The lock lives on one pinned connection for the whole run, so two runs can never overlap,
    // including runs from different servers sharing one database.
    const report = await this.prisma.$transaction(async (tx: any) => {
      const got: any[] = await tx.$queryRaw(sql`SELECT GET_LOCK(${LOCK_NAME}, 0) AS got`);
      if (Number(got?.[0]?.got) !== 1) {
        return { startedAt: startedAt.toISOString(), finishedAt: new Date((opts.clock ?? Date.now)()).toISOString(), durationMs: 0, dryRun: !!opts.dryRun, skipped: 'another cleanup run holds the lock', jobs: [], errors: [] } as RunReport;
      }
      try { return await this.runJobs(cfg, opts, started); }
      finally { await tx.$queryRaw(sql`SELECT RELEASE_LOCK(${LOCK_NAME}) AS released`); }
    }, { maxWait: 10_000, timeout: (cfg.maxSeconds + 300) * 1000 });

    if (!report.skipped) {
      await this.audit.log({
        actorType: 'SYSTEM', actorLabel: 'retention', action: opts.dryRun ? 'retention.dry_run' : 'retention.run',
        result: report.errors.length ? 'FAILURE' : 'SUCCESS',
        metadata: { durationMs: report.durationMs, jobs: report.jobs.map((j) => ({ job: j.job, affected: j.affected, wouldAffect: j.wouldAffect, stoppedEarly: j.stoppedEarly, error: j.error })) },
      });
    }
    return report;
  }

  private async runJobs(cfg: RetentionConfig, opts: RunOptions, started: number): Promise<RunReport> {
    const now = opts.now ?? new Date();
    const clock = opts.clock ?? Date.now;
    const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const deadline = started + cfg.maxSeconds * 1000;
    const jobs: JobReport[] = [];
    const errors: string[] = [];

    for (const job of JOBS) {
      const days = job.days(cfg);
      const rep: JobReport = { job: job.name, description: job.description, affected: 0, batches: 0 };
      if (days === 0) { rep.disabled = true; jobs.push(rep); continue; }
      const cutoff = job.cutoff(cfg, now);
      rep.cutoff = cutoff.toISOString();
      try {
        if (opts.dryRun) {
          const r: any[] = await this.prisma.$queryRaw(this.countSql(job, cutoff));
          rep.wouldAffect = Number(r?.[0]?.n ?? 0);
        } else {
          const limit = Math.min(cfg.batchSize, job.batchCap ?? cfg.batchSize);
          let cursor: { at: Date; id: string } | null = null;
          for (;;) {
            if (clock() >= deadline) { rep.stoppedEarly = true; break; }
            const rows: any[] = await this.retry(() => this.prisma.$queryRaw(this.bind(job, cutoff, cursor, limit)), sleep);
            if (!rows.length) break;
            const ids = rows.map((r) => String(r.id));
            const n = await this.retry(() => this.prisma.$executeRaw(this.applySql(job, ids)), sleep);
            rep.affected += Number(n);
            rep.batches++;
            const last = rows[rows.length - 1];
            if (job.keyset) cursor = { at: new Date(last.ts), id: String(last.id) };
            if (rows.length < limit) break;
            if (cfg.pauseMs > 0) await sleep(cfg.pauseMs);
          }
        }
      } catch (e: any) {
        rep.error = String(e?.message ?? e).split('\n')[0].slice(0, 300);
        errors.push(`${job.name}: ${rep.error}`);
        this.logger.error(`cleanup job ${job.name} failed: ${rep.error}`);
      }
      jobs.push(rep);
    }
    const finished = clock();
    return { startedAt: new Date(started).toISOString(), finishedAt: new Date(finished).toISOString(), durationMs: finished - started, dryRun: !!opts.dryRun, jobs, errors };
  }
}
