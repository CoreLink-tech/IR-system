import { Injectable } from '@nestjs/common';
import { sqltag as sql } from '@prisma/client/runtime/library';
import { PrismaService } from '../prisma/prisma.service';
import { Decision, LockoutConfig, ThrottleState, decide, loadLockoutConfig } from './login-throttle';

const isDeadlock = (e: any) => /deadlock|1213|40001|P2034/i.test(String(e?.message ?? e) + String(e?.code ?? ''));

/** Counts failed sign-ins per hashed email, in the database, so every API server shares one count. */
@Injectable()
export class LoginThrottleService {
  private cfg: LockoutConfig | null = null;
  constructor(private readonly prisma: PrismaService, private readonly clock: () => Date = () => new Date()) {}

  config(): LockoutConfig {
    if (!this.cfg) this.cfg = loadLockoutConfig().config;
    return this.cfg;
  }

  /**
   * Counts this attempt and returns whether the password may be checked. The row is locked (FOR UPDATE) only
   * for the length of this small transaction, never while the password is checked, so attempts for one email
   * line up here and cannot all slip past a lock that has not been written yet.
   */
  async reserve(key: string): Promise<Decision> {
    for (let attempt = 1; ; attempt++) {
      try {
        const now = this.clock();
        return await this.prisma.$transaction(async (tx: any) => {
          // Make sure the row exists AND take its exclusive lock in one step. A plain INSERT IGNORE takes only a
          // shared lock on a row that already exists, and the SELECT ... FOR UPDATE below then has to upgrade
          // it: many simultaneous attempts for one account deadlock each other (found on a real database with
          // forty at once). ON DUPLICATE KEY UPDATE locks exclusively from the start, so they simply queue.
          await tx.$executeRaw(sql`INSERT INTO security_login_throttle (\`key\`, failures, lockedUntil, lastFailureAt, updatedAt) VALUES (${key}, 0, NULL, ${now}, ${now}) ON DUPLICATE KEY UPDATE \`key\` = \`key\``);
          const rows: any[] = await tx.$queryRaw(sql`SELECT failures, lockedUntil, lastFailureAt FROM security_login_throttle WHERE \`key\` = ${key} FOR UPDATE`);
          const r = rows[0];
          const prev: ThrottleState | null = r ? { failures: Number(r.failures), lockedUntil: r.lockedUntil ? new Date(r.lockedUntil) : null, lastFailureAt: new Date(r.lastFailureAt) } : null;
          const d = decide(prev, now, this.config());
          if (d.allowed && d.state) {
            await tx.$executeRaw(sql`UPDATE security_login_throttle SET failures = ${d.state.failures}, lockedUntil = ${d.state.lockedUntil}, lastFailureAt = ${d.state.lastFailureAt}, updatedAt = ${now} WHERE \`key\` = ${key}`);
          }
          return d;
        }, { maxWait: 5000, timeout: 5000 });
      } catch (e) {
        if (attempt >= 6 || !isDeadlock(e)) throw e;
        await new Promise((r) => setTimeout(r, 20 * attempt + Math.floor(Math.random() * 40)));
      }
    }
  }

  /** A correct password, an administrator unlock or an administrator password reset forgets the failures. */
  async reset(key: string): Promise<void> {
    await this.prisma.securityLoginThrottle.deleteMany({ where: { key } });
  }

  /** Which of these keys are locked right now, and until when. */
  async lockedUntil(keys: string[]): Promise<Map<string, Date>> {
    if (!keys.length) return new Map();
    const rows: any[] = await this.prisma.securityLoginThrottle.findMany({ where: { key: { in: keys }, lockedUntil: { gt: this.clock() } }, select: { key: true, lockedUntil: true } });
    return new Map(rows.map((r) => [r.key, new Date(r.lockedUntil)]));
  }
}
