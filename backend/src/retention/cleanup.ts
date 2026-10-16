import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { RetentionModule } from './retention.module';
import { RetentionService } from './retention.service';

/**
 * Cleanup command. Run it on a schedule (cron or a systemd timer, see docs/DATABASE.md):
 *
 *   node dist/retention/cleanup.js              delete and switch off what is past its limit
 *   node dist/retention/cleanup.js --dry-run    only count what would be affected
 *
 * Exit code 0: finished (or another run holds the lock). 1: a job failed or the settings are invalid.
 */
async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const app = await NestFactory.createApplicationContext(RetentionModule, { logger: ['error', 'warn'] });
  try {
    const report = await app.get(RetentionService).run({ dryRun });
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    process.exitCode = report.errors.length ? 1 : 0;
  } finally {
    await app.close();
  }
}
main().catch((e) => { process.stderr.write(`cleanup failed: ${String(e?.message ?? e)}\n`); process.exit(1); });
