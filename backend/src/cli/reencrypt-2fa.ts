import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AdminCliModule } from './admin-cli.module';
import { PrismaService } from '../prisma/prisma.service';
import { loadKeyRing, reencrypt, usesCurrentKey } from '../auth/two-factor.crypto';
import { AuditService } from '../audit/audit.service';
import { AUDIT_ACTIONS } from '../common/constants';

/**
 * Re-encrypt every stored TOTP secret with the current TOTP_ENCRYPTION_KEY.
 * Run after rotating the key (set the old key as TOTP_ENCRYPTION_KEY_PREVIOUS).
 *
 *   npm run admin:reencrypt-2fa
 *   npm run admin:reencrypt-2fa -- --dry-run
 *
 * Recovery-code hashes already verify under both keys; after all secrets are on the
 * current key you may remove TOTP_ENCRYPTION_KEY_PREVIOUS. Unused recovery codes that
 * were hashed only under the previous key will stop working if the previous key is
 * removed before the user regenerates them — document this for operators.
 *
 * Exit 0 on success, 1 on failure. Batched and resumable (skips rows already on the current key).
 */
async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const ring = loadKeyRing();
  if (!ring) {
    process.stderr.write('TOTP_ENCRYPTION_KEY is not set or invalid. Generate one with: openssl rand -hex 32\n');
    process.exit(1);
  }
  if (!ring.previous && !dryRun) {
    process.stdout.write('No TOTP_ENCRYPTION_KEY_PREVIOUS set. Nothing to re-encrypt (all secrets should already use the current key).\n');
    process.exit(0);
  }

  const app = await NestFactory.createApplicationContext(AdminCliModule, {
    logger: ['error', 'warn'],
  });

  try {
    const prisma = app.get(PrismaService);
    const audit = app.get(AuditService);

    const users = await prisma.securityUser.findMany({
      where: { totpSecret: { not: null } },
      select: { id: true, email: true, totpSecret: true },
    });

    let alreadyCurrent = 0;
    let reencrypted = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const u of users) {
      if (!u.totpSecret) continue;
      try {
        if (usesCurrentKey(u.totpSecret, ring)) {
          alreadyCurrent++;
          continue;
        }
        if (dryRun) {
          reencrypted++;
          continue;
        }
        const next = reencrypt(u.totpSecret, ring);
        await prisma.securityUser.update({
          where: { id: u.id },
          data: { totpSecret: next },
        });
        reencrypted++;
      } catch (e: any) {
        failed++;
        errors.push(`${u.email}: ${e?.message ?? e}`);
      }
    }

    if (!dryRun && reencrypted > 0) {
      await audit.log({
        actorType: 'SYSTEM',
        actorLabel: 'cli',
        action: AUDIT_ACTIONS.TWOFA_RESET, // closest existing; no dedicated reencrypt action yet
        result: failed ? 'PARTIAL' : 'SUCCESS',
        metadata: {
          via: 'admin:reencrypt-2fa',
          alreadyCurrent,
          reencrypted,
          failed,
          dryRun: false,
        },
      });
    }

    process.stdout.write(
      JSON.stringify(
        {
          dryRun,
          totalWithSecret: users.length,
          alreadyCurrent,
          reencrypted,
          failed,
          errors: errors.length ? errors : undefined,
          note:
            'After every secret uses the current key you may remove TOTP_ENCRYPTION_KEY_PREVIOUS. ' +
            'Recovery codes hashed only under the previous key will stop working once that key is removed; ' +
            'ask users to regenerate recovery codes if any remain on the old key.',
        },
        null,
        2,
      ) + '\n',
    );
    process.exitCode = failed ? 1 : 0;
  } finally {
    await app.close();
  }
}

main().catch((e) => {
  process.stderr.write(`admin:reencrypt-2fa failed: ${String(e?.message ?? e)}\n`);
  process.exit(1);
});
