import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AdminCliModule } from './admin-cli.module';
import { PrismaService } from '../prisma/prisma.service';
import { LoginThrottleService } from '../auth/login-throttle.service';
import { AuditService } from '../audit/audit.service';
import { loginKey } from '../auth/login-throttle';
import { AUDIT_ACTIONS } from '../common/constants';

/**
 * Break-glass: clear the sign-in lockout for an account.
 *   npm run admin:unlock -- user@example.com
 */
async function main() {
  const email = (process.argv[2] || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    process.stderr.write('Usage: npm run admin:unlock -- <email>\n');
    process.exit(1);
  }
  const app = await NestFactory.createApplicationContext(AdminCliModule, { logger: ['error', 'warn'] });
  try {
    const prisma = app.get(PrismaService);
    const throttle = app.get(LoginThrottleService);
    const audit = app.get(AuditService);
    const user = await prisma.securityUser.findUnique({ where: { email }, select: { id: true, email: true } });
    if (!user) {
      process.stderr.write(`No account found for ${email}\n`);
      process.exitCode = 1;
      return;
    }
    await throttle.reset(loginKey(user.email));
    await audit.log({
      actorType: 'SYSTEM', actorLabel: 'cli', action: AUDIT_ACTIONS.UNLOCK,
      targetType: 'user', targetId: user.id, result: 'SUCCESS',
      metadata: { email: user.email, via: 'admin:unlock' },
    });
    process.stdout.write(JSON.stringify({
      ok: true, email: user.email,
      message: 'Lockout cleared. The next five attempts are free again.',
    }, null, 2) + '\n');
    process.exitCode = 0;
  } finally {
    await app.close();
  }
}
main().catch((e) => {
  process.stderr.write(`admin:unlock failed: ${String(e?.message ?? e)}\n`);
  process.exit(1);
});
