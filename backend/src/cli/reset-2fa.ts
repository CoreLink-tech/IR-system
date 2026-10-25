import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AdminCliModule } from './admin-cli.module';
import { TwoFactorService } from '../auth/two-factor.service';

/**
 * Break-glass: clear two-step verification for an account.
 *   npm run admin:reset-2fa -- user@example.com
 */
async function main() {
  const email = (process.argv[2] || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    process.stderr.write('Usage: npm run admin:reset-2fa -- <email>\n');
    process.exit(1);
  }
  const app = await NestFactory.createApplicationContext(AdminCliModule, { logger: ['error', 'warn'] });
  try {
    const twoFactor = app.get(TwoFactorService);
    const result = await twoFactor.cliResetByEmail(email);
    process.stdout.write(JSON.stringify({
      ...result,
      message: result.mustEnrolAtNextSignIn
        ? 'Two-step verification cleared. The account must enrol again at next sign-in.'
        : 'Two-step verification cleared.',
    }, null, 2) + '\n');
    process.exitCode = 0;
  } finally {
    await app.close();
  }
}
main().catch((e) => {
  process.stderr.write(`admin:reset-2fa failed: ${String(e?.message ?? e)}\n`);
  process.exit(1);
});
