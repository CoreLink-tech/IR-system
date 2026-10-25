import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { getEnv } from '@/lib/env';

export const runtime = 'nodejs';

/** Non-secret operational settings for the dashboard. */
export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  const env = getEnv();
  return json(
    {
      version: process.env.npm_package_version || '2.0.0',
      require2fa: env.require2fa,
      totpIssuer: env.totpIssuer,
      apiKeyPrefix: env.apiKeyPrefix,
      database: env.databaseUrl.startsWith('libsql:') ? 'turso' : env.databaseUrl.startsWith('file:') ? 'sqlite' : 'configured',
      sessions: { accessTokenMinutes: 15, refreshTokenDays: 7 },
      rateLimits: { ingestPerKeyPerIpPerMinute: 120 },
    },
    { requestId: rid },
  );
}
