import { eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { users } from '@/server/db/schema';
import { generateTotpSecret, otpauthUri } from '@/server/auth/totp';
import { getEnv } from '@/lib/env';

export const runtime = 'nodejs';

export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.totpEnabledAt) {
    return err(409, 'Two-step verification is already on', { code: 'two_factor_already_enabled', requestId: rid });
  }
  const secret = generateTotpSecret();
  await db.update(users).set({ totpSecret: secret }).where(eq(users.id, me.id));
  return json(
    {
      secret,
      otpauthUri: otpauthUri(secret, me.email, getEnv().totpIssuer),
    },
    { requestId: rid },
  );
}
