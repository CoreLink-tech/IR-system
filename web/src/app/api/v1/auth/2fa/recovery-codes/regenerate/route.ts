import { eq } from 'drizzle-orm';
import { compareSync } from 'bcryptjs';
import { createHash } from 'crypto';
import { err, json, requestId, clientIp } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { recoveryCodes, users } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';
import { generateRecoveryCodes, verifyTotp } from '@/server/auth/totp';
import { writeAudit } from '@/server/services/audit';

export const runtime = 'nodejs';

export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (!me.totpEnabledAt || !me.totpSecret) {
    return err(400, 'Two-step is not enabled', { code: 'two_factor_not_enabled', requestId: rid });
  }
  let body: { password?: string; code?: string };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  if (!compareSync(body.password || '', me.passwordHash)) {
    return err(401, 'Invalid credentials', { code: 'invalid_credentials', requestId: rid });
  }
  const check = verifyTotp(me.totpSecret, body.code || '', { window: 1, lastStep: me.totpLastStep });
  if (!check.ok) return err(401, 'Invalid code', { code: 'invalid_code', requestId: rid });

  await db.delete(recoveryCodes).where(eq(recoveryCodes.userId, me.id));
  const plain = generateRecoveryCodes(10);
  for (const c of plain) {
    await db.insert(recoveryCodes).values({
      id: newId(),
      userId: me.id,
      codeHash: createHash('sha256').update(c.replace(/\s/g, '').toUpperCase()).digest('hex'),
      createdAt: new Date(),
    });
  }
  await db.update(users).set({ totpLastStep: check.step! }).where(eq(users.id, me.id));
  await writeAudit({
    requestId: rid,
    actorType: 'USER',
    actorId: me.id,
    actorLabel: me.email,
    action: 'twofa.recovery_regenerate',
    targetType: 'user',
    targetId: me.id,
    ipAddress: clientIp(req),
  });
  return json({ recoveryCodes: plain }, { requestId: rid });
}
