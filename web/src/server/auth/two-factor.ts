import { and, eq, isNull } from 'drizzle-orm';
import { createHash } from 'crypto';
import { db } from '@/server/db/client';
import { recoveryCodes, users } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';
import { generateRecoveryCodes, generateTotpSecret, otpauthUri, verifyTotp } from '@/server/auth/totp';
import { getEnv } from '@/lib/env';
import { issueSession } from '@/server/auth/session';
import { verifyChallenge } from '@/server/auth/jwt';

function hashCode(code: string): string {
  return createHash('sha256').update(code.replace(/\s/g, '').toUpperCase()).digest('hex');
}

export async function verifyMfaAndLogin(
  challengeToken: string,
  code: string | undefined,
  recoveryCode: string | undefined,
  meta: { ip?: string; userAgent?: string },
) {
  const claims = await verifyChallenge(challengeToken);
  if (!claims || claims.typ !== 'mfa') {
    throw Object.assign(new Error('Challenge expired or invalid'), { status: 401, code: 'challenge_expired' });
  }
  const rows = await db.select().from(users).where(eq(users.id, claims.sub)).limit(1);
  const user = rows[0];
  if (!user || !user.totpEnabledAt || !user.totpSecret) {
    throw Object.assign(new Error('Two-step not enabled'), { status: 400, code: 'two_factor_not_enabled' });
  }

  if (recoveryCode) {
    const h = hashCode(recoveryCode);
    const codes = await db.select().from(recoveryCodes)
      .where(and(eq(recoveryCodes.userId, user.id), eq(recoveryCodes.codeHash, h), isNull(recoveryCodes.usedAt)))
      .limit(1);
    if (!codes[0]) {
      throw Object.assign(new Error('Invalid code'), { status: 401, code: 'invalid_code' });
    }
    await db.update(recoveryCodes).set({ usedAt: new Date() }).where(eq(recoveryCodes.id, codes[0].id));
    return issueSession(user, meta);
  }

  if (!code) {
    throw Object.assign(new Error('Code required'), { status: 400, code: 'code_required' });
  }
  const check = verifyTotp(user.totpSecret, code, { window: 1, lastStep: user.totpLastStep });
  if (!check.ok) {
    throw Object.assign(new Error('Invalid code'), { status: 401, code: 'invalid_code' });
  }
  await db.update(users).set({ totpLastStep: check.step! }).where(eq(users.id, user.id));
  return issueSession(user, meta);
}

export async function enrollStart(challengeToken: string) {
  const claims = await verifyChallenge(challengeToken);
  if (!claims || claims.typ !== 'enroll') {
    throw Object.assign(new Error('Challenge expired or invalid'), { status: 401, code: 'challenge_expired' });
  }
  const rows = await db.select().from(users).where(eq(users.id, claims.sub)).limit(1);
  const user = rows[0];
  if (!user) throw Object.assign(new Error('User not found'), { status: 404, code: 'user_not_found' });
  if (user.totpEnabledAt) {
    throw Object.assign(new Error('Already enabled'), { status: 409, code: 'two_factor_already_enabled' });
  }
  const secret = generateTotpSecret();
  await db.update(users).set({ totpSecret: secret }).where(eq(users.id, user.id));
  return {
    secret,
    otpauthUri: otpauthUri(secret, user.email, getEnv().totpIssuer),
  };
}

export async function enrollConfirm(
  challengeToken: string,
  code: string,
  meta: { ip?: string; userAgent?: string },
) {
  const claims = await verifyChallenge(challengeToken);
  if (!claims || claims.typ !== 'enroll') {
    throw Object.assign(new Error('Challenge expired or invalid'), { status: 401, code: 'challenge_expired' });
  }
  const rows = await db.select().from(users).where(eq(users.id, claims.sub)).limit(1);
  const user = rows[0];
  if (!user || !user.totpSecret) {
    throw Object.assign(new Error('No pending enrolment'), { status: 400, code: 'no_pending_enrolment' });
  }
  const check = verifyTotp(user.totpSecret, code, { window: 1 });
  if (!check.ok) {
    throw Object.assign(new Error('Invalid code'), { status: 401, code: 'invalid_code' });
  }
  const plainCodes = generateRecoveryCodes(10);
  for (const c of plainCodes) {
    await db.insert(recoveryCodes).values({
      id: newId(),
      userId: user.id,
      codeHash: hashCode(c),
      createdAt: new Date(),
    });
  }
  await db.update(users).set({
    totpEnabledAt: new Date(),
    totpLastStep: check.step!,
  }).where(eq(users.id, user.id));

  const session = await issueSession(user, meta);
  return { ...session, recoveryCodes: plainCodes };
}
