import { and, eq, isNull } from 'drizzle-orm';
import { createHash } from 'crypto';
import { db } from '@/server/db/client';
import { recoveryCodes, users, usedChallenges, loginThrottle } from '@/server/db/schema';
import { newId, sha256 } from '@/server/auth/crypto';
import { generateRecoveryCodes, generateTotpSecret, otpauthUri, verifyTotp } from '@/server/auth/totp';
import { getEnv } from '@/lib/env';
import { issueSession, recordThrottleFailure } from '@/server/auth/session';
import { verifyChallenge } from '@/server/auth/jwt';
import { writeAudit } from '@/server/services/audit';

function hashCode(code: string): string {
  return createHash('sha256').update(code.replace(/\s/g, '').toUpperCase()).digest('hex');
}

const MAX_CHALLENGE_FAILURES = 5;

async function challengeGate(jti: string, userId: string, ip?: string) {
  const rows = await db.select().from(usedChallenges).where(eq(usedChallenges.jti, jti)).limit(1);
  const row = rows[0];
  if (row?.burnedAt || (row && row.failures >= MAX_CHALLENGE_FAILURES)) {
    if (row && !row.burnedAt) {
      await db.update(usedChallenges).set({ burnedAt: new Date() }).where(eq(usedChallenges.jti, jti));
    }
    await writeAudit({
      actorType: 'USER',
      actorId: userId,
      action: 'auth.challenge_burned',
      result: 'FAILURE',
      ipAddress: ip || null,
    });
    throw Object.assign(new Error('Challenge expired or invalid'), {
      status: 401,
      code: 'challenge_expired',
    });
  }
  if (!row) {
    await db.insert(usedChallenges).values({ jti, userId, failures: 0, createdAt: new Date() });
  }
}

async function recordChallengeFailure(jti: string, userId: string, ip?: string) {
  const rows = await db.select().from(usedChallenges).where(eq(usedChallenges.jti, jti)).limit(1);
  const failures = (rows[0]?.failures || 0) + 1;
  if (!rows[0]) {
    await db.insert(usedChallenges).values({ jti, userId, failures, createdAt: new Date() });
  } else {
    await db
      .update(usedChallenges)
      .set({ failures, burnedAt: failures >= MAX_CHALLENGE_FAILURES ? new Date() : null })
      .where(eq(usedChallenges.jti, jti));
  }
  await writeAudit({
    actorType: 'USER',
    actorId: userId,
    action: 'auth.mfa_failed',
    result: 'FAILURE',
    ipAddress: ip || null,
  });
  const retry = await recordThrottleFailure(`mfa:${userId}`);
  if (retry) {
    await writeAudit({
      actorType: 'USER',
      actorId: userId,
      action: 'auth.locked',
      result: 'FAILURE',
      ipAddress: ip || null,
      metadata: { scope: 'mfa' },
    });
    throw Object.assign(new Error('Too many MFA attempts'), {
      status: 429,
      code: 'rate_limited',
      retryAfterSeconds: retry,
    });
  }
  if (failures >= MAX_CHALLENGE_FAILURES) {
    await writeAudit({
      actorType: 'USER',
      actorId: userId,
      action: 'auth.challenge_burned',
      result: 'FAILURE',
      ipAddress: ip || null,
    });
    throw Object.assign(new Error('Challenge expired or invalid'), {
      status: 401,
      code: 'challenge_expired',
    });
  }
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
  const jti = (claims as { jti?: string }).jti || sha256(challengeToken).slice(0, 32);
  const rows = await db.select().from(users).where(eq(users.id, claims.sub)).limit(1);
  const user = rows[0];
  if (!user || !user.totpEnabledAt || !user.totpSecret) {
    throw Object.assign(new Error('Two-step not enabled'), { status: 400, code: 'two_factor_not_enabled' });
  }

  const mfaKey = `mfa:${user.id}`;
  const mfaRows = await db.select().from(loginThrottle).where(eq(loginThrottle.keyHash, mfaKey)).limit(1);
  if (mfaRows[0]?.lockedUntil && mfaRows[0].lockedUntil.getTime() > Date.now()) {
    throw Object.assign(new Error('Too many MFA attempts'), {
      status: 429,
      code: 'rate_limited',
      retryAfterSeconds: Math.ceil((mfaRows[0].lockedUntil.getTime() - Date.now()) / 1000),
    });
  }

  await challengeGate(jti, user.id, meta.ip);

  if (recoveryCode) {
    const h = hashCode(recoveryCode);
    const codes = await db
      .select()
      .from(recoveryCodes)
      .where(and(eq(recoveryCodes.userId, user.id), eq(recoveryCodes.codeHash, h), isNull(recoveryCodes.usedAt)))
      .limit(1);
    if (!codes[0]) {
      await recordChallengeFailure(jti, user.id, meta.ip);
      throw Object.assign(new Error('Invalid code'), { status: 401, code: 'invalid_code' });
    }
    await db.update(recoveryCodes).set({ usedAt: new Date() }).where(eq(recoveryCodes.id, codes[0].id));
    await db.update(usedChallenges).set({ burnedAt: new Date() }).where(eq(usedChallenges.jti, jti));
    return issueSession(user, meta);
  }

  if (!code) {
    throw Object.assign(new Error('Code required'), { status: 400, code: 'code_required' });
  }
  const check = verifyTotp(user.totpSecret, code, { window: 1, lastStep: user.totpLastStep });
  if (!check.ok) {
    await recordChallengeFailure(jti, user.id, meta.ip);
    throw Object.assign(new Error('Invalid code'), { status: 401, code: 'invalid_code' });
  }
  await db.update(users).set({ totpLastStep: check.step! }).where(eq(users.id, user.id));
  await db.update(usedChallenges).set({ burnedAt: new Date() }).where(eq(usedChallenges.jti, jti));
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
  await db
    .update(users)
    .set({
      totpEnabledAt: new Date(),
      totpLastStep: check.step!,
    })
    .where(eq(users.id, user.id));

  const session = await issueSession(user, meta);
  return { ...session, recoveryCodes: plainCodes };
}
