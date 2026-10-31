import { and, eq, isNull } from 'drizzle-orm';
import { createHash } from 'crypto';
import { createClient } from '@libsql/client';
import { db } from '@/server/db/client';
import { recoveryCodes, users, loginThrottle } from '@/server/db/schema';
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

function libsql() {
  const url = process.env.DATABASE_URL || 'file:./data/ir.db';
  return createClient({ url, authToken: process.env.DATABASE_AUTH_TOKEN || undefined });
}

/** Atomic reserve of an MFA attempt slot before verifying the code. */
async function reserveChallengeAttempt(jti: string, userId: string): Promise<number> {
  const client = libsql();
  try {
    await client.execute({
      sql: `INSERT INTO used_challenges (jti, user_id, failures, created_at)
            VALUES (?, ?, 0, ?)
            ON CONFLICT(jti) DO NOTHING`,
      args: [jti, userId, Date.now()],
    });
    const updated = await client.execute({
      sql: `UPDATE used_challenges SET failures = failures + 1
            WHERE jti = ? AND burned_at IS NULL AND failures < ?
            RETURNING failures`,
      args: [jti, MAX_CHALLENGE_FAILURES],
    });
    if (!updated.rows.length) {
      throw Object.assign(new Error('Challenge expired or invalid'), {
        status: 401,
        code: 'challenge_expired',
      });
    }
    return Number(updated.rows[0].failures);
  } finally {
    client.close();
  }
}

async function burnChallenge(jti: string) {
  const client = libsql();
  try {
    await client.execute({
      sql: `UPDATE used_challenges SET burned_at = ? WHERE jti = ?`,
      args: [Date.now(), jti],
    });
  } finally {
    client.close();
  }
}

async function clearMfaThrottle(userId: string) {
  await db.delete(loginThrottle).where(eq(loginThrottle.keyHash, `mfa:${userId}`));
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

  // Per-user MFA: increment first (lockout after threshold)
  const mfaRetry = await recordThrottleFailure(`mfa:${user.id}`);
  if (mfaRetry) {
    await writeAudit({
      actorType: 'USER',
      actorId: user.id,
      action: 'auth.locked',
      result: 'FAILURE',
      ipAddress: meta.ip || null,
      metadata: { scope: 'mfa' },
    });
    throw Object.assign(new Error('Too many MFA attempts'), {
      status: 429,
      code: 'rate_limited',
      retryAfterSeconds: mfaRetry,
    });
  }

  // Reserve attempt slot before verifying (prevents parallel brute force)
  let failures: number;
  try {
    failures = await reserveChallengeAttempt(jti, user.id);
  } catch (e) {
    await writeAudit({
      actorType: 'USER',
      actorId: user.id,
      action: 'auth.challenge_burned',
      result: 'FAILURE',
      ipAddress: meta.ip || null,
    });
    throw e;
  }

  const rejectInvalid = async () => {
    await writeAudit({
      actorType: 'USER',
      actorId: user.id,
      action: 'auth.mfa_failed',
      result: 'FAILURE',
      ipAddress: meta.ip || null,
    });
    if (failures >= MAX_CHALLENGE_FAILURES) {
      await burnChallenge(jti);
      await writeAudit({
        actorType: 'USER',
        actorId: user.id,
        action: 'auth.challenge_burned',
        result: 'FAILURE',
        ipAddress: meta.ip || null,
      });
      throw Object.assign(new Error('Challenge expired or invalid'), {
        status: 401,
        code: 'challenge_expired',
      });
    }
    throw Object.assign(new Error('Invalid code'), { status: 401, code: 'invalid_code' });
  };

  if (recoveryCode) {
    const h = hashCode(recoveryCode);
    const codes = await db
      .select()
      .from(recoveryCodes)
      .where(and(eq(recoveryCodes.userId, user.id), eq(recoveryCodes.codeHash, h), isNull(recoveryCodes.usedAt)))
      .limit(1);
    if (!codes[0]) await rejectInvalid();
    await db.update(recoveryCodes).set({ usedAt: new Date() }).where(eq(recoveryCodes.id, codes[0]!.id));
    await burnChallenge(jti);
    await clearMfaThrottle(user.id);
    return issueSession(user, meta);
  }

  if (!code) {
    throw Object.assign(new Error('Code required'), { status: 400, code: 'code_required' });
  }
  const check = verifyTotp(user.totpSecret, code, { window: 1, lastStep: user.totpLastStep });
  if (!check.ok) await rejectInvalid();
  await db.update(users).set({ totpLastStep: check.step! }).where(eq(users.id, user.id));
  await burnChallenge(jti);
  await clearMfaThrottle(user.id);
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
