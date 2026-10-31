import { eq, sql } from 'drizzle-orm';
import { compareSync } from 'bcryptjs';
import { db } from '@/server/db/client';
import { users, refreshTokens, loginThrottle } from '@/server/db/schema';
import { hashRefreshToken, newId, sha256 } from '@/server/auth/crypto';
import { csrfFor, newRefreshToken, signAccess, signChallenge } from '@/server/auth/jwt';
import { getEnv } from '@/lib/env';

const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function loginKey(email: string) {
  return sha256(email.trim().toLowerCase());
}

export async function checkLockout(email: string): Promise<number | null> {
  const key = loginKey(email);
  const rows = await db.select().from(loginThrottle).where(eq(loginThrottle.keyHash, key)).limit(1);
  const row = rows[0];
  if (!row?.lockedUntil) return null;
  const remaining = row.lockedUntil.getTime() - Date.now();
  return remaining > 0 ? Math.ceil(remaining / 1000) : null;
}

export async function recordFailure(email: string): Promise<number | null> {
  return recordThrottleFailure(loginKey(email));
}

/** Atomic windowed failure counter for login or MFA keys. */
export async function recordThrottleFailure(key: string): Promise<number | null> {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  await db
    .insert(loginThrottle)
    .values({
      keyHash: key,
      failures: 1,
      lockedUntil: null,
      updatedAt: new Date(now),
    })
    .onConflictDoUpdate({
      target: loginThrottle.keyHash,
      set: {
        failures: sql`CASE WHEN (${now} - ${loginThrottle.updatedAt}) > ${windowMs} THEN 1 ELSE ${loginThrottle.failures} + 1 END`,
        lockedUntil: sql`CASE
          WHEN (${now} - ${loginThrottle.updatedAt}) > ${windowMs} THEN NULL
          WHEN ${loginThrottle.failures} + 1 >= ${LOCKOUT_THRESHOLD} THEN ${now + LOCKOUT_MS}
          ELSE NULL
        END`,
        updatedAt: new Date(now),
      },
    });
  const rows = await db.select().from(loginThrottle).where(eq(loginThrottle.keyHash, key)).limit(1);
  const row = rows[0];
  if (row?.lockedUntil && row.lockedUntil.getTime() > now) {
    return Math.ceil((row.lockedUntil.getTime() - now) / 1000);
  }
  return null;
}

export async function clearFailures(email: string) {
  const key = loginKey(email);
  await db.delete(loginThrottle).where(eq(loginThrottle.keyHash, key));
}

export type LoginOutcome =
  | { kind: 'session'; user: PublicUser; accessToken: string; refreshToken: string; csrfToken: string }
  | { kind: 'mfa'; challengeToken: string; expiresInSeconds: number }
  | { kind: 'enroll'; challengeToken: string; expiresInSeconds: number };

export type PublicUser = {
  id: string;
  email: string;
  name: string | null;
  role: string;
  isActive: boolean;
  mustChangePassword: boolean;
  twoFactorEnabled: boolean;
};

function toPublic(u: typeof users.$inferSelect): PublicUser {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    isActive: u.isActive,
    mustChangePassword: u.mustChangePassword,
    twoFactorEnabled: !!u.totpEnabledAt,
  };
}

export async function loginWithPassword(
  email: string,
  password: string,
  meta: { ip?: string; userAgent?: string },
): Promise<LoginOutcome> {
  const locked = await checkLockout(email);
  if (locked) {
    throw Object.assign(new Error('Account locked'), { status: 429, code: 'account_locked', retryAfterSeconds: locked });
  }

  const rows = await db.select().from(users).where(eq(users.email, email.trim().toLowerCase())).limit(1);
  const user = rows[0];
  if (!user || !user.isActive || !compareSync(password, user.passwordHash)) {
    const retry = await recordFailure(email);
    throw Object.assign(new Error('Invalid credentials'), {
      status: 401,
      code: 'invalid_credentials',
      retryAfterSeconds: retry || undefined,
    });
  }

  await clearFailures(email);

  const require2fa = getEnv().require2fa;
  const isAdmin = user.role === 'SUPER_ADMIN' || user.role === 'SECURITY_ADMIN';

  if (user.totpEnabledAt) {
    const challengeToken = await signChallenge({
      sub: user.id,
      email: user.email,
      role: user.role,
      typ: 'mfa',
    });
    return { kind: 'mfa', challengeToken, expiresInSeconds: 300 };
  }

  if (require2fa && isAdmin) {
    const challengeToken = await signChallenge({
      sub: user.id,
      email: user.email,
      role: user.role,
      typ: 'enroll',
    });
    return { kind: 'enroll', challengeToken, expiresInSeconds: 300 };
  }

  return issueSession(user, meta);
}

export async function issueSession(
  user: typeof users.$inferSelect,
  meta: { ip?: string; userAgent?: string },
) {
  const accessToken = await signAccess({
    sub: user.id,
    email: user.email,
    role: user.role,
    tv: user.tokenVersion,
  });
  const refreshToken = newRefreshToken();
  const sessionId = newId();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await db.insert(refreshTokens).values({
    id: newId(),
    userId: user.id,
    tokenHash: hashRefreshToken(refreshToken),
    sessionId,
    sessionStartedAt: new Date(),
    lastUsedAt: new Date(),
    deviceLabel: null,
    ipAddress: meta.ip || null,
    userAgent: meta.userAgent || null,
    expiresAt,
    createdAt: new Date(),
  });

  await db.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, user.id));

  return {
    kind: 'session' as const,
    user: toPublic(user),
    accessToken,
    refreshToken,
    csrfToken: csrfFor(refreshToken),
  };
}

export async function getUserById(id: string) {
  const rows = await db.select().from(users).where(eq(users.id, id)).limit(1);
  return rows[0] || null;
}

/** Rotate refresh token. Reuse of a revoked token ends all sessions for that user. */
export async function refreshSession(
  presented: string,
  meta: { ip?: string; userAgent?: string },
): Promise<{ accessToken: string; refreshToken: string; csrfToken: string; user: PublicUser }> {
  const hash = hashRefreshToken(presented);
  const rows = await db.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, hash)).limit(1);
  const row = rows[0];
  if (!row) {
    throw Object.assign(new Error('Invalid refresh token'), { status: 401, code: 'invalid_refresh' });
  }
  if (row.revokedAt) {
    // Reuse of rotated token → compromise signal: revoke all for user
    await db
      .update(refreshTokens)
      .set({ revokedAt: new Date(), revokedReason: 'reuse' })
      .where(eq(refreshTokens.userId, row.userId));
    throw Object.assign(new Error('Session compromised'), { status: 401, code: 'compromised' });
  }
  if (row.expiresAt.getTime() < Date.now()) {
    throw Object.assign(new Error('Refresh expired'), { status: 401, code: 'expired' });
  }
  const user = await getUserById(row.userId);
  if (!user || !user.isActive) {
    throw Object.assign(new Error('User inactive'), { status: 401, code: 'unauthorized' });
  }

  // Revoke old, issue new (rotation)
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date(), revokedReason: 'rotated' })
    .where(eq(refreshTokens.id, row.id));

  const session = await issueSession(user, meta);
  return {
    accessToken: session.accessToken,
    refreshToken: session.refreshToken,
    csrfToken: session.csrfToken,
    user: session.user,
  };
}

export async function logoutByRefresh(presented: string | undefined) {
  if (!presented) return;
  const hash = hashRefreshToken(presented);
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date(), revokedReason: 'logout' })
    .where(eq(refreshTokens.tokenHash, hash));
}

export async function listSessions(userId: string, currentHash?: string) {
  const rows = await db
    .select()
    .from(refreshTokens)
    .where(eq(refreshTokens.userId, userId));
  const now = Date.now();
  return rows
    .filter((r) => !r.revokedAt && r.expiresAt.getTime() > now)
    .map((r) => ({
      id: r.id,
      device: r.deviceLabel,
      ipAddress: r.ipAddress,
      createdAt: r.sessionStartedAt.toISOString(),
      lastUsedAt: r.lastUsedAt?.toISOString() ?? null,
      expiresAt: r.expiresAt.toISOString(),
      current: currentHash ? r.tokenHash === currentHash : false,
    }));
}

export async function revokeSession(userId: string, sessionRowId: string) {
  const rows = await db.select().from(refreshTokens).where(eq(refreshTokens.id, sessionRowId)).limit(1);
  if (!rows[0] || rows[0].userId !== userId) {
    throw Object.assign(new Error('Not found'), { status: 404, code: 'not_found' });
  }
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date(), revokedReason: 'user_revoke' })
    .where(eq(refreshTokens.id, sessionRowId));
}

export async function revokeAllSessions(userId: string) {
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date(), revokedReason: 'revoke_all' })
    .where(eq(refreshTokens.userId, userId));
}
