import { eq } from 'drizzle-orm';
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
  const key = loginKey(email);
  const rows = await db.select().from(loginThrottle).where(eq(loginThrottle.keyHash, key)).limit(1);
  const failures = (rows[0]?.failures || 0) + 1;
  const lockedUntil = failures >= LOCKOUT_THRESHOLD ? new Date(Date.now() + LOCKOUT_MS) : null;
  if (rows[0]) {
    await db.update(loginThrottle).set({ failures, lockedUntil, updatedAt: new Date() }).where(eq(loginThrottle.keyHash, key));
  } else {
    await db.insert(loginThrottle).values({ keyHash: key, failures, lockedUntil, updatedAt: new Date() });
  }
  if (lockedUntil) return Math.ceil(LOCKOUT_MS / 1000);
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
