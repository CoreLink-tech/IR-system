import { compareSync, hashSync } from 'bcryptjs';
import { eq } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { users } from '@/server/db/schema';
import { revokeAllSessions } from '@/server/auth/session';

export function assertStrongPassword(password: string) {
  if (!password || password.length < 8) {
    throw Object.assign(new Error('Password must be at least 8 characters'), {
      status: 400,
      code: 'weak_password',
    });
  }
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    throw Object.assign(new Error('Password needs upper, lower, and a digit'), {
      status: 400,
      code: 'weak_password',
    });
  }
}

export async function changePassword(userId: string, current: string, next: string) {
  assertStrongPassword(next);
  const rows = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  const user = rows[0];
  if (!user) throw Object.assign(new Error('Not found'), { status: 404, code: 'not_found' });
  if (!compareSync(current, user.passwordHash)) {
    throw Object.assign(new Error('Current password is wrong'), { status: 401, code: 'invalid_credentials' });
  }
  if (compareSync(next, user.passwordHash)) {
    throw Object.assign(new Error('New password must be different'), { status: 400, code: 'same_password' });
  }
  await db
    .update(users)
    .set({
      passwordHash: hashSync(next, 12),
      mustChangePassword: false,
      passwordChangedAt: new Date(),
      tokenVersion: user.tokenVersion + 1,
    })
    .where(eq(users.id, userId));
  await revokeAllSessions(userId);
  return { ok: true };
}
