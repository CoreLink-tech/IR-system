import { eq } from 'drizzle-orm';
import { verifyAccess } from '@/server/auth/jwt';
import { db } from '@/server/db/client';
import { users } from '@/server/db/schema';

export async function requireUser(req: Request) {
  const auth = req.headers.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) return null;
  const claims = await verifyAccess(token);
  if (!claims) return null;
  const rows = await db.select().from(users).where(eq(users.id, claims.sub)).limit(1);
  const user = rows[0];
  if (!user || !user.isActive) return null;
  if (user.tokenVersion !== claims.tv) return null;
  return user;
}

export function publicUser(u: typeof users.$inferSelect) {
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
