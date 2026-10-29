import { hashSync } from 'bcryptjs';
import { asc, eq } from 'drizzle-orm';
import { z } from 'zod';
import { clientIp, err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { newId } from '@/server/auth/crypto';
import { db } from '@/server/db/client';
import { users } from '@/server/db/schema';
import { assertStrongPassword } from '@/server/auth/password';
import { writeAudit } from '@/server/services/audit';

export const runtime = 'nodejs';

const validRoles = ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST', 'VIEWER'] as const;
const createUserSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(12),
  name: z.string().trim().max(120).optional(),
  role: z.string().optional(),
});

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN') {
    return err(403, 'Super admin only', { code: 'forbidden', requestId: rid });
  }

  const rows = await db.select().from(users).orderBy(asc(users.createdAt));
  return json(
    {
      data: rows.map((u) => ({
        id: u.id,
        email: u.email,
        name: u.name,
        role: u.role,
        isActive: u.isActive,
        mustChangePassword: u.mustChangePassword,
        twoFactorEnabled: !!u.totpEnabledAt,
        lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
        createdAt: u.createdAt.toISOString(),
      })),
    },
    { requestId: rid },
  );
}

export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN') {
    return err(403, 'Super admin only', { code: 'forbidden', requestId: rid });
  }

  let rawBody: unknown;
  try {
    rawBody = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  const parsed = createUserSchema.safeParse(rawBody);
  if (!parsed.success) {
    return err(400, parsed.error.issues[0]?.message || 'Invalid user details', {
      code: 'invalid_body',
      requestId: rid,
    });
  }

  const email = parsed.data.email.toLowerCase();
  const password = parsed.data.password;
  try {
    assertStrongPassword(password);
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string };
    return err(ex.status || 400, ex.message || 'Invalid password', {
      code: ex.code || 'weak_password',
      requestId: rid,
    });
  }

  const existing = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
  if (existing.length) {
    return err(409, 'An account with this email already exists', {
      code: 'email_exists',
      requestId: rid,
    });
  }

  const role = validRoles.includes(parsed.data.role as (typeof validRoles)[number])
    ? parsed.data.role!
    : 'VIEWER';
  const userId = newId();
  try {
    await db.insert(users).values({
      id: userId,
      email,
      name: parsed.data.name || null,
      passwordHash: hashSync(password, 12),
      role,
      isActive: true,
      mustChangePassword: true,
      createdAt: new Date(),
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : '';
    if (/unique|constraint/i.test(message)) {
      return err(409, 'An account with this email already exists', {
        code: 'email_exists',
        requestId: rid,
      });
    }
    console.error(rid, e);
    return err(500, 'Failed to create user', { requestId: rid });
  }

  await writeAudit({
    requestId: rid,
    actorType: 'USER',
    actorId: me.id,
    actorLabel: me.email,
    action: 'USER_CREATED',
    targetType: 'USER',
    targetId: userId,
    metadata: { email, role },
    ipAddress: clientIp(req),
    userAgent: req.headers.get('user-agent'),
  });

  return json(
    { data: { id: userId, email, name: parsed.data.name || null, role, isActive: true, mustChangePassword: true } },
    { status: 201, requestId: rid },
  );
}
