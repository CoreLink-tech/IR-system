import { eq } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { tenants, tenantMembers } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';

export const DEFAULT_TENANT_SLUG = 'default';

/** Ensure a default tenant exists (single-tenant → multi-tenant migration). */
export async function ensureDefaultTenant(): Promise<string> {
  const rows = await db.select().from(tenants).where(eq(tenants.slug, DEFAULT_TENANT_SLUG)).limit(1);
  if (rows[0]) return rows[0].id;
  const id = newId();
  await db.insert(tenants).values({
    id,
    name: 'Default workspace',
    slug: DEFAULT_TENANT_SLUG,
    plan: 'pilot',
    isActive: true,
    createdAt: new Date(),
  });
  return id;
}

export async function ensureUserMembership(userId: string, tenantId: string, role: string) {
  const existing = await db
    .select()
    .from(tenantMembers)
    .where(eq(tenantMembers.userId, userId))
    .limit(1);
  if (existing[0]) return existing[0];
  const id = newId();
  await db.insert(tenantMembers).values({
    id,
    tenantId,
    userId,
    role,
    createdAt: new Date(),
  });
  return { id, tenantId, userId, role };
}
