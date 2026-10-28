import { desc } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { generateApiKey, newId } from '@/server/auth/crypto';
import { db } from '@/server/db/client';
import { apiKeys } from '@/server/db/schema';
import { getEnv } from '@/lib/env';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN' && me.role !== 'SECURITY_ADMIN') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  const rows = await db.select().from(apiKeys).orderBy(desc(apiKeys.createdAt));
  return json(
    {
      data: rows.map((k) => ({
        id: k.id,
        name: k.name,
        keyPrefix: k.keyPrefix,
        scopes: k.scopes,
        isActive: k.isActive,
        expiresAt: k.expiresAt?.toISOString() ?? null,
        lastUsedAt: k.lastUsedAt?.toISOString() ?? null,
        revokedAt: k.revokedAt?.toISOString() ?? null,
        createdAt: k.createdAt.toISOString(),
      })),
    },
    { requestId: rid },
  );
}

export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN' && me.role !== 'SECURITY_ADMIN') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  let body: { name?: string; scopes?: string[]; expiresInDays?: number };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  if (!body.name?.trim()) return err(400, 'name required', { code: 'invalid_body', requestId: rid });
  const scopes = (body.scopes && body.scopes.length ? body.scopes : ['events:write', 'block:read']).join(',');
  const generated = generateApiKey(getEnv().apiKeyPrefix);
  const expiresAt =
    body.expiresInDays && body.expiresInDays > 0
      ? new Date(Date.now() + body.expiresInDays * 86400000)
      : null;
  const id = newId();
  await db.insert(apiKeys).values({
    id,
    name: body.name.trim(),
    keyPrefix: generated.prefix,
    keyHash: generated.hash,
    scopes,
    expiresAt,
    createdBy: me.id,
    createdAt: new Date(),
  });
  return json(
    {
      id,
      name: body.name.trim(),
      scopes: scopes.split(','),
      expiresAt: expiresAt?.toISOString() ?? null,
      apiKey: generated.raw,
    },
    { requestId: rid },
  );
}
