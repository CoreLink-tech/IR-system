import { desc, eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { newId } from '@/server/auth/crypto';
import { db } from '@/server/db/client';
import { allowlist } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  const rows = await db.select().from(allowlist).orderBy(desc(allowlist.createdAt));
  return json(
    {
      data: rows.map((r) => ({
        id: r.id,
        ipAddress: r.ipAddress,
        reason: r.reason,
        addedBy: r.addedBy,
        expiresAt: r.expiresAt?.toISOString() ?? null,
        createdAt: r.createdAt.toISOString(),
      })),
    },
    { requestId: rid },
  );
}

export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER' || me.role === 'ANALYST') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  let body: { ipAddress?: string; reason?: string; ttlMinutes?: number };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  const ip = (body.ipAddress || '').trim();
  const reason = (body.reason || '').trim();
  if (!ip || !reason) return err(400, 'ipAddress and reason required', { code: 'invalid_body', requestId: rid });
  const existing = await db.select().from(allowlist).where(eq(allowlist.ipAddress, ip)).limit(1);
  if (existing[0]) return err(409, 'Already on allowlist', { code: 'already_allowed', requestId: rid });
  const expiresAt =
    body.ttlMinutes && body.ttlMinutes > 0 ? new Date(Date.now() + body.ttlMinutes * 60_000) : null;
  const id = newId();
  await db.insert(allowlist).values({
    id,
    ipAddress: ip,
    reason,
    addedBy: me.id,
    expiresAt,
    createdAt: new Date(),
  });
  return json({ id, ipAddress: ip, reason, expiresAt: expiresAt?.toISOString() ?? null }, { requestId: rid });
}
