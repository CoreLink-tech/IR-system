import { and, eq } from 'drizzle-orm';
import { err, json, requestId, clientIp } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { newId } from '@/server/auth/crypto';
import { db } from '@/server/db/client';
import { allowlist, ipBlocks } from '@/server/db/schema';
import { writeAudit } from '@/server/services/audit';

export const runtime = 'nodejs';

function isPrivateIp(ip: string): boolean {
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
  );
}

export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER' || me.role === 'ANALYST') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  let body: { ipAddress?: string; reason?: string; permanent?: boolean; ttlMinutes?: number };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  const ip = (body.ipAddress || '').trim();
  const reason = (body.reason || '').trim();
  if (!ip || !reason) return err(400, 'ipAddress and reason required', { code: 'invalid_body', requestId: rid });
  if (isPrivateIp(ip)) {
    return err(400, 'Internal and private addresses cannot be blocked', { code: 'private_ip', requestId: rid });
  }
  const allowed = await db.select().from(allowlist).where(eq(allowlist.ipAddress, ip)).limit(1);
  if (allowed[0]) {
    return err(400, 'IP is on the allowlist', { code: 'allowlisted', requestId: rid });
  }
  const activeKey = `block:${ip}`;
  const existing = await db
    .select()
    .from(ipBlocks)
    .where(and(eq(ipBlocks.activeKey, activeKey), eq(ipBlocks.active, true)))
    .limit(1);
  if (existing[0]) {
    return err(409, 'Already blocked', { code: 'already_blocked', requestId: rid });
  }
  const permanent = !!body.permanent;
  const expiresAt =
    !permanent && body.ttlMinutes && body.ttlMinutes > 0
      ? new Date(Date.now() + body.ttlMinutes * 60_000)
      : permanent
        ? null
        : new Date(Date.now() + 60 * 60_000);
  const id = newId();
  await db.insert(ipBlocks).values({
    id,
    ipAddress: ip,
    action: 'BLOCK',
    reason,
    administratorId: me.id,
    isPermanent: permanent,
    expiresAt,
    active: true,
    automatic: false,
    activeKey,
    createdAt: new Date(),
  });
  await writeAudit({
    requestId: rid,
    actorType: 'USER',
    actorId: me.id,
    actorLabel: me.email,
    action: 'ip.block',
    targetType: 'ip',
    targetId: ip,
    metadata: { reason, permanent },
    ipAddress: clientIp(req),
  });
  return json(
    {
      id,
      ipAddress: ip,
      reason,
      permanent,
      expiresAt: expiresAt?.toISOString() ?? null,
      actorIp: clientIp(req),
    },
    { requestId: rid },
  );
}
