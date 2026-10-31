import { desc, eq } from 'drizzle-orm';
import { err, json, requestId, clientIp } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { newId } from '@/server/auth/crypto';
import { db } from '@/server/db/client';
import { webhooks } from '@/server/db/schema';
import { ensureDefaultTenant, ensureUserMembership } from '@/server/services/tenancy';
import { newWebhookSecret } from '@/server/services/webhooks';
import { writeAudit } from '@/server/services/audit';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  const tenantId = await ensureDefaultTenant();
  await ensureUserMembership(me.id, tenantId, me.role);
  const rows = await db.select().from(webhooks).where(eq(webhooks.tenantId, tenantId)).orderBy(desc(webhooks.createdAt));
  return json(
    {
      data: rows.map((w) => ({
        id: w.id,
        url: w.url,
        events: w.events.split(',').map((s) => s.trim()),
        isActive: w.isActive,
        createdAt: w.createdAt.toISOString(),
        // secret never returned after create
      })),
    },
    { requestId: rid },
  );
}

export async function POST(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER') return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  let body: { url?: string; events?: string[] };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  if (!body.url || !/^https:\/\//i.test(body.url)) {
    return err(400, 'url must be https', { code: 'invalid_body', requestId: rid });
  }
  const tenantId = await ensureDefaultTenant();
  await ensureUserMembership(me.id, tenantId, me.role);
  const secret = newWebhookSecret();
  const id = newId();
  const eventsList = (body.events?.length ? body.events : ['incident.created', 'block.created']).join(',');
  await db.insert(webhooks).values({
    id,
    tenantId,
    url: body.url,
    secret,
    events: eventsList,
    isActive: true,
    createdAt: new Date(),
  });
  await writeAudit({
    requestId: rid,
    actorType: 'USER',
    actorId: me.id,
    actorLabel: me.email,
    action: 'webhook.create',
    targetType: 'webhook',
    targetId: id,
    ipAddress: clientIp(req),
  });
  return json(
    {
      id,
      url: body.url,
      events: eventsList.split(','),
      secret, // shown once
    },
    { requestId: rid },
  );
}

export async function DELETE(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER') return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  const id = new URL(req.url).searchParams.get('id');
  if (!id) return err(400, 'id required', { code: 'invalid_body', requestId: rid });
  const tenantId = await ensureDefaultTenant();
  const rows = await db.select().from(webhooks).where(eq(webhooks.id, id)).limit(1);
  if (!rows[0] || rows[0].tenantId !== tenantId) {
    return err(404, 'Not found', { code: 'not_found', requestId: rid });
  }
  await db.delete(webhooks).where(eq(webhooks.id, id));
  return json({ ok: true }, { requestId: rid });
}
