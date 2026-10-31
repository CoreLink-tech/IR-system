import { desc, eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { db } from '@/server/db/client';
import { webhookDeliveries, webhooks } from '@/server/db/schema';
import { ensureDefaultTenant } from '@/server/services/tenancy';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER') return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  const tenantId = await ensureDefaultTenant();
  const hooks = await db.select().from(webhooks).where(eq(webhooks.tenantId, tenantId));
  const ids = new Set(hooks.map((h) => h.id));
  const rows = await db.select().from(webhookDeliveries).orderBy(desc(webhookDeliveries.createdAt)).limit(50);
  const data = rows
    .filter((d) => ids.has(d.webhookId))
    .map((d) => ({
      id: d.id,
      webhookId: d.webhookId,
      eventType: d.eventType,
      success: d.success,
      attempts: d.attempts,
      statusCode: d.statusCode,
      lastError: d.lastError,
      dead: d.dead,
      nextAttemptAt: d.nextAttemptAt?.toISOString() ?? null,
      createdAt: d.createdAt.toISOString(),
    }));
  return json({ data }, { requestId: rid });
}
