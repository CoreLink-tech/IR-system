import { err, json, requestId, clientIp } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { redeliverWebhook } from '@/server/services/webhooks';
import { writeAudit } from '@/server/services/audit';

export const runtime = 'nodejs';

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN' && me.role !== 'SECURITY_ADMIN') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  const { id } = await ctx.params;
  try {
    await redeliverWebhook(id);
    await writeAudit({
      requestId: rid,
      actorType: 'USER',
      actorId: me.id,
      actorLabel: me.email,
      action: 'webhook.redeliver',
      targetType: 'webhook_delivery',
      targetId: id,
      ipAddress: clientIp(req),
    });
    return json({ ok: true }, { requestId: rid });
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string };
    if (ex.status) return err(ex.status, ex.message || 'Error', { code: ex.code, requestId: rid });
    return err(500, 'Internal server error', { requestId: rid });
  }
}
