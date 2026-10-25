import { err, json, requestId, clientIp } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { updateRule } from '@/server/services/rules';
import { writeAudit } from '@/server/services/audit';

export const runtime = 'nodejs';

export async function PATCH(req: Request, ctx: { params: Promise<{ code: string }> }) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN' && me.role !== 'SECURITY_ADMIN') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  const { code } = await ctx.params;
  let body: { isEnabled?: boolean; config?: Record<string, number> };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  try {
    const rule = await updateRule(code, body);
    await writeAudit({
      requestId: rid,
      actorType: 'USER',
      actorId: me.id,
      actorLabel: me.email,
      action: 'rule.update',
      targetType: 'rule',
      targetId: code,
      metadata: body as Record<string, unknown>,
      ipAddress: clientIp(req),
    });
    return json(rule, { requestId: rid });
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string };
    if (ex.status) return err(ex.status, ex.message || 'Error', { code: ex.code, requestId: rid });
    return err(500, 'Internal server error', { requestId: rid });
  }
}
