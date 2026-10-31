import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { verifyAuditChain } from '@/server/services/audit';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role !== 'SUPER_ADMIN') return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  const limit = Math.min(2000, Math.max(10, Number(new URL(req.url).searchParams.get('limit') || 500)));
  const result = await verifyAuditChain(limit);
  return json(result, { requestId: rid });
}
