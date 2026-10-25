import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { listRules } from '@/server/services/rules';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER' || me.role === 'ANALYST') {
    return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  }
  return json({ data: await listRules() }, { requestId: rid });
}
