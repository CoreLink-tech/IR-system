import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { technicalReport } from '@/server/services/reports';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  if (me.role === 'VIEWER') return err(403, 'Forbidden', { code: 'forbidden', requestId: rid });
  const url = new URL(req.url);
  const days = Math.min(90, Math.max(1, Number(url.searchParams.get('days') || 7)));
  const data = await technicalReport(days);
  return json(data, { requestId: rid });
}
