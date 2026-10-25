import { err, json, requestId } from '@/server/api';
import { publicUser, requireUser } from '@/server/auth/require-user';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const user = await requireUser(req);
  if (!user) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  return json({ user: publicUser(user) }, { requestId: rid });
}
