import { cookies } from 'next/headers';
import { json, requestId } from '@/server/api';
import { logoutByRefresh } from '@/server/auth/session';

export const runtime = 'nodejs';

export async function POST(req: Request) {
  const rid = requestId(req);
  const jar = await cookies();
  const token = jar.get('ir_rt')?.value;
  await logoutByRefresh(token);
  jar.set('ir_rt', '', { httpOnly: true, path: '/api/v1/auth', maxAge: 0 });
  return json({ ok: true }, { requestId: rid });
}
