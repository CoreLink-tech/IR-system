import { err, json, requestId } from '@/server/api';
import { enrollStart } from '@/server/auth/two-factor';

export const runtime = 'nodejs';

export async function POST(req: Request) {
  const rid = requestId(req);
  let body: { challengeToken?: string };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  try {
    const result = await enrollStart(body.challengeToken || '');
    return json(result, { requestId: rid });
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string };
    if (ex.status) return err(ex.status, ex.message || 'Error', { code: ex.code, requestId: rid });
    console.error(rid, e);
    return err(500, 'Internal server error', { requestId: rid });
  }
}
