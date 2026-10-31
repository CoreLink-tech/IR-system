import { err, json, requestId } from '@/server/api';
import { verifyApiKey } from '@/server/services/events';
import { requireUser } from '@/server/auth/require-user';
import { recordDecisionOutcome } from '@/server/services/decide';

export const runtime = 'nodejs';

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const rid = requestId(req);
  const { id } = await ctx.params;

  // Accept API key or dashboard user
  const auth = req.headers.get('authorization') || '';
  const raw = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  let ok = false;
  if (raw.startsWith('IRS_') || raw.length > 20) {
    const key = await verifyApiKey(raw);
    ok = !!key;
  }
  if (!ok) {
    const user = await requireUser(req);
    ok = !!user;
  }
  if (!ok) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });

  let body: { feedback?: string };
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }
  const allowed = ['confirmed_fraud', 'false_positive', 'chargeback', 'legitimate'] as const;
  if (!body.feedback || !allowed.includes(body.feedback as (typeof allowed)[number])) {
    return err(400, `feedback must be one of ${allowed.join(', ')}`, { code: 'invalid_body', requestId: rid });
  }

  try {
    const result = await recordDecisionOutcome(id, body.feedback as (typeof allowed)[number]);
    return json(result, { requestId: rid });
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string };
    if (ex.status) return err(ex.status, ex.message || 'Error', { code: ex.code, requestId: rid });
    return err(500, 'Internal server error', { requestId: rid });
  }
}
