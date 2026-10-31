import { err, json, requestId } from '@/server/api';
import { processWebhookRetries } from '@/server/services/webhooks';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const secret = process.env.CRON_SECRET;
  if (!secret) return err(503, 'CRON_SECRET not configured', { requestId: rid });
  const auth = req.headers.get('authorization') || '';
  if (auth !== `Bearer ${secret}`) return err(401, 'Unauthorized', { requestId: rid });
  const result = await processWebhookRetries(50);
  return json({ ok: true, ...result, ranAt: new Date().toISOString() }, { requestId: rid });
}
