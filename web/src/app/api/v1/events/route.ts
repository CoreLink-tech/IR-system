import { err, json, requestId } from '@/server/api';
import { ingestEvent, verifyApiKey, type IngestBody } from '@/server/services/events';

export const runtime = 'nodejs';

/**
 * POST /api/v1/events
 * Client website (PHP or other) sends security events with API key.
 * Authorization: Bearer IRS_...
 */
export async function POST(req: Request) {
  const rid = requestId(req);
  const auth = req.headers.get('authorization') || '';
  const raw = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!raw) return err(401, 'API key required', { code: 'unauthorized', requestId: rid });

  const key = await verifyApiKey(raw);
  if (!key) return err(401, 'Invalid or revoked API key', { code: 'unauthorized', requestId: rid });

  const scopes = key.scopes.split(',').map((s) => s.trim());
  if (!scopes.includes('events:write') && !scopes.includes('*')) {
    return err(403, 'API key lacks events:write scope', { code: 'forbidden', requestId: rid });
  }

  let body: IngestBody;
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON body', { code: 'invalid_body', requestId: rid });
  }

  if (!body?.event_type) {
    return err(400, 'event_type is required', { code: 'invalid_body', requestId: rid });
  }

  try {
    const result = await ingestEvent(key.id, body);
    return json(result, { requestId: rid });
  } catch (e: unknown) {
    const ex = e as { status?: number; code?: string; message?: string };
    if (ex.status === 400) {
      return err(400, ex.message || 'Bad request', { code: ex.code, requestId: rid });
    }
    console.error(rid, e);
    return err(500, 'Internal server error', { requestId: rid });
  }
}
