import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { listActiveBlocks, verifyApiKey } from '@/server/services/events';

export const runtime = 'nodejs';

/** GET /api/v1/security/blocked-ips — API key (website) or JWT (dashboard). */
export async function GET(req: Request) {
  const rid = requestId(req);
  const auth = req.headers.get('authorization') || '';
  const raw = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!raw) return err(401, 'Authorization required', { code: 'unauthorized', requestId: rid });

  const prefix = process.env.API_KEY_PREFIX || 'IRS_';
  if (raw.startsWith(prefix)) {
    const key = await verifyApiKey(raw);
    if (!key) return err(401, 'Invalid or revoked API key', { code: 'unauthorized', requestId: rid });
    const scopes = key.scopes.split(',').map((s) => s.trim());
    if (!scopes.includes('block:read') && !scopes.includes('events:write') && !scopes.includes('*')) {
      return err(403, 'API key lacks block:read scope', { code: 'forbidden', requestId: rid });
    }
  } else {
    const user = await requireUser(req);
    if (!user) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  }

  const data = await listActiveBlocks();
  return json({ data }, { requestId: rid });
}
