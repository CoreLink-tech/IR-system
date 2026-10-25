import { err, json, requestId } from '@/server/api';
import { listActiveBlocks, verifyApiKey } from '@/server/services/events';

export const runtime = 'nodejs';

/**
 * GET /api/v1/security/blocked-ips
 * Website polls this list and enforces blocks locally (PHP library).
 * Accepts API key with block:read or JWT (dashboard) — key path implemented first.
 */
export async function GET(req: Request) {
  const rid = requestId(req);
  const auth = req.headers.get('authorization') || '';
  const raw = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';

  if (raw.startsWith(process.env.API_KEY_PREFIX || 'IRS_')) {
    const key = await verifyApiKey(raw);
    if (!key) return err(401, 'Invalid or revoked API key', { code: 'unauthorized', requestId: rid });
    const scopes = key.scopes.split(',').map((s) => s.trim());
    if (!scopes.includes('block:read') && !scopes.includes('events:write') && !scopes.includes('*')) {
      return err(403, 'API key lacks block:read scope', { code: 'forbidden', requestId: rid });
    }
  } else if (!raw) {
    return err(401, 'Authorization required', { code: 'unauthorized', requestId: rid });
  }
  // JWT path can be added with session verification later.

  const data = await listActiveBlocks();
  return json({ data }, { requestId: rid });
}
