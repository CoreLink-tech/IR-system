import { err, json, requestId, clientIp } from '@/server/api';
import { verifyApiKey } from '@/server/services/events';
import { makeDecision, type DecideInput } from '@/server/services/decide';
import { rateLimitAsync } from '@/server/services/rate-limit';

export const runtime = 'nodejs';

/**
 * POST /api/v1/decide
 * Authorization: Bearer IRS_...
 *
 * Client policy (recommended):
 * - browse: fail-open if timeout
 * - admin / checkout: prefer challenge on timeout, never silent allow for admin if configured client-side
 */
export async function POST(req: Request) {
  const started = Date.now();
  const rid = requestId(req);
  const auth = req.headers.get('authorization') || '';
  const raw = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!raw) return err(401, 'API key required', { code: 'unauthorized', requestId: rid });

  const key = await verifyApiKey(raw);
  if (!key) return err(401, 'Invalid API key', { code: 'unauthorized', requestId: rid });

  const scopes = key.scopes.split(',').map((s) => s.trim());
  if (!scopes.includes('decide') && !scopes.includes('events:write') && !scopes.includes('*')) {
    return err(403, 'API key lacks decide scope', { code: 'forbidden', requestId: rid });
  }

  const limit = key.rateLimitPerMinute && key.rateLimitPerMinute > 0 ? key.rateLimitPerMinute : 300;
  const rl = await rateLimitAsync(`decide:${key.id}:${clientIp(req)}`, limit, 60_000);
  if (!rl.ok) {
    return err(429, 'Too many decisions', {
      code: 'rate_limited',
      requestId: rid,
      retryAfterSeconds: rl.retryAfterSeconds,
    });
  }

  let body: DecideInput;
  try {
    body = await req.json();
  } catch {
    return err(400, 'Invalid JSON', { code: 'invalid_body', requestId: rid });
  }

  if (!body.ip_address && !body.user_id && !body.session_id) {
    return err(400, 'ip_address, user_id, or session_id required', { code: 'invalid_body', requestId: rid });
  }

  try {
    const result = await makeDecision(key.id, key.tenantId, body);
    const ms = Date.now() - started;
    return json(
      {
        ...result,
        meta: { latency_ms: ms, request_id: rid },
      },
      { requestId: rid },
    );
  } catch (e: unknown) {
    console.error('decide failed', e);
    // Fail-open response for resilience: allow with reason (client may still enforce stricter)
    return json(
      {
        decision_id: 'error',
        outcome: 'allow',
        score: 0,
        reasons: ['decide_error_fail_open'],
        rule_hits: [],
        ttl_seconds: 10,
        meta: { latency_ms: Date.now() - started, request_id: rid, degraded: true },
      },
      { requestId: rid },
    );
  }
}
