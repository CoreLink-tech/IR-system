import { desc, eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { newId } from '@/server/auth/crypto';
import { db } from '@/server/db/client';
import { logEntries } from '@/server/db/schema';
import { verifyApiKey } from '@/server/services/events';
import { ensureDefaultTenant } from '@/server/services/tenancy';
import { rateLimitAsync } from '@/server/services/rate-limit';
import { redactJsonValue, redactText } from '@/server/services/redact';

export const runtime = 'nodejs';

const MAX_BODY = 1_000_000; // 1 MB
const BATCH = 100;

/**
 * POST /api/v1/logs — NDJSON or JSON array.
 * Prefer scope logs:write; events:write still accepted (deprecated).
 */
export async function POST(req: Request) {
  const rid = requestId(req);
  const auth = req.headers.get('authorization') || '';
  const rawKey = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!rawKey) return err(401, 'API key required', { code: 'unauthorized', requestId: rid });

  const key = await verifyApiKey(rawKey);
  if (!key) return err(401, 'Invalid API key', { code: 'unauthorized', requestId: rid });

  const scopes = key.scopes.split(',').map((s) => s.trim());
  const hasLogs = scopes.includes('logs:write') || scopes.includes('*');
  const hasEvents = scopes.includes('events:write');
  if (!hasLogs && !hasEvents) {
    return err(403, 'API key lacks logs:write', { code: 'forbidden', requestId: rid });
  }

  const limit = key.rateLimitPerMinute && key.rateLimitPerMinute > 0 ? key.rateLimitPerMinute : 120;
  const rl = await rateLimitAsync(`logs:${key.id}`, limit, 60_000);
  if (!rl.ok) {
    return err(429, 'Too many log batches', {
      code: 'rate_limited',
      requestId: rid,
      retryAfterSeconds: rl.retryAfterSeconds,
    });
  }

  const contentLength = Number(req.headers.get('content-length') || 0);
  if (contentLength > MAX_BODY) {
    return err(413, 'Body too large (max 1MB)', { code: 'payload_too_large', requestId: rid });
  }

  const buf = Buffer.from(await req.arrayBuffer());
  if (buf.byteLength > MAX_BODY) {
    return err(413, 'Body too large (max 1MB)', { code: 'payload_too_large', requestId: rid });
  }
  const text = buf.toString('utf8');

  const lines: unknown[] = [];
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) lines.push(...parsed);
    else lines.push(parsed);
  } catch {
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try {
        lines.push(JSON.parse(line));
      } catch {
        lines.push({ message: line });
      }
    }
  }
  if (lines.length > 500) {
    return err(400, 'Max 500 log lines per request', { code: 'batch_too_large', requestId: rid });
  }

  const tenantId = key.tenantId || (await ensureDefaultTenant());
  const redactEmails = true; // tenant setting default on
  const values = lines.map((item) => {
    const rawObj = (item && typeof item === 'object' ? item : { message: String(item) }) as Record<string, unknown>;
    const o = redactJsonValue(rawObj, { redactEmails }) as Record<string, unknown>;
    const message = String(o.message || o.msg || o.log || JSON.stringify(o)).slice(0, 8000);
    const raw = JSON.stringify(o).slice(0, 16000);
    return {
      id: newId(),
      tenantId,
      source: String(o.source || 'https'),
      severity: o.severity ? String(o.severity) : null,
      message,
      ipAddress: o.ip || o.ip_address ? String(o.ip || o.ip_address) : null,
      path: o.path ? String(o.path) : null,
      method: o.method ? String(o.method) : null,
      statusCode: typeof o.status === 'number' ? o.status : typeof o.status_code === 'number' ? o.status_code : null,
      userAgent: o.user_agent || o.userAgent ? String(o.user_agent || o.userAgent) : null,
      raw,
      createdAt: new Date(),
    };
  });

  for (let i = 0; i < values.length; i += BATCH) {
    await db.insert(logEntries).values(values.slice(i, i + BATCH));
  }

  const headers: Record<string, string> = {};
  if (!hasLogs && hasEvents) {
    // TODO(remove after 2026-12-30): stop accepting events:write for log ingest
    headers['Deprecation'] = 'true';
  }

  return json({ inserted: values.length }, { requestId: rid, headers });
}

export async function GET(req: Request) {
  const rid = requestId(req);
  const me = await requireUser(req);
  if (!me) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  const tenantId = await ensureDefaultTenant();
  const url = new URL(req.url);
  const pageSize = Math.min(100, Math.max(1, Number(url.searchParams.get('pageSize') || 50)));
  const rows = await db
    .select()
    .from(logEntries)
    .where(eq(logEntries.tenantId, tenantId))
    .orderBy(desc(logEntries.createdAt))
    .limit(pageSize);
  return json(
    {
      data: rows.map((r) => ({
        id: r.id,
        source: r.source,
        severity: r.severity,
        message: r.message,
        ipAddress: r.ipAddress,
        path: r.path,
        method: r.method,
        statusCode: r.statusCode,
        createdAt: r.createdAt.toISOString(),
      })),
    },
    { requestId: rid },
  );
}
