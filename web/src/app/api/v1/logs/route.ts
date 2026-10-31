import { desc, eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { newId } from '@/server/auth/crypto';
import { db } from '@/server/db/client';
import { logEntries } from '@/server/db/schema';
import { verifyApiKey } from '@/server/services/events';
import { ensureDefaultTenant } from '@/server/services/tenancy';
import { rateLimit } from '@/server/services/rate-limit';

export const runtime = 'nodejs';

/**
 * Phase 1 MVP log ingest: NDJSON or JSON array via API key (scope logs:write or *).
 * Storage is Turso — fine for pilot volume; not a long-term log warehouse.
 */
export async function POST(req: Request) {
  const rid = requestId(req);
  const auth = req.headers.get('authorization') || '';
  const raw = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!raw) return err(401, 'API key required', { code: 'unauthorized', requestId: rid });
  const key = await verifyApiKey(raw);
  if (!key) return err(401, 'Invalid API key', { code: 'unauthorized', requestId: rid });
  const scopes = key.scopes.split(',').map((s) => s.trim());
  if (!scopes.includes('logs:write') && !scopes.includes('events:write') && !scopes.includes('*')) {
    return err(403, 'API key lacks logs:write', { code: 'forbidden', requestId: rid });
  }
  const limit = key.rateLimitPerMinute && key.rateLimitPerMinute > 0 ? key.rateLimitPerMinute : 120;
  const rl = rateLimit(`logs:${key.id}`, limit, 60_000);
  if (!rl.ok) {
    return err(429, 'Too many log batches', { code: 'rate_limited', requestId: rid, retryAfterSeconds: rl.retryAfterSeconds });
  }

  const tenantId = key.tenantId || (await ensureDefaultTenant());
  const text = await req.text();
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

  let inserted = 0;
  for (const item of lines) {
    const o = (item && typeof item === 'object' ? item : { message: String(item) }) as Record<string, unknown>;
    const message = String(o.message || o.msg || o.log || JSON.stringify(o)).slice(0, 8000);
    await db.insert(logEntries).values({
      id: newId(),
      tenantId,
      source: String(o.source || 'https'),
      severity: o.severity ? String(o.severity) : null,
      message,
      ipAddress: o.ip || o.ip_address ? String(o.ip || o.ip_address) : null,
      path: o.path ? String(o.path) : null,
      method: o.method ? String(o.method) : null,
      statusCode: typeof o.status === 'number' ? o.status : typeof o.status_code === 'number' ? o.status_code : null,
      userAgent: o.user_agent ? String(o.user_agent) : null,
      raw: JSON.stringify(o).slice(0, 16000),
      createdAt: new Date(),
    });
    inserted += 1;
  }
  return json({ inserted }, { requestId: rid });
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
