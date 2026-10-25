import { desc, eq } from 'drizzle-orm';
import { err, json, requestId } from '@/server/api';
import { requireUser } from '@/server/auth/require-user';
import { ingestEvent, verifyApiKey, type IngestBody } from '@/server/services/events';
import { db } from '@/server/db/client';
import { events } from '@/server/db/schema';

export const runtime = 'nodejs';

export async function GET(req: Request) {
  const rid = requestId(req);
  const user = await requireUser(req);
  if (!user) return err(401, 'Unauthorized', { code: 'unauthorized', requestId: rid });
  const url = new URL(req.url);
  const pageSize = Math.min(100, Math.max(1, Number(url.searchParams.get('pageSize') || 50)));
  const ip = url.searchParams.get('ip');
  let rows;
  if (ip) {
    rows = await db.select().from(events).where(eq(events.ipAddress, ip)).orderBy(desc(events.createdAt)).limit(pageSize);
  } else {
    rows = await db.select().from(events).orderBy(desc(events.createdAt)).limit(pageSize);
  }
  return json(
    {
      data: rows.map((e) => ({
        id: e.id,
        eventType: e.eventType,
        severity: e.severity,
        ipAddress: e.ipAddress,
        riskScore: e.riskScore,
        riskLevel: e.riskLevel,
        incidentId: e.incidentId,
        occurredAt: e.occurredAt?.toISOString() ?? null,
        createdAt: e.createdAt.toISOString(),
      })),
    },
    { requestId: rid },
  );
}

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
