import { createHmac, randomBytes } from 'crypto';
import { and, eq } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { webhooks, webhookDeliveries } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';

export function newWebhookSecret(): string {
  return randomBytes(24).toString('base64url');
}

function sign(secret: string, body: string, ts: number): string {
  return createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
}

/**
 * Fire-and-forget delivery. Failures are recorded; ingest never waits long.
 * Production: move to a queue (QStash/Inngest) — this is Phase 1 MVP.
 */
export async function dispatchWebhook(
  tenantId: string | null | undefined,
  eventType: string,
  data: Record<string, unknown>,
) {
  if (!tenantId) return;
  const rows = await db
    .select()
    .from(webhooks)
    .where(and(eq(webhooks.tenantId, tenantId), eq(webhooks.isActive, true)));
  const targets = rows.filter((w) =>
    (w.events || '')
      .split(',')
      .map((s) => s.trim())
      .includes(eventType),
  );
  if (!targets.length) return;

  const envelope = {
    id: newId(),
    type: eventType,
    created_at: new Date().toISOString(),
    data,
  };
  const body = JSON.stringify(envelope);
  const ts = Math.floor(Date.now() / 1000);

  await Promise.allSettled(
    targets.map(async (w) => {
      const deliveryId = newId();
      let statusCode: number | null = null;
      let success = false;
      let lastError: string | null = null;
      try {
        const res = await fetch(w.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Watcher-Signature': sign(w.secret, body, ts),
            'X-Watcher-Timestamp': String(ts),
            'User-Agent': 'Watcher-Webhooks/1.0',
          },
          body,
          signal: AbortSignal.timeout(5000),
        });
        statusCode = res.status;
        success = res.ok;
        if (!res.ok) lastError = `HTTP ${res.status}`;
      } catch (e) {
        lastError = e instanceof Error ? e.message : 'delivery failed';
      }
      await db.insert(webhookDeliveries).values({
        id: deliveryId,
        webhookId: w.id,
        eventType,
        payload: body,
        statusCode,
        success,
        attempts: 1,
        lastError,
        createdAt: new Date(),
      });
    }),
  );
}
