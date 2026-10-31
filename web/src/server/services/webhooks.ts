import { createHmac, randomBytes } from 'crypto';
import { lookup } from 'dns/promises';
import { isIP } from 'net';
import { and, eq, lte, or, isNull, sql } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { webhooks, webhookDeliveries } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';

export function newWebhookSecret(): string {
  return randomBytes(24).toString('base64url');
}

function sign(secret: string, body: string, ts: number): string {
  return createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
}

const RETRY_MINUTES = [1, 5, 30, 120, 720]; // then dead

function isPrivateIp(ip: string): boolean {
  if (ip === '::1' || ip === '0.0.0.0') return true;
  if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.'))
    return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  // unique local IPv6 fc00::/7
  if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) return true;
  return false;
}

/** SSRF guard: https only, no private/link-local/metadata IPs. */
export async function assertSafeWebhookUrl(urlStr: string): Promise<void> {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    throw Object.assign(new Error('Invalid webhook URL'), { status: 400, code: 'invalid_url' });
  }
  if (u.protocol !== 'https:') {
    throw Object.assign(new Error('Webhook URL must be https'), { status: 400, code: 'invalid_url' });
  }
  const host = u.hostname;
  if (host === 'localhost' || host.endsWith('.localhost') || host === 'metadata.google.internal') {
    throw Object.assign(new Error('Webhook host not allowed'), { status: 400, code: 'ssrf_blocked' });
  }
  if (isIP(host)) {
    if (isPrivateIp(host) || host === '169.254.169.254') {
      throw Object.assign(new Error('Webhook host not allowed'), { status: 400, code: 'ssrf_blocked' });
    }
    return;
  }
  const records = await lookup(host, { all: true });
  for (const r of records) {
    if (isPrivateIp(r.address) || r.address === '169.254.169.254') {
      throw Object.assign(new Error('Webhook host resolves to private IP'), {
        status: 400,
        code: 'ssrf_blocked',
      });
    }
  }
}

async function deliverOnce(
  w: { id: string; url: string; secret: string },
  eventType: string,
  body: string,
  eventId: string,
  deliveryId: string,
  attempts: number,
) {
  const ts = Math.floor(Date.now() / 1000);
  let statusCode: number | null = null;
  let success = false;
  let lastError: string | null = null;
  try {
    await assertSafeWebhookUrl(w.url);
    const res = await fetch(w.url, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/json',
        'X-Watcher-Signature': sign(w.secret, body, ts),
        'X-Watcher-Timestamp': String(ts),
        'X-Watcher-Event-Id': eventId,
        'User-Agent': 'Watcher-Webhooks/1.0',
      },
      body,
      signal: AbortSignal.timeout(5000),
    });
    statusCode = res.status;
    success = res.ok;
    if (!res.ok) lastError = `HTTP ${res.status}`;
    if (res.status >= 300 && res.status < 400) {
      success = false;
      lastError = 'redirect_not_followed';
    }
  } catch (e) {
    lastError = e instanceof Error ? e.message : 'delivery failed';
  }

  const nextAttempt =
    success || attempts >= RETRY_MINUTES.length
      ? null
      : new Date(Date.now() + RETRY_MINUTES[Math.min(attempts, RETRY_MINUTES.length - 1)] * 60_000);
  const dead = !success && attempts >= RETRY_MINUTES.length;

  await db
    .update(webhookDeliveries)
    .set({
      statusCode,
      success,
      attempts,
      lastError,
      nextAttemptAt: nextAttempt,
      dead,
      eventId,
    })
    .where(eq(webhookDeliveries.id, deliveryId));

  return success;
}

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

  const eventId = newId();
  const envelope = {
    id: eventId,
    type: eventType,
    created_at: new Date().toISOString(),
    data,
  };
  const body = JSON.stringify(envelope);

  await Promise.allSettled(
    targets.map(async (w) => {
      const deliveryId = newId();
      await db.insert(webhookDeliveries).values({
        id: deliveryId,
        webhookId: w.id,
        eventType,
        payload: body,
        attempts: 0,
        success: false,
        eventId,
        createdAt: new Date(),
      });
      await deliverOnce(w, eventType, body, eventId, deliveryId, 1);
    }),
  );
}

/** Process due webhook retries (cron). */
export async function processWebhookRetries(limit = 50) {
  const now = new Date();
  const due = await db
    .select()
    .from(webhookDeliveries)
    .where(
      and(
        eq(webhookDeliveries.success, false),
        eq(webhookDeliveries.dead, false),
        lte(webhookDeliveries.nextAttemptAt, now),
      ),
    )
    .limit(limit);

  let processed = 0;
  for (const d of due) {
    const hooks = await db.select().from(webhooks).where(eq(webhooks.id, d.webhookId)).limit(1);
    const w = hooks[0];
    if (!w || !w.isActive) {
      await db.update(webhookDeliveries).set({ dead: true, nextAttemptAt: null }).where(eq(webhookDeliveries.id, d.id));
      continue;
    }
    await deliverOnce(
      w,
      d.eventType,
      d.payload,
      d.eventId || d.id,
      d.id,
      (d.attempts || 0) + 1,
    );
    processed += 1;
  }
  return { processed };
}

export async function redeliverWebhook(deliveryId: string) {
  const rows = await db.select().from(webhookDeliveries).where(eq(webhookDeliveries.id, deliveryId)).limit(1);
  const d = rows[0];
  if (!d) throw Object.assign(new Error('Not found'), { status: 404, code: 'not_found' });
  const hooks = await db.select().from(webhooks).where(eq(webhooks.id, d.webhookId)).limit(1);
  const w = hooks[0];
  if (!w) throw Object.assign(new Error('Webhook gone'), { status: 404, code: 'not_found' });
  await db
    .update(webhookDeliveries)
    .set({ dead: false, nextAttemptAt: null, lastError: null })
    .where(eq(webhookDeliveries.id, d.id));
  await deliverOnce(w, d.eventType, d.payload, d.eventId || d.id, d.id, (d.attempts || 0) + 1);
  return { ok: true };
}
