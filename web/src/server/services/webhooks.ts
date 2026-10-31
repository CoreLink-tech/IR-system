import { createHmac, randomBytes } from 'crypto';
import { lookup } from 'dns/promises';
import { isIP } from 'net';
import { Agent, fetch as undiciFetch } from 'undici';
import { and, eq, lte } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { webhooks, webhookDeliveries } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';
import { createClient } from '@libsql/client';

export function newWebhookSecret(): string {
  return randomBytes(24).toString('base64url');
}

function sign(secret: string, body: string, ts: number): string {
  return createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
}

const RETRY_MINUTES = [1, 5, 30, 120, 720];

/** Reject private, reserved, link-local, CGNAT, metadata, and mapped addresses. */
export function isBlockedIp(ip: string): boolean {
  const raw = ip.toLowerCase().trim();
  let v4 = raw;
  if (raw.startsWith('::ffff:')) v4 = raw.slice(7);
  // IPv4
  if (isIP(v4) === 4) {
    const parts = v4.split('.').map(Number);
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 192 && b === 0 && parts[2] === 2) return true; // 192.0.2.0/24 docs
    if (a >= 224) return true; // multicast/reserved
    return false;
  }
  // IPv6
  if (isIP(raw) === 6) {
    if (raw === '::1' || raw === '::') return true;
    if (raw.startsWith('fc') || raw.startsWith('fd')) return true; // ULA
    if (raw.startsWith('fe8') || raw.startsWith('fe9') || raw.startsWith('fea') || raw.startsWith('feb'))
      return true; // fe80::/10
    if (raw.startsWith('ff')) return true; // multicast
    return false;
  }
  return true; // unknown form → reject
}

export async function assertSafeWebhookUrl(urlStr: string): Promise<string[]> {
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
    if (isBlockedIp(host)) {
      throw Object.assign(new Error('Webhook host not allowed'), { status: 400, code: 'ssrf_blocked' });
    }
    return [host];
  }
  const records = await lookup(host, { all: true });
  const addrs = records.map((r) => r.address);
  for (const addr of addrs) {
    if (isBlockedIp(addr)) {
      throw Object.assign(new Error('Webhook host resolves to private IP'), {
        status: 400,
        code: 'ssrf_blocked',
      });
    }
  }
  if (!addrs.length) {
    throw Object.assign(new Error('Webhook host did not resolve'), { status: 400, code: 'ssrf_blocked' });
  }
  return addrs;
}

function pinnedAgent(allowedIps: string[]) {
  const allow = new Set(allowedIps);
  return new Agent({
    connect: {
      lookup: (hostname, options, callback) => {
        // Force only previously vetted addresses
        const first = allowedIps[0];
        if (!first) {
          callback(new Error('ssrf_blocked'), '', 4);
          return;
        }
        const family = isIP(first) === 6 ? 6 : 4;
        if (typeof options === 'function') {
          // overload
          (options as (err: Error | null, address: string, family: number) => void)(null, first, family);
          return;
        }
        callback(null, first, family);
      },
    },
  });
}

async function deliverOnce(
  w: { id: string; url: string; secret: string },
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
    const addrs = await assertSafeWebhookUrl(w.url);
    const agent = pinnedAgent(addrs);
    const res = await undiciFetch(w.url, {
      method: 'POST',
      redirect: 'manual',
      dispatcher: agent,
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

  const idx = Math.min(Math.max(attempts - 1, 0), RETRY_MINUTES.length - 1);
  const nextAttempt =
    success || attempts >= RETRY_MINUTES.length
      ? null
      : new Date(Date.now() + RETRY_MINUTES[idx] * 60_000);
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
        nextAttemptAt: new Date(), // claimable if process dies mid-delivery
        createdAt: new Date(),
      });
      await deliverOnce(w, body, eventId, deliveryId, 1);
    }),
  );
}

function libsql() {
  const url = process.env.DATABASE_URL || 'file:./data/ir.db';
  return createClient({ url, authToken: process.env.DATABASE_AUTH_TOKEN || undefined });
}

/** Process due webhook retries (cron). Claims rows atomically. */
export async function processWebhookRetries(limit = 50) {
  const now = Date.now();
  const client = libsql();
  const due = await client.execute({
    sql: `SELECT id, webhook_id, event_type, payload, attempts, event_id, next_attempt_at
          FROM webhook_deliveries
          WHERE success = 0 AND IFNULL(dead, 0) = 0 AND next_attempt_at IS NOT NULL AND next_attempt_at <= ?
          ORDER BY next_attempt_at ASC LIMIT ?`,
    args: [now, limit],
  });

  let processed = 0;
  for (const row of due.rows) {
    const id = String(row.id);
    const claimed = await client.execute({
      sql: `UPDATE webhook_deliveries SET next_attempt_at = NULL
            WHERE id = ? AND next_attempt_at = ?
            RETURNING id`,
      args: [id, row.next_attempt_at],
    });
    if (!claimed.rows.length) continue;

    const hooks = await db.select().from(webhooks).where(eq(webhooks.id, String(row.webhook_id))).limit(1);
    const w = hooks[0];
    if (!w || !w.isActive) {
      await db.update(webhookDeliveries).set({ dead: true, nextAttemptAt: null }).where(eq(webhookDeliveries.id, id));
      continue;
    }
    await deliverOnce(
      w,
      String(row.payload),
      String(row.event_id || id),
      id,
      Number(row.attempts || 0) + 1,
    );
    processed += 1;
  }
  client.close();
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
  await deliverOnce(w, d.payload, d.eventId || d.id, d.id, (d.attempts || 0) + 1);
  return { ok: true };
}
