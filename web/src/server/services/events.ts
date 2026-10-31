import { and, eq } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { apiKeys, events, incidents, ipBlocks, allowlist, ipIntelligence } from '@/server/db/schema';
import { hashApiKey, newId, safeEqual } from '@/server/auth/crypto';
import { getEnv } from '@/lib/env';
import { dispatchWebhook } from '@/server/services/webhooks';
import { ensureDefaultTenant } from '@/server/services/tenancy';

const EVENT_TYPES = new Set([
  'login_failed',
  'login_success',
  'password_reset',
  'account_change',
  'admin_access',
  'suspicious_request',
  'rate_limit_exceeded',
  'payment_security_event',
  'application_error',
  'server_error',
  'logout',
  'session_anomaly',
]);

export type IngestBody = {
  event_type: string;
  severity?: string;
  ip_address?: string;
  user_id?: string;
  session_id?: string;
  user_agent?: string;
  request_method?: string;
  request_path?: string;
  request_id?: string;
  metadata?: Record<string, unknown>;
  timestamp?: string;
  event_id?: string;
};

export async function verifyApiKey(raw: string) {
  const prefixLen = getEnv().apiKeyPrefix.length + 16;
  const prefix = raw.slice(0, prefixLen);
  const rows = await db.select().from(apiKeys).where(eq(apiKeys.keyPrefix, prefix)).limit(1);
  const record = rows[0];
  if (!record || !record.isActive || record.revokedAt) return null;
  if (record.expiresAt && record.expiresAt.getTime() < Date.now()) return null;
  if (!safeEqual(hashApiKey(raw), record.keyHash)) return null;
  await db.update(apiKeys).set({ lastUsedAt: new Date() }).where(eq(apiKeys.id, record.id));
  return record;
}

function scrubMetadata(meta: Record<string, unknown> | undefined): string | null {
  if (!meta) return null;
  const banned = /password|secret|token|authorization|cookie|credit|card|cvv/i;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(meta)) {
    if (banned.test(k)) out[k] = '[redacted]';
    else out[k] = v;
  }
  return JSON.stringify(out);
}

async function scoreEvent(
  type: string,
  severity: string | undefined,
  ctx: { ip?: string | null; tenantId?: string | null; userId?: string | null },
): Promise<{
  riskScore: number;
  riskLevel: string;
  matched: string[];
  autoBlockThreshold: number;
  blockMinutes: number;
  incidentThreshold: number;
  skipAutoBlock: boolean;
}> {
  const { getRuleRuntime } = await import('@/server/services/rules');
  const {
    countEventsInWindow,
    countDistinctUsersLoginFailed,
    countLogPathHits,
    isOnCooldown,
    bumpEntityScore,
  } = await import('@/server/services/velocity');
  const rules = await getRuleRuntime();
  const matched: string[] = [];
  let riskScore = 0;
  const add = (code: string, eventTypes: string[]) => {
    const r = rules[code];
    if (!r?.enabled) return;
    if (eventTypes.includes(type)) {
      riskScore += r.config.baseScore ?? 0;
      matched.push(code);
    }
  };
  add('login_failed', ['login_failed']);
  add('suspicious_request', ['suspicious_request']);
  add('rate_limit', ['rate_limit_exceeded']);
  add('payment', ['payment_security_event']);
  add('admin_access', ['admin_access']);
  if (severity === 'CRITICAL') riskScore += 30;
  else if (severity === 'HIGH') riskScore += 20;
  else if (severity === 'MEDIUM') riskScore += 10;

  // Phase 2 velocity / sequence-lite signals (DB window counts)
  if (ctx.ip) {
    const spray = rules['password_spray'];
    if (spray?.enabled && type === 'login_failed' && (ctx as { userId?: string }).userId) {
      const { countEventsForUser } = await import('@/server/services/velocity');
      const n = await countEventsForUser({
        userId: (ctx as { userId: string }).userId,
        eventType: 'login_failed',
        windowMinutes: spray.config.windowMinutes ?? 60,
      });
      if (n + 1 >= (spray.config.threshold ?? 10)) {
        riskScore += spray.config.bonusScore ?? 20;
        matched.push('password_spray');
      }
    }
    const checkout = rules['checkout_abuse'];
    if (checkout?.enabled && type === 'payment_security_event') {
      const n = await countEventsInWindow({
        ip: ctx.ip,
        eventType: 'payment_security_event',
        windowMinutes: checkout.config.windowMinutes ?? 10,
      });
      if (n + 1 >= (checkout.config.threshold ?? 4)) {
        riskScore += checkout.config.bonusScore ?? 30;
        matched.push('checkout_abuse');
      }
    }
        const bf = rules['brute_force'];
    if (bf?.enabled && type === 'login_failed') {
      const n = await countEventsInWindow({
        ip: ctx.ip,
        eventType: 'login_failed',
        windowMinutes: bf.config.windowMinutes ?? 15,
      });
      // +1 for current event not yet inserted
      if (n + 1 >= (bf.config.threshold ?? 5)) {
        riskScore += bf.config.bonusScore ?? 25;
        matched.push('brute_force');
      }
    }
    const cs = rules['credential_stuffing'];
    if (cs?.enabled && type === 'login_failed') {
      const users = await countDistinctUsersLoginFailed({
        ip: ctx.ip,
        windowMinutes: cs.config.windowMinutes ?? 30,
      });
      if (users >= (cs.config.distinctUsers ?? 8)) {
        riskScore += cs.config.bonusScore ?? 35;
        matched.push('credential_stuffing');
      }
    }
    const wp = rules['wp_probe'];
    if (wp?.enabled && ctx.tenantId) {
      const hits =
        (await countLogPathHits({
          tenantId: ctx.tenantId,
          ip: ctx.ip,
          pathSubstring: 'wp-login',
          windowMinutes: wp.config.windowMinutes ?? 10,
        })) +
        (await countLogPathHits({
          tenantId: ctx.tenantId,
          ip: ctx.ip,
          pathSubstring: 'xmlrpc.php',
          windowMinutes: wp.config.windowMinutes ?? 10,
        }));
      if (hits >= (wp.config.threshold ?? 10)) {
        riskScore += wp.config.bonusScore ?? 30;
        matched.push('wp_probe');
      }
    }
    const entity = await bumpEntityScore({
      tenantId: ctx.tenantId,
      entityType: 'ip',
      entityKey: ctx.ip,
      delta: Math.min(15, Math.floor(riskScore / 10)),
    });
    if (entity >= 60 && !matched.includes('entity_ip_elevated')) {
      riskScore = Math.min(100, riskScore + 10);
      matched.push('entity_ip_elevated');
    }
  }

  riskScore = Math.min(100, riskScore);
  const riskLevel =
    riskScore >= 85 ? 'CRITICAL' : riskScore >= 60 ? 'HIGH' : riskScore >= 30 ? 'SUSPICIOUS' : 'NORMAL';
  const ab = rules['auto_block'];
  const autoBlockThreshold = ab?.enabled ? (ab.config.threshold ?? 70) : 999;
  const blockMinutes = ab?.config.blockMinutes ?? 60;
  const incidentThreshold = 35;
  let skipAutoBlock = false;
  if (ctx.ip) {
    skipAutoBlock = await isOnCooldown('auto_block', `ip:${ctx.ip}`);
  }
  return { riskScore, riskLevel, matched, autoBlockThreshold, blockMinutes, incidentThreshold, skipAutoBlock };
}

function isPrivateIp(ip: string): boolean {
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
  );
}

/**
 * Attach to any active incident for this IP (OPEN / INVESTIGATING / CONTAINED),
 * or create a new one. Never inserts a second row with the same open_key.
 */
async function attachOrCreateIncident(opts: {
  ip: string;
  eventType: string;
  userId?: string | null;
  riskScore: number;
  riskLevel: string;
  tenantId: string;
}): Promise<string> {
  const openKey = `ip:${opts.ip}`;
  const existing = await db.select().from(incidents).where(eq(incidents.openKey, openKey)).limit(1);
  if (existing[0]) {
    await db
      .update(incidents)
      .set({
        eventCount: existing[0].eventCount + 1,
        riskScore: Math.max(existing[0].riskScore, opts.riskScore),
        updatedAt: new Date(),
        // If somehow status drifted but openKey remains, keep counts current
      })
      .where(eq(incidents.id, existing[0].id));
    return existing[0].id;
  }

  const incidentId = newId();
  const publicNumber = Date.now() % 1_000_000_000;
  try {
    await db.insert(incidents).values({
      id: incidentId,
      tenantId: opts.tenantId,
      publicNumber,
      title: `${opts.eventType} from ${opts.ip}`,
      status: 'OPEN',
      severity: opts.riskLevel === 'CRITICAL' ? 'CRITICAL' : opts.riskLevel === 'HIGH' ? 'HIGH' : 'MEDIUM',
      sourceIp: opts.ip,
      userId: opts.userId || null,
      openKey,
      riskScore: opts.riskScore,
      eventCount: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    return incidentId;
  } catch (e) {
    // Race: another request created the same open_key — attach to it
    const raced = await db.select().from(incidents).where(eq(incidents.openKey, openKey)).limit(1);
    if (raced[0]) {
      await db
        .update(incidents)
        .set({
          eventCount: raced[0].eventCount + 1,
          riskScore: Math.max(raced[0].riskScore, opts.riskScore),
          updatedAt: new Date(),
        })
        .where(eq(incidents.id, raced[0].id));
      return raced[0].id;
    }
    throw e;
  }
}

export async function ingestEvent(apiKeyId: string, body: IngestBody, tenantId?: string | null) {
  if (!EVENT_TYPES.has(body.event_type)) {
    throw Object.assign(new Error('Invalid event_type'), { status: 400, code: 'invalid_event_type' });
  }

  if (body.event_id) {
    const existing = await db
      .select()
      .from(events)
      .where(and(eq(events.apiKeyId, apiKeyId), eq(events.externalId, body.event_id)))
      .limit(1);
    if (existing[0]) {
      return {
        id: existing[0].id,
        riskScore: existing[0].riskScore,
        riskLevel: existing[0].riskLevel,
        incidentId: existing[0].incidentId,
        duplicate: true,
      };
    }
  }

  const resolvedTenant = tenantId || (await ensureDefaultTenant());
  const { riskScore, riskLevel, matched, autoBlockThreshold, blockMinutes, incidentThreshold, skipAutoBlock } =
    await scoreEvent(body.event_type, body.severity, { ip: body.ip_address, tenantId: resolvedTenant, userId: body.user_id });
  const eventId = newId();
  const occurredAt = body.timestamp ? new Date(body.timestamp) : new Date();

  // Persist event first so incident/block failures cannot drop evidence

  await db.insert(events).values({
    id: eventId,
    tenantId: resolvedTenant,
    apiKeyId,
    externalId: body.event_id || null,
    eventType: body.event_type,
    severity: body.severity || 'INFO',
    ipAddress: body.ip_address || null,
    userId: body.user_id || null,
    sessionId: body.session_id || null,
    userAgent: body.user_agent || null,
    requestMethod: body.request_method || null,
    requestPath: body.request_path || null,
    requestId: body.request_id || null,
    metadata: scrubMetadata(body.metadata),
    riskScore,
    riskLevel,
    matchedRules: JSON.stringify(matched),
    incidentId: null,
    occurredAt,
    createdAt: new Date(),
  });

  let incidentId: string | null = null;

  if (riskScore >= incidentThreshold && body.ip_address) {
    try {
      incidentId = await attachOrCreateIncident({
        ip: body.ip_address,
        eventType: body.event_type,
        userId: body.user_id,
        riskScore,
        riskLevel,
        tenantId: resolvedTenant,
      });
      await db.update(events).set({ incidentId }).where(eq(events.id, eventId));
      void dispatchWebhook(resolvedTenant, 'incident.created', {
        incident_id: incidentId,
        ip: body.ip_address,
        event_type: body.event_type,
        risk_score: riskScore,
      });
    } catch (e) {
      console.error('incident attach failed; event retained', eventId, e);
    }

    if (!skipAutoBlock && riskScore >= autoBlockThreshold && body.ip_address && !isPrivateIp(body.ip_address)) {
      try {
        const allowed = await db
          .select()
          .from(allowlist)
          .where(eq(allowlist.ipAddress, body.ip_address))
          .limit(1);
        if (!allowed[0]) {
          const activeKey = `block:${body.ip_address}`;
          const existingBlock = await db
            .select()
            .from(ipBlocks)
            .where(and(eq(ipBlocks.activeKey, activeKey), eq(ipBlocks.active, true)))
            .limit(1);
          if (!existingBlock[0]) {
            const expires = new Date(Date.now() + blockMinutes * 60 * 1000);
            await db.insert(ipBlocks).values({
              id: newId(),
              tenantId: resolvedTenant,
              ipAddress: body.ip_address,
              action: 'BLOCK',
              reason: `Automatic: risk ${riskScore} (${matched.join(', ')})`,
              relatedIncidentId: incidentId,
              isPermanent: false,
              expiresAt: expires,
              active: true,
              automatic: true,
              activeKey,
              createdAt: new Date(),
            });
            void dispatchWebhook(resolvedTenant, 'block.created', {
              ip: body.ip_address,
              reason: `Automatic: risk ${riskScore}`,
              incident_id: incidentId,
            });
            const { setCooldown } = await import('@/server/services/velocity');
            const { getRuleRuntime: gr } = await import('@/server/services/rules');
            const rt = await gr();
            const cdMin = rt['cooldown']?.config?.blockCooldownMinutes ?? 30;
            await setCooldown({
              tenantId: resolvedTenant,
              ruleCode: 'auto_block',
              entityKey: `ip:${body.ip_address}`,
              minutes: cdMin,
            });
          }
        }
      } catch (e) {
        console.error('auto-block failed; event retained', eventId, e);
      }
    }
  }

  if (body.ip_address) {
    try {
      const existing = await db
        .select()
        .from(ipIntelligence)
        .where(eq(ipIntelligence.ipAddress, body.ip_address))
        .limit(1);
      const failed = body.event_type === 'login_failed' ? 1 : 0;
      if (existing[0]) {
        await db
          .update(ipIntelligence)
          .set({
            lastSeenAt: new Date(),
            eventCount: existing[0].eventCount + 1,
            failedLogins: existing[0].failedLogins + failed,
            riskScore: Math.max(existing[0].riskScore, riskScore),
            riskLevel,
          })
          .where(eq(ipIntelligence.ipAddress, body.ip_address));
      } else {
        await db.insert(ipIntelligence).values({
          id: newId(),
          ipAddress: body.ip_address,
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
          eventCount: 1,
          failedLogins: failed,
          riskScore,
          riskLevel,
        });
      }
    } catch (e) {
      console.error('ip intelligence upsert failed', e);
    }
  }

  return { id: eventId, riskScore, riskLevel, incidentId, duplicate: false };
}

export async function listActiveBlocks() {
  const now = new Date();
  const rows = await db.select().from(ipBlocks).where(eq(ipBlocks.active, true));
  return rows
    .filter((b) => b.isPermanent || !b.expiresAt || b.expiresAt > now)
    .map((b) => ({
      ipAddress: b.ipAddress,
      reason: b.reason,
      expiresAt: b.expiresAt?.toISOString() ?? null,
      permanent: b.isPermanent,
      automatic: b.automatic,
      createdAt: b.createdAt.toISOString(),
    }));
}
