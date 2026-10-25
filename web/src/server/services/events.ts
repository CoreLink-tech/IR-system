import { and, eq, isNull } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { apiKeys, events, incidents, ipBlocks, allowlist, ipIntelligence } from '@/server/db/schema';
import { hashApiKey, newId, safeEqual } from '@/server/auth/crypto';
import { getEnv } from '@/lib/env';

const EVENT_TYPES = new Set([
  'login_failed', 'login_success', 'password_reset', 'account_change', 'admin_access',
  'suspicious_request', 'rate_limit_exceeded', 'payment_security_event',
  'application_error', 'server_error', 'logout', 'session_anomaly',
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
  event_id?: string; // client idempotency key → externalId
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

async function scoreEvent(type: string, severity?: string): Promise<{ riskScore: number; riskLevel: string; matched: string[]; autoBlockThreshold: number; blockMinutes: number }> {
  const { getRuleRuntime } = await import('@/server/services/rules');
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
  riskScore = Math.min(100, riskScore);
  const riskLevel =
    riskScore >= 85 ? 'CRITICAL' : riskScore >= 60 ? 'HIGH' : riskScore >= 30 ? 'SUSPICIOUS' : 'NORMAL';
  const ab = rules['auto_block'];
  const autoBlockThreshold = ab?.enabled ? (ab.config.threshold ?? 85) : 999;
  const blockMinutes = ab?.config.blockMinutes ?? 60;
  return { riskScore, riskLevel, matched, autoBlockThreshold, blockMinutes };
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

export async function ingestEvent(apiKeyId: string, body: IngestBody) {
  if (!EVENT_TYPES.has(body.event_type)) {
    throw Object.assign(new Error('Invalid event_type'), { status: 400, code: 'invalid_event_type' });
  }

  // Idempotency: same apiKey + externalId → return existing
  if (body.event_id) {
    const existing = await db.select().from(events)
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

  const { riskScore, riskLevel, matched, autoBlockThreshold, blockMinutes } = await scoreEvent(body.event_type, body.severity);
  const eventId = newId();
  const occurredAt = body.timestamp ? new Date(body.timestamp) : new Date();

  let incidentId: string | null = null;

  // Open or attach incident for elevated risk
  if (riskScore >= 40 && body.ip_address) {
    const openKey = `ip:${body.ip_address}`;
    const open = await db.select().from(incidents)
      .where(and(eq(incidents.openKey, openKey), eq(incidents.status, 'OPEN')))
      .limit(1);
    if (open[0]) {
      incidentId = open[0].id;
      await db.update(incidents).set({
        eventCount: open[0].eventCount + 1,
        riskScore: Math.max(open[0].riskScore, riskScore),
        updatedAt: new Date(),
      }).where(eq(incidents.id, open[0].id));
    } else {
      const publicNumber = Date.now() % 1_000_000_000;
      incidentId = newId();
      await db.insert(incidents).values({
        id: incidentId,
        publicNumber,
        title: `${body.event_type} from ${body.ip_address}`,
        status: 'OPEN',
        severity: riskLevel === 'CRITICAL' ? 'CRITICAL' : riskLevel === 'HIGH' ? 'HIGH' : 'MEDIUM',
        sourceIp: body.ip_address,
        userId: body.user_id || null,
        openKey,
        riskScore,
        eventCount: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    }

    // Auto-block high risk (never private / allowlisted)
    if (riskScore >= autoBlockThreshold && body.ip_address && !isPrivateIp(body.ip_address)) {
      const allowed = await db.select().from(allowlist).where(eq(allowlist.ipAddress, body.ip_address)).limit(1);
      if (!allowed[0]) {
        const activeKey = `block:${body.ip_address}`;
        const existingBlock = await db.select().from(ipBlocks)
          .where(and(eq(ipBlocks.activeKey, activeKey), eq(ipBlocks.active, true)))
          .limit(1);
        if (!existingBlock[0]) {
          const expires = new Date(Date.now() + blockMinutes * 60 * 1000);
          await db.insert(ipBlocks).values({
            id: newId(),
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
        }
      }
    }
  }

  await db.insert(events).values({
    id: eventId,
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
    incidentId,
    occurredAt,
    createdAt: new Date(),
  });


  // Upsert lightweight IP intelligence
  if (body.ip_address) {
    const existing = await db.select().from(ipIntelligence).where(eq(ipIntelligence.ipAddress, body.ip_address)).limit(1);
    const failed = body.event_type === 'login_failed' ? 1 : 0;
    if (existing[0]) {
      await db.update(ipIntelligence).set({
        lastSeenAt: new Date(),
        eventCount: existing[0].eventCount + 1,
        failedLogins: existing[0].failedLogins + failed,
        riskScore: Math.max(existing[0].riskScore, riskScore),
        riskLevel: riskLevel,
      }).where(eq(ipIntelligence.ipAddress, body.ip_address));
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
