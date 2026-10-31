import { and, eq } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { decisions, ipBlocks, allowlist } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';
import { ensureDefaultTenant } from '@/server/services/tenancy';

export type DecideInput = {
  ip_address?: string;
  user_id?: string;
  session_id?: string;
  user_agent?: string;
  action?: string; // browse | login | checkout | admin | password_reset | custom
  event_type?: string;
  severity?: string;
  idempotency_key?: string;
  metadata?: Record<string, unknown>;
};

export type DecideOutcome = 'allow' | 'review' | 'challenge' | 'block';

export type DecideResult = {
  decision_id: string;
  outcome: DecideOutcome;
  score: number;
  reasons: string[];
  rule_hits: string[];
  ttl_seconds: number;
  duplicate?: boolean;
};

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
 * Real-time decision for storefront middleware / PHP agent.
 * Fail-open guidance is client-side; this endpoint always returns a decision when authenticated.
 */
export async function makeDecision(
  apiKeyId: string,
  tenantId: string | null | undefined,
  body: DecideInput,
): Promise<DecideResult> {
  const resolvedTenant = tenantId || (await ensureDefaultTenant());

  if (body.idempotency_key) {
    const existing = await db
      .select()
      .from(decisions)
      .where(and(eq(decisions.apiKeyId, apiKeyId), eq(decisions.idempotencyKey, body.idempotency_key)))
      .limit(1);
    if (existing[0]) {
      return {
        decision_id: existing[0].id,
        outcome: existing[0].outcome as DecideOutcome,
        score: existing[0].score,
        reasons: JSON.parse(existing[0].reasons || '[]') as string[],
        rule_hits: JSON.parse(existing[0].ruleHits || '[]') as string[],
        ttl_seconds: existing[0].ttlSeconds,
        duplicate: true,
      };
    }
  }

  const reasons: string[] = [];
  const ruleHits: string[] = [];
  let score = 0;
  let outcome: DecideOutcome = 'allow';
  let ttl = 60;

  const ip = body.ip_address?.trim();
  const action = (body.action || body.event_type || 'browse').toLowerCase();

  // 1) Explicit allowlist wins
  if (ip) {
    const allowed = await db.select().from(allowlist).where(eq(allowlist.ipAddress, ip)).limit(1);
    if (allowed[0]) {
      reasons.push('allowlisted');
      outcome = 'allow';
      score = 0;
      ttl = 300;
      return persist(apiKeyId, resolvedTenant, body, outcome, score, reasons, ruleHits, ttl);
    }
  }

  // 2) Active block
  if (ip && !isPrivateIp(ip)) {
    const now = new Date();
    const blocks = await db
      .select()
      .from(ipBlocks)
      .where(and(eq(ipBlocks.ipAddress, ip), eq(ipBlocks.active, true)))
      .limit(5);
    const active = blocks.find((b) => b.isPermanent || !b.expiresAt || b.expiresAt > now);
    if (active) {
      reasons.push('active_block');
      ruleHits.push('blocklist');
      outcome = 'block';
      score = 100;
      ttl = 30;
      return persist(apiKeyId, resolvedTenant, body, outcome, score, reasons, ruleHits, ttl);
    }
  }

  // 3) Score via detection engine (synthetic event types from action)
  const eventType =
    body.event_type ||
    ({
      login: 'login_failed',
      admin: 'admin_access',
      checkout: 'payment_security_event',
      password_reset: 'password_reset',
      browse: 'suspicious_request',
    }[action] as string) ||
    'suspicious_request';

  // For decide on browse we should NOT use full suspicious_request base if action is browse only
  // Use a lighter path: call score with event types mapped carefully
  const typeForScore =
    action === 'browse'
      ? 'logout' // neutral-ish; won't match high base rules
      : action === 'login'
        ? 'login_failed'
        : action === 'admin'
          ? 'admin_access'
          : action === 'checkout'
            ? 'payment_security_event'
            : action === 'password_reset'
              ? 'password_reset'
              : eventType;

  // Import scoring internals by running a dry score via events module pattern
  // Use velocity + rules without inserting an event — call shared scorer exported below
  const { scoreForDecision } = await import('@/server/services/events');
  const scored = await scoreForDecision(typeForScore, body.severity, {
    ip,
    tenantId: resolvedTenant,
    userId: body.user_id,
    sessionId: body.session_id,
    userAgent: body.user_agent,
  });

  score = scored.riskScore;
  ruleHits.push(...scored.matched);
  if (scored.matched.length) reasons.push(`rules:${scored.matched.join(',')}`);

  // Map score + action to outcome
  if (score >= scored.autoBlockThreshold) {
    outcome = 'block';
    reasons.push('score_above_block_threshold');
    ttl = 30;
  } else if (score >= 70 || (action === 'admin' && score >= 50)) {
    outcome = action === 'browse' ? 'review' : 'challenge';
    reasons.push(action === 'browse' ? 'elevated_risk_review' : 'elevated_risk_challenge');
    ttl = 45;
  } else if (score >= 40) {
    outcome = action === 'admin' || action === 'checkout' ? 'challenge' : 'review';
    reasons.push('moderate_risk');
    ttl = 60;
  } else {
    outcome = 'allow';
    reasons.push('below_threshold');
    ttl = 120;
  }

  // Stricter for admin
  if (action === 'admin' && outcome === 'allow' && score >= 25) {
    outcome = 'challenge';
    reasons.push('admin_hardening');
    ttl = 45;
  }

  return persist(apiKeyId, resolvedTenant, body, outcome, score, reasons, ruleHits, ttl);
}

async function persist(
  apiKeyId: string,
  tenantId: string,
  body: DecideInput,
  outcome: DecideOutcome,
  score: number,
  reasons: string[],
  ruleHits: string[],
  ttl: number,
): Promise<DecideResult> {
  const id = newId();
  try {
    await db.insert(decisions).values({
      id,
      tenantId,
      apiKeyId,
      idempotencyKey: body.idempotency_key || null,
      outcome,
      score,
      reasons: JSON.stringify(reasons),
      ruleHits: JSON.stringify(ruleHits),
      ipAddress: body.ip_address || null,
      userId: body.user_id || null,
      sessionId: body.session_id || null,
      actionContext: body.action || body.event_type || null,
      ttlSeconds: ttl,
      createdAt: new Date(),
    });
  } catch {
    // unique idempotency race
    if (body.idempotency_key) {
      const existing = await db
        .select()
        .from(decisions)
        .where(and(eq(decisions.apiKeyId, apiKeyId), eq(decisions.idempotencyKey, body.idempotency_key)))
        .limit(1);
      if (existing[0]) {
        return {
          decision_id: existing[0].id,
          outcome: existing[0].outcome as DecideOutcome,
          score: existing[0].score,
          reasons: JSON.parse(existing[0].reasons || '[]') as string[],
          rule_hits: JSON.parse(existing[0].ruleHits || '[]') as string[],
          ttl_seconds: existing[0].ttlSeconds,
          duplicate: true,
        };
      }
    }
    throw new Error('failed to persist decision');
  }

  // Optional: fire webhook
  try {
    const { dispatchWebhook } = await import('@/server/services/webhooks');
    if (outcome === 'block' || outcome === 'challenge') {
      void dispatchWebhook(tenantId, 'decision.made', {
        decision_id: id,
        outcome,
        score,
        ip: body.ip_address,
      });
    }
  } catch {
    /* ignore */
  }

  return {
    decision_id: id,
    outcome,
    score,
    reasons,
    rule_hits: ruleHits,
    ttl_seconds: ttl,
  };
}

export async function recordDecisionOutcome(
  decisionId: string,
  feedback: 'confirmed_fraud' | 'false_positive' | 'chargeback' | 'legitimate',
) {
  const rows = await db.select().from(decisions).where(eq(decisions.id, decisionId)).limit(1);
  if (!rows[0]) throw Object.assign(new Error('Not found'), { status: 404, code: 'not_found' });
  await db.update(decisions).set({ feedback }).where(eq(decisions.id, decisionId));
  return { ok: true, decision_id: decisionId, feedback };
}
