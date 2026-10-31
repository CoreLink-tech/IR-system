import { createHash } from 'crypto';
import { desc } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { auditLog } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';

function hashPayload(prevHash: string, body: Record<string, unknown>): string {
  const canonical = JSON.stringify(body);
  return createHash('sha256').update(`${prevHash}|${canonical}`).digest('hex');
}

export async function writeAudit(entry: {
  requestId?: string;
  actorType: 'USER' | 'API_KEY' | 'SYSTEM';
  actorId?: string | null;
  actorLabel?: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  result?: string;
  metadata?: Record<string, unknown> | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  tenantId?: string | null;
}) {
  const id = newId();
  const createdAt = new Date();

  const body = {
    id,
    actorType: entry.actorType,
    actorId: entry.actorId || null,
    action: entry.action,
    targetType: entry.targetType || null,
    targetId: entry.targetId || null,
    result: entry.result || 'SUCCESS',
    createdAt: createdAt.toISOString(),
  };

  try {
    await db.transaction(async (tx) => {
      let prevHash = 'GENESIS';
      const last = await tx.select().from(auditLog).orderBy(desc(auditLog.createdAt)).limit(1);
      if (last[0]?.entryHash) prevHash = last[0].entryHash;
      const entryHash = hashPayload(prevHash, body);
      await tx.insert(auditLog).values({
        id,
        prevHash,
        entryHash,
        requestId: entry.requestId || null,
        actorType: entry.actorType,
        actorId: entry.actorId || null,
        actorLabel: entry.actorLabel || null,
        action: entry.action,
        targetType: entry.targetType || null,
        targetId: entry.targetId || null,
        result: entry.result || 'SUCCESS',
        metadata: entry.metadata ? JSON.stringify(entry.metadata) : null,
        ipAddress: entry.ipAddress || null,
        userAgent: entry.userAgent || null,
        tenantId: entry.tenantId || null,
        createdAt,
      });
    });
  } catch {
    // Fallback without hash columns / transaction support
    await db.insert(auditLog).values({
      id,
      requestId: entry.requestId || null,
      actorType: entry.actorType,
      actorId: entry.actorId || null,
      actorLabel: entry.actorLabel || null,
      action: entry.action,
      targetType: entry.targetType || null,
      targetId: entry.targetId || null,
      result: entry.result || 'SUCCESS',
      metadata: entry.metadata ? JSON.stringify(entry.metadata) : null,
      ipAddress: entry.ipAddress || null,
      userAgent: entry.userAgent || null,
      createdAt,
    });
  }
}

export async function verifyAuditChain(limit = 500): Promise<{
  ok: boolean;
  checked: number;
  brokenAt: string | null;
}> {
  const rows = await db.select().from(auditLog).orderBy(desc(auditLog.createdAt)).limit(limit);
  const chronological = [...rows].reverse();
  let prev = 'GENESIS';
  let checked = 0;
  for (const row of chronological) {
    if (!row.entryHash) continue;
    const body = {
      id: row.id,
      actorType: row.actorType,
      actorId: row.actorId || null,
      action: row.action,
      targetType: row.targetType || null,
      targetId: row.targetId || null,
      result: row.result || 'SUCCESS',
      createdAt: row.createdAt.toISOString(),
    };
    const expectedPrev = row.prevHash || 'GENESIS';
    if (checked > 0 && expectedPrev !== prev) {
      return { ok: false, checked, brokenAt: row.id };
    }
    const expected = hashPayload(expectedPrev, body);
    if (expected !== row.entryHash) {
      return { ok: false, checked, brokenAt: row.id };
    }
    prev = row.entryHash;
    checked += 1;
  }
  return { ok: true, checked, brokenAt: null };
}
