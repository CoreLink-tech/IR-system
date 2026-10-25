import { db } from '@/server/db/client';
import { auditLog } from '@/server/db/schema';
import { newId } from '@/server/auth/crypto';

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
}) {
  await db.insert(auditLog).values({
    id: newId(),
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
    createdAt: new Date(),
  });
}
