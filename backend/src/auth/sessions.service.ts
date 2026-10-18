import { Injectable, NotFoundException } from '@nestjs/common';
import { ActorContext } from '../common/decorators/current-actor.decorator';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_ACTIONS } from '../common/constants';

export interface SessionView {
  id: string;
  device: string;
  ipAddress: string | null;
  createdAt: Date;
  lastUsedAt: Date | null;
  expiresAt: Date;
  /** True for the session the request itself belongs to. */
  current: boolean;
}

/** Sign-ins (sessions) of an account: list them, end one, end all. */
@Injectable()
export class SessionsService {
  constructor(private readonly prisma: PrismaService, private readonly audit: AuditService) {}

  /**
   * Active sessions, most recently used first. A refresh token is replaced on every use, so each session
   * has one live token; the sessionId is what stays the same.
   */
  async list(userId: string, currentSessionId?: string): Promise<SessionView[]> {
    const rows: any[] = await this.prisma.securityRefreshToken.findMany({
      where: { userId, revokedAt: null, expiresAt: { gt: new Date() } },
      orderBy: { lastUsedAt: 'desc' },
      take: 200,
    });
    const seen = new Set<string>();
    const out: SessionView[] = [];
    for (const r of rows) {
      if (seen.has(r.sessionId)) continue;
      seen.add(r.sessionId);
      out.push({
        id: r.sessionId, device: r.deviceLabel ?? 'Unknown device', ipAddress: r.ipAddress ?? null,
        createdAt: r.sessionStartedAt, lastUsedAt: r.lastUsedAt ?? null, expiresAt: r.expiresAt,
        current: !!currentSessionId && r.sessionId === currentSessionId,
      });
    }
    return out;
  }

  /**
   * Ends one session. Its refresh token stops working at once. Its current access token (at most 15
   * minutes old) keeps working until it expires: checking the session on every request would cost a second
   * database lookup per request. "Sign out everywhere" has no such delay.
   */
  async revoke(userId: string, sessionId: string, actor: ActorContext, targetEmail?: string) {
    if (!sessionId || sessionId.length > 100) throw new NotFoundException('Session not found');
    const r = await this.prisma.securityRefreshToken.updateMany({
      where: { userId, sessionId, revokedAt: null },
      data: { revokedAt: new Date(), revokedReason: 'session_revoked' },
    });
    if (!r.count) throw new NotFoundException('Session not found');
    await this.audit.log({
      requestId: actor.requestId, actorType: 'USER', actorId: actor.id, actorLabel: actor.label,
      action: AUDIT_ACTIONS.SESSION_REVOKE, targetType: 'user', targetId: userId, result: 'SUCCESS',
      ipAddress: actor.ip, userAgent: actor.userAgent,
      metadata: { sessionId, byOwner: actor.id === userId, ...(targetEmail ? { email: targetEmail } : {}) },
    });
    return { ok: true };
  }

  /**
   * Signs the account out everywhere, this device included. Raising the token version also ends every
   * access token at once.
   */
  async revokeAll(userId: string, actor: ActorContext, targetEmail?: string) {
    const [, tokens] = await this.prisma.$transaction([
      this.prisma.securityUser.update({ where: { id: userId }, data: { tokenVersion: { increment: 1 } } }),
      this.prisma.securityRefreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date(), revokedReason: 'revoked_all' } }),
    ]);
    await this.audit.log({
      requestId: actor.requestId, actorType: 'USER', actorId: actor.id, actorLabel: actor.label,
      action: AUDIT_ACTIONS.SESSIONS_REVOKE_ALL, targetType: 'user', targetId: userId, result: 'SUCCESS',
      ipAddress: actor.ip, userAgent: actor.userAgent,
      metadata: { sessionsEnded: (tokens as any)?.count ?? 0, byOwner: actor.id === userId, ...(targetEmail ? { email: targetEmail } : {}) },
    });
    return { ok: true, sessionsEnded: (tokens as any)?.count ?? 0 };
  }

  async userEmail(userId: string): Promise<string> {
    const u = await this.prisma.securityUser.findUnique({ where: { id: userId }, select: { email: true } });
    if (!u) throw new NotFoundException('User not found');
    return u.email;
  }
}
