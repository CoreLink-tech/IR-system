import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { ActorContext } from '../common/decorators/current-actor.decorator';
import { AUDIT_ACTIONS, ROLES } from '../common/constants';
import { assertStrongPassword } from './password-policy';
import { LoginThrottleService } from './login-throttle.service';
import { loginKey } from './login-throttle';

const USER_FIELDS = {
  id: true, email: true, name: true, role: true, isActive: true,
  mustChangePassword: true, lastLoginAt: true, createdAt: true,
  // Only whether two-step verification is on is read; the secret itself is never selected.
  totpEnabledAt: true,
} as const;

/** Administration of dashboard accounts. Every route that reaches this is super admin only. */
@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService, private readonly audit: AuditService, private readonly throttle: LoginThrottleService) {}

  /** All accounts, each with lockedUntil (null unless sign-in is locked after too many wrong attempts). */
  async list() {
    const rows: any[] = await this.prisma.securityUser.findMany({ select: USER_FIELDS, orderBy: { createdAt: 'asc' } });
    const locked = await this.throttle.lockedUntil(rows.map((r) => loginKey(r.email)));
    return rows.map(({ totpEnabledAt, ...r }) => ({ ...r, twoFactorEnabled: !!totpEnabledAt, lockedUntil: locked.get(loginKey(r.email)) ?? null }));
  }

  /**
   * Lets an account sign in again right away after a lockout. The lock expires by itself anyway; this is for
   * the person who is waiting. The wrong attempts are forgotten, so the next five are free again. Audited.
   */
  async unlock(id: string, actor: ActorContext) {
    const target = await this.prisma.securityUser.findUnique({ where: { id }, select: { id: true, email: true } });
    if (!target) throw new NotFoundException('User not found');
    await this.throttle.reset(loginKey(target.email));
    await this.audit.log({
      requestId: actor.requestId, actorType: 'USER', actorId: actor.id, actorLabel: actor.label,
      action: AUDIT_ACTIONS.UNLOCK, targetType: 'user', targetId: id, result: 'SUCCESS',
      ipAddress: actor.ip, userAgent: actor.userAgent, metadata: { email: target.email },
    });
    return { ok: true };
  }

  /** The minimum needed to choose who an incident is assigned to. Active accounts only. */
  assignable() {
    return this.prisma.securityUser.findMany({
      where: { isActive: true },
      select: { id: true, email: true, name: true, role: true },
      orderBy: { email: 'asc' },
    });
  }

  /**
   * Changes a role or switches an account on or off. Two safeguards, both enforced here and
   * not only in the dashboard: nobody changes their own role or status, and the last active
   * super admin can never be demoted or deactivated. The check and the change run in one
   * serializable transaction, so two super admins demoting each other at the same moment
   * cannot both succeed and leave the system without one.
   */
  async update(id: string, dto: { role?: string; isActive?: boolean }, actor: ActorContext) {
    if (dto.role === undefined && dto.isActive === undefined) throw new BadRequestException('Nothing to change');
    if (dto.role !== undefined && !Object.values(ROLES).includes(dto.role as any)) throw new BadRequestException('Invalid role');

    let before: any;
    let updated: any;
    try {
      ({ before, updated } = await this.prisma.$transaction(async (tx: any) => {
        const found = await tx.securityUser.findUnique({ where: { id } });
        if (!found) throw new NotFoundException('User not found');
        const target = { ...found }; // a snapshot, so the old values survive the update below
        const role = dto.role ?? target.role;
        const isActive = dto.isActive ?? target.isActive;
        if (role === target.role && isActive === target.isActive) return { before: target, updated: target };

        if (actor.id === id) {
          throw new BadRequestException({ message: 'You cannot change your own role or deactivate your own account', code: 'self_change_forbidden' });
        }
        const losesSuperAdmin = target.role === ROLES.SUPER_ADMIN && target.isActive && (role !== ROLES.SUPER_ADMIN || !isActive);
        if (losesSuperAdmin) {
          const others = await tx.securityUser.count({ where: { role: ROLES.SUPER_ADMIN, isActive: true, id: { not: id } } });
          if (others === 0) {
            throw new ConflictException({ message: 'This is the last active super admin. Make another account a super admin first.', code: 'last_super_admin' });
          }
        }
        const next = await tx.securityUser.update({ where: { id }, data: { role, isActive } });
        // A switched-off account must not keep working through a refresh token it already holds.
        if (!isActive && target.isActive) {
          await tx.securityRefreshToken.updateMany({ where: { userId: id, revokedAt: null }, data: { revokedAt: new Date(), revokedReason: 'user_disabled' } });
          await tx.securityUser.update({ where: { id }, data: { tokenVersion: { increment: 1 } } });
        }
        return { before: target, updated: next };
      }, { isolationLevel: 'Serializable' }));
    } catch (err: any) {
      if (err?.code === 'P2034') throw new ConflictException('Another change was in progress. Please try again.');
      await this.audit.log({
        requestId: actor.requestId, actorType: 'USER', actorId: actor.id, actorLabel: actor.label,
        action: AUDIT_ACTIONS.USER_UPDATE, targetType: 'user', targetId: id, result: 'FAILURE',
        ipAddress: actor.ip, userAgent: actor.userAgent,
        metadata: { requested: dto, reason: err?.response?.code ?? err?.message },
      });
      throw err;
    }

    if (before.role !== updated.role || before.isActive !== updated.isActive) {
      await this.audit.log({
        requestId: actor.requestId, actorType: 'USER', actorId: actor.id, actorLabel: actor.label,
        action: AUDIT_ACTIONS.USER_UPDATE, targetType: 'user', targetId: id, result: 'SUCCESS',
        ipAddress: actor.ip, userAgent: actor.userAgent,
        metadata: {
          email: updated.email,
          old: { role: before.role, isActive: before.isActive },
          new: { role: updated.role, isActive: updated.isActive },
        },
      });
    }
    return this.pick(updated);
  }

  /**
   * Sets a temporary password for another account and ends all of its sessions. The person
   * must choose their own password at next sign-in (the server refuses everything else until
   * then). Returns nothing sensitive. A super admin cannot reset their own password this way,
   * because that would skip the current-password check.
   */
  async resetPassword(id: string, newPassword: string, actor: ActorContext) {
    if (actor.id === id) {
      throw new BadRequestException({ message: 'Use change password for your own account', code: 'self_reset_forbidden' });
    }
    const target = await this.prisma.securityUser.findUnique({ where: { id } });
    if (!target) throw new NotFoundException('User not found');
    assertStrongPassword(newPassword, { email: target.email, name: target.name });
    await this.throttle.reset(loginKey(target.email));   // so the person can sign in with the temporary password
    await this.prisma.securityUser.update({
      where: { id },
      data: { passwordHash: await bcrypt.hash(newPassword, 12), mustChangePassword: true, passwordChangedAt: new Date(), tokenVersion: { increment: 1 } },
    });
    const revoked = await this.prisma.securityRefreshToken.updateMany({ where: { userId: id, revokedAt: null }, data: { revokedAt: new Date(), revokedReason: 'admin_reset' } });
    await this.audit.log({
      requestId: actor.requestId, actorType: 'USER', actorId: actor.id, actorLabel: actor.label,
      action: AUDIT_ACTIONS.USER_PASSWORD_RESET, targetType: 'user', targetId: id, result: 'SUCCESS',
      ipAddress: actor.ip, userAgent: actor.userAgent,
      metadata: { email: target.email, sessionsEnded: revoked?.count ?? 0 },
    });
    return { ok: true };
  }

  private pick(u: any) {
    return {
      id: u.id, email: u.email, name: u.name, role: u.role, isActive: u.isActive,
      mustChangePassword: !!u.mustChangePassword, lastLoginAt: u.lastLoginAt ?? null, createdAt: u.createdAt,
    };
  }
}
