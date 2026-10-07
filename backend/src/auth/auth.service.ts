import { BadRequestException, ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { ActorContext } from '../common/decorators/current-actor.decorator';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { createHash, randomBytes } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_ACTIONS, ROLES } from '../common/constants';

/** Where a request came from, recorded in the audit log. */
type Ctx = { ip?: string; userAgent?: string; requestId?: string };

/**
 * A real bcrypt hash of a random value. When an email is unknown or the account
 * is disabled, the password is still compared against this so the response takes
 * as long as a real login. Without it, response time reveals which emails exist.
 */
const DUMMY_HASH = bcrypt.hashSync(randomBytes(16).toString('hex'), 12);

/** How long a refresh token (and the browser cookie that carries it) stays valid. */
export const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly audit: AuditService,
  ) {}

  private hashRefresh(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  async login(email: string, password: string, ctx: { ip?: string; userAgent?: string; requestId?: string }) {
    const user = await this.prisma.securityUser.findUnique({ where: { email: email.toLowerCase() } });
    if (!user || !user.isActive) {
      await bcrypt.compare(password, DUMMY_HASH);
      await this.audit.log({
        requestId: ctx.requestId, actorType: 'ANONYMOUS', actorLabel: email,
        action: AUDIT_ACTIONS.LOGIN, result: 'FAILURE', ipAddress: ctx.ip, userAgent: ctx.userAgent,
      });
      throw new UnauthorizedException('Invalid credentials');
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      await this.audit.log({
        requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email,
        action: AUDIT_ACTIONS.LOGIN, result: 'FAILURE', ipAddress: ctx.ip, userAgent: ctx.userAgent,
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    const tokens = await this.issueTokens(user, ctx);
    await this.prisma.securityUser.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email,
      action: AUDIT_ACTIONS.LOGIN, result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent,
    });
    return { user: this.publicUser(user), ...tokens };
  }

  private async issueTokens(user: any, ctx: { ip?: string; userAgent?: string }) {
    const accessToken = await this.jwt.signAsync(
      { sub: user.id, email: user.email, role: user.role, type: 'access' },
      { secret: process.env.JWT_SECRET, expiresIn: process.env.JWT_EXPIRES_IN || '15m' },
    );
    const refreshRaw = randomBytes(48).toString('base64url');
    const refreshToken = await this.jwt.signAsync(
      { sub: user.id, nonce: refreshRaw, type: 'refresh' },
      { secret: process.env.JWT_REFRESH_SECRET, expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' },
    );
    const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);
    await this.prisma.securityRefreshToken.create({
      data: {
        userId: user.id, tokenHash: this.hashRefresh(refreshToken), expiresAt,
        ipAddress: ctx.ip, userAgent: ctx.userAgent,
      },
    });
    return { accessToken, refreshToken };
  }

  async refresh(refreshToken: string, ctx: { ip?: string; userAgent?: string; requestId?: string }) {
    let payload: any;
    try {
      payload = await this.jwt.verifyAsync(refreshToken, { secret: process.env.JWT_REFRESH_SECRET });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
    if (payload.type !== 'refresh') throw new UnauthorizedException('Invalid token type');
    const hash = this.hashRefresh(refreshToken);
    const stored = await this.prisma.securityRefreshToken.findUnique({ where: { tokenHash: hash } });
    if (stored && stored.revokedAt) {
      // A token that was already used is being presented again. Either the owner or a
      // thief holds a copy, and there is no way to tell which, so end every session.
      await this.prisma.securityRefreshToken.updateMany({
        where: { userId: stored.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await this.audit.log({
        requestId: ctx.requestId, actorType: 'USER', actorId: stored.userId,
        action: AUDIT_ACTIONS.REFRESH, result: 'FAILURE', ipAddress: ctx.ip, userAgent: ctx.userAgent,
        metadata: { reason: 'refresh_token_reuse', sessionsRevoked: true },
      });
      // The code lets the dashboard tell the owner plainly that every session was ended.
      throw new UnauthorizedException({ message: 'Refresh token expired or revoked', code: 'refresh_token_reuse' });
    }
    if (!stored || stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token expired or revoked');
    }
    const user = await this.prisma.securityUser.findUnique({ where: { id: payload.sub } });
    if (!user || !user.isActive) throw new UnauthorizedException('User inactive');

    await this.prisma.securityRefreshToken.update({ where: { id: stored.id }, data: { revokedAt: new Date() } });
    const tokens = await this.issueTokens(user, ctx);
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email,
      action: AUDIT_ACTIONS.REFRESH, result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent,
    });
    return { user: this.publicUser(user), ...tokens };
  }

  /** Throws 401 unless the value is a correctly signed, unexpired refresh token. */
  async verifyRefreshJwt(refreshToken: string): Promise<void> {
    try {
      const payload: any = await this.jwt.verifyAsync(refreshToken, { secret: process.env.JWT_REFRESH_SECRET });
      if (payload.type !== 'refresh') throw new Error('type');
    } catch {
      throw new UnauthorizedException({ message: 'Invalid refresh token', code: 'no_session' });
    }
  }

  async me(userId: string) {
    const user = await this.prisma.securityUser.findUnique({ where: { id: userId } });
    if (!user || !user.isActive) throw new UnauthorizedException();
    return this.publicUser(user);
  }

  async logout(refreshToken: string) {
    if (!refreshToken) return;
    const hash = this.hashRefresh(refreshToken);
    await this.prisma.securityRefreshToken.updateMany({
      where: { tokenHash: hash, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  async createUser(
    dto: { email: string; password: string; name?: string; role: string; requirePasswordChange?: boolean },
    actor?: ActorContext,
  ) {
    if (!Object.values(ROLES).includes(dto.role as any)) throw new BadRequestException('Invalid role');
    const email = dto.email.toLowerCase();
    const exists = await this.prisma.securityUser.findUnique({ where: { email } });
    if (exists) throw new ConflictException('Email already exists');
    const passwordHash = await bcrypt.hash(dto.password, 12);
    const user = await this.prisma.securityUser.create({
      data: {
        email, passwordHash, name: dto.name ?? null, role: dto.role,
        ...(dto.requirePasswordChange ? { mustChangePassword: true } : {}),
      },
    });
    // Creating an account is one of the most sensitive things an administrator can do.
    await this.audit.log({
      requestId: actor?.requestId, actorType: actor ? 'USER' : 'SYSTEM', actorId: actor?.id,
      actorLabel: actor?.label, action: AUDIT_ACTIONS.USER_CREATE, targetType: 'user', targetId: user.id,
      result: 'SUCCESS', ipAddress: actor?.ip, userAgent: actor?.userAgent,
      metadata: { email, role: dto.role, requirePasswordChange: !!dto.requirePasswordChange },
    });
    return this.publicUser(user);
  }

  /**
   * Changes the signed-in user's own password. The current password must be right,
   * the new one must differ, and every refresh token is revoked so other devices
   * must sign in again. Both outcomes are audited.
   */
  async changePassword(userId: string, currentPassword: string, newPassword: string, ctx: Ctx) {
    const user = await this.prisma.securityUser.findUnique({ where: { id: userId } });
    if (!user || !user.isActive) throw new UnauthorizedException();
    const fail = async (reason: string) => {
      await this.audit.log({
        requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email,
        action: AUDIT_ACTIONS.PASSWORD_CHANGE, result: 'FAILURE', ipAddress: ctx.ip, userAgent: ctx.userAgent,
        metadata: { reason },
      });
    };
    if (!(await bcrypt.compare(currentPassword, user.passwordHash))) {
      await fail('wrong_current_password');
      throw new UnauthorizedException('Current password invalid');
    }
    if (currentPassword === newPassword) {
      await fail('same_password');
      throw new BadRequestException('New password must be different from the current one');
    }
    await this.prisma.securityUser.update({ where: { id: user.id }, data: { passwordHash: await bcrypt.hash(newPassword, 12), mustChangePassword: false } });
    await this.prisma.securityRefreshToken.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date() } });
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email,
      action: AUDIT_ACTIONS.PASSWORD_CHANGE, result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent,
    });
    return { ok: true };
  }

  private publicUser(user: any) {
    return { id: user.id, email: user.email, name: user.name, role: user.role, isActive: user.isActive, mustChangePassword: !!user.mustChangePassword };
  }
}
