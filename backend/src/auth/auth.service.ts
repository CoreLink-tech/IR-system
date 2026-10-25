import { BadRequestException, ConflictException, HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { ActorContext } from '../common/decorators/current-actor.decorator';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { createHash, randomBytes, randomUUID } from 'crypto';
import { deviceLabel } from './device-label';
import { assertStrongPassword, checkPassword } from './password-policy';
import { LoginThrottleService } from './login-throttle.service';
import { CHALLENGE_SECONDS, TwoFactorService } from './two-factor.service';
import { Decision, isExempt, loginKey, waitText } from './login-throttle';
export { waitText };
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { AUDIT_ACTIONS, ROLES } from '../common/constants';
import { loadAccessKeyRing, loadRefreshKeyRing, secretForKid } from './jwt-keys';

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
    private readonly throttle: LoginThrottleService,
    private readonly twoFactor: TwoFactorService,
  ) {}

  private hashRefresh(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  async login(email: string, password: string, ctx: { ip?: string; userAgent?: string; requestId?: string; useCookie?: boolean }) {
    // Lockout. Counted per email address, whether or not an account exists, so a lock looks the same for real
    // and invented addresses. The attempt is counted and any lock set BEFORE the password is checked, so
    // simultaneous attempts cannot get around it. While locked the password is not checked at all.
    const key = loginKey(email);
    const exempt = isExempt(ctx.ip, this.throttle.config());
    let lock: Decision | null = null;
    if (!exempt) {
      const d = await this.throttle.reserve(key);
      if (!d.allowed) {
        throw new HttpException({ message: `Too many sign-in attempts. Try again in ${waitText(d.retryAfterSeconds)}.`, code: 'account_locked', retryAfterSeconds: d.retryAfterSeconds }, HttpStatus.TOO_MANY_REQUESTS);
      }
      if (d.lockedNow) lock = d;
    }
    const refuse = async (actor: { actorType: 'ANONYMOUS' | 'USER'; actorId?: string; actorLabel: string }) => {
      await this.audit.log({
        requestId: ctx.requestId, ...actor, action: AUDIT_ACTIONS.LOGIN, result: 'FAILURE', ipAddress: ctx.ip, userAgent: ctx.userAgent,
      });
      if (lock) {
        await this.audit.log({
          requestId: ctx.requestId, ...actor, action: AUDIT_ACTIONS.LOCKOUT, result: 'FAILURE', ipAddress: ctx.ip, userAgent: ctx.userAgent,
          metadata: { failures: lock.state?.failures, lockedForSeconds: lock.retryAfterSeconds },
        });
        throw new UnauthorizedException({ message: `Incorrect email or password. Too many attempts: try again in ${waitText(lock.retryAfterSeconds)}.`, code: 'invalid_credentials', retryAfterSeconds: lock.retryAfterSeconds });
      }
      throw new UnauthorizedException('Invalid credentials');
    };

    const user = await this.prisma.securityUser.findUnique({ where: { email: email.toLowerCase() } });
    if (!user || !user.isActive) {
      await bcrypt.compare(password, DUMMY_HASH);
      return refuse({ actorType: 'ANONYMOUS', actorLabel: email });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return refuse({ actorType: 'USER', actorId: user.id, actorLabel: user.email });
    if (!exempt) await this.throttle.reset(key);

    // The password is right. With two-step verification on, no session yet: a short-lived step asks for the code.
    // Where it is required but not set up, the step makes the person set it up before they get in.
    if (user.totpEnabledAt) {
      return { twoFactorRequired: true as const, challengeToken: await this.twoFactor.signChallenge(user, 'mfa', ctx.useCookie), expiresInSeconds: CHALLENGE_SECONDS };
    }
    if (this.twoFactor.isRequiredFor(user.role)) {
      return { twoFactorEnrollmentRequired: true as const, challengeToken: await this.twoFactor.signChallenge(user, 'enroll', ctx.useCookie), expiresInSeconds: CHALLENGE_SECONDS };
    }
    return this.finishSignIn(user, ctx);
  }

  /** Starts the session once every step has passed. `method` says how the second step was done, for the audit log. */
  async completeSignIn(userId: string, ctx: { ip?: string; userAgent?: string; requestId?: string }, method: 'totp' | 'recovery' | 'enrolment') {
    const user = await this.prisma.securityUser.findUnique({ where: { id: userId } });
    if (!user || !user.isActive) throw new UnauthorizedException('Invalid credentials');
    return this.finishSignIn(user, ctx, method);
  }

  private async finishSignIn(user: any, ctx: { ip?: string; userAgent?: string; requestId?: string }, twoFactor?: string) {
    const tokens = await this.issueTokens(user, ctx);
    await this.prisma.securityUser.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email,
      action: AUDIT_ACTIONS.LOGIN, result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent,
      ...(twoFactor ? { metadata: { twoFactor } } : {}),
    });
    return { user: this.publicUser(user), ...tokens };
  }

  /**
   * Issues an access token and a refresh token. Both carry the account's token version (tv) and the
   * session they belong to (sid). A refresh keeps the same session; a sign-in starts a new one.
   */

  /** Verify a refresh JWT, accepting the current or previous secret during a key rotation. */
  private async verifyRefreshToken(refreshToken: string): Promise<any> {
    const ring = loadRefreshKeyRing();
    const secrets = [ring.current, ring.previous].filter(Boolean) as string[];
    let lastErr: any;
    for (const secret of secrets) {
      try {
        return await this.jwt.verifyAsync(refreshToken, { secret });
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr ?? new UnauthorizedException('Invalid refresh token');
  }

  private async issueTokens(user: any, ctx: { ip?: string; userAgent?: string }, session?: { id: string; startedAt: Date }) {
    const sessionId = session?.id ?? randomUUID();
    const startedAt = session?.startedAt ?? new Date();
    const tv = user.tokenVersion ?? 0;
    const accessRing = loadAccessKeyRing();
    const refreshRing = loadRefreshKeyRing();
    const accessToken = await this.jwt.signAsync(
      { sub: user.id, email: user.email, role: user.role, type: 'access', tv, sid: sessionId },
      { secret: accessRing.current, expiresIn: process.env.JWT_EXPIRES_IN || '15m', keyid: accessRing.currentKid },
    );
    const refreshRaw = randomBytes(48).toString('base64url');
    const refreshToken = await this.jwt.signAsync(
      { sub: user.id, nonce: refreshRaw, type: 'refresh', tv, sid: sessionId },
      { secret: refreshRing.current, expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d', keyid: refreshRing.currentKid },
    );
    const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);
    await this.prisma.securityRefreshToken.create({
      data: {
        userId: user.id, tokenHash: this.hashRefresh(refreshToken), expiresAt,
        ipAddress: ctx.ip, userAgent: ctx.userAgent,
        sessionId, sessionStartedAt: startedAt, lastUsedAt: new Date(), deviceLabel: deviceLabel(ctx.userAgent),
      },
    });
    return { accessToken, refreshToken };
  }

  async refresh(refreshToken: string, ctx: { ip?: string; userAgent?: string; requestId?: string }) {
    let payload: any;
    try {
      payload = await this.verifyRefreshToken(refreshToken);
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
    if (payload.type !== 'refresh') throw new UnauthorizedException('Invalid token type');
    const hash = this.hashRefresh(refreshToken);
    const stored = await this.prisma.securityRefreshToken.findUnique({ where: { tokenHash: hash } });
    if (stored && stored.revokedAt && (stored.revokedReason ?? 'rotated') !== 'rotated') {
      // This session was ended on purpose (signed out, revoked from the sessions page, password changed).
      // That is not a sign of theft, so it only fails; it does not end the account's other sessions.
      throw new UnauthorizedException({ message: 'This session has ended. Please sign in again.', code: 'session_ended' });
    }
    if (stored && stored.revokedAt) {
      // A token that was already replaced is being presented again. Either the owner or a
      // thief holds a copy, and there is no way to tell which, so end every session.
      await this.prisma.securityRefreshToken.updateMany({
        where: { userId: stored.userId, revokedAt: null },
        data: { revokedAt: new Date(), revokedReason: 'reuse_detected' },
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
    // A password change, "sign out everywhere" or an administrator reset raised the version after this token was issued.
    if ((payload.tv ?? 0) !== (user.tokenVersion ?? 0)) {
      throw new UnauthorizedException({ message: 'This session has ended. Please sign in again.', code: 'session_ended' });
    }

    await this.prisma.securityRefreshToken.update({ where: { id: stored.id }, data: { revokedAt: new Date(), revokedReason: 'rotated' } });
    const tokens = await this.issueTokens(user, ctx, { id: stored.sessionId, startedAt: stored.sessionStartedAt });
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email,
      action: AUDIT_ACTIONS.REFRESH, result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent,
    });
    return { user: this.publicUser(user), ...tokens };
  }

  /** Throws 401 unless the value is a correctly signed, unexpired refresh token. */
  async verifyRefreshJwt(refreshToken: string): Promise<void> {
    try {
      const payload: any = await this.verifyRefreshToken(refreshToken);
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
      data: { revokedAt: new Date(), revokedReason: 'logout' },
    });
  }

  async createUser(
    dto: { email: string; password: string; name?: string; role: string; requirePasswordChange?: boolean },
    actor?: ActorContext,
  ) {
    if (!Object.values(ROLES).includes(dto.role as any)) throw new BadRequestException('Invalid role');
    const email = dto.email.toLowerCase();
    assertStrongPassword(dto.password, { email, name: dto.name });
    const exists = await this.prisma.securityUser.findUnique({ where: { email } });
    if (exists) throw new ConflictException('Email already exists');
    const passwordHash = await bcrypt.hash(dto.password, 12);
    const user = await this.prisma.securityUser.create({
      data: {
        email, passwordHash, name: dto.name ?? null, role: dto.role, passwordChangedAt: new Date(),
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
    // Raising tokenVersion ends every access token of this account at once, not after 15 minutes.
    const strength = checkPassword(newPassword, { email: user.email, name: user.name });
    if (!strength.ok) {
      await fail('weak_password');
      assertStrongPassword(newPassword, { email: user.email, name: user.name });
    }
    await this.prisma.securityUser.update({
      where: { id: user.id },
      data: { passwordHash: await bcrypt.hash(newPassword, 12), mustChangePassword: false, passwordChangedAt: new Date(), tokenVersion: { increment: 1 } },
    });
    await this.prisma.securityRefreshToken.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date(), revokedReason: 'password_changed' } });
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
