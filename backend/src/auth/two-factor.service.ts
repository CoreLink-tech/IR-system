import {
  BadRequestException, ConflictException, ForbiddenException, HttpException, HttpStatus, Injectable, NotFoundException,
  ServiceUnavailableException, UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { ActorContext } from '../common/decorators/current-actor.decorator';
import { AUDIT_ACTIONS } from '../common/constants';
import { LoginThrottleService } from './login-throttle.service';
import { Decision, waitText } from './login-throttle';
import { isMandatoryRole, twoFactorConfig } from './two-factor.config';
import { KeyRing, decryptSecret, encryptSecret, hashRecoveryCode, hashRecoveryCodeAll, looksLikeRecoveryCode, newRecoveryCode } from './two-factor.crypto';
import { newTotpSecret, otpauthUri, verifyTotp } from './totp';

export const CHALLENGE_SECONDS = 300;
export const RECOVERY_CODE_COUNT = 10;
type Ctx = { ip?: string; userAgent?: string; requestId?: string };

/**
 * Two-step verification with an authenticator app (TOTP), recovery codes, and the administrator reset.
 *
 * Every place a code is checked is rate limited per account with the same growing delays as passwords, a code
 * works once (the step it belongs to is claimed with a conditional update), and recovery codes are consumed with
 * one conditional update so two simultaneous uses cannot both succeed.
 */
@Injectable()
export class TwoFactorService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly throttle: LoginThrottleService,
    private readonly jwt: JwtService,
  ) {}

  config() { return twoFactorConfig(); }
  isRequiredFor(role: string): boolean { return this.config().required && isMandatoryRole(role); }

  private ring(): KeyRing {
    const r = this.config().ring;
    if (!r) throw new ServiceUnavailableException({ message: 'Two-step verification is not set up on this server (TOTP_ENCRYPTION_KEY is missing). Ask the person who runs the server.', code: 'two_factor_unavailable' });
    return r;
  }

  // ---- the short-lived step between the password and the session ---------------------------------

  /** "mfa" = enter your code, "enroll" = you must set up two-step verification first. Not an access token. */
  signChallenge(user: any, purpose: 'mfa' | 'enroll', useCookie?: boolean): Promise<string> {
    return this.jwt.signAsync({ sub: user.id, typ: purpose, tv: user.tokenVersion ?? 0, uc: !!useCookie }, { secret: process.env.JWT_SECRET, expiresIn: CHALLENGE_SECONDS });
  }

  async readChallenge(token: string, purpose: 'mfa' | 'enroll'): Promise<{ user: any; useCookie: boolean }> {
    const expired = () => new UnauthorizedException({ message: 'This sign-in step has expired. Please sign in again.', code: 'challenge_expired' });
    let p: any;
    try { p = await this.jwt.verifyAsync(token, { secret: process.env.JWT_SECRET }); } catch { throw expired(); }
    if (p.typ !== purpose) throw expired();
    const user = await this.prisma.securityUser.findUnique({ where: { id: p.sub } });
    if (!user || !user.isActive || (user.tokenVersion ?? 0) !== (p.tv ?? 0)) throw expired();
    return { user, useCookie: !!p.uc };
  }

  // ---- rate limit on code attempts ---------------------------------------------------------------

  private async attempt(userId: string): Promise<Decision> {
    const d = await this.throttle.reserve(`mfa:${userId}`);
    if (!d.allowed) {
      throw new HttpException({ message: `Too many wrong codes. Try again in ${waitText(d.retryAfterSeconds)}.`, code: 'two_factor_locked', retryAfterSeconds: d.retryAfterSeconds }, HttpStatus.TOO_MANY_REQUESTS);
    }
    return d;
  }
  private clearAttempts(userId: string) { return this.throttle.reset(`mfa:${userId}`); }

  private async rejectCode(user: any, d: Decision, ctx: Ctx, what: string): Promise<never> {
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email, action: AUDIT_ACTIONS.TWOFA_FAIL,
      result: 'FAILURE', ipAddress: ctx.ip, userAgent: ctx.userAgent, metadata: { what, lockedForSeconds: d.lockedNow ? d.retryAfterSeconds : undefined },
    });
    const wait = d.lockedNow ? ` Too many wrong codes: try again in ${waitText(d.retryAfterSeconds)}.` : '';
    throw new UnauthorizedException({
      message: `That code is not right, or it was already used. Check the time on your phone and try the next code.${wait}`,
      code: 'invalid_code', ...(d.lockedNow ? { retryAfterSeconds: d.retryAfterSeconds } : {}),
    });
  }

  // ---- checking a code ---------------------------------------------------------------------------

  /** True when the code is right and has not been used. Claims its time step so it cannot be used again. */
  private async checkTotp(user: any, code: string): Promise<boolean> {
    if (!user.totpSecret || !user.totpEnabledAt) return false;
    let secret: string;
    try { secret = decryptSecret(user.totpSecret, this.ring()); } catch (e) { if (e instanceof ServiceUnavailableException) throw e; return false; }
    const r = verifyTotp(secret, code, new Date(), { window: this.config().window, lastStep: user.totpLastStep });
    if (!r.ok) return false;
    const claimed = await this.prisma.securityUser.updateMany({
      where: { id: user.id, OR: [{ totpLastStep: null }, { totpLastStep: { lt: r.step } }] },
      data: { totpLastStep: r.step },
    });
    return claimed.count === 1;
  }

  private async consumeRecovery(userId: string, code: string): Promise<boolean> {
    if (!looksLikeRecoveryCode(code)) return false;
    const r = await this.prisma.securityRecoveryCode.updateMany({
      where: { userId, usedAt: null, codeHash: { in: hashRecoveryCodeAll(code, this.ring()) } },
      data: { usedAt: new Date() },
    });
    return r.count === 1;
  }

  private remaining(userId: string) { return this.prisma.securityRecoveryCode.count({ where: { userId, usedAt: null } }); }

  /** The second step of signing in. Throws unless the code (or a recovery code) is right. */
  async verifySignIn(user: any, body: { code?: string; recoveryCode?: string }, ctx: Ctx): Promise<{ method: 'totp' | 'recovery'; recoveryCodesRemaining: number }> {
    if (!body.code && !body.recoveryCode) throw new BadRequestException({ message: 'Enter the 6 digit code from your authenticator app, or a recovery code.', code: 'code_required' });
    this.ring();
    const d = await this.attempt(user.id);
    if (body.recoveryCode) {
      if (!(await this.consumeRecovery(user.id, body.recoveryCode))) return this.rejectCode(user, d, ctx, 'recovery');
      await this.clearAttempts(user.id);
      const left = await this.remaining(user.id);
      await this.audit.log({
        requestId: ctx.requestId, actorType: 'USER', actorId: user.id, actorLabel: user.email, action: AUDIT_ACTIONS.TWOFA_RECOVERY_USED,
        result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent, metadata: { remaining: left },
      });
      return { method: 'recovery', recoveryCodesRemaining: left };
    }
    if (!(await this.checkTotp(user, body.code!))) return this.rejectCode(user, d, ctx, 'totp');
    await this.clearAttempts(user.id);
    return { method: 'totp', recoveryCodesRemaining: await this.remaining(user.id) };
  }

  // ---- enrolment ---------------------------------------------------------------------------------

  /** Creates a new, not yet confirmed, secret. Starting again replaces an unconfirmed one. */
  async startEnrolment(userId: string) {
    const ring = this.ring();
    const user = await this.prisma.securityUser.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');
    if (user.totpEnabledAt) throw new ConflictException({ message: 'Two-step verification is already on for this account.', code: 'two_factor_already_enabled' });
    const secret = newTotpSecret();
    await this.prisma.securityUser.update({ where: { id: userId }, data: { totpSecret: encryptSecret(secret, ring), totpLastStep: null } });
    const cfg = this.config();
    return {
      secret, manualKey: secret.match(/.{1,4}/g)!.join(' '), issuer: cfg.issuer, accountName: user.email,
      otpauthUri: otpauthUri(secret, user.email, cfg.issuer),
    };
  }

  /** Confirms with a first valid code, switches two-step verification on, and returns the recovery codes (once). */
  async confirmEnrolment(userId: string, code: string, ctx: Ctx): Promise<{ recoveryCodes: string[] }> {
    const ring = this.ring();
    const user = await this.prisma.securityUser.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');
    if (user.totpEnabledAt) throw new ConflictException({ message: 'Two-step verification is already on for this account.', code: 'two_factor_already_enabled' });
    if (!user.totpSecret) throw new BadRequestException({ message: 'Start setting up two-step verification first.', code: 'no_pending_enrolment' });
    const d = await this.attempt(userId);
    let secret: string;
    try { secret = decryptSecret(user.totpSecret, ring); } catch { throw new BadRequestException({ message: 'Start setting up two-step verification again.', code: 'no_pending_enrolment' }); }
    const r = verifyTotp(secret, code, new Date(), { window: this.config().window });
    if (!r.ok) return this.rejectCode(user, d, ctx, 'enrolment');
    const claimed = await this.prisma.securityUser.updateMany({
      where: { id: userId, totpEnabledAt: null, totpSecret: user.totpSecret },
      data: { totpEnabledAt: new Date(), totpLastStep: r.step },
    });
    if (claimed.count !== 1) throw new ConflictException({ message: 'Two-step verification was changed while you were setting it up. Start again.', code: 'enrolment_conflict' });
    const recoveryCodes = await this.issueRecoveryCodes(userId, ring);
    await this.clearAttempts(userId);
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: userId, actorLabel: user.email, action: AUDIT_ACTIONS.TWOFA_ENABLE,
      result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent,
    });
    return { recoveryCodes };
  }

  /** Replaces every recovery code with a new set. The old ones stop working. Returns the new ones, once. */
  private async issueRecoveryCodes(userId: string, ring: KeyRing): Promise<string[]> {
    const codes = Array.from({ length: RECOVERY_CODE_COUNT }, newRecoveryCode);
    await this.prisma.$transaction([
      this.prisma.securityRecoveryCode.deleteMany({ where: { userId } }),
      this.prisma.securityRecoveryCode.createMany({ data: codes.map((c) => ({ userId, codeHash: hashRecoveryCode(c, ring) })) }),
    ]);
    return codes;
  }

  // ---- managing it once signed in ----------------------------------------------------------------

  async status(userId: string) {
    const user = await this.prisma.securityUser.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');
    const enabled = !!user.totpEnabledAt;
    const left = enabled ? await this.remaining(userId) : 0;
    return {
      available: !!this.config().ring, enabled, enabledAt: user.totpEnabledAt ?? null,
      required: this.isRequiredFor(user.role), recoveryCodesRemaining: left, recoveryCodesLow: enabled && left <= 2,
    };
  }

  /** Both the password and a current code are needed to change two-step settings, so a borrowed session cannot. */
  private async confirmPasswordAndCode(userId: string, password: string, code: string, ctx: Ctx) {
    const user = await this.prisma.securityUser.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');
    if (!user.totpEnabledAt) throw new BadRequestException({ message: 'Two-step verification is not on for this account.', code: 'two_factor_not_enabled' });
    const d = await this.attempt(userId);
    const passwordOk = await bcrypt.compare(password, user.passwordHash);
    const codeOk = passwordOk && (await this.checkTotp(user, code));
    if (!passwordOk || !codeOk) return this.rejectCode(user, d, ctx, passwordOk ? 'change-code' : 'change-password');
    await this.clearAttempts(userId);
    return user;
  }

  async regenerateRecoveryCodes(userId: string, password: string, code: string, ctx: Ctx): Promise<{ recoveryCodes: string[] }> {
    const ring = this.ring();
    const user = await this.confirmPasswordAndCode(userId, password, code, ctx);
    const recoveryCodes = await this.issueRecoveryCodes(userId, ring);
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: userId, actorLabel: user.email, action: AUDIT_ACTIONS.TWOFA_RECOVERY_REGEN,
      result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent,
    });
    return { recoveryCodes };
  }

  /** Switches it off, unless the role must have it. Signs the account out everywhere. */
  async disable(userId: string, password: string, code: string, ctx: Ctx) {
    const probe = await this.prisma.securityUser.findUnique({ where: { id: userId } });
    if (!probe) throw new NotFoundException('User not found');
    if (this.isRequiredFor(probe.role)) throw new ForbiddenException({ message: 'Two-step verification is required for your role and cannot be turned off. If you lost your device, ask a super admin to reset it.', code: 'two_factor_required' });
    const user = await this.confirmPasswordAndCode(userId, password, code, ctx);
    await this.clear(userId, 'two_factor_disabled');
    await this.audit.log({
      requestId: ctx.requestId, actorType: 'USER', actorId: userId, actorLabel: user.email, action: AUDIT_ACTIONS.TWOFA_DISABLE,
      result: 'SUCCESS', ipAddress: ctx.ip, userAgent: ctx.userAgent,
    });
    return { ok: true };
  }

  /** Removes the secret and the recovery codes, ends every session. */
  private async clear(userId: string, reason: string) {
    await this.prisma.$transaction([
      this.prisma.securityUser.update({ where: { id: userId }, data: { totpSecret: null, totpEnabledAt: null, totpLastStep: null, tokenVersion: { increment: 1 } } }),
      this.prisma.securityRecoveryCode.deleteMany({ where: { userId } }),
      this.prisma.securityRefreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date(), revokedReason: reason } }),
    ]);
    await this.clearAttempts(userId);
  }

  /**
   * A super admin clears the two-step setup of another account (a lost phone). The account is signed out
   * everywhere, and where two-step verification is required the person must enrol again at the next sign-in.
   * Nobody can reset their own: a stolen session must not be able to remove its own second step.
   */
  async adminReset(targetId: string, actor: ActorContext) {
    if (actor.id === targetId) throw new ForbiddenException({ message: 'You cannot reset your own two-step verification. Ask another super admin.', code: 'self_reset_forbidden' });
    const target = await this.prisma.securityUser.findUnique({ where: { id: targetId } });
    if (!target) throw new NotFoundException('User not found');
    const wasEnabled = !!target.totpEnabledAt;
    await this.clear(targetId, 'two_factor_reset');
    await this.audit.log({
      requestId: actor.requestId, actorType: 'USER', actorId: actor.id, actorLabel: actor.label, action: AUDIT_ACTIONS.TWOFA_RESET,
      targetType: 'user', targetId, result: 'SUCCESS', ipAddress: actor.ip, userAgent: actor.userAgent, metadata: { email: target.email, wasEnabled },
    });
    return { ok: true, mustEnrolAtNextSignIn: this.isRequiredFor(target.role) };
  }
}
