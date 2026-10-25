import {
  Body, Controller, Delete, ForbiddenException, Get, Param, Patch, Post, Req, Res, UnauthorizedException, UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import type { Response } from 'express';
import { AuthService, REFRESH_TTL_MS } from './auth.service';
import { UsersService } from './users.service';
import { SessionsService } from './sessions.service';
import { TwoFactorService } from './two-factor.service';
import {
  ChangePasswordDto, CodeDto, CreateUserDto, EnrolConfirmDto, EnrolStartDto, LoginDto, PasswordAndCodeDto, RefreshDto,
  ResetUserPasswordDto, UpdateUserDto, VerifyTwoFactorDto,
} from './dto';
import { extractIp } from '../common/utils/ip.util';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { ActorContext, CurrentActor } from '../common/decorators/current-actor.decorator';
import { Public } from '../common/decorators/public.decorator';
import {
  buildRefreshCookie, checkCookieRequest, clearRefreshCookie, csrfTokenFor, readRefreshCookie,
} from './session-cookie';

const ALL_ROLES = [ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER] as const;
const LOGIN_THROTTLE = {
  ip: { limit: () => Number(process.env.THROTTLE_LOGIN_LIMIT || 20), ttl: () => Number(process.env.THROTTLE_TTL || 60) * 1000 },
};

@Controller('api/v1/auth')
export class AuthController {
  constructor(private readonly auth: AuthService, private readonly users: UsersService, private readonly sessions: SessionsService, private readonly twoFactor: TwoFactorService) {}

  @Public()
  // Password guessing is the most attractive target on a security product, so signing in
  // gets its own, much smaller allowance per address (read when the request arrives, so
  // it follows the environment file).
  @Throttle(LOGIN_THROTTLE)
  @Post('login')
  async login(@Body() dto: LoginDto, @Req() req: any, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    const result = await this.auth.login(dto.email, dto.password, {
      ip: extractIp(req), userAgent: req.headers['user-agent'], requestId: req.requestId, useCookie: !!dto.useCookie,
    });
    // Password right but a second step is needed: no session and no cookie yet, only the short-lived step token.
    if (!('accessToken' in result)) return result;
    return this.sessionResponse(result, !!dto.useCookie, res);
  }

  /** Browser sign-in: the refresh token goes into an httpOnly cookie and never into the body. */
  private sessionResponse<T extends { refreshToken: string }>(result: T, useCookie: boolean, res: Response): Omit<T, 'refreshToken'> & { refreshToken?: string; csrfToken?: string } {
    if (!useCookie) return result;
    const { refreshToken, ...rest } = result;
    res.append('Set-Cookie', buildRefreshCookie(refreshToken, REFRESH_TTL_MS));
    return { ...rest, csrfToken: csrfTokenFor(refreshToken) };
  }

  private ctxOf(req: any) { return { ip: extractIp(req), userAgent: req.headers['user-agent'], requestId: req.requestId }; }

  // ---- Two-step verification ---------------------------------------------------------------------

  /** Second step of signing in. Takes the step token from login and a code (or a recovery code). */
  @Public()
  @Throttle(LOGIN_THROTTLE)
  @Post('2fa/verify')
  async verifyTwoFactor(@Body() dto: VerifyTwoFactorDto, @Req() req: any, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    const { user, useCookie } = await this.twoFactor.readChallenge(dto.challengeToken, 'mfa');
    const ctx = this.ctxOf(req);
    const out = await this.twoFactor.verifySignIn(user, dto, ctx);
    const session = await this.auth.completeSignIn(user.id, ctx, out.method);
    return this.sessionResponse({ ...session, recoveryCodesRemaining: out.recoveryCodesRemaining }, useCookie, res);
  }

  /** Where two-step verification is required but not set up: start setting it up (before there is a session). */
  @Public()
  @Throttle(LOGIN_THROTTLE)
  @Post('2fa/enroll/start')
  async enrolStart(@Body() dto: EnrolStartDto, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    const { user } = await this.twoFactor.readChallenge(dto.challengeToken, 'enroll');
    return this.twoFactor.startEnrolment(user.id);
  }

  /** Confirms with a first code. Returns the recovery codes (shown once) and starts the session. */
  @Public()
  @Throttle(LOGIN_THROTTLE)
  @Post('2fa/enroll/confirm')
  async enrolConfirm(@Body() dto: EnrolConfirmDto, @Req() req: any, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    const { user, useCookie } = await this.twoFactor.readChallenge(dto.challengeToken, 'enroll');
    const ctx = this.ctxOf(req);
    const { recoveryCodes } = await this.twoFactor.confirmEnrolment(user.id, dto.code, ctx);
    const session = await this.auth.completeSignIn(user.id, ctx, 'enrolment');
    return this.sessionResponse({ ...session, recoveryCodes }, useCookie, res);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(...ALL_ROLES)
  @Get('2fa')
  twoFactorStatus(@CurrentActor() actor: ActorContext, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return this.twoFactor.status(actor.id!);
  }

  /** For accounts where it is optional: set it up while signed in. */
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(...ALL_ROLES)
  @Post('2fa/setup/start')
  setupStart(@CurrentActor() actor: ActorContext, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return this.twoFactor.startEnrolment(actor.id!);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(...ALL_ROLES)
  @Post('2fa/setup/confirm')
  setupConfirm(@Body() dto: CodeDto, @CurrentActor() actor: ActorContext, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return this.twoFactor.confirmEnrolment(actor.id!, dto.code, actor);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(...ALL_ROLES)
  @Post('2fa/recovery-codes/regenerate')
  regenerateCodes(@Body() dto: PasswordAndCodeDto, @CurrentActor() actor: ActorContext, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return this.twoFactor.regenerateRecoveryCodes(actor.id!, dto.password, dto.code, actor);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(...ALL_ROLES)
  @Post('2fa/disable')
  disableTwoFactor(@Body() dto: PasswordAndCodeDto, @CurrentActor() actor: ActorContext) {
    return this.twoFactor.disable(actor.id!, dto.password, dto.code, actor);
  }

  /** A super admin clears another account's two-step setup (lost phone). Not your own. Signs that account out everywhere. */
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN)
  @Post('users/:id/2fa/reset')
  resetTwoFactor(@Param('id') id: string, @CurrentActor() actor: ActorContext) {
    return this.twoFactor.adminReset(id, actor);
  }

  @Public()
  @Throttle(LOGIN_THROTTLE)
  @Post('refresh')
  async refresh(@Body() dto: RefreshDto, @Req() req: any, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    // A token in the body is the original flow for non-browser clients. With no body token,
    // the cookie is used, and then the cross-site checks apply.
    const fromCookie = !dto.refreshToken;
    const token = dto.refreshToken ?? readRefreshCookie(req);
    if (!token) throw new UnauthorizedException({ message: 'No session', code: 'no_session' });
    if (fromCookie) this.assertSameSite(req, token);
    let result;
    try {
      result = await this.auth.refresh(token, {
        ip: extractIp(req), userAgent: req.headers['user-agent'], requestId: req.requestId,
      });
    } catch (err) {
      if (fromCookie) res.append('Set-Cookie', clearRefreshCookie());
      throw err;
    }
    if (!fromCookie) return result;
    const { refreshToken, ...rest } = result;
    res.append('Set-Cookie', buildRefreshCookie(refreshToken, REFRESH_TTL_MS));
    return { ...rest, csrfToken: csrfTokenFor(refreshToken) };
  }

  /**
   * The token a browser must send with refresh and logout. Another site cannot read this
   * answer (CORS), so it cannot forge the follow-up request. After a page reload the
   * dashboard has only the cookie, so it asks here first.
   */
  @Public()
  @Get('csrf')
  async csrf(@Req() req: any, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    const token = readRefreshCookie(req);
    if (!token) throw new UnauthorizedException({ message: 'No session', code: 'no_session' });
    await this.auth.verifyRefreshJwt(token);
    return { csrfToken: csrfTokenFor(token) };
  }

  @Public()
  @Post('logout')
  async logout(@Body() dto: RefreshDto, @Req() req: any, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    const fromCookie = !dto.refreshToken;
    const token = dto.refreshToken ?? readRefreshCookie(req);
    if (fromCookie && token) this.assertSameSite(req, token);
    if (token) await this.auth.logout(token);
    if (fromCookie) res.append('Set-Cookie', clearRefreshCookie());
    return { ok: true };
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(...ALL_ROLES)
  @Get('me')
  async me(@CurrentActor() actor: ActorContext, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return this.auth.me(actor.id!);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN)
  @Get('users')
  listUsers() {
    return this.users.list().then((data) => ({ data }));
  }

  /** Lets an account that is locked after too many wrong attempts sign in again now. */
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN)
  @Post('users/:id/unlock')
  unlockUser(@Param('id') id: string, @CurrentActor() actor: ActorContext) {
    return this.users.unlock(id, actor);
  }

  /** Active accounts an incident can be assigned to. Names and roles only. */
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  @Get('assignees')
  assignees() {
    return this.users.assignable().then((data) => ({ data }));
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN)
  @Post('users')
  async createUser(@Body() dto: CreateUserDto, @CurrentActor() actor: ActorContext) {
    return this.auth.createUser(dto, actor);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN)
  @Patch('users/:id')
  updateUser(@Param('id') id: string, @Body() dto: UpdateUserDto, @CurrentActor() actor: ActorContext) {
    return this.users.update(id, dto, actor);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN)
  @Post('users/:id/reset-password')
  resetPassword(@Param('id') id: string, @Body() dto: ResetUserPasswordDto, @CurrentActor() actor: ActorContext) {
    return this.users.resetPassword(id, dto.newPassword, actor);
  }

  // ---- Sessions: the sign-ins of an account -------------------------------------------------

  /** The signed-in account's own sessions. The one making this request is marked current. */
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(...ALL_ROLES)
  @Get('sessions')
  async listSessions(@CurrentActor() actor: ActorContext, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return { data: await this.sessions.list(actor.id!, actor.sessionId) };
  }

  /** Signs the account out everywhere, this device included, and ends every access token at once. */
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(...ALL_ROLES)
  @Post('sessions/revoke-all')
  async revokeAllMine(@CurrentActor() actor: ActorContext, @Req() req: any, @Res({ passthrough: true }) res: Response) {
    const out = await this.sessions.revokeAll(actor.id!, actor);
    if (readRefreshCookie(req)) res.append('Set-Cookie', clearRefreshCookie());
    return out;
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(...ALL_ROLES)
  @Delete('sessions/:id')
  async revokeMine(@Param('id') id: string, @CurrentActor() actor: ActorContext, @Req() req: any, @Res({ passthrough: true }) res: Response) {
    const out = await this.sessions.revoke(actor.id!, id, actor);
    if (id === actor.sessionId && readRefreshCookie(req)) res.append('Set-Cookie', clearRefreshCookie());
    return out;
  }

  /** Another account's sessions, for a super admin. */
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN)
  @Get('users/:id/sessions')
  async listUserSessions(@Param('id') id: string, @Res({ passthrough: true }) res: Response) {
    await this.sessions.userEmail(id);
    res.setHeader('Cache-Control', 'no-store');
    return { data: await this.sessions.list(id) };
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN)
  @Post('users/:id/sessions/revoke-all')
  async revokeAllForUser(@Param('id') id: string, @CurrentActor() actor: ActorContext) {
    return this.sessions.revokeAll(id, actor, await this.sessions.userEmail(id));
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN)
  @Delete('users/:id/sessions/:sessionId')
  async revokeForUser(@Param('id') id: string, @Param('sessionId') sessionId: string, @CurrentActor() actor: ActorContext) {
    return this.sessions.revoke(id, sessionId, actor, await this.sessions.userEmail(id));
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  async changePassword(@Body() dto: ChangePasswordDto, @CurrentActor() actor: ActorContext) {
    return this.auth.changePassword(actor.id!, dto.currentPassword, dto.newPassword, {
      ip: actor.ip, userAgent: actor.userAgent, requestId: actor.requestId,
    });
  }

  private assertSameSite(req: any, token: string) {
    const failure = checkCookieRequest(req, token);
    if (failure) {
      throw new ForbiddenException({
        message: 'Request rejected',
        code: failure === 'origin' ? 'origin_not_allowed' : 'csrf_invalid',
      });
    }
  }
}
