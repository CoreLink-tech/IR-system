import {
  Body, Controller, ForbiddenException, Get, Param, Patch, Post, Req, Res, UnauthorizedException, UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import type { Response } from 'express';
import { AuthService, REFRESH_TTL_MS } from './auth.service';
import { UsersService } from './users.service';
import { ChangePasswordDto, CreateUserDto, LoginDto, RefreshDto, ResetUserPasswordDto, UpdateUserDto } from './dto';
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
  constructor(private readonly auth: AuthService, private readonly users: UsersService) {}

  @Public()
  // Password guessing is the most attractive target on a security product, so signing in
  // gets its own, much smaller allowance per address (read when the request arrives, so
  // it follows the environment file).
  @Throttle(LOGIN_THROTTLE)
  @Post('login')
  async login(@Body() dto: LoginDto, @Req() req: any, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    const result = await this.auth.login(dto.email, dto.password, {
      ip: extractIp(req), userAgent: req.headers['user-agent'], requestId: req.requestId,
    });
    if (!dto.useCookie) return result;
    // Browser sign-in: the refresh token goes into an httpOnly cookie and never into the body.
    const { refreshToken, ...rest } = result;
    res.append('Set-Cookie', buildRefreshCookie(refreshToken, REFRESH_TTL_MS));
    return { ...rest, csrfToken: csrfTokenFor(refreshToken) };
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
