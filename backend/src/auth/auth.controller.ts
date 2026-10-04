import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ChangePasswordDto, CreateUserDto, LoginDto, RefreshDto } from './dto';
import { extractIp } from '../common/utils/ip.util';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { ActorContext, CurrentActor } from '../common/decorators/current-actor.decorator';
import { Public } from '../common/decorators/public.decorator';

@Controller('api/v1/auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Post('login')
  async login(@Body() dto: LoginDto, @Req() req: any) {
    return this.auth.login(dto.email, dto.password, {
      ip: extractIp(req), userAgent: req.headers['user-agent'], requestId: req.requestId,
    });
  }

  @Public()
  @Post('refresh')
  async refresh(@Body() dto: RefreshDto, @Req() req: any) {
    return this.auth.refresh(dto.refreshToken, {
      ip: extractIp(req), userAgent: req.headers['user-agent'], requestId: req.requestId,
    });
  }

  @Public()
  @Post('logout')
  async logout(@Body() dto: RefreshDto) {
    await this.auth.logout(dto.refreshToken);
    return { ok: true };
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(ROLES.SUPER_ADMIN)
  @Post('users')
  async createUser(@Body() dto: CreateUserDto, @CurrentActor() actor: ActorContext) {
    return this.auth.createUser(dto, actor);
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  async changePassword(@Body() dto: ChangePasswordDto, @CurrentActor() actor: ActorContext) {
    return this.auth.changePassword(actor.id!, dto.currentPassword, dto.newPassword, {
      ip: actor.ip, userAgent: actor.userAgent, requestId: actor.requestId,
    });
  }
}
