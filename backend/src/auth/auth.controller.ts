import { Body, Controller, Post, Req, UnauthorizedException, UseGuards } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { AuthService } from './auth.service';
import { ChangePasswordDto, CreateUserDto, LoginDto, RefreshDto } from './dto';
import { extractIp } from '../common/utils/ip.util';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { ActorContext, CurrentActor } from '../common/decorators/current-actor.decorator';
import { Public } from '../common/decorators/public.decorator';
import { PrismaService } from '../prisma/prisma.service';

@Controller('api/v1/auth')
export class AuthController {
  constructor(private readonly auth: AuthService, private readonly prisma: PrismaService) {}

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
  async createUser(@Body() dto: CreateUserDto) {
    return this.auth.createUser(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  async changePassword(@Body() dto: ChangePasswordDto, @CurrentActor() actor: ActorContext) {
    const user = await this.prisma.securityUser.findUnique({ where: { id: actor.id! } });
    if (!user) throw new UnauthorizedException();
    const ok = await bcrypt.compare(dto.currentPassword, user.passwordHash);
    if (!ok) throw new UnauthorizedException('Current password invalid');
    const hash = await bcrypt.hash(dto.newPassword, 12);
    await this.prisma.securityUser.update({ where: { id: user.id }, data: { passwordHash: hash } });
    await this.prisma.securityRefreshToken.updateMany({
      where: { userId: user.id, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    return { ok: true };
  }
}
