import { Body, Controller, Delete, Get, Param, Post, UseGuards } from '@nestjs/common';
import { BlockingService } from './blocking.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { AllowIpDto, BlockIpDto, UnblockIpDto } from './dto';
import { ActorContext, CurrentActor } from '../common/decorators/current-actor.decorator';

// The blocklist read routes (blocked-ips, blocks/history) live in SecuritySyncController,
// which serves both administrators and the website's API key.
@Controller('api/v1/security')
@UseGuards(JwtAuthGuard, RolesGuard)
export class BlockingController {
  constructor(private readonly service: BlockingService) {}

  @Get('allowlist')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER)
  allowlist() { return this.service.allowlist(); }

  @Post('block')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  block(@Body() dto: BlockIpDto, @CurrentActor() actor: ActorContext) {
    return this.service.block(dto.ipAddress, {
      reason: dto.reason, permanent: dto.permanent, ttlMinutes: dto.ttlMinutes,
      administratorId: actor.id, relatedIncidentId: dto.relatedIncidentId, automatic: false,
    });
  }

  @Post('unblock')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  unblock(@Body() dto: UnblockIpDto, @CurrentActor() actor: ActorContext) {
    return this.service.unblock(dto.ipAddress, dto.reason, actor.id!);
  }

  @Post('allow')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  allow(@Body() dto: AllowIpDto, @CurrentActor() actor: ActorContext) {
    return this.service.allow(dto.ipAddress, dto.reason, dto.ttlMinutes, actor.id!);
  }

  @Delete('allow/:ip')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  unallow(@Param('ip') ip: string, @CurrentActor() actor: ActorContext) {
    return this.service.unallow(ip, actor.id!);
  }
}
