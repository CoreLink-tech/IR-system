import { Body, Controller, Delete, Get, Param, Post, UseGuards } from '@nestjs/common';
import { ApiKeysService } from './api-keys.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { CreateApiKeyDto } from './dto';
import { ActorContext, CurrentActor } from '../common/decorators/current-actor.decorator';

@Controller('api/v1/api-keys')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ApiKeysController {
  constructor(private readonly service: ApiKeysService) {}

  @Get()
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  list() { return this.service.list(); }

  @Post()
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  create(@Body() dto: CreateApiKeyDto, @CurrentActor() actor: ActorContext) {
    return this.service.create(dto, actor.id);
  }

  @Delete(':id')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  revoke(@Param('id') id: string) { return this.service.revoke(id); }

  @Post(':id/rotate')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  rotate(@Param('id') id: string) { return this.service.rotate(id); }
}
