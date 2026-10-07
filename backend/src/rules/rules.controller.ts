import { Body, Controller, Get, Param, Patch, Post, UseGuards } from '@nestjs/common';
import { RulesService } from './rules.service';
import { ResetRuleDto, UpdateRuleDto } from './dto';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { ActorContext, CurrentActor } from '../common/decorators/current-actor.decorator';

@Controller('api/v1/rules')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
export class RulesController {
  constructor(private readonly service: RulesService) {}

  @Get()
  async list() { return { data: await this.service.list() }; }

  @Patch(':code')
  update(@Param('code') code: string, @Body() dto: UpdateRuleDto, @CurrentActor() actor: ActorContext) {
    return this.service.update(code, dto, actor);
  }

  @Post(':code/reset')
  reset(@Param('code') code: string, @Body() dto: ResetRuleDto, @CurrentActor() actor: ActorContext) {
    return this.service.reset(code, dto.reason, actor);
  }
}
