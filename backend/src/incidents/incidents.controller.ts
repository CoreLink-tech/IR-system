import { Body, Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { IncidentsService } from './incidents.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { AddIncidentNoteDto, AssignIncidentDto, UpdateIncidentStatusDto } from './dto';
import { parsePagination, toPaginated } from '../common/utils/pagination.util';
import { ActorContext, CurrentActor } from '../common/decorators/current-actor.decorator';

@Controller('api/v1/incidents')
@UseGuards(JwtAuthGuard, RolesGuard)
export class IncidentsController {
  constructor(private readonly service: IncidentsService) {}

  @Get()
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER)
  async list(@Query() q: any) {
    const p = parsePagination(q, {
      sortBy: 'createdAt', allowedSort: ['createdAt', 'updatedAt', 'severity', 'riskScore', 'status'],
    });
    const { data, total } = await this.service.list({
      ...p,
      filters: { status: q.status, severity: q.severity, sourceIp: q.sourceIp, assignedTo: q.assignedTo, search: q.search },
    });
    return toPaginated(data, total, p.page, p.pageSize);
  }

  @Get(':id')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER)
  async findOne(@Param('id') id: string, @CurrentActor() actor: ActorContext) {
    const incident = await this.service.findOne(id);
    // Viewers get the incident and its timeline, but not the raw events behind it
    // (addresses, user ids and request detail). They use the plain-English report.
    if (actor.role === ROLES.VIEWER) {
      const { events: _omitted, ...rest } = incident as any;
      return rest;
    }
    return incident;
  }

  @Post(':id/status')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST)
  updateStatus(@Param('id') id: string, @Body() dto: UpdateIncidentStatusDto, @CurrentActor() actor: ActorContext) {
    return this.service.updateStatus(id, dto.status, dto.notes, actor.id!, actor.label || actor.role || 'unknown');
  }

  @Post(':id/notes')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST)
  addNote(@Param('id') id: string, @Body() dto: AddIncidentNoteDto, @CurrentActor() actor: ActorContext) {
    return this.service.addNote(id, dto.note, actor.id!, actor.label || actor.role || 'unknown');
  }

  @Post(':id/assign')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN)
  assign(@Param('id') id: string, @Body() dto: AssignIncidentDto, @CurrentActor() actor: ActorContext) {
    return this.service.assign(id, dto.assignedTo, actor.id!, actor.label || actor.role || 'unknown');
  }
}
