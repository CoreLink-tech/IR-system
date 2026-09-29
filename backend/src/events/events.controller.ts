import { Body, Controller, Get, Param, Post, Query, Req, UseGuards } from '@nestjs/common';
import { EventsService } from './events.service';
import { CreateEventDto } from './dto';
import { ApiKeyGuard } from '../common/guards/api-key.guard';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { ScopesGuard } from '../common/guards/scopes.guard';
import { Scopes } from '../common/decorators/scopes.decorator';
import { SCOPES } from '../common/constants';
import { extractIp } from '../common/utils/ip.util';
import { parsePagination, toPaginated } from '../common/utils/pagination.util';

@Controller('api/v1/events')
export class EventsController {
  constructor(private readonly events: EventsService) {}

  @UseGuards(ApiKeyGuard, ScopesGuard)
  @Scopes(SCOPES.EVENTS_WRITE)
  @Post()
  async ingest(@Body() dto: CreateEventDto, @Req() req: any) {
    return this.events.ingest(dto, {
      apiKeyId: req.apiKey?.id,
      requestId: req.requestId,
      ip: extractIp(req),
      userAgent: req.headers['user-agent'],
    });
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  async list(@Query() q: any) {
    const p = parsePagination(q, { sortBy: 'occurredAt' });
    const { data, total } = await this.events.list({
      ...p,
      filters: {
        eventType: q.eventType, severity: q.severity, ipAddress: q.ipAddress,
        userId: q.userId, from: q.from, to: q.to,
      },
    });
    return toPaginated(data, total, p.page, p.pageSize);
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) { return this.events.findOne(id); }
}
