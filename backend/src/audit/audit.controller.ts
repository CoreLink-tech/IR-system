import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { parseDateParam, parsePagination, toPaginated } from '../common/utils/pagination.util';

@Controller('api/v1/audit-logs')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AuditController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST)
  async list(@Query() q: any) {
    const { skip, take, page, pageSize, sortBy, sortOrder } = parsePagination(q, {
      sortBy: 'createdAt', allowedSort: ['createdAt', 'action', 'actorType', 'result'],
    });
    const where: any = {};
    if (q.actorType) where.actorType = q.actorType;
    if (q.action) where.action = { contains: q.action };
    if (q.result) where.result = q.result;
    const from = parseDateParam(q.from, 'from');
    const to = parseDateParam(q.to, 'to');
    if (from || to) {
      where.createdAt = {};
      if (from) where.createdAt.gte = from;
      if (to) where.createdAt.lte = to;
    }
    const [data, total] = await Promise.all([
      this.prisma.securityAuditLog.findMany({ where, skip, take, orderBy: { [sortBy]: sortOrder } }),
      this.prisma.securityAuditLog.count({ where }),
    ]);
    return toPaginated(data, total, page, pageSize);
  }
}
