import { Controller, Get, Param, Query, Res, UseGuards } from '@nestjs/common';
import type { Response } from 'express';
import { ReportsService } from './reports.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { ROLES } from '../common/constants';
import { ActorContext, CurrentActor } from '../common/decorators/current-actor.decorator';
import { AuditService } from '../audit/audit.service';
import { PeriodQuery, ReportFormatQuery, resolvePeriod } from './dto';

const TEXT = 'text/plain; charset=utf-8';

/**
 * Report endpoints. All are read-only and require an administrator login.
 * Because reports summarize sensitive security activity, every read is written
 * to the audit log (the global audit interceptor skips GET requests).
 *
 *   plain-English reports     any role, including VIEWER
 *   technical reports         SUPER_ADMIN, SECURITY_ADMIN, ANALYST
 */
@Controller('api/v1/reports')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ReportsController {
  constructor(
    private readonly reports: ReportsService,
    private readonly audit: AuditService,
  ) {}

  @Get('incidents/:id')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER)
  async incident(
    @Param('id') id: string, @Query() q: ReportFormatQuery,
    @CurrentActor() actor: ActorContext, @Res({ passthrough: true }) res: Response,
  ) {
    const out = q.format === 'text' ? await this.reports.incidentReportText(id) : await this.reports.incidentReport(id);
    await this.record(actor, 'report.incident', id, q.format);
    return this.send(res, out);
  }

  @Get('technical/:id')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST)
  async technical(
    @Param('id') id: string, @CurrentActor() actor: ActorContext,
  ) {
    const out = await this.reports.technicalReport(id);
    await this.record(actor, 'report.technical', id, 'json');
    return out;
  }

  @Get('executive-summary')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST, ROLES.VIEWER)
  async executive(
    @Query() q: PeriodQuery, @CurrentActor() actor: ActorContext, @Res({ passthrough: true }) res: Response,
  ) {
    const { from, to } = resolvePeriod(q);
    const out = q.format === 'text'
      ? await this.reports.executiveSummaryText(from, to)
      : await this.reports.executiveSummary(from, to);
    await this.record(actor, 'report.executive_summary', undefined, q.format, { from, to });
    return this.send(res, out);
  }

  @Get('security-summary')
  @Roles(ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN, ROLES.ANALYST)
  async security(
    @Query() q: PeriodQuery, @CurrentActor() actor: ActorContext, @Res({ passthrough: true }) res: Response,
  ) {
    const { from, to } = resolvePeriod(q);
    const out = q.format === 'text'
      ? await this.reports.securitySummaryText(from, to)
      : await this.reports.securitySummary(from, to);
    await this.record(actor, 'report.security_summary', undefined, q.format, { from, to });
    return this.send(res, out);
  }

  /** Strings are sent as plain text, objects as JSON. Reports are never cached. */
  private send(res: Response, out: unknown) {
    res.setHeader('Cache-Control', 'no-store');
    if (typeof out === 'string') {
      res.setHeader('Content-Type', TEXT);
      res.send(out);
      return;
    }
    return out;
  }

  private async record(actor: ActorContext, action: string, targetId: string | undefined, format?: string, period?: { from: Date; to: Date }) {
    await this.audit.log({
      requestId: actor.requestId,
      actorType: actor.type,
      actorId: actor.id,
      actorLabel: actor.label || actor.role,
      action,
      targetType: 'report',
      targetId,
      result: 'SUCCESS',
      ipAddress: actor.ip,
      userAgent: actor.userAgent,
      metadata: {
        format: format ?? 'json',
        ...(period ? { from: period.from.toISOString(), to: period.to.toISOString() } : {}),
      },
    });
  }
}
