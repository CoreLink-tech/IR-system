import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable, tap } from 'rxjs';
import { AuditService } from '../../audit/audit.service';
import { extractIp } from '../utils/ip.util';

const AUDITED_PREFIXES = ['/api/v1/security', '/api/v1/incidents', '/api/v1/api-keys', '/api/v1/rules'];

@Injectable()
export class AuditInterceptor implements NestInterceptor {
  constructor(private readonly audit: AuditService) {}
  intercept(ctx: ExecutionContext, next: CallHandler): Observable<any> {
    const req = ctx.switchToHttp().getRequest();
    const path: string = req.originalUrl || req.url || '';
    const shouldAudit = AUDITED_PREFIXES.some((p) => path.startsWith(p));
    if (!shouldAudit) return next.handle();
    if (req.method === 'GET') return next.handle();
    const start = Date.now();
    return next.handle().pipe(
      tap({
        next: () => this.write(req, 'SUCCESS', Date.now() - start),
        error: () => this.write(req, 'FAILURE', Date.now() - start),
      }),
    );
  }

  private write(req: any, result: 'SUCCESS' | 'FAILURE', durationMs: number) {
    const actor = req.actor || { type: 'ANONYMOUS' };
    const action = `${req.method} ${req.route?.path || req.originalUrl?.split('?')[0] || ''}`;
    this.audit.log({
      requestId: req.requestId,
      actorType: actor.type,
      actorId: actor.id,
      actorLabel: actor.label || actor.role,
      action,
      targetType: 'endpoint',
      targetId: req.params?.id,
      result,
      ipAddress: extractIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { durationMs },
    }).catch(() => void 0);
  }
}
