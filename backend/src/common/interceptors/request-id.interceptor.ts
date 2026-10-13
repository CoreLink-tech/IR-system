import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable } from 'rxjs';
import { newRequestId } from '../request-id';

/** Normally the id is already set by requestIdMiddleware; this covers apps built without it. */
@Injectable()
export class RequestIdInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest();
    if (!req.requestId) req.requestId = newRequestId(req.headers['x-request-id']);
    const res = context.switchToHttp().getResponse();
    if (res?.setHeader) res.setHeader('X-Request-Id', req.requestId);
    return next.handle();
  }
}
