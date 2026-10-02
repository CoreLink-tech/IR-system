import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { ActorContext } from '../decorators/current-actor.decorator';
import { extractIp } from '../utils/ip.util';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) { super(); }
  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(), context.getClass(),
    ]);
    if (isPublic) return true;
    return super.canActivate(context);
  }

  /**
   * After Passport validates the token, record who is acting. Without this,
   * request.actor was never set for logged-in administrators, so the audit log
   * and incident timeline recorded their actions as anonymous.
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext, status?: any) {
    const result = super.handleRequest(err, user, info, context, status);
    const req = context.switchToHttp().getRequest();
    const actor: ActorContext = {
      type: 'USER',
      id: result.id,
      label: result.email,
      role: result.role,
      ip: extractIp(req),
      userAgent: req.headers?.['user-agent'] as string | undefined,
      requestId: req.requestId,
    };
    req.actor = actor;
    return result;
  }
}
