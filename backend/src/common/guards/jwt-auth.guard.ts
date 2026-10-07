import { ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { ActorContext } from '../decorators/current-actor.decorator';
import { extractIp } from '../utils/ip.util';

/** Routes a signed-in account may still use while it is required to change its password. */
export const MAY_CHANGE_PASSWORD_ROUTES = ['/api/v1/auth/me', '/api/v1/auth/change-password'];

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
    // After an administrator resets a password, the account may do nothing except look at
    // itself and set a new password. Enforced here, on the server, not only in the dashboard.
    if (result.mustChangePassword) {
      const path = String(req.originalUrl || req.url || '').split('?')[0];
      if (!MAY_CHANGE_PASSWORD_ROUTES.includes(path)) {
        throw new ForbiddenException({ message: 'You must change your password before continuing', code: 'password_change_required' });
      }
    }
    return result;
  }
}
