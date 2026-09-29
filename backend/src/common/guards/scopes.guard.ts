import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Scope, SCOPES_KEY } from '../constants';

@Injectable()
export class ScopesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  canActivate(ctx: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<Scope[]>(SCOPES_KEY, [ctx.getHandler(), ctx.getClass()]);
    if (!required || required.length === 0) return true;
    const req = ctx.switchToHttp().getRequest();
    const actor = req.actor;
    if (!actor) throw new ForbiddenException('No actor');
    if (actor.type === 'USER') return true;
    const scopes: string[] = actor.scopes || [];
    const ok = required.every((s) => scopes.includes(s));
    if (!ok) throw new ForbiddenException('Missing required scope');
    return true;
  }
}
