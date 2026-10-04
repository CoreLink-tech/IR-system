import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable, lastValueFrom } from 'rxjs';
import { ROLES_KEY, SCOPES_KEY, Role, Scope } from '../constants';
import { ApiKeyGuard } from './api-key.guard';
import { JwtAuthGuard } from './jwt-auth.guard';

/**
 * For the few routes that both an administrator (JWT) and the PishonMarket website
 * (API key) must be able to call. The kind of credential is decided by the token
 * prefix, then the matching rule applies:
 *
 *   API key        must carry every scope named by @Scopes(...)
 *   administrator  must hold one of the roles named by @Roles(...)
 *
 * Using one route with one guard avoids registering the same path twice, where the
 * first registration would shadow the second and lock out the other kind of caller.
 */
@Injectable()
export class JwtOrApiKeyGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly apiKeyGuard: ApiKeyGuard,
    private readonly jwtGuard: JwtAuthGuard,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest();
    const header = req.headers['authorization'];
    const prefix = process.env.API_KEY_PREFIX || 'PMS_';
    const token = typeof header === 'string' && header.startsWith('Bearer ') ? header.substring(7).trim() : '';

    if (token.startsWith(prefix)) {
      await this.apiKeyGuard.canActivate(ctx);
      const required = this.reflector.getAllAndOverride<Scope[]>(SCOPES_KEY, [ctx.getHandler(), ctx.getClass()]) ?? [];
      const scopes: string[] = req.actor?.scopes ?? [];
      if (!required.every((s) => scopes.includes(s))) throw new ForbiddenException('Missing required scope');
      return true;
    }

    const allowed = await this.resolve(this.jwtGuard.canActivate(ctx));
    if (!allowed) return false;
    const roles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [ctx.getHandler(), ctx.getClass()]) ?? [];
    const role = req.actor?.role || req.user?.role;
    if (roles.length > 0 && (!role || !roles.includes(role))) throw new ForbiddenException('Insufficient role');
    return true;
  }

  private async resolve(r: boolean | Promise<boolean> | Observable<boolean>): Promise<boolean> {
    if (typeof r === 'boolean') return r;
    if (r instanceof Promise) return r;
    return lastValueFrom(r);
  }
}
