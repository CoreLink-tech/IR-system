import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ApiKeysService } from '../../api-keys/api-keys.service';
import { ActorContext } from '../decorators/current-actor.decorator';
import { extractIp } from '../utils/ip.util';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(private readonly apiKeys: ApiKeysService) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest();
    const header = req.headers['authorization'];
    if (!header || typeof header !== 'string' || !header.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or malformed Authorization header');
    }
    const raw = header.substring(7).trim();
    if (!raw.startsWith(process.env.API_KEY_PREFIX || 'PMS_')) {
      throw new UnauthorizedException('Invalid API key prefix');
    }
    const key = await this.apiKeys.verifyApiKey(raw);
    if (!key) throw new UnauthorizedException('Invalid or expired API key');

    const actor: ActorContext = {
      type: 'API_KEY',
      id: key.id,
      label: key.name,
      scopes: key.scopes.split(',').map((s) => s.trim()).filter(Boolean),
      ip: extractIp(req),
      userAgent: req.headers['user-agent'] as string | undefined,
      requestId: req.requestId,
    };
    (req as any).actor = actor;
    (req as any).apiKey = key;
    return true;
  }
}
