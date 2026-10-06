import { ExecutionContext, Injectable } from '@nestjs/common';
import { ThrottlerGuard, ThrottlerLimitDetail, ThrottlerRequest } from '@nestjs/throttler';

/**
 * Rate limiting with two separate budgets.
 *
 *   "ip"   administrators and anonymous callers, counted per client address.
 *   "key"  the PishonMarket website, counted per API key.
 *
 * The website sends every visitor's events from ONE server address. Counting by address
 * would give the whole shop the same small allowance as a single person, and events
 * would be refused during exactly the busy moments when an attack is under way. So a
 * request carrying an API key is counted against its key, with a much larger allowance,
 * and a leaked key is still bounded.
 *
 * Each request is counted by exactly one of the two budgets.
 */
@Injectable()
export class AppThrottlerGuard extends ThrottlerGuard {
  protected async handleRequest(props: ThrottlerRequest): Promise<boolean> {
    const req = props.context.switchToHttp().getRequest();
    const isKey = apiKeyToken(req) !== null;
    if ((props.throttler.name === 'key') !== isKey) return true; // not this budget's request
    return super.handleRequest(props);
  }

  /**
   * With named budgets the library labels its header "Retry-After-ip". Clients, including
   * the PHP library and any HTTP library, look for the standard "Retry-After", so it is set
   * under that name (in whole seconds) as well.
   */
  protected async throwThrottlingException(context: ExecutionContext, detail: ThrottlerLimitDetail): Promise<void> {
    const res = context.switchToHttp().getResponse();
    const seconds = Math.max(1, Math.ceil(detail.isBlocked ? detail.timeToBlockExpire : detail.timeToExpire));
    res.setHeader('Retry-After', String(seconds));
    return super.throwThrottlingException(context, detail);
  }

  protected async getTracker(req: Record<string, any>): Promise<string> {
    const token = apiKeyToken(req);
    // The leading part of a key is its public lookup prefix, not the secret.
    return token !== null ? `key:${token.slice(0, 24)}` : super.getTracker(req);
  }
}

/** The presented API key, or null if the request does not carry one. */
export function apiKeyToken(req: { headers?: Record<string, any> }): string | null {
  const header = req.headers?.['authorization'];
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return null;
  const token = header.substring(7).trim();
  return token.startsWith(process.env.API_KEY_PREFIX || 'PMS_') ? token : null;
}
