import { INestApplication } from '@nestjs/common';
import { clientIpConfig, isTrustedProxy, normalizeIp } from './utils/ip.util';
import { requestIdMiddleware } from './request-id';

/**
 * Settings that must be the same in production and in tests: the request id exists before any
 * guard runs, and Express trusts proxy hops by exactly the same rule as the client address function.
 */
export function configureApp(app: INestApplication): void {
  app.use(requestIdMiddleware);
  const http: any = app.getHttpAdapter().getInstance();
  if (typeof http?.set === 'function') {
    http.set('trust proxy', (addr: string) => {
      const ip = normalizeIp(addr);
      return !!ip && isTrustedProxy(ip, clientIpConfig().trusted);
    });
  }
}
