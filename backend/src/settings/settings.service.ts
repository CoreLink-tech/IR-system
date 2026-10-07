import { Injectable } from '@nestjs/common';
import { IpIntelligenceService } from '../ips/ip-intelligence.service';
import { API_VERSION } from '../common/version';
import { cookieSecure } from '../auth/session-cookie';

const num = (v: string | undefined, fallback: number) => {
  const n = Number(v);
  return v !== undefined && v !== '' && Number.isFinite(n) ? n : fallback;
};

/**
 * Operational facts for the Settings page. Everything here is a setting that is safe to show
 * to an administrator. Secrets, keys, connection strings and origins never appear.
 */
@Injectable()
export class SettingsService {
  constructor(private readonly intel: IpIntelligenceService) {}

  operational(env: NodeJS.ProcessEnv = process.env) {
    return {
      version: API_VERSION,
      intelligenceProviders: [...this.intel.providerNames],
      autoBlock: {
        enabled: String(env.AUTO_BLOCK_ENABLED || 'true') === 'true',
        minimumRisk: num(env.AUTO_BLOCK_MIN_RISK, 85),
        blockMinutes: num(env.AUTO_BLOCK_TTL_MINUTES, 60),
      },
      rateLimits: {
        windowSeconds: num(env.THROTTLE_TTL, 60),
        perAddress: num(env.THROTTLE_LIMIT, 120),
        perWebsiteKey: num(env.THROTTLE_KEY_LIMIT, 6000),
        signIn: num(env.THROTTLE_LOGIN_LIMIT, 20),
      },
      riskLevels: {
        suspicious: num(env.RISK_LEVEL_SUSPICIOUS, 30),
        high: num(env.RISK_LEVEL_HIGH, 60),
        critical: num(env.RISK_LEVEL_CRITICAL, 80),
      },
      sessions: {
        accessTokenLifetime: env.JWT_EXPIRES_IN || '15m',
        refreshTokenDays: 7,
        secureCookie: cookieSecure(env),
      },
    };
  }
}
