import { Logger } from '@nestjs/common';
import { AbuseIpDbProvider } from './abuseipdb.provider';
import { IpApiProvider } from './ip-api.provider';
import { IpInfoProvider } from './ipinfo.provider';
import { IpIntelProvider } from './provider.types';
import { TorExitProvider } from './tor-exit.provider';

/**
 * Builds the active provider list from configuration.
 *
 *   IP_INTEL_PROVIDERS=tor,ipapi,abuseipdb     (preferred, comma separated)
 *   IP_INTEL_PROVIDER=ipapi                    (legacy single value, still honoured)
 *   IP_INTEL_TIMEOUT_MS=3000                   (per provider request timeout)
 *
 * "none" or an empty value disables enrichment. Order matters: when two
 * providers disagree on geography, the earlier one wins. Flags are combined
 * with OR and the reputation score takes the highest value.
 *
 * A provider that is misconfigured (for example a missing API key) is skipped
 * with a warning instead of preventing the application from starting.
 */
export function buildProvidersFromEnv(env: NodeJS.ProcessEnv = process.env): IpIntelProvider[] {
  const logger = new Logger('IpIntelProviders');
  const raw = env.IP_INTEL_PROVIDERS ?? env.IP_INTEL_PROVIDER ?? 'none';
  const names = raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s && s !== 'none');
  const timeoutMs = Number(env.IP_INTEL_TIMEOUT_MS || 3000);

  const providers: IpIntelProvider[] = [];
  for (const name of Array.from(new Set(names))) {
    try {
      switch (name) {
        case 'tor':
          providers.push(new TorExitProvider(timeoutMs));
          break;
        case 'ipapi':
          providers.push(new IpApiProvider(timeoutMs, env.IP_API_KEY));
          break;
        case 'ipinfo':
          providers.push(new IpInfoProvider(timeoutMs, env.IPINFO_TOKEN));
          break;
        case 'abuseipdb':
          providers.push(
            new AbuseIpDbProvider(
              timeoutMs,
              env.ABUSEIPDB_API_KEY,
              Number(env.ABUSEIPDB_MALICIOUS_THRESHOLD || 75),
            ),
          );
          break;
        default:
          logger.warn(`Unknown IP intelligence provider '${name}' ignored`);
      }
    } catch (err) {
      logger.warn(`Provider '${name}' disabled: ${(err as Error).message}`);
    }
  }
  logger.log(
    providers.length
      ? `Active providers: ${providers.map((p) => p.name).join(', ')}`
      : 'No IP intelligence providers configured; enrichment is disabled',
  );
  return providers;
}
