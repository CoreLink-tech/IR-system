import { fetchJson } from './http.util';
import { IpIntelProvider, PartialIntel } from './provider.types';

/**
 * AbuseIPDB adapter. Requires ABUSEIPDB_API_KEY (the free tier allows 1000
 * checks per day, which the 24 hour result cache keeps well within).
 *
 * abuseConfidenceScore (0-100) becomes the reputation score. An address is
 * flagged malicious only when the score reaches ABUSEIPDB_MALICIOUS_THRESHOLD
 * (default 75), so a few stray reports do not label an address malicious.
 */
export class AbuseIpDbProvider implements IpIntelProvider {
  readonly name = 'abuseipdb';

  constructor(
    private readonly timeoutMs: number,
    private readonly apiKey: string | undefined = process.env.ABUSEIPDB_API_KEY,
    private readonly threshold: number = Number(process.env.ABUSEIPDB_MALICIOUS_THRESHOLD || 75),
  ) {
    if (!this.apiKey) throw new Error('ABUSEIPDB_API_KEY is required for the abuseipdb provider');
  }

  async lookup(ip: string): Promise<PartialIntel | null> {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const body = await fetchJson<any>(url, {
      headers: { Key: this.apiKey! },
      timeoutMs: this.timeoutMs,
    });
    const d = body?.data;
    if (!d) return null;
    const score = Math.max(0, Math.min(100, Number(d.abuseConfidenceScore) || 0));
    const usage = String(d.usageType || '').toLowerCase();
    return {
      country: d.countryCode || undefined,
      reputationScore: score,
      isMalicious: score >= this.threshold,
      isTor: d.isTor === true,
      isDatacenter: usage.includes('data center') || usage.includes('hosting'),
    };
  }
}
